package alertengine

import (
	"context"
	"fmt"
	"log"
	"math"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/alertmetrics"
	"modern-dns/pkg/db"
	"modern-dns/pkg/notify"

	"gorm.io/gorm"
)

// Engine periodically evaluates monitor rules and alert-subscribe rules
// against recent QueryLog data, emitting AlertEvent rows when thresholds
// are breached.
type Engine struct {
	interval   time.Duration // tick interval (default 30s)
	cooldown   time.Duration // min gap between duplicate alerts (default 5m)
	hotTrigger chan struct{}
	minHotGap  time.Duration
	ruleFor    time.Duration
	lastEvalAt time.Time
	history    *historyWriter
	stopCh     chan struct{}
	wg         sync.WaitGroup
	tickCount  int // counts ticks for periodic housekeeping

	leaderKey  string
	instanceID string
	lastLeader bool

	stateMu      sync.Mutex
	activeRules  map[string]bool
	pendingSince map[string]time.Time
}

// New creates an Engine with the given tick interval.
// A zero or negative interval defaults to 30 seconds.
func New(interval time.Duration) *Engine {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Engine{
		interval:     interval,
		cooldown:     5 * time.Minute,
		hotTrigger:   make(chan struct{}, 1),
		minHotGap:    1 * time.Second,
		ruleFor:      1 * time.Minute,
		history:      newHistoryWriter(),
		stopCh:       make(chan struct{}),
		leaderKey:    "alert:engine:leader",
		instanceID:   buildInstanceID(),
		activeRules:  make(map[string]bool),
		pendingSince: make(map[string]time.Time),
	}
}

// TriggerHotEval requests a near-real-time evaluation pass from the query-log
// write path. Calls are coalesced to one buffered signal so burst traffic does
// not fan out into unbounded evaluator pressure.
func (e *Engine) TriggerHotEval() {
	select {
	case e.hotTrigger <- struct{}{}:
	default:
	}
}

// Start launches the background goroutine.
func (e *Engine) Start() {
	e.history.Start()
	e.wg.Add(1)
	go e.loop()
	log.Printf("[alert-engine] started (interval=%s cooldown=%s)", e.interval, e.cooldown)
}

// Stop signals the goroutine and waits for it to finish.
func (e *Engine) Stop() {
	close(e.stopCh)
	e.wg.Wait()
	e.history.Stop()
	log.Println("[alert-engine] stopped")
}

func (e *Engine) loop() {
	defer e.wg.Done()
	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.tick(true)
		case <-e.hotTrigger:
			e.tick(false)
		}
	}
}

// ─── tick: one evaluation cycle ──────────────────────────────────────────────

func (e *Engine) tick(periodic bool) {
	if !e.tryAcquireLeadership() {
		return
	}

	if !periodic {
		if last := e.lastEvalAt; !last.IsZero() && time.Since(last) < e.minHotGap {
			return
		}
	}
	e.lastEvalAt = time.Now()

	defer func() {
		if r := recover(); r != nil {
			log.Printf("[alert-engine] recovered from panic: %v", r)
		}
	}()

	evalStarted := time.Now()

	e.evalMonitorRules()
	e.evalSubscribeRules()
	alertmetrics.ObserveRuleEvalDuration(time.Since(evalStarted).Seconds())

	// Periodic housekeeping: clean up old QueryLogs and resolved alerts
	// every ~60 ticks (≈30 min at default 30s interval).
	if periodic {
		e.tickCount++
		if e.tickCount%60 == 0 {
			e.cleanupOldData()
		}
	}
}

// cleanupOldData removes QueryLog rows older than 30 days and resolved
// AlertEvent rows older than 7 days to keep the database lean.
func (e *Engine) cleanupOldData() {
	cutoff30d := time.Now().Add(-30 * 24 * time.Hour)
	if result := db.DB.Where("created_at < ?", cutoff30d).Delete(&model.QueryLog{}); result.RowsAffected > 0 {
		log.Printf("[alert-engine] cleaned %d old query logs (>30d)", result.RowsAffected)
	}

	cutoff7d := time.Now().Add(-7 * 24 * time.Hour)
	if result := db.DB.Where("status = ? AND updated_at < ?", "已处理", cutoff7d).Delete(&model.AlertEvent{}); result.RowsAffected > 0 {
		log.Printf("[alert-engine] cleaned %d resolved alert events (>7d)", result.RowsAffected)
	}

	if result := db.DB.Where("handle_status = ? AND trigger_at < ?", "已处理", cutoff7d).Delete(&model.MonitorRuleHistory{}); result.RowsAffected > 0 {
		log.Printf("[alert-engine] cleaned %d old rule history (>7d)", result.RowsAffected)
	}
}

// ─── Monitor rules (singleton rows, id=1) ───────────────────────────────────

func (e *Engine) evalMonitorRules() {
	// QPS spike
	var qps model.MonitorQPSRule
	if db.DB.First(&qps, 1).Error == nil && qps.Enabled {
		e.checkQPS(qps)
	}

	// NXDOMAIN spike
	var nxd model.MonitorNXDomainRule
	if db.DB.First(&nxd, 1).Error == nil && nxd.Enabled {
		e.checkNXDomain(nxd)
	}

	// Latency
	var lat model.MonitorLatencyRule
	if db.DB.First(&lat, 1).Error == nil && lat.Enabled {
		e.checkLatency(lat)
	}

	// Cache hit rate
	var ch model.MonitorCacheHitRule
	if db.DB.First(&ch, 1).Error == nil && ch.Enabled {
		e.checkCacheHit(ch)
	}
}

// checkQPS fires when query count in the period exceeds
// GlobalThresholdPercent of the previous period's count.
func (e *Engine) checkQPS(rule model.MonitorQPSRule) {
	ruleKey := "monitor:qps_spike"
	period := time.Duration(rule.PeriodSec) * time.Second
	if period <= 0 {
		period = 60 * time.Second
	}
	now := time.Now()
	curStart := now.Add(-period)
	prevStart := curStart.Add(-period)

	var curCnt, prevCnt int64
	db.DB.Model(&model.QueryLog{}).Where("created_at >= ? AND created_at < ?", curStart, now).Count(&curCnt)
	db.DB.Model(&model.QueryLog{}).Where("created_at >= ? AND created_at < ?", prevStart, curStart).Count(&prevCnt)

	if prevCnt == 0 {
		e.handleRuleTransition(ruleKey, "warning", "qps_spike", "", "", "QPS突变已恢复")
		return
	}
	pct := float64(curCnt-prevCnt) / float64(prevCnt) * 100
	if pct >= float64(rule.GlobalThresholdPercent) {
		content := fmt.Sprintf("QPS突变: 当前周期 %d 次, 上周期 %d 次, 涨幅 %.1f%% (阈值 %d%%)",
			curCnt, prevCnt, pct, rule.GlobalThresholdPercent)
		e.handleRuleTransition(ruleKey, "warning", "qps_spike", "", content, "QPS突变已恢复")
		return
	}
	e.handleRuleTransition(ruleKey, "warning", "qps_spike", "", "", "QPS突变已恢复")
}

// checkNXDomain fires when NXDOMAIN percentage exceeds ThresholdPercent.
func (e *Engine) checkNXDomain(rule model.MonitorNXDomainRule) {
	ruleKey := "monitor:nxdomain_spike"
	period := time.Duration(rule.PeriodSec) * time.Second
	if period <= 0 {
		period = 60 * time.Second
	}
	since := time.Now().Add(-period)

	var total, nxCnt int64
	db.DB.Model(&model.QueryLog{}).Where("created_at >= ?", since).Count(&total)
	if total == 0 {
		e.handleRuleTransition(ruleKey, "warning", "nxdomain_spike", "", "", "NXDOMAIN比例已恢复")
		return
	}
	db.DB.Model(&model.QueryLog{}).Where("created_at >= ? AND rcode = ?", since, "NXDOMAIN").Count(&nxCnt)

	pct := float64(nxCnt) / float64(total) * 100
	if pct >= float64(rule.ThresholdPercent) {
		content := fmt.Sprintf("NXDOMAIN激增: %d/%d (%.1f%%), 阈值 %d%%",
			nxCnt, total, pct, rule.ThresholdPercent)
		e.handleRuleTransition(ruleKey, "warning", "nxdomain_spike", "", content, "NXDOMAIN比例已恢复")
		return
	}
	e.handleRuleTransition(ruleKey, "warning", "nxdomain_spike", "", "", "NXDOMAIN比例已恢复")
}

// checkLatency fires when avg response time exceeds ThresholdMs.
func (e *Engine) checkLatency(rule model.MonitorLatencyRule) {
	ruleKey := "monitor:latency_high"
	period := time.Duration(rule.PeriodSec) * time.Second
	if period <= 0 {
		period = 60 * time.Second
	}
	since := time.Now().Add(-period)

	var result struct {
		Avg float64 `gorm:"column:avg_rt"`
		Cnt int64   `gorm:"column:cnt"`
	}
	db.DB.Model(&model.QueryLog{}).
		Select("COALESCE(AVG(response_time),0) AS avg_rt, COUNT(*) AS cnt").
		Where("created_at >= ?", since).
		Scan(&result)

	if result.Cnt == 0 {
		e.handleRuleTransition(ruleKey, "warning", "latency_high", "", "", "响应延迟已恢复")
		return
	}
	if int(result.Avg) >= rule.ThresholdMs {
		content := fmt.Sprintf("响应延迟过高: 平均 %.0fms, 阈值 %dms (近 %ds, %d 次查询)",
			result.Avg, rule.ThresholdMs, rule.PeriodSec, result.Cnt)
		e.handleRuleTransition(ruleKey, "warning", "latency_high", "", content, "响应延迟已恢复")
		return
	}
	e.handleRuleTransition(ruleKey, "warning", "latency_high", "", "", "响应延迟已恢复")
}

// checkCacheHit fires when cache hit rate drops below MinHitPercent.
func (e *Engine) checkCacheHit(rule model.MonitorCacheHitRule) {
	ruleKey := "monitor:cache_low"
	period := time.Duration(rule.PeriodSec) * time.Second
	if period <= 0 {
		period = 300 * time.Second
	}
	since := time.Now().Add(-period)

	var total, hitCnt int64
	db.DB.Model(&model.QueryLog{}).Where("created_at >= ?", since).Count(&total)
	if total == 0 {
		e.handleRuleTransition(ruleKey, "info", "cache_low", "", "", "缓存命中率已恢复")
		return
	}
	db.DB.Model(&model.QueryLog{}).Where("created_at >= ? AND response_status = ?", since, "成功").Count(&hitCnt)

	pct := float64(hitCnt) / float64(total) * 100
	if pct < float64(rule.MinHitPercent) {
		content := fmt.Sprintf("缓存命中率过低: %.1f%%, 下限 %d%% (近 %ds, 共 %d 次查询)",
			pct, rule.MinHitPercent, rule.PeriodSec, total)
		e.handleRuleTransition(ruleKey, "info", "cache_low", "", content, "缓存命中率已恢复")
		return
	}
	e.handleRuleTransition(ruleKey, "info", "cache_low", "", "", "缓存命中率已恢复")
}

// ─── Alert Subscribe Rules ──────────────────────────────────────────────────

func (e *Engine) evalSubscribeRules() {
	var rules []model.AlertSubscribeRule
	db.DB.Where("status = ?", "启用").Find(&rules)
	for _, r := range rules {
		e.evalOneSubscribe(r)
	}
}

func (e *Engine) evalOneSubscribe(rule model.AlertSubscribeRule) {
	period := time.Duration(rule.Duration) * time.Second
	if period <= 0 {
		period = 60 * time.Second
	}
	since := time.Now().Add(-period)

	val := e.metricValue(rule.Metric, since)
	if val < 0 {
		return // unknown metric or no data
	}

	triggered := false
	switch rule.Operator {
	case ">":
		triggered = val > rule.Threshold
	case ">=":
		triggered = val >= rule.Threshold
	case "<":
		triggered = val < rule.Threshold
	case "<=":
		triggered = val <= rule.Threshold
	case "==", "=":
		triggered = val == rule.Threshold
	}

	if triggered {
		content := fmt.Sprintf("订阅告警 [%s]: %s %s %.2f (当前 %.2f)",
			rule.Name, rule.Metric, rule.Operator, rule.Threshold, val)
		level := "warning"
		if fired, _ := e.handleRuleTransition(
			fmt.Sprintf("subscribe:%d", rule.ID),
			level,
			"subscribe_"+rule.Metric,
			"",
			content,
			fmt.Sprintf("订阅告警 [%s] 已恢复", rule.Name),
		); fired {
			// Update trigger count
			db.DB.Model(&model.AlertSubscribeRule{}).Where("id = ?", rule.ID).Updates(map[string]interface{}{
				"trigger_count":  gorm.Expr("trigger_count + 1"),
				"last_triggered": time.Now().Format("2006-01-02 15:04:05"),
			})
		}
		return
	}
	e.handleRuleTransition(
		fmt.Sprintf("subscribe:%d", rule.ID),
		"warning",
		"subscribe_"+rule.Metric,
		"",
		"",
		fmt.Sprintf("订阅告警 [%s] 已恢复", rule.Name),
	)
}

// metricValue computes the current metric value for the given period.
// Returns -1 when the metric name is unknown or data is insufficient.
func (e *Engine) metricValue(metric string, since time.Time) float64 {
	metric = normalizeSubscribeMetric(metric)
	switch metric {
	case "qps":
		var cnt int64
		db.DB.Model(&model.QueryLog{}).Where("created_at >= ?", since).Count(&cnt)
		elapsed := time.Since(since).Seconds()
		if elapsed <= 0 {
			return -1
		}
		return float64(cnt) / elapsed

	case "latency", "avg_latency":
		var result struct {
			Avg float64 `gorm:"column:avg_rt"`
			Cnt int64   `gorm:"column:cnt"`
		}
		db.DB.Model(&model.QueryLog{}).
			Select("COALESCE(AVG(response_time),0) AS avg_rt, COUNT(*) AS cnt").
			Where("created_at >= ?", since).Scan(&result)
		if result.Cnt == 0 {
			return -1
		}
		return result.Avg

	case "nxdomain_rate":
		return e.rcodeRate(since, "NXDOMAIN")

	case "cache_hit_rate":
		var total, hitCnt int64
		db.DB.Model(&model.QueryLog{}).Where("created_at >= ?", since).Count(&total)
		if total == 0 {
			return -1
		}
		db.DB.Model(&model.QueryLog{}).Where("created_at >= ? AND response_status = ?", since, "成功").Count(&hitCnt)
		return float64(hitCnt) / float64(total) * 100

	case "error_rate":
		var total, errCnt int64
		db.DB.Model(&model.QueryLog{}).Where("created_at >= ?", since).Count(&total)
		if total == 0 {
			return -1
		}
		db.DB.Model(&model.QueryLog{}).Where("created_at >= ? AND response_status != ?", since, "成功").Count(&errCnt)
		return float64(errCnt) / float64(total) * 100

	case "success_rate":
		v := e.metricValue("error_rate", since)
		if v < 0 {
			return -1
		}
		return 100 - v

	case "servfail_rate":
		return e.rcodeRate(since, "SERVFAIL")

	case "refused_rate":
		return e.rcodeRate(since, "REFUSED")

	case "formerr_rate":
		return e.rcodeRate(since, "FORMERR")

	case "p99_latency":
		var total int64
		db.DB.Model(&model.QueryLog{}).Where("created_at >= ?", since).Count(&total)
		if total == 0 {
			return -1
		}
		offset := int(math.Ceil(float64(total)*0.99)) - 1
		if offset < 0 {
			offset = 0
		}
		var row struct {
			ResponseTime float64 `gorm:"column:response_time"`
		}
		db.DB.Model(&model.QueryLog{}).
			Select("response_time").
			Where("created_at >= ?", since).
			Order("response_time ASC").
			Offset(offset).
			Limit(1).
			Scan(&row)
		if row.ResponseTime <= 0 {
			return -1
		}
		return row.ResponseTime

	case "domain_qps_spike_ratio":
		period := time.Since(since)
		if period <= 0 {
			period = 5 * time.Minute
		}
		prevStart := since.Add(-period)
		var curTop, prevTop int64
		db.DB.Raw("SELECT COALESCE(MAX(c),0) FROM (SELECT COUNT(*) AS c FROM query_logs WHERE created_at >= ? GROUP BY domain) t", since).Scan(&curTop)
		db.DB.Raw("SELECT COALESCE(MAX(c),0) FROM (SELECT COUNT(*) AS c FROM query_logs WHERE created_at >= ? AND created_at < ? GROUP BY domain) t", prevStart, since).Scan(&prevTop)
		if prevTop <= 0 {
			return -1
		}
		return float64(curTop-prevTop) / float64(prevTop) * 100

	case "cache_hit_drop_pct":
		period := time.Since(since)
		if period <= 0 {
			period = 5 * time.Minute
		}
		prevStart := since.Add(-period)
		cur := e.cacheHitRate(since, time.Time{})
		prev := e.cacheHitRate(prevStart, since)
		if cur < 0 || prev < 0 {
			return -1
		}
		return prev - cur

	case "dnssec_failure_rate":
		var total, bad int64
		db.DB.Model(&model.SecurityDNSSEC{}).Count(&total)
		if total == 0 {
			return -1
		}
		db.DB.Model(&model.SecurityDNSSEC{}).Where("signature_status <> ?", "正常").Count(&bad)
		return float64(bad) / float64(total) * 100

	case "cert_expiring_30d_count":
		var cnt int64
		db.DB.Model(&model.TLSCert{}).Where("days_left >= 0 AND days_left <= 30").Count(&cnt)
		return float64(cnt)

	case "cluster_sync_failed_count":
		var cnt int64
		db.DB.Model(&model.ClusterConfigSync{}).
			Where("sync_status NOT IN ?", []string{"已同步", "一致", "success"}).
			Count(&cnt)
		return float64(cnt)

	case "notify_deadletter_15m_count":
		var cnt int64
		db.DB.Model(&model.AlertNotifyDeadLetter{}).Where("created_at >= ?", since).Count(&cnt)
		return float64(cnt)

	default:
		return -1
	}
}

func normalizeSubscribeMetric(metric string) string {
	m := strings.ToLower(strings.TrimSpace(metric))
	switch m {
	case "qps":
		return "qps"
	case "响应时间", "latency", "avg_latency":
		return "latency"
	case "错误率", "error_rate":
		return "error_rate"
	case "成功率", "success_rate", "upstream_success_rate":
		return "success_rate"
	case "nxdomain率", "nxdomain_rate":
		return "nxdomain_rate"
	case "缓存命中率", "cache_hit_rate":
		return "cache_hit_rate"
	case "servfail率", "servfail_rate":
		return "servfail_rate"
	case "refused率", "refused_rate":
		return "refused_rate"
	case "formerr率", "formerr_rate":
		return "formerr_rate"
	case "p99延迟", "p99_latency":
		return "p99_latency"
	case "域名突发倍数", "domain_qps_spike_ratio":
		return "domain_qps_spike_ratio"
	case "缓存退化", "cache_hit_drop_pct":
		return "cache_hit_drop_pct"
	case "dnssec失败率", "dnssec_failure_rate":
		return "dnssec_failure_rate"
	case "证书到期数", "cert_expiring_30d_count":
		return "cert_expiring_30d_count"
	case "集群同步失败节点数", "cluster_sync_failed_count":
		return "cluster_sync_failed_count"
	case "通知死信数", "notify_deadletter_15m_count":
		return "notify_deadletter_15m_count"
	default:
		return m
	}
}

func (e *Engine) rcodeRate(since time.Time, rcode string) float64 {
	var total, cnt int64
	db.DB.Model(&model.QueryLog{}).Where("created_at >= ?", since).Count(&total)
	if total == 0 {
		return -1
	}
	db.DB.Model(&model.QueryLog{}).Where("created_at >= ? AND rcode = ?", since, rcode).Count(&cnt)
	return float64(cnt) / float64(total) * 100
}

func (e *Engine) cacheHitRate(start time.Time, end time.Time) float64 {
	var total, hitCnt int64
	q := db.DB.Model(&model.QueryLog{}).Where("created_at >= ?", start)
	if !end.IsZero() {
		q = q.Where("created_at < ?", end)
	}
	q.Count(&total)
	if total == 0 {
		return -1
	}
	h := db.DB.Model(&model.QueryLog{}).Where("created_at >= ? AND response_status = ?", start, "成功")
	if !end.IsZero() {
		h = h.Where("created_at < ?", end)
	}
	h.Count(&hitCnt)
	return float64(hitCnt) / float64(total) * 100
}

// ─── emit: de-duplicated alert event creation ───────────────────────────────

// emit creates an AlertEvent if no duplicate exists within the cooldown window.
// Returns true if a new event was created.
func (e *Engine) emit(level, alertType, domain, content string) bool {
	if e.isSilenced(level, alertType, domain) {
		e.emitSuppressed("silence", level, alertType, domain, content)
		return false
	}
	if e.isInhibited(level, alertType, domain) {
		e.emitSuppressed("inhibit", level, alertType, domain, content)
		return false
	}
	if !e.acquireCooldown(level, alertType, domain) {
		return false // duplicate within cooldown
	}

	event := model.AlertEvent{
		Level:       level,
		Type:        alertType,
		Domain:      domain,
		Content:     content,
		Status:      "未处理",
		IsRead:      false,
		TriggeredAt: time.Now(),
	}
	if err := db.DB.Create(&event).Error; err != nil {
		log.Printf("[alert-engine] failed to create event: %v", err)
		return false
	}

	alertmetrics.IncEventFired()

	// Also record in monitor_rule_history for the monitor UI, via async writer
	queued := e.history.Enqueue(model.MonitorRuleHistory{
		RuleID:       fmt.Sprintf("AUTO-%d", event.ID),
		RuleType:     alertType,
		Content:      content,
		HandleStatus: "未处理",
		TriggerAt:    event.TriggeredAt,
	})
	if !queued {
		log.Printf("[alert-engine] history queue full, drop event %d", event.ID)
	}

	log.Printf("[alert-engine] emitted [%s] %s: %s", level, alertType, content)

	// Fan out to operator notification channels (email / webhook / SMS).
	// Async on purpose: a slow SMTP server or unreachable webhook must not
	// stall the alert engine's evaluation tick.
	go notify.Dispatch(notify.Event{
		Level:       level,
		Type:        alertType,
		Title:       alertType,
		Message:     content,
		Domain:      domain,
		TriggeredAt: event.TriggeredAt,
	})
	return true
}

func (e *Engine) emitSuppressed(kind, level, alertType, domain, content string) {
	if !e.acquireSuppressedCooldown(kind, alertType, domain) {
		return
	}
	reason := "静默命中"
	if kind == "inhibit" {
		reason = "抑制命中"
	}
	event := model.AlertEvent{
		Level:          level,
		Type:           alertType,
		Domain:         domain,
		Content:        content,
		SuppressType:   kind,
		SuppressReason: reason,
		Status:         "已抑制",
		IsRead:         true,
		TriggeredAt:    time.Now(),
	}
	if err := db.DB.Create(&event).Error; err != nil {
		log.Printf("[alert-engine] failed to create suppressed event: %v", err)
		return
	}
	log.Printf("[alert-engine] suppressed [%s] %s: %s", kind, alertType, content)
}

func (e *Engine) emitResolved(alertType, domain, content string) {
	event := model.AlertEvent{
		Level:       "info",
		Type:        alertType,
		Domain:      domain,
		Content:     content,
		Status:      "已恢复",
		IsRead:      false,
		TriggeredAt: time.Now(),
	}
	if err := db.DB.Create(&event).Error; err != nil {
		log.Printf("[alert-engine] failed to create resolved event: %v", err)
		return
	}
	alertmetrics.IncEventResolved(1)
	go notify.Dispatch(notify.Event{
		Level:       "info",
		Type:        alertType,
		Title:       alertType + " 已恢复",
		Message:     content,
		Domain:      domain,
		TriggeredAt: event.TriggeredAt,
	})
}

func (e *Engine) handleRuleTransition(ruleKey, level, alertType, domain, firingContent, resolvedContent string) (bool, bool) {
	now := time.Now()
	e.stateMu.Lock()
	active := e.activeRules[ruleKey]
	pendingAt, hasPending := e.pendingSince[ruleKey]

	if firingContent != "" {
		if active {
			delete(e.pendingSince, ruleKey)
			e.stateMu.Unlock()
			return false, false
		}
		if !hasPending {
			e.pendingSince[ruleKey] = now
			e.stateMu.Unlock()
			return false, false
		}
		if now.Sub(pendingAt) < e.ruleFor {
			e.stateMu.Unlock()
			return false, false
		}
		delete(e.pendingSince, ruleKey)
		e.stateMu.Unlock()

		if e.emit(level, alertType, domain, firingContent) {
			e.stateMu.Lock()
			e.activeRules[ruleKey] = true
			e.stateMu.Unlock()
			return true, false
		}
		return false, false
	}

	delete(e.pendingSince, ruleKey)
	if !active {
		e.stateMu.Unlock()
		return false, false
	}
	delete(e.activeRules, ruleKey)
	e.stateMu.Unlock()

	if strings.TrimSpace(resolvedContent) == "" {
		resolvedContent = fmt.Sprintf("%s 已恢复", alertType)
	}
	e.emitResolved(alertType, domain, resolvedContent)
	return false, true
}

func (e *Engine) tryAcquireLeadership() bool {
	if db.RDBRateLimit == nil {
		return true
	}

	ttl := e.interval * 2
	if ttl < 10*time.Second {
		ttl = 10 * time.Second
	}
	ctx := context.Background()

	ok, err := db.RDBRateLimit.SetNX(ctx, e.leaderKey, e.instanceID, ttl).Result()
	if err != nil {
		log.Printf("[alert-engine] leader election redis error: %v", err)
		return true // fail open to keep alerting alive
	}
	if ok {
		e.markLeaderState(true)
		return true
	}

	owner, err := db.RDBRateLimit.Get(ctx, e.leaderKey).Result()
	if err == nil && owner == e.instanceID {
		_ = db.RDBRateLimit.Expire(ctx, e.leaderKey, ttl).Err()
		e.markLeaderState(true)
		return true
	}

	e.markLeaderState(false)
	return false
}

func (e *Engine) markLeaderState(isLeader bool) {
	if e.lastLeader == isLeader {
		return
	}
	e.lastLeader = isLeader
	if isLeader {
		log.Printf("[alert-engine] leadership acquired: %s", e.instanceID)
	} else {
		log.Printf("[alert-engine] leadership lost: %s", e.instanceID)
	}
}

func (e *Engine) isSilenced(level, alertType, domain string) bool {
	now := time.Now()
	var rules []model.AlertSilenceRule
	if err := db.DB.Where("status = ? AND start_at <= ? AND end_at >= ?", "启用", now, now).Find(&rules).Error; err != nil || len(rules) == 0 {
		return false
	}
	for _, r := range rules {
		if !wildcardMatch(r.AlertTypePattern, alertType) {
			continue
		}
		if !wildcardMatch(r.DomainPattern, normalizeDomain(domain)) {
			continue
		}
		if !levelMatch(r.Levels, level) {
			continue
		}
		return true
	}
	return false
}

func (e *Engine) isInhibited(level, alertType, domain string) bool {
	var rules []model.AlertInhibitRule
	if err := db.DB.Where("status = ?", "启用").Find(&rules).Error; err != nil || len(rules) == 0 {
		return false
	}
	for _, r := range rules {
		if !wildcardMatch(r.TargetAlertType, alertType) {
			continue
		}
		if !levelMatch(r.TargetLevel, level) {
			continue
		}

		q := db.DB.Model(&model.AlertEvent{}).Where("status = ?", "未处理")
		if strings.TrimSpace(r.SourceAlertType) != "" {
			q = q.Where("type = ?", r.SourceAlertType)
		}
		if strings.TrimSpace(r.SourceLevel) != "" {
			q = q.Where("level = ?", r.SourceLevel)
		}
		if r.DomainScoped {
			q = q.Where("domain = ?", domain)
		}
		var cnt int64
		q.Count(&cnt)
		if cnt > 0 {
			return true
		}
	}
	return false
}

func wildcardMatch(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || pattern == "*" {
		return true
	}
	value = strings.TrimSpace(value)
	if value == "" {
		value = "_"
	}
	if strings.Contains(pattern, "*") {
		ok, _ := path.Match(pattern, value)
		return ok
	}
	return pattern == value
}

func levelMatch(expr, level string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" || expr == "*" {
		return true
	}
	for _, part := range strings.FieldsFunc(expr, func(r rune) bool { return r == ',' || r == ';' || r == '|' }) {
		if strings.EqualFold(strings.TrimSpace(part), strings.TrimSpace(level)) {
			return true
		}
	}
	return false
}

func normalizeDomain(domain string) string {
	d := strings.TrimSpace(domain)
	if d == "" {
		return "_"
	}
	return d
}

func buildInstanceID() string {
	host, _ := os.Hostname()
	if host == "" {
		host = "unknown"
	}
	return host + ":" + strconv.Itoa(os.Getpid())
}

func (e *Engine) cooldownForLevel(level string) time.Duration {
	switch level {
	case "critical", "严重":
		return 1 * time.Minute
	case "info", "提示":
		return 2 * time.Minute
	default:
		return e.cooldown
	}
}

func cooldownKey(alertType, domain string) string {
	if domain == "" {
		domain = "_"
	}
	return fmt.Sprintf("alert:cooldown:%s:%s", alertType, domain)
}

func suppressedCooldownKey(kind, alertType, domain string) string {
	if domain == "" {
		domain = "_"
	}
	return fmt.Sprintf("alert:suppress:%s:%s:%s", kind, alertType, domain)
}

// acquireCooldown persists de-dup state in Redis so restart / multi-instance
// deployments share one cooldown window. Falls back to DB window check when
// Redis is unavailable.
func (e *Engine) acquireCooldown(level, alertType, domain string) bool {
	cd := e.cooldownForLevel(level)
	if cd <= 0 {
		cd = 1 * time.Minute
	}
	if db.RDBRateLimit != nil {
		ok, err := db.RDBRateLimit.SetNX(context.Background(), cooldownKey(alertType, domain), "1", cd).Result()
		if err == nil {
			return ok
		}
		log.Printf("[alert-engine] cooldown redis error: %v", err)
	}

	cutoff := time.Now().Add(-cd)
	var cnt int64
	db.DB.Model(&model.AlertEvent{}).
		Where("type = ? AND domain = ? AND triggered_at >= ?", alertType, domain, cutoff).
		Count(&cnt)
	return cnt == 0
}

func (e *Engine) acquireSuppressedCooldown(kind, alertType, domain string) bool {
	cd := 1 * time.Minute
	if db.RDBRateLimit != nil {
		ok, err := db.RDBRateLimit.SetNX(context.Background(), suppressedCooldownKey(kind, alertType, domain), "1", cd).Result()
		if err == nil {
			return ok
		}
		log.Printf("[alert-engine] suppress cooldown redis error: %v", err)
	}

	cutoff := time.Now().Add(-cd)
	var cnt int64
	db.DB.Model(&model.AlertEvent{}).
		Where("type = ? AND domain = ? AND suppress_type = ? AND triggered_at >= ?", alertType, domain, kind, cutoff).
		Count(&cnt)
	return cnt == 0
}

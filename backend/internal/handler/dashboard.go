package handler

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"modern-dns/internal/model"
	"modern-dns/middleware"
	"modern-dns/pkg/alertmetrics"
	"modern-dns/pkg/db"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
)

// ─── GET /api/dashboard/overview?range=today|7d|30d|custom ───────────────────
//
// When `range=custom`, the caller supplies `start` and `end` as
// `yyyy-MM-dd` strings; we expand the closed interval into per-day
// buckets so the four chart cards line up with the date picker. Any
// other range value uses the fixed grid in computeOverviewBuckets().
func DashboardOverview(c *gin.Context) {
	rangeParam := c.DefaultQuery("range", "today")

	now := time.Now()
	var buckets []overviewBucket
	if rangeParam == "custom" {
		startQ := c.Query("start")
		endQ := c.Query("end")
		buckets = computeCustomBuckets(startQ, endQ, now)
	}
	if len(buckets) == 0 {
		// Either non-custom range or custom with missing / malformed
		// dates — fall back to the fixed grid so the chart never
		// renders empty just because the picker hadn't fired yet.
		buckets = computeOverviewBuckets(rangeParam, now)
	}
	start := buckets[0].startAt

	xLabels := make([]string, len(buckets))
	for i, b := range buckets {
		xLabels[i] = b.label
	}

	// One SQL aggregation per range — pushes the heavy lifting to MySQL
	// instead of pulling every row into Go memory.
	aggs, totalCnt, totalSuccess, totalSumRT := aggregateOverview(buckets, start)

	avgRT := 0
	if totalCnt > 0 {
		avgRT = int(totalSumRT / totalCnt)
	}
	cacheHitRate := 0.0
	if totalCnt > 0 {
		cacheHitRate = float64(totalSuccess) / float64(totalCnt) * 100
	}

	avgArr := make([]float64, len(buckets))
	maxArr := make([]float64, len(buckets))
	minArr := make([]float64, len(buckets))
	qpsArr := make([]float64, len(buckets))
	totalArr := make([]float64, len(buckets))
	countArr := make([]float64, len(buckets))

	for i, b := range buckets {
		a := aggs[i]
		countArr[i] = float64(a.Cnt)
		if a.Cnt > 0 {
			avgArr[i] = math.Round(a.AvgRT*10) / 10
			maxArr[i] = float64(a.MaxRT)
			minArr[i] = float64(a.MinRT)
		}
		durationH := b.endAt.Sub(b.startAt).Hours()
		if durationH < 1 {
			durationH = 1
		}
		qpsArr[i] = math.Round(float64(a.Cnt)/durationH/3600*10) / 10
		totalArr[i] = math.Round(float64(a.Cnt)/1e4*10) / 10
	}
	total := totalCnt
	successCount := totalSuccess

	activeQpsArr := activeOverviewSeries(rangeParam, now, buckets, qpsArr)
	activeAvgArr := activeOverviewSeries(rangeParam, now, buckets, avgArr)
	activeCountArr := activeOverviewSeries(rangeParam, now, buckets, countArr)

	// ── metrics 卡片 ──
	qpsLabel, qpsTrend, qpsDir := buildMetricCard(activeQpsArr)
	_, rtTrend, rtDir := buildMetricCard(activeAvgArr)
	_, totalTrend, totalDir := buildMetricCard(activeCountArr)
	rtStatus := "normal"
	if avgRT > 80 {
		rtStatus = "abnormal"
	} else if avgRT > 40 {
		rtStatus = "elevated"
	}

	metrics := []gin.H{
		{"key": "qps", "labelKey": "dnsQps", "value": qpsLabel, "trend": qpsTrend, "trendDirection": qpsDir},
		{"key": "response", "labelKey": "avgResponseTime", "value": fmt.Sprintf("%dms", avgRT), "trend": rtTrend, "trendDirection": rtDir, "status": rtStatus},
		{"key": "cache", "labelKey": "cacheHitRate", "value": fmt.Sprintf("%.1f%%", cacheHitRate), "percent": cacheHitRate},
		{"key": "total", "labelKey": "totalResolves", "value": formatCount(total), "trend": totalTrend, "trendDirection": totalDir},
	}

	// All four chart cards follow the page-level range selector
	// (今日 / 近7天 / 近30天 / 自定义). We emit `qps / response / cache /
	// total` as a flat, range-scoped payload; the frontend simply
	// binds each chart to its matching key. No per-chart granularity
	// toggle is necessary.
	resp.OK(c, gin.H{
		"metrics": metrics,
		"qps": gin.H{
			"xAxis": xLabels,
			"data":  qpsArr,
		},
		"response": gin.H{
			"xAxis": xLabels,
			"avg":   avgArr,
			"max":   maxArr,
			"min":   minArr,
		},
		"cache": gin.H{
			"total": total,
			"series": []gin.H{
				{"name": "hit", "value": successCount},
				{"name": "miss", "value": total - successCount},
			},
		},
		"total": gin.H{
			"xAxis": xLabels,
			"data":  totalArr,
		},
	})
}

// ─── GET /api/dashboard/domain-status ────────────────────────────────────────
func DashboardDomainStatus(c *gin.Context) {
	// Fetch all zones
	var zones []model.Zone
	db.DB.Order("created_at DESC").Find(&zones)

	// Fetch existing health records indexed by domain
	var healthRows []model.DomainHealth
	db.DB.Find(&healthRows)
	healthMap := make(map[string]model.DomainHealth, len(healthRows))
	for _, h := range healthRows {
		healthMap[h.Domain] = h
	}

	// Merge: every zone gets a health row; missing ones default to "未检测"
	var result []model.DomainHealth
	seen := make(map[string]bool)
	for _, z := range zones {
		seen[z.Domain] = true
		if h, ok := healthMap[z.Domain]; ok {
			result = append(result, h)
		} else {
			result = append(result, model.DomainHealth{
				Domain:       z.Domain,
				Status:       "undetected",
				Availability: "--",
				CheckIP:      "--",
			})
		}
	}
	// Include orphan health rows whose zone was deleted (optional)
	for _, h := range healthRows {
		if !seen[h.Domain] {
			result = append(result, h)
		}
	}
	if result == nil {
		result = []model.DomainHealth{}
	}
	resp.OK(c, result)
}

// ─── GET /api/dashboard/alerts ───────────────────────────────────────────────
//
// Returns the alert center's three feeds in one round-trip. The
// `events` slice is bounded by `?limit=` (default 500, hard cap 5000)
// so the「告警中心」table no longer silently truncates at 50 rows
// when an operator wants to scroll a full week of alerts. The KPI
// tiles on the page should now read off the new `total` field which
// counts *all* alert_events rows, not just the returned slice.
func DashboardAlerts(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "500"))
	if limit < 1 {
		limit = 500
	}
	if limit > 5000 {
		limit = 5000
	}

	var rules []model.AlertRule
	var events []model.AlertEvent
	var auditLogs []model.AlertAuditLog
	var total int64
	db.DB.Model(&model.AlertEvent{}).Count(&total)
	db.DB.Order("created_at DESC").Find(&rules)
	db.DB.Order("triggered_at DESC").Limit(limit).Find(&events)
	db.DB.Order("created_at DESC").Limit(20).Find(&auditLogs)
	if rules == nil {
		rules = []model.AlertRule{}
	}
	if events == nil {
		events = []model.AlertEvent{}
	}
	if auditLogs == nil {
		auditLogs = []model.AlertAuditLog{}
	}
	resp.OK(c, gin.H{
		"rules":     rules,
		"rows":      events,
		"total":     total,
		"auditLogs": auditLogs,
	})
}

// ─── GET /api/dashboard/resource?dim=day|month|year ──────────────────────────
//
// `dim` selects calendar-aligned periods:
//
//   - day   → today, 00:00 .. 24:00 in 4-hour buckets
//   - month → 1st of current month .. now, in daily buckets
//   - year  → Jan 1 of current year .. now, in monthly buckets
//
// The headline "queries" KPI returns the count of query_log rows that
// fall in [periodStart, now], so picking 月/年 actually shows the
// month-to-date / year-to-date totals instead of an unchanging
// all-time count.
func DashboardResource(c *gin.Context) {
	dim := c.DefaultQuery("dim", "day")

	var zoneCount, recordCount int64
	db.DB.Model(&model.Zone{}).Count(&zoneCount)
	db.DB.Model(&model.DNSRecord{}).Count(&recordCount)

	buckets := computeResourceBuckets(dim, time.Now())
	xLabels := make([]string, len(buckets))
	for i, b := range buckets {
		xLabels[i] = b.label
	}
	periodStart := buckets[0].startAt

	// Three independent CASE-WHEN bucket aggregations: queries from
	// query_logs, new zones from zones.created_at, new records from
	// dns_records.created_at. Each is a single round-trip; the older
	// implementation here pretended zones/records had a trend by
	// repeating the lifetime total in every bucket which produced a
	// flat plateau line in the UI.
	queryCounts := aggregateBucketCountsForModel(&model.QueryLog{}, buckets, periodStart)
	zoneDeltas := aggregateBucketCountsForModel(&model.Zone{}, buckets, periodStart)
	recordDeltas := aggregateBucketCountsForModel(&model.DNSRecord{}, buckets, periodStart)

	queriesPerBucket := make([]float64, len(buckets))
	zonesPerBucket := make([]float64, len(buckets))
	recordsPerBucket := make([]float64, len(buckets))
	var queryPeriod int64
	for i := range buckets {
		// Queries kept in 万-units (×10⁴) with one decimal so the
		// y-axis stays human-readable for production traffic where a
		// single day can easily clear 100k requests. Zones / records
		// are raw deltas because their totals are bounded by the
		// quotas (2k zones / 56k records).
		queriesPerBucket[i] = math.Round(float64(queryCounts[i])/1e4*10) / 10
		zonesPerBucket[i] = float64(zoneDeltas[i])
		recordsPerBucket[i] = float64(recordDeltas[i])
		queryPeriod += queryCounts[i]
	}

	// Label key is dim-aware so the frontend can render
	// "今日 / 本月 / 本年查询量" without an extra lookup.
	queryLabelKey := "todayQueries"
	switch dim {
	case "month":
		queryLabelKey = "monthQueries"
	case "year":
		queryLabelKey = "yearQueries"
	}

	const queryQuota = 100_000_000
	const zoneCapacity = 2000
	const recordCapacity = 56000

	metrics := []gin.H{
		{
			"key":       "queries",
			"labelKey":  queryLabelKey,
			"value":     formatCount(queryPeriod),
			"detail":    fmt.Sprintf("%d%%", safePercent(queryPeriod, queryQuota)),
			"detailKey": "quotaUsage",
		},
		{
			"key":       "zones",
			"labelKey":  "hostedZones",
			"value":     formatCount(zoneCount),
			"detail":    fmt.Sprintf("%d / %d", zoneCount, zoneCapacity),
			"detailKey": "capacity",
		},
		{
			"key":       "records",
			"labelKey":  "totalRecordsCount",
			"value":     formatCount(recordCount),
			"detail":    fmt.Sprintf("%d / %d", recordCount, recordCapacity),
			"detailKey": "recordPool",
		},
	}

	// Usage rates compare lifetime totals against the static quotas;
	// they are intentionally NOT dim-scoped — "this month uses 0.1 %
	// of the monthly quota" would be misleading next to a global
	// quota threshold. We keep `queryTotal` here for that purpose.
	var queryTotal int64
	db.DB.Model(&model.QueryLog{}).Count(&queryTotal)
	usage := []gin.H{
		{"labelKey": "queryQuotaUsage", "percent": safePercent(queryTotal, queryQuota), "detail": fmt.Sprintf("%s / %s", formatCount(queryTotal), formatCount(queryQuota))},
		{"labelKey": "zoneCapacityUsage", "percent": safePercent(zoneCount, zoneCapacity), "detail": fmt.Sprintf("%d / %d", zoneCount, zoneCapacity)},
		{"labelKey": "recordPoolUsage", "percent": safePercent(recordCount, recordCapacity), "detail": fmt.Sprintf("%d / %d", recordCount, recordCapacity)},
	}

	resp.OK(c, gin.H{
		dim: gin.H{
			"metrics": metrics,
			"trend": gin.H{
				"xAxis":   xLabels,
				"queries": queriesPerBucket,
				"zones":   zonesPerBucket,
				"records": recordsPerBucket,
			},
			"usage": usage,
		},
	})
}

// ─── GET /api/dashboard/alert-rules ──────────────────────────────────────────
func ListAlertRules(c *gin.Context) {
	keyword := strings.TrimSpace(c.Query("keyword"))
	alertType := c.Query("alertType")
	status := c.Query("status")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "10"))
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 100 {
		size = 10
	}

	query := db.DB.Model(&model.AlertRule{})
	if keyword != "" {
		like := "%" + keyword + "%"
		query = query.Where("rule_name LIKE ? OR rule_id LIKE ? OR target LIKE ? OR remark LIKE ?", like, like, like, like)
	}
	if alertType != "" {
		query = query.Where("alert_type = ?", alertType)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}

	var total int64
	query.Count(&total)
	var rules []model.AlertRule
	query.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&rules)
	if rules == nil {
		rules = []model.AlertRule{}
	}
	resp.OK(c, gin.H{"list": rules, "total": total})
}

// ─── POST /api/dashboard/alert-rules ─────────────────────────────────────────
func AddAlertRule(c *gin.Context) {
	var rule model.AlertRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		resp.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	rule.ID = 0
	rule.RuleID = "ALT-RULE-" + time.Now().Format("20060102150405")
	if err := db.DB.Create(&rule).Error; err != nil {
		resp.ServerError(c, "创建失败: "+err.Error())
		return
	}
	appendAlertAudit(c, "新增告警规则", rule.RuleName)
	resp.OK(c, rule)
}

// ─── PUT /api/dashboard/alert-rules/:id ──────────────────────────────────────
func EditAlertRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var payload struct {
		RuleName  string `json:"ruleName"`
		AlertType string `json:"alertType"`
		Level     string `json:"level"`
		Channel   string `json:"channel"`
		Target    string `json:"target"`
		Threshold int    `json:"threshold"`
		Status    string `json:"status"`
		Remark    string `json:"remark"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	if err := db.DB.Model(&model.AlertRule{}).Where("id = ?", id).Updates(map[string]interface{}{
		"rule_name":  payload.RuleName,
		"alert_type": payload.AlertType,
		"level":      payload.Level,
		"channel":    payload.Channel,
		"target":     payload.Target,
		"threshold":  payload.Threshold,
		"status":     payload.Status,
		"remark":     payload.Remark,
	}).Error; err != nil {
		resp.ServerError(c, "更新失败: "+err.Error())
		return
	}
	var rule model.AlertRule
	db.DB.First(&rule, id)
	appendAlertAudit(c, "编辑告警规则", rule.RuleName)
	resp.OK(c, rule)
}

// ─── DELETE /api/dashboard/alert-rules/:id ───────────────────────────────────
func DeleteAlertRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var rule model.AlertRule
	db.DB.First(&rule, id)
	db.DB.Delete(&model.AlertRule{}, id)
	appendAlertAudit(c, "删除告警规则", rule.RuleName)
	resp.OK(c, gin.H{"id": id})
}

// ─── POST /api/dashboard/alert-rules/:id/test ────────────────────────────────
func TestAlertRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var rule model.AlertRule
	db.DB.First(&rule, id)
	appendAlertAudit(c, "测试发送告警规则", rule.RuleName)
	resp.OK(c, gin.H{"success": true, "id": id, "sentAt": time.Now().Format("2006-01-02 15:04:05")})
}

// ─── PATCH /api/dashboard/alerts/:id/handle ──────────────────────────────────
func HandleAlertEvent(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var event model.AlertEvent
	if err := db.DB.First(&event, id).Error; err != nil {
		resp.NotFound(c, "告警事件不存在")
		return
	}
	result := db.DB.Model(&model.AlertEvent{}).Where("id = ? AND status <> ?", id, "已处理").Updates(map[string]interface{}{
		"status":  "已处理",
		"is_read": true,
	})
	if result.Error == nil && result.RowsAffected > 0 {
		alertmetrics.IncEventResolved(result.RowsAffected)
	}
	markMonitorRuleHistoryHandledByEvent(event)
	appendAlertAudit(c, "标记告警已处理", event.Domain)
	resp.OK(c, gin.H{"id": id, "success": true})
}

// ─── PATCH /api/dashboard/alerts/read-all ────────────────────────────────────
func MarkAllAlertsRead(c *gin.Context) {
	db.DB.Model(&model.AlertEvent{}).Where("is_read = ?", false).Update("is_read", true)
	appendAlertAudit(c, "标记所有告警已读", "全部告警")
	resp.OK(c, gin.H{"success": true})
}

// ─── DELETE /api/dashboard/alerts/batch ──────────────────────────────────────
//
// Hard-delete the selected alert_events rows. The「告警中心」table's
// row-level "处理" button only flips status → 已处理 (audit-friendly,
// reversible at the DB level), but operators also need a way to wipe
// rows they've already triaged from the live list — that's what this
// does. We keep the existing `CleanAlertEvents` (delete-by-age, default
// 30 days) because it's used by retention policy / cron, and split the
// row-selected case off here so we can return the actual deleted count
// to the UI for the success toast.
//
// Body: { "ids": [1,2,3] }. Empty/missing → 400; we deliberately don't
// fall through to "delete all" the way some endpoints do, because the
// action is destructive and ambiguous body shouldn't trigger it.
func BatchDeleteAlertEvents(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if len(req.IDs) == 0 {
		resp.BadRequest(c, "ids 不能为空")
		return
	}

	result := db.DB.Where("id IN ?", req.IDs).Delete(&model.AlertEvent{})
	if result.Error != nil {
		resp.ServerError(c, result.Error.Error())
		return
	}
	appendAlertAudit(c, "批量清理告警", fmt.Sprintf("删除 %d 条", result.RowsAffected))
	resp.OK(c, gin.H{
		"success": true,
		"deleted": result.RowsAffected,
	})
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func appendAlertAudit(c *gin.Context, action, target string) {
	operator := "系统"
	if claims := middleware.GetClaims(c); claims != nil {
		operator = claims.Username
	}
	db.DB.Create(&model.AlertAuditLog{
		Operator: operator,
		Action:   action,
		Target:   target,
		Result:   "成功",
	})
}

// ─── Bucket aggregation helpers ──────────────────────────────────────────────

type overviewBucket struct {
	label   string
	startAt time.Time
	endAt   time.Time
}

// computeCustomBuckets expands a closed date interval [startDate, endDate]
// (both `yyyy-MM-dd`, local-zone semantics) into per-day buckets. Returns
// nil when the inputs are missing / malformed / inverted so the caller
// can fall back to the fixed grid — we never want a broken date picker
// to produce an empty chart.
//
// The interval is capped at 90 days to keep the SQL CASE expression in
// aggregateOverview from blowing up on accidental year-wide picks.
func computeCustomBuckets(startStr, endStr string, now time.Time) []overviewBucket {
	if startStr == "" || endStr == "" {
		return nil
	}
	const layout = "2006-01-02"
	loc := now.Location()
	startDay, err := time.ParseInLocation(layout, startStr, loc)
	if err != nil {
		return nil
	}
	endDay, err := time.ParseInLocation(layout, endStr, loc)
	if err != nil {
		return nil
	}
	if endDay.Before(startDay) {
		return nil
	}
	const maxDays = 90
	days := int(endDay.Sub(startDay).Hours()/24) + 1
	if days > maxDays {
		days = maxDays
		startDay = endDay.AddDate(0, 0, -(maxDays - 1))
	}
	buckets := make([]overviewBucket, 0, days)
	for i := 0; i < days; i++ {
		ds := startDay.AddDate(0, 0, i)
		buckets = append(buckets, overviewBucket{
			label:   ds.Format("01-02"),
			startAt: ds,
			endAt:   ds.AddDate(0, 0, 1),
		})
	}
	return buckets
}

// computeOverviewBuckets builds the fixed-shape time grid used by
// DashboardOverview for each range. The result is always non-empty.
func computeOverviewBuckets(rangeParam string, now time.Time) []overviewBucket {
	var buckets []overviewBucket
	switch rangeParam {
	case "7d":
		for i := 6; i >= 0; i-- {
			d := now.AddDate(0, 0, -i)
			ds := time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, d.Location())
			buckets = append(buckets, overviewBucket{
				label:   ds.Format("01-02"),
				startAt: ds,
				endAt:   ds.AddDate(0, 0, 1),
			})
		}
	case "30d":
		for i := 6; i >= 0; i-- {
			d := now.AddDate(0, 0, -i*5)
			ds := time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, d.Location())
			buckets = append(buckets, overviewBucket{
				label:   ds.Format("01-02"),
				startAt: ds,
				endAt:   ds.AddDate(0, 0, 5),
			})
		}
	default:
		hours := []string{"00:00", "04:00", "08:00", "12:00", "16:00", "20:00", "24:00"}
		for i, h := range hours {
			startH := i * 4
			endH := startH + 4
			if endH > 24 {
				endH = 24
			}
			buckets = append(buckets, overviewBucket{
				label:   h,
				startAt: time.Date(now.Year(), now.Month(), now.Day(), startH, 0, 0, 0, now.Location()),
				endAt:   time.Date(now.Year(), now.Month(), now.Day(), endH, 0, 0, 0, now.Location()),
			})
		}
	}
	return buckets
}

// computeResourceBuckets is the resource-page variant; semantics identical to
// the original DashboardResource implementation.
func computeResourceBuckets(dim string, now time.Time) []overviewBucket {
	loc := now.Location()
	var buckets []overviewBucket
	switch dim {
	case "month":
		// Daily buckets from the 1st of the current month up to (and
		// including) today. End of the last bucket is the end of today
		// so any query log written between 00:00 and now is counted.
		firstOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, loc)
		todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
		for d := firstOfMonth; !d.After(todayStart); d = d.AddDate(0, 0, 1) {
			buckets = append(buckets, overviewBucket{
				label:   d.Format("01-02"),
				startAt: d,
				endAt:   d.AddDate(0, 0, 1),
			})
		}
	case "year":
		// Monthly buckets from January of the current year through
		// the current month inclusive.
		yearStart := time.Date(now.Year(), 1, 1, 0, 0, 0, 0, loc)
		curMonthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, loc)
		for m := yearStart; !m.After(curMonthStart); m = m.AddDate(0, 1, 0) {
			buckets = append(buckets, overviewBucket{
				label:   m.Format("2006-01"),
				startAt: m,
				endAt:   m.AddDate(0, 1, 0),
			})
		}
	default: // day → today 00:00..24:00 in 4-hour buckets (6 total)
		period := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
		hours := []string{"00:00", "04:00", "08:00", "12:00", "16:00", "20:00"}
		for i, h := range hours {
			ts := period.Add(time.Duration(i*4) * time.Hour)
			buckets = append(buckets, overviewBucket{
				label:   h,
				startAt: ts,
				endAt:   ts.Add(4 * time.Hour),
			})
		}
	}
	return buckets
}

type bucketAggRow struct {
	Idx        int     `gorm:"column:bucket_idx"`
	Cnt        int64   `gorm:"column:cnt"`
	AvgRT      float64 `gorm:"column:avg_rt"`
	MaxRT      int     `gorm:"column:max_rt"`
	MinRT      int     `gorm:"column:min_rt"`
	SuccessCnt int64   `gorm:"column:success_cnt"`
}

// aggregateOverview pushes the per-bucket aggregation into a single SQL query
// using a CASE expression to label each row with its bucket index.
// Returns the indexed slice plus overall totals (count, success, sum response_time).
func aggregateOverview(buckets []overviewBucket, since time.Time) ([]bucketAggRow, int64, int64, int64) {
	agg := make([]bucketAggRow, len(buckets))
	if len(buckets) == 0 {
		return agg, 0, 0, 0
	}
	caseExpr, args := buildBucketCase(buckets)

	var rows []bucketAggRow
	db.DB.Model(&model.QueryLog{}).
		Select(caseExpr+" AS bucket_idx, COUNT(*) AS cnt, COALESCE(AVG(response_time),0) AS avg_rt, COALESCE(MAX(response_time),0) AS max_rt, COALESCE(MIN(response_time),0) AS min_rt, SUM(CASE WHEN response_status = '成功' THEN 1 ELSE 0 END) AS success_cnt", args...).
		Where("created_at >= ?", since).
		Group("bucket_idx").
		Scan(&rows)

	var totalCnt, totalSuccess, totalSumRT int64
	for _, r := range rows {
		if r.Idx >= 0 && r.Idx < len(agg) {
			agg[r.Idx] = r
		}
		totalCnt += r.Cnt
		totalSuccess += r.SuccessCnt
		totalSumRT += int64(r.AvgRT * float64(r.Cnt))
	}
	return agg, totalCnt, totalSuccess, totalSumRT
}

// aggregateBucketCounts is a lighter aggregation when only counts per bucket
// are needed (DashboardResource). Retained as a thin wrapper over
// aggregateBucketCountsForModel so existing call sites keep compiling.
func aggregateBucketCounts(buckets []overviewBucket, since time.Time) []int64 {
	return aggregateBucketCountsForModel(&model.QueryLog{}, buckets, since)
}

// aggregateBucketCountsForModel computes a COUNT(*) per bucket for any
// model whose table has a `created_at` column. Collapses into a single
// GROUP BY query using a CASE expression that maps every row to its
// bucket index, so the caller pays exactly one round-trip regardless
// of bucket count.
func aggregateBucketCountsForModel(target any, buckets []overviewBucket, since time.Time) []int64 {
	counts := make([]int64, len(buckets))
	if len(buckets) == 0 {
		return counts
	}
	caseExpr, args := buildBucketCase(buckets)

	var rows []struct {
		Idx int   `gorm:"column:bucket_idx"`
		Cnt int64 `gorm:"column:cnt"`
	}
	db.DB.Model(target).
		Select(caseExpr+" AS bucket_idx, COUNT(*) AS cnt", args...).
		Where("created_at >= ?", since).
		Group("bucket_idx").
		Scan(&rows)
	for _, r := range rows {
		if r.Idx >= 0 && r.Idx < len(counts) {
			counts[r.Idx] = r.Cnt
		}
	}
	return counts
}

// buildBucketCase constructs a SQL CASE expression that maps a query_log row
// to its bucket index, plus the matching positional args.
func buildBucketCase(buckets []overviewBucket) (string, []interface{}) {
	var sb strings.Builder
	args := make([]interface{}, 0, len(buckets)*2)
	sb.WriteString("(CASE ")
	for i, b := range buckets {
		sb.WriteString("WHEN created_at >= ? AND created_at < ? THEN ")
		sb.WriteString(strconv.Itoa(i))
		sb.WriteString(" ")
		args = append(args, b.startAt, b.endAt)
	}
	sb.WriteString("ELSE -1 END)")
	return sb.String(), args
}

func formatCount(n int64) string {
	if n >= 1_000_000_000 {
		return fmt.Sprintf("%.1fB", float64(n)/1e9)
	}
	if n >= 1_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.1fK", float64(n)/1e3)
	}
	return strconv.FormatInt(n, 10)
}

func safePercent(cur, total int64) int {
	if total == 0 {
		return 0
	}
	p := int(float64(cur) / float64(total) * 100)
	if p > 100 {
		return 100
	}
	return p
}

func buildMetricCard(arr []float64) (label, trend, dir string) {
	if len(arr) == 0 {
		return "0", "+0%", "up"
	}
	last := arr[len(arr)-1]
	prev := 0.0
	if len(arr) >= 2 {
		prev = arr[len(arr)-2]
	}
	label = fmt.Sprintf("%.0f", last)
	if prev == 0 {
		return label, "+0%", "up"
	}
	delta := (last - prev) / prev * 100
	if delta >= 0 {
		trend = fmt.Sprintf("+%.1f%%", delta)
		dir = "up"
	} else {
		trend = fmt.Sprintf("%.1f%%", delta)
		dir = "down"
	}
	return
}

// activeOverviewSeries trims trailing future buckets for the "today" range
// so cards don't read the untouched future bucket as current value.
func activeOverviewSeries(rangeParam string, now time.Time, buckets []overviewBucket, arr []float64) []float64 {
	if len(arr) == 0 || rangeParam != "today" {
		return arr
	}
	activeEnd := 0
	for i, b := range buckets {
		if !b.startAt.After(now) {
			activeEnd = i + 1
		}
	}
	if activeEnd <= 0 {
		activeEnd = 1
	}
	if activeEnd > len(arr) {
		activeEnd = len(arr)
	}
	return arr[:activeEnd]
}

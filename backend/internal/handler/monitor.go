package handler

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// ─── Real-time ────────────────────────────────────────────────────────────────

// GET /api/monitor/realtime
func GetRealTimeLogs(c *gin.Context) {
	domain := c.Query("domain")
	sourceIP := c.Query("sourceIp")
	status := c.Query("status")
	rcode := c.Query("rcode")
	recordType := c.Query("recordType")
	startTime := c.Query("startTime")
	endTime := c.Query("endTime")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "500"))
	if page < 1 {
		page = 1
	}
	// Default page size 500 for the table view; allow up to 10000 per
	// request so the「导出全部」flow can drain 70k+ rows in a handful
	// of round-trips instead of being silently capped at 5k. The
	// frontend page-loops once it observes (page * size < total).
	if size < 1 {
		size = 500
	}
	if size > 10000 {
		size = 10000
	}

	query := db.DB.Model(&model.QueryLog{})
	if domain != "" {
		query = query.Where("domain LIKE ?", "%"+domain+"%")
	}
	if sourceIP != "" {
		query = query.Where("source_ip LIKE ?", "%"+sourceIP+"%")
	}
	if rcode != "" {
		query = query.Where("r_code = ?", rcode)
	} else if status != "" {
		// Backward compatibility: older callers send `status` for the
		// return-code selector. Match both textual response status
		// (成功/失败/处理中) and protocol rcode (NOERROR/NXDOMAIN/...)
		// so existing clients continue to work.
		query = query.Where("response_status = ? OR r_code = ?", status, status)
	}
	if recordType != "" {
		query = query.Where("record_type = ?", recordType)
	}
	if startTime != "" {
		query = query.Where("created_at >= ?", startTime)
	}
	if endTime != "" {
		query = query.Where("created_at <= ?", endTime)
	}

	var total int64
	query.Count(&total)
	var logs []model.QueryLog
	query.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&logs)
	if logs == nil {
		logs = []model.QueryLog{}
	}
	resp.OK(c, gin.H{"total": total, "rows": logs})
}

// POST /api/monitor/realtime/refresh
func RefreshRealTime(c *gin.Context) {
	resp.OK(c, gin.H{"success": true, "refreshedAt": time.Now().Format("2006-01-02 15:04:05")})
}

// ─── Resolve Logs ─────────────────────────────────────────────────────────────

// GET /api/monitor/resolve-logs
func GetResolveLogs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	if page < 1 {
		page = 1
	}
	domain := c.Query("domain")
	sourceIP := c.Query("sourceIp")
	status := c.Query("status")
	rcode := c.Query("rcode")
	recordType := c.Query("recordType")
	startTime := c.Query("startTime")
	endTime := c.Query("endTime")
	keyword := c.Query("keyword")

	query := db.DB.Model(&model.QueryLog{})
	if keyword != "" {
		query = query.Where("domain LIKE ? OR source_ip LIKE ? OR query_id LIKE ?",
			"%"+keyword+"%", "%"+keyword+"%", "%"+keyword+"%")
	}
	if domain != "" {
		query = query.Where("domain LIKE ?", "%"+domain+"%")
	}
	if sourceIP != "" {
		query = query.Where("source_ip LIKE ?", "%"+sourceIP+"%")
	}
	if status != "" {
		query = query.Where("response_status = ?", status)
	}
	if rcode != "" {
		query = query.Where("r_code = ?", rcode)
	}
	if recordType != "" {
		query = query.Where("record_type = ?", recordType)
	}
	if startTime != "" {
		query = query.Where("created_at >= ?", startTime)
	}
	if endTime != "" {
		query = query.Where("created_at <= ?", endTime)
	}

	var total int64
	query.Count(&total)

	var logs []model.QueryLog
	query.Order("created_at DESC").
		Offset((page - 1) * size).
		Limit(size).
		Find(&logs)
	if logs == nil {
		logs = []model.QueryLog{}
	}
	resp.OK(c, gin.H{"total": total, "rows": logs})
}

// POST /api/monitor/resolve-logs/export
// Returns metadata; actual file generation would be handled by a job queue in production.
func ExportResolveLogs(c *gin.Context) {
	var req struct {
		Format    string   `json:"format"`
		Scope     string   `json:"scope"`
		Domain    string   `json:"domain"`
		TimeRange []string `json:"timeRange"`
	}
	c.ShouldBindJSON(&req)
	if req.Format == "" {
		req.Format = "xlsx"
	}
	// Human-readable Chinese target for the audit table; raw key=value
	// kept in Detail for parsers.
	scopeLabel := req.Scope
	if scopeLabel == "" {
		scopeLabel = "全部"
	}
	writeOpLogAuth(c, "导出", "解析日志",
		fmt.Sprintf("导出 %s 格式 · 范围：%s", strings.ToUpper(req.Format), scopeLabel),
		fmt.Sprintf(`{"format":"%s","scope":"%s"}`, req.Format, req.Scope),
	)
	resp.OK(c, gin.H{
		"success":    true,
		"format":     req.Format,
		"exportedAt": time.Now().Format("2006-01-02 15:04:05"),
	})
}

// ─── Monitor Rules ────────────────────────────────────────────────────────────

// GET /api/monitor/rules
func GetMonitorRules(c *gin.Context) {
	var qps model.MonitorQPSRule
	var nxd model.MonitorNXDomainRule
	var lat model.MonitorLatencyRule
	var ch model.MonitorCacheHitRule
	// FirstOrCreate treats every non-zero field of the conditions
	// struct as part of the WHERE clause. Passing default values
	// directly (e.g. ThresholdMs: 200) meant that once an operator
	// tuned the threshold in the UI the lookup missed on the next
	// request and GORM re-attempted INSERT id=1 → primary-key
	// collision, producing the noisy `Duplicate entry '1'` log on
	// every /api/monitor/rules hit.
	//
	// Correct shape: WHERE only on ID, set defaults via Attrs (which
	// are applied exclusively when creating, never when querying).
	db.DB.Where(model.MonitorQPSRule{ID: 1}).FirstOrCreate(&qps)
	db.DB.Where(model.MonitorNXDomainRule{ID: 1}).FirstOrCreate(&nxd)
	db.DB.Where(model.MonitorLatencyRule{ID: 1}).
		Attrs(model.MonitorLatencyRule{ThresholdMs: 200, PeriodSec: 60, Enabled: false}).
		FirstOrCreate(&lat)
	db.DB.Where(model.MonitorCacheHitRule{ID: 1}).
		Attrs(model.MonitorCacheHitRule{MinHitPercent: 70, PeriodSec: 300, Enabled: false}).
		FirstOrCreate(&ch)

	page, _ := strconv.Atoi(c.DefaultQuery("historyPage", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("historySize", "20"))
	if page < 1 {
		page = 1
	}
	// Repair stale rows from earlier builds where handling an alert event did
	// not propagate to monitor_rule_history.
	reconcileMonitorRuleHistoryHandled(120)
	ruleType := c.Query("ruleType")
	handleStatus := c.Query("handleStatus")

	query := db.DB.Model(&model.MonitorRuleHistory{})
	if ruleType != "" {
		query = query.Where("rule_type = ?", ruleType)
	}
	if handleStatus != "" {
		query = query.Where("handle_status = ?", handleStatus)
	}
	var histTotal int64
	query.Count(&histTotal)
	var history []model.MonitorRuleHistory
	query.Order("trigger_at DESC").Offset((page - 1) * size).Limit(size).Find(&history)
	if history == nil {
		history = []model.MonitorRuleHistory{}
	}
	resp.OK(c, gin.H{
		"qps":          qps,
		"nxdomain":     nxd,
		"latency":      lat,
		"cacheHit":     ch,
		"history":      history,
		"historyTotal": histTotal,
	})
}

// PUT /api/monitor/rules/qps
func SaveQPSRule(c *gin.Context) {
	var req model.MonitorQPSRule
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	req.ID = 1
	db.DB.Save(&req)
	// Record to history
	entry := model.MonitorRuleHistory{
		RuleID:       fmt.Sprintf("MON-RULE-%d", time.Now().UnixMilli()%1000000),
		RuleType:     "QPS突变",
		TriggerAt:    time.Now(),
		Content:      fmt.Sprintf("更新QPS阈值：全局 %d%% / 单域名 %d%%", req.GlobalThresholdPercent, req.DomainThresholdPercent),
		HandleStatus: "已处理",
	}
	db.DB.Create(&entry)
	resp.OK(c, req)
}

// POST /api/monitor/rules/qps/reset
func ResetQPSRule(c *gin.Context) {
	defaults := model.MonitorQPSRule{
		ID:                     1,
		GlobalThresholdPercent: 50,
		DomainThresholdPercent: 100,
		PeriodSec:              60,
		Enabled:                true,
	}
	db.DB.Save(&defaults)
	resp.OK(c, defaults)
}

// PUT /api/monitor/rules/nxdomain
func SaveNXDomainRule(c *gin.Context) {
	var req model.MonitorNXDomainRule
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	req.ID = 1
	db.DB.Save(&req)
	entry := model.MonitorRuleHistory{
		RuleID:       fmt.Sprintf("MON-RULE-%d", time.Now().UnixMilli()%1000000),
		RuleType:     "NXDOMAIN激增",
		TriggerAt:    time.Now(),
		Content:      fmt.Sprintf("更新NXDOMAIN阈值：%d%%", req.ThresholdPercent),
		HandleStatus: "已处理",
	}
	db.DB.Create(&entry)
	resp.OK(c, req)
}

// POST /api/monitor/rules/nxdomain/reset
func ResetNXDomainRule(c *gin.Context) {
	defaults := model.MonitorNXDomainRule{
		ID:               1,
		ThresholdPercent: 200,
		PeriodSec:        60,
		Enabled:          true,
	}
	db.DB.Save(&defaults)
	resp.OK(c, defaults)
}

// PUT /api/monitor/rules/latency
func SaveLatencyRule(c *gin.Context) {
	var req model.MonitorLatencyRule
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	req.ID = 1
	db.DB.Save(&req)
	entry := model.MonitorRuleHistory{
		RuleID:       fmt.Sprintf("MON-RULE-%d", time.Now().UnixMilli()%1000000),
		RuleType:     "响应延迟",
		TriggerAt:    time.Now(),
		Content:      fmt.Sprintf("更新响应延迟阈值：%dms", req.ThresholdMs),
		HandleStatus: "已处理",
	}
	db.DB.Create(&entry)
	resp.OK(c, req)
}

// POST /api/monitor/rules/latency/reset
func ResetLatencyRule(c *gin.Context) {
	defaults := model.MonitorLatencyRule{
		ID:          1,
		ThresholdMs: 200,
		PeriodSec:   60,
		Enabled:     true,
	}
	db.DB.Save(&defaults)
	resp.OK(c, defaults)
}

// PUT /api/monitor/rules/cache-hit
func SaveCacheHitRule(c *gin.Context) {
	var req model.MonitorCacheHitRule
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	req.ID = 1
	db.DB.Save(&req)
	entry := model.MonitorRuleHistory{
		RuleID:       fmt.Sprintf("MON-RULE-%d", time.Now().UnixMilli()%1000000),
		RuleType:     "缓存命中率",
		TriggerAt:    time.Now(),
		Content:      fmt.Sprintf("更新缓存命中率下限：%d%%", req.MinHitPercent),
		HandleStatus: "已处理",
	}
	db.DB.Create(&entry)
	resp.OK(c, req)
}

// POST /api/monitor/rules/cache-hit/reset
func ResetCacheHitRule(c *gin.Context) {
	defaults := model.MonitorCacheHitRule{
		ID:            1,
		MinHitPercent: 70,
		PeriodSec:     300,
		Enabled:       true,
	}
	db.DB.Save(&defaults)
	resp.OK(c, defaults)
}

// PATCH /api/monitor/rule-history/:id/handle
func HandleRuleHistory(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Model(&model.MonitorRuleHistory{}).Where("id = ?", id).
		Update("handle_status", "已处理")
	resp.OK(c, gin.H{"id": id, "success": true})
}

// ─── Report ───────────────────────────────────────────────────────────────────

// GET /api/monitor/report
func GetMonitorReport(c *gin.Context) {
	startTime := c.Query("startTime")
	endTime := c.Query("endTime")
	domain := c.Query("domain")

	base := db.DB.Model(&model.QueryLog{})
	if startTime != "" {
		base = base.Where("created_at >= ?", startTime)
	}
	if endTime != "" {
		base = base.Where("created_at <= ?", endTime)
	}
	if domain != "" {
		base = base.Where("domain LIKE ?", "%"+domain+"%")
	}

	type nameCount struct {
		Name  string `json:"name"`
		Value int64  `json:"value"`
	}

	var topDomains []nameCount
	base.Session(&gorm.Session{}).
		Select("domain as name, COUNT(*) as value").
		Group("domain").Order("value DESC").Limit(10).
		Scan(&topDomains)

	var topIPs []nameCount
	base.Session(&gorm.Session{}).
		Select("source_ip as name, COUNT(*) as value").
		Group("source_ip").Order("value DESC").Limit(10).
		Scan(&topIPs)

	var statusDist []nameCount
	base.Session(&gorm.Session{}).
		Select("response_status as name, COUNT(*) as value").
		Group("response_status").
		Scan(&statusDist)

	// Heatmap: region × time-period buckets
	type heatRow struct {
		Region string `json:"region"`
		Hour   int    `json:"hour"`
		Count  int64  `json:"count"`
	}
	var heatRows []heatRow
	base.Session(&gorm.Session{}).
		Select("region, HOUR(created_at) as hour, COUNT(*) as count").
		Group("region, HOUR(created_at)").
		Scan(&heatRows)

	regions := []string{"华东", "华北", "华南", "西南", "海外"}
	periods := []string{"00-06", "06-12", "12-18", "18-24"}
	periodOf := func(h int) int {
		if h < 6 {
			return 0
		} else if h < 12 {
			return 1
		} else if h < 18 {
			return 2
		}
		return 3
	}
	regionIdx := map[string]int{}
	for i, r := range regions {
		regionIdx[r] = i
	}
	heatMatrix := make(map[[2]int]int64)
	for _, row := range heatRows {
		ri, ok := regionIdx[row.Region]
		if !ok {
			continue
		}
		pi := periodOf(row.Hour)
		heatMatrix[[2]int{ri, pi}] += row.Count
	}
	heatValues := make([][]int64, 0, len(heatMatrix))
	for k, v := range heatMatrix {
		heatValues = append(heatValues, []int64{int64(k[0]), int64(k[1]), v})
	}

	if topDomains == nil {
		topDomains = []nameCount{}
	}
	if topIPs == nil {
		topIPs = []nameCount{}
	}
	if statusDist == nil {
		statusDist = []nameCount{}
	}

	resp.OK(c, gin.H{
		"topDomain": topDomains,
		"topIp":     topIPs,
		"heatmap": gin.H{
			"regions": regions,
			"periods": periods,
			"values":  heatValues,
		},
		"statusDistribution": statusDist,
	})
}

// GET /api/monitor/report/extended
//
// Companion of GetMonitorReport that returns the five A-tier
// aggregations the operator UI uses to fill the「扩展报表」grid.
// Kept on a separate route (rather than bolted onto the base report
// payload) because:
//
//   - older clients still parse the original four-field shape;
//   - the queries here scan the same `query_logs` window but a couple
//     of them are non-trivial (rcode time-series in particular), so
//     isolating them lets us add caching or async pre-aggregation
//     later without disturbing the main report endpoint.
//
// Time window defaults to the last 24h when no range is supplied so a
// blank request still returns something useful for embedding in a
// dashboard.
func GetMonitorReportExtended(c *gin.Context) {
	startTime := c.Query("startTime")
	endTime := c.Query("endTime")
	domain := c.Query("domain")

	base := db.DB.Model(&model.QueryLog{})
	if startTime != "" {
		base = base.Where("created_at >= ?", startTime)
	} else {
		base = base.Where("created_at >= ?", time.Now().Add(-24*time.Hour))
	}
	if endTime != "" {
		base = base.Where("created_at <= ?", endTime)
	}
	if domain != "" {
		base = base.Where("domain LIKE ?", "%"+domain+"%")
	}

	type nameCount struct {
		Name  string `json:"name"`
		Value int64  `json:"value"`
	}

	// ── 1) Record type distribution ─────────────────────────────────
	var recordTypes []nameCount
	base.Session(&gorm.Session{}).
		Select("record_type as name, COUNT(*) as value").
		Where("record_type <> ''").
		Group("record_type").Order("value DESC").
		Scan(&recordTypes)
	if recordTypes == nil {
		recordTypes = []nameCount{}
	}

	// ── 2) Response-time histogram (six fixed buckets) ──────────────
	//
	// One scan, six COUNT(*) ... WHEN clauses. CASE WHEN inside a
	// single SELECT is far cheaper than six separate queries when the
	// table is partitioned by created_at.
	type latencyRow struct {
		B0   int64 `json:"b0"`
		B10  int64 `json:"b10"`
		B50  int64 `json:"b50"`
		B200 int64 `json:"b200"`
		B500 int64 `json:"b500"`
		BHi  int64 `json:"bHi"`
	}
	var lat latencyRow
	base.Session(&gorm.Session{}).
		Select(`
			SUM(CASE WHEN response_time <  10 THEN 1 ELSE 0 END) AS b0,
			SUM(CASE WHEN response_time >= 10 AND response_time <  50 THEN 1 ELSE 0 END) AS b10,
			SUM(CASE WHEN response_time >= 50 AND response_time < 200 THEN 1 ELSE 0 END) AS b50,
			SUM(CASE WHEN response_time >= 200 AND response_time < 500 THEN 1 ELSE 0 END) AS b200,
			SUM(CASE WHEN response_time >= 500 AND response_time < 1000 THEN 1 ELSE 0 END) AS b500,
			SUM(CASE WHEN response_time >= 1000 THEN 1 ELSE 0 END) AS b_hi
		`).
		Scan(&lat)
	latencyBuckets := []nameCount{
		{Name: "<10ms", Value: lat.B0},
		{Name: "10-50ms", Value: lat.B10},
		{Name: "50-200ms", Value: lat.B50},
		{Name: "200-500ms", Value: lat.B200},
		{Name: "500-1000ms", Value: lat.B500},
		{Name: ">=1000ms", Value: lat.BHi},
	}

	// ── 3) QPS trend (hour-bucketed) + 4) rcode trend (same buckets)
	//
	// We share the bucket axis between the two charts so the rcode
	// stack lines up exactly with the QPS curve.
	type bucketRow struct {
		Bucket time.Time `json:"bucket"`
		RCode  string    `json:"rCode"`
		Count  int64     `json:"count"`
	}
	var rows []bucketRow
	base.Session(&gorm.Session{}).
		Select(`
			DATE_FORMAT(created_at, '%Y-%m-%d %H:00:00') AS bucket,
			r_code AS r_code,
			COUNT(*) AS count
		`).
		Group("bucket, r_code").
		Order("bucket ASC").
		Scan(&rows)

	// Build axis + per-rcode series.
	bucketSet := map[string]struct{}{}
	rcodeSet := map[string]struct{}{}
	cellMap := map[string]map[string]int64{} // bucket -> rcode -> count
	for _, r := range rows {
		key := r.Bucket.Format("2006-01-02 15:04")
		bucketSet[key] = struct{}{}
		rcode := r.RCode
		if rcode == "" {
			rcode = "UNKNOWN"
		}
		rcodeSet[rcode] = struct{}{}
		if cellMap[key] == nil {
			cellMap[key] = map[string]int64{}
		}
		cellMap[key][rcode] += r.Count
	}
	// Stable axes — sort the bucket strings lexicographically (the
	// format keeps lexicographic == chronological) and sort rcodes by
	// total volume descending so the legend reads largest-first.
	periodsX := make([]string, 0, len(bucketSet))
	for k := range bucketSet {
		periodsX = append(periodsX, k)
	}
	sortStrings(periodsX)
	rcodes := make([]string, 0, len(rcodeSet))
	for k := range rcodeSet {
		rcodes = append(rcodes, k)
	}
	totals := map[string]int64{}
	for _, cells := range cellMap {
		for code, n := range cells {
			totals[code] += n
		}
	}
	sortStringsByInt64Desc(rcodes, totals)

	type rcodeSeries struct {
		Name string  `json:"name"`
		Data []int64 `json:"data"`
	}
	rcodeTrendSeries := make([]rcodeSeries, 0, len(rcodes))
	qpsValues := make([]int64, len(periodsX))
	for _, code := range rcodes {
		data := make([]int64, len(periodsX))
		for i, p := range periodsX {
			n := cellMap[p][code]
			data[i] = n
			qpsValues[i] += n
		}
		rcodeTrendSeries = append(rcodeTrendSeries, rcodeSeries{Name: code, Data: data})
	}

	// ── 5) Top slow domains (avg response_time) ─────────────────────
	//
	// Floor count at 5 so a single slow outlier from a low-volume
	// domain doesn't pollute the list; rank by avg latency desc.
	type slowDomainRow struct {
		Name         string  `json:"name"`
		AvgLatencyMs float64 `json:"avgLatencyMs"`
		MaxLatencyMs int64   `json:"maxLatencyMs"`
		SampleCount  int64   `json:"sampleCount"`
	}
	var slowDomains []slowDomainRow
	base.Session(&gorm.Session{}).
		Select(`
			domain AS name,
			AVG(response_time) AS avg_latency_ms,
			MAX(response_time) AS max_latency_ms,
			COUNT(*) AS sample_count
		`).
		Group("domain").
		Having("COUNT(*) >= 5").
		Order("avg_latency_ms DESC").
		Limit(10).
		Scan(&slowDomains)
	if slowDomains == nil {
		slowDomains = []slowDomainRow{}
	}

	resp.OK(c, gin.H{
		"recordTypes":    recordTypes,
		"latencyBuckets": latencyBuckets,
		"qpsTrend": gin.H{
			"periods": periodsX,
			"values":  qpsValues,
		},
		"rcodeTrend": gin.H{
			"periods": periodsX,
			"series":  rcodeTrendSeries,
		},
		"slowDomains": slowDomains,
	})
}

// sortStrings is a tiny helper so the report handler doesn't have to
// import sort just for one call site.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// sortStringsByInt64Desc reorders `s` so that elements whose
// `weights[s[i]]` is larger come first. Insertion sort suits us here
// because the input is small (a handful of rcodes).
func sortStringsByInt64Desc(s []string, weights map[string]int64) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && weights[s[j-1]] < weights[s[j]]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"modern-dns/internal/dnsengine"
	"modern-dns/internal/model"
	"modern-dns/pkg/db"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// GET /api/forward/global
func GetForwardGlobal(c *gin.Context) {
	var cfg model.ForwardGlobal
	db.DB.FirstOrCreate(&cfg, model.ForwardGlobal{ID: 1})
	var servers []model.ForwardServer
	db.DB.Order("priority").Find(&servers)
	resp.OK(c, gin.H{
		"enabled":          cfg.Enabled,
		"publicDns":        cfg.PublicDNS,
		"publicDnsEnabled": cfg.PublicDNSEnabled,
		"publicDnsCustom":  cfg.PublicDNSCustom,
		"timeout":          cfg.Timeout,
		"retries":          cfg.Retries,
		"strategy":         cfg.Strategy,
		"servers":          servers,
		"providers": []gin.H{
			{"label": "Google DNS", "value": "Google DNS", "ips": []string{"8.8.8.8", "8.8.4.4"}},
			{"label": "Cloudflare DNS", "value": "Cloudflare DNS", "ips": []string{"1.1.1.1", "1.0.0.1"}},
			{"label": "阿里DNS", "value": "AliDNS", "ips": []string{"223.5.5.5", "223.6.6.6"}},
			{"label": "腾讯DNS", "value": "Tencent DNS", "ips": []string{"119.29.29.29", "182.254.116.116"}},
		},
	})
}

// PUT /api/forward/global
func SaveForwardGlobal(c *gin.Context) {
	var req model.ForwardGlobal
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	req.ID = 1
	db.DB.Save(&req)
	resp.OK(c, req)
}

// POST /api/forward/global/toggle
func ToggleForwardGlobal(c *gin.Context) {
	var req struct {
		Enabled          *bool `json:"enabled"`
		PublicDNSEnabled *bool `json:"publicDnsEnabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	db.DB.FirstOrCreate(&model.ForwardGlobal{}, model.ForwardGlobal{ID: 1})

	updates := map[string]interface{}{}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}
	if req.PublicDNSEnabled != nil {
		updates["public_dns_enabled"] = *req.PublicDNSEnabled
	}
	if len(updates) == 0 {
		resp.BadRequest(c, "缺少可更新的开关字段")
		return
	}
	if err := db.DB.Model(&model.ForwardGlobal{}).Where("id = 1").Updates(updates).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}

	var cfg model.ForwardGlobal
	if err := db.DB.First(&cfg, 1).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	resp.OK(c, gin.H{
		"enabled":          cfg.Enabled,
		"publicDnsEnabled": cfg.PublicDNSEnabled,
	})
}

// GET /api/forward/servers
func ListForwardServers(c *gin.Context) {
	var servers []model.ForwardServer
	db.DB.Order("priority").Find(&servers)
	resp.OK(c, servers)
}

// POST /api/forward/servers
func CreateForwardServer(c *gin.Context) {
	var server model.ForwardServer
	if err := c.ShouldBindJSON(&server); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if server.Port <= 0 {
		server.Port = 53
	}
	if server.Priority <= 0 {
		server.Priority = 1
	}
	server.ID = 0
	if err := db.DB.Create(&server).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	resp.OK(c, server)
}

// PUT /api/forward/servers/:id
func UpdateForwardServer(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var payload struct {
		Name     string `json:"name"`
		Address  string `json:"address"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Priority int    `json:"priority"`
		Status   string `json:"status"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	db.DB.Model(&model.ForwardServer{}).Where("id = ?", id).Updates(map[string]interface{}{
		"name":     payload.Name,
		"address":  payload.Address,
		"port":     payload.Port,
		"protocol": payload.Protocol,
		"priority": payload.Priority,
		"status":   payload.Status,
	})
	var server model.ForwardServer
	db.DB.First(&server, id)
	resp.OK(c, server)
}

// DELETE /api/forward/servers/:id
func DeleteForwardServer(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Delete(&model.ForwardServer{}, id)
	db.DB.Model(&model.ForwardRule{}).Where("upstream_id = ?", id).Update("status", "禁用")
	resp.OK(c, gin.H{"id": id})
}

// GET /api/forward/condition/rules
func ListForwardRules(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	size, _ := strconv.Atoi(c.DefaultQuery("size", "10"))
	if size < 1 {
		size = 10
	}
	if size > 200 {
		size = 200
	}

	keyword := strings.TrimSpace(c.Query("keyword"))
	status := strings.TrimSpace(c.Query("status"))
	sortProp := strings.TrimSpace(c.DefaultQuery("sortProp", "priority"))
	sortOrder := strings.TrimSpace(c.DefaultQuery("sortOrder", "ascending"))
	timeRange := c.QueryArray("timeRange")
	if len(timeRange) == 0 {
		timeRange = c.QueryArray("timeRange[]")
	}

	query := db.DB.Model(&model.ForwardRule{})
	if keyword != "" {
		like := "%" + keyword + "%"
		query = query.Where("rule_id LIKE ? OR domains LIKE ? OR upstream_name LIKE ? OR remark LIKE ?", like, like, like, like)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if len(timeRange) >= 2 {
		startAt, startErr := parseForwardRuleTimeRange(timeRange[0], false)
		endAt, endErr := parseForwardRuleTimeRange(timeRange[1], true)
		if startErr == nil && endErr == nil {
			query = query.Where("created_at BETWEEN ? AND ?", startAt, endAt)
		}
	}

	orderColumnMap := map[string]string{
		"id":           "id",
		"ruleId":       "rule_id",
		"domains":      "domains",
		"upstreamId":   "upstream_id",
		"upstreamName": "upstream_name",
		"priority":     "priority",
		"status":       "status",
		"remark":       "remark",
		"createdAt":    "created_at",
		"updatedAt":    "updated_at",
	}
	orderColumn, ok := orderColumnMap[sortProp]
	if !ok {
		orderColumn = "priority"
	}
	orderDirection := "ASC"
	if strings.EqualFold(sortOrder, "descending") {
		orderDirection = "DESC"
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}

	var rules []model.ForwardRule
	if err := query.Order(orderColumn + " " + orderDirection).
		Order("id ASC").
		Offset((page - 1) * size).
		Limit(size).
		Find(&rules).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}

	resp.OK(c, gin.H{
		"list":  rules,
		"total": total,
	})
}

// POST /api/forward/condition/rules
func CreateForwardRule(c *gin.Context) {
	var rule model.ForwardRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if rule.Priority <= 0 {
		rule.Priority = 1
	}
	var server model.ForwardServer
	if db.DB.First(&server, rule.UpstreamID).Error == nil {
		rule.UpstreamName = fmt.Sprintf("%s / %s:%d", server.Name, server.Address, server.Port)
	}
	rule.ID = 0
	rule.RuleID = "FWD-RULE-" + strconv.FormatInt(time.Now().UnixMilli()%1000000, 10)
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&rule).Error; err != nil {
			return err
		}
		return syncForwardPrioritiesTx(tx)
	}); err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	resp.OK(c, rule)
}

// PUT /api/forward/condition/rules/:id
//
// PATCH-style: only fields actually present in the JSON are written
// back. LbGroupID accepts three shapes from the frontend:
//   - omitted          → don't touch the column
//   - explicit null    → clear the binding (rule reverts to UpstreamID-only)
//   - non-zero number  → bind the rule to that LB group
//
// Distinguishing "absent" from "explicit null" requires a
// **pointer-to-pointer** (`**uint`) since a single-pointer field cannot
// tell the two apart after json.Unmarshal. We instead read the raw map
// once for presence detection and the typed payload for value extraction.
func UpdateForwardRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	var payload struct {
		Domains    string  `json:"domains"`
		UpstreamID *uint   `json:"upstreamId"`
		LbGroupID  *uint   `json:"lbGroupId"`
		Priority   *int    `json:"priority"`
		Status     string  `json:"status"`
		Remark     string  `json:"remark"`
		Protocol   *string `json:"protocol"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	var present map[string]json.RawMessage
	_ = json.Unmarshal(body, &present)

	updates := map[string]interface{}{
		"domains": payload.Domains,
		"status":  payload.Status,
		"remark":  payload.Remark,
	}
	if payload.UpstreamID != nil {
		updates["upstream_id"] = *payload.UpstreamID
		var server model.ForwardServer
		if db.DB.First(&server, *payload.UpstreamID).Error == nil {
			updates["upstream_name"] = fmt.Sprintf("%s / %s:%d", server.Name, server.Address, server.Port)
		}
	}
	if _, hasLb := present["lbGroupId"]; hasLb {
		// Either explicit null (clear) or a non-zero ID (bind). Storing
		// nil writes SQL NULL via gorm so the resolver's pointer check
		// correctly treats it as "no LB binding".
		if payload.LbGroupID != nil && *payload.LbGroupID > 0 {
			updates["lb_group_id"] = *payload.LbGroupID
		} else {
			updates["lb_group_id"] = nil
		}
	}
	if payload.Priority != nil {
		updates["priority"] = *payload.Priority
	}
	if payload.Protocol != nil {
		// Empty string is a valid value here — it clears the override
		// so the rule reverts to inheriting the global UpstreamProtocolOrder.
		updates["protocol"] = *payload.Protocol
	}
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.ForwardRule{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			return err
		}
		return syncForwardPrioritiesTx(tx)
	}); err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	var rule model.ForwardRule
	if err := db.DB.First(&rule, id).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	resp.OK(c, rule)
}

// DELETE /api/forward/condition/rules/:id
func DeleteForwardRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&model.ForwardRule{}, id).Error; err != nil {
			return err
		}
		return syncForwardPrioritiesTx(tx)
	}); err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	resp.OK(c, gin.H{"id": id})
}

// PUT /api/forward/condition/rules/batch-status
func BatchUpdateForwardRuleStatus(c *gin.Context) {
	var req struct {
		IDs    []uint `json:"ids"`
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	db.DB.Model(&model.ForwardRule{}).Where("id IN ?", req.IDs).Update("status", req.Status)
	resp.OK(c, req)
}

// DELETE /api/forward/condition/rules/batch
func BatchDeleteForwardRules(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if _, err := validateForwardRuleIDs(db.DB, req.IDs); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&model.ForwardRule{}, req.IDs).Error; err != nil {
			return err
		}
		return syncForwardPrioritiesTx(tx)
	}); err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	resp.OK(c, gin.H{"ids": req.IDs})
}

// PUT /api/forward/condition/rules/reorder
func ReorderForwardRules(c *gin.Context) {
	var req struct {
		OrderedIDs []uint `json:"orderedIds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	// 校验必须提交所有规则ID，不能只传部分ID
	var allIDs []uint
	if err := db.DB.Model(&model.ForwardRule{}).Pluck("id", &allIDs).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	if len(req.OrderedIDs) != len(allIDs) {
		resp.BadRequest(c, fmt.Errorf("必须提交全部 %d 个规则ID，实际只提交了 %d 个", len(allIDs), len(req.OrderedIDs)).Error())
		return
	}
	allSet := make(map[uint]struct{}, len(allIDs))
	for _, id := range allIDs {
		allSet[id] = struct{}{}
	}
	for _, id := range req.OrderedIDs {
		if _, ok := allSet[id]; !ok {
			resp.BadRequest(c, fmt.Errorf("提交的规则ID %d 不存在于当前规则集合", id).Error())
			return
		}
	}
	if _, err := validateForwardRuleIDs(db.DB, req.OrderedIDs); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		priorities := make(map[uint]int, len(req.OrderedIDs))
		for i, id := range req.OrderedIDs {
			priorities[id] = i + 1
		}
		return bulkUpdateForwardRulePrioritiesTx(tx, priorities)
	}); err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	resp.OK(c, req)
}

// GET /api/forward/traffic-stats
// Returns hourly query counts for the last 24 hours, broken down by response status.
func GetForwardTrafficStats(c *gin.Context) {
	type hourBucket struct {
		Hour    string `json:"hour"`
		Total   int64  `json:"total"`
		Success int64  `json:"success"`
		Fail    int64  `json:"fail"`
	}

	now := time.Now()
	buckets := make([]hourBucket, 24)
	for i := 0; i < 24; i++ {
		t := now.Add(time.Duration(i-23) * time.Hour)
		buckets[i].Hour = t.Format("15:00")
	}

	startTime := now.Add(-24 * time.Hour)

	type dbRow struct {
		HourLabel string `gorm:"column:hour_label"`
		Status    string `gorm:"column:response_status"`
		Cnt       int64  `gorm:"column:cnt"`
	}
	var rows []dbRow
	db.DB.Model(&model.QueryLog{}).
		Select("DATE_FORMAT(created_at, '%H:00') AS hour_label, response_status, COUNT(*) AS cnt").
		Where("created_at >= ?", startTime).
		Group("hour_label, response_status").
		Scan(&rows)

	hourMap := map[string]*hourBucket{}
	for i := range buckets {
		hourMap[buckets[i].Hour] = &buckets[i]
	}
	for _, r := range rows {
		b, ok := hourMap[r.HourLabel]
		if !ok {
			continue
		}
		b.Total += r.Cnt
		if r.Status == "成功" {
			b.Success += r.Cnt
		} else {
			b.Fail += r.Cnt
		}
	}

	// Totals
	var totalQueries int64
	var successQueries int64
	for _, b := range buckets {
		totalQueries += b.Total
		successQueries += b.Success
	}

	resp.OK(c, gin.H{
		"buckets": buckets,
		"total":   totalQueries,
		"success": successQueries,
		"fail":    totalQueries - successQueries,
		"successRate": func() float64 {
			if totalQueries == 0 {
				return 0
			}
			return float64(successQueries) / float64(totalQueries) * 100
		}(),
	})
}

// POST /api/forward/latency-test
//
// Probes a batch of DNS upstreams and returns per-target latency +
// status. Body:
//
//	{ "targets": [
//	    { "id": 1, "label": "Google", "ip": "8.8.8.8",
//	      "port": 53, "protocol": "UDP" },
//	    ...
//	]}
//
// `id` / `port` / `protocol` are optional; when omitted we fall back
// to UDP/53 so callers that only know the IP (the historical contract)
// still work. The probe itself is delegated to dnsengine.ProbeUpstream
// so the global-forward health card and the LB health card share one
// implementation — historically these had drifted (the global card
// used a UDP-only RD=0 probe to <random>.invalid which 公共 recursive
// resolvers silently drop, so every upstream looked dead in the UI
// even when DNS resolution worked).
//
// Concurrency is bounded so a 50-target batch with several DoH timeouts
// can't burn N*timeout = 100s of wall clock; instead the worst case
// is `ceil(N/probeFanout) * timeout`.
func LatencyTest(c *gin.Context) {
	type targetReq struct {
		ID       uint   `json:"id"`
		Label    string `json:"label"`
		IP       string `json:"ip"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
	}
	var req struct {
		Targets []targetReq `json:"targets"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if len(req.Targets) == 0 || len(req.Targets) > 50 {
		resp.BadRequest(c, "targets 数量应在 1-50 之间")
		return
	}

	type result struct {
		ID        uint   `json:"id"`
		Label     string `json:"label"`
		IP        string `json:"ip"`
		LatencyMs *int64 `json:"latencyMs"`
		Status    string `json:"status"` // "done" | "fail"
		Error     string `json:"error,omitempty"`
	}
	results := make([]result, len(req.Targets))

	const probeTimeout = 3 * time.Second
	// Cap fan-out so a batch full of DoH timeouts can't exhaust the
	// goroutine scheduler or the upstream's connection budget. 16 is
	// well above the ~6 protocol clients we maintain warm pools for
	// but small enough that 50 targets * 3s timeout still finishes
	// inside the gateway request deadline.
	const probeFanout = 16
	sem := make(chan struct{}, probeFanout)

	var wg sync.WaitGroup
	for i, t := range req.Targets {
		if strings.TrimSpace(t.IP) == "" {
			results[i] = result{ID: t.ID, Label: t.Label, IP: t.IP, Status: "fail", Error: "empty ip"}
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, tg targetReq) {
			defer wg.Done()
			defer func() { <-sem }()

			port := tg.Port
			if port <= 0 {
				port = 53
			}
			ms, ok, err := dnsengine.ProbeUpstream(tg.IP, port, tg.Protocol, probeTimeout)
			if ok {
				latency := ms
				results[idx] = result{ID: tg.ID, Label: tg.Label, IP: tg.IP, LatencyMs: &latency, Status: "done"}
				return
			}
			errStr := ""
			if err != nil {
				errStr = err.Error()
				if len(errStr) > 200 {
					errStr = errStr[:200] + "…"
				}
			}
			results[idx] = result{ID: tg.ID, Label: tg.Label, IP: tg.IP, LatencyMs: nil, Status: "fail", Error: errStr}
		}(i, t)
	}
	wg.Wait()

	// Aggregate KPIs so the frontend doesn't have to re-derive them
	// (and so different views — overview card, modal popover — agree).
	var (
		online, slow, timeout int
		latSum, latCount      int64
	)
	for _, r := range results {
		if r.Status != "done" || r.LatencyMs == nil {
			timeout++
			continue
		}
		latSum += *r.LatencyMs
		latCount++
		if *r.LatencyMs < 200 {
			online++
		} else {
			slow++
		}
	}
	var avg *int64
	if latCount > 0 {
		v := latSum / latCount
		avg = &v
	}

	resp.OK(c, gin.H{
		"results": results,
		"summary": gin.H{
			"total":      len(results),
			"online":     online,
			"slow":       slow,
			"timeout":    timeout,
			"avgLatency": avg,
		},
	})
}

func syncForwardPriorities() {
	_ = syncForwardPrioritiesTx(db.DB)
}

func syncForwardPrioritiesTx(tx *gorm.DB) error {
	var rules []model.ForwardRule
	if err := tx.Order("priority, id").Find(&rules).Error; err != nil {
		return err
	}
	priorities := make(map[uint]int, len(rules))
	for i, r := range rules {
		priorities[r.ID] = i + 1
	}
	return bulkUpdateForwardRulePrioritiesTx(tx, priorities)
}

func validateForwardRuleIDs(tx *gorm.DB, ids []uint) ([]uint, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("规则 ID 不能为空")
	}

	seen := make(map[uint]struct{}, len(ids))
	uniqueIDs := make([]uint, 0, len(ids))
	for _, id := range ids {
		if id == 0 {
			return nil, fmt.Errorf("规则 ID 必须大于 0")
		}
		if _, exists := seen[id]; exists {
			return nil, fmt.Errorf("规则 ID %d 重复", id)
		}
		seen[id] = struct{}{}
		uniqueIDs = append(uniqueIDs, id)
	}

	var existingIDs []uint
	if err := tx.Model(&model.ForwardRule{}).Where("id IN ?", uniqueIDs).Pluck("id", &existingIDs).Error; err != nil {
		return nil, err
	}
	if len(existingIDs) != len(uniqueIDs) {
		existingSet := make(map[uint]struct{}, len(existingIDs))
		for _, id := range existingIDs {
			existingSet[id] = struct{}{}
		}
		missingIDs := make([]string, 0)
		for _, id := range uniqueIDs {
			if _, exists := existingSet[id]; !exists {
				missingIDs = append(missingIDs, strconv.FormatUint(uint64(id), 10))
			}
		}
		return nil, fmt.Errorf("规则 ID 不存在: %s", strings.Join(missingIDs, ", "))
	}

	return uniqueIDs, nil
}

func bulkUpdateForwardRulePrioritiesTx(tx *gorm.DB, priorities map[uint]int) error {
	if len(priorities) == 0 {
		return nil
	}

	tableName := model.ForwardRule{}.TableName()
	var builder strings.Builder
	args := make([]interface{}, 0, len(priorities)*3)
	idList := make([]uint, 0, len(priorities))

	builder.WriteString("UPDATE ")
	builder.WriteString(tableName)
	builder.WriteString(" SET priority = CASE id")
	for id, priority := range priorities {
		builder.WriteString(" WHEN ? THEN ?")
		args = append(args, id, priority)
		idList = append(idList, id)
	}
	builder.WriteString(" END WHERE id IN ?")
	args = append(args, idList)

	return tx.Exec(builder.String(), args...).Error
}

func parseForwardRuleTimeRange(raw string, endOfDay bool) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, fmt.Errorf("empty time range value")
	}

	layouts := []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02",
	}
	for _, layout := range layouts {
		parsed, err := time.ParseInLocation(layout, raw, time.Local)
		if err != nil {
			continue
		}
		if layout == "2006-01-02" && endOfDay {
			return parsed.Add(23*time.Hour + 59*time.Minute + 59*time.Second), nil
		}
		return parsed, nil
	}

	return time.Time{}, fmt.Errorf("invalid time range value: %s", raw)
}

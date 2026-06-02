package handler

import (
	"strconv"
	"strings"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
)

// GET /api/monitor/alert-subscribe/rules
func ListAlertSubscribeRules(c *gin.Context) {
	ensureBuiltinAlertSubscribeRules()
	var rules []model.AlertSubscribeRule
	db.DB.Order("created_at DESC").Find(&rules)
	if rules == nil {
		rules = []model.AlertSubscribeRule{}
	}
	resp.OK(c, rules)
}

// POST /api/monitor/alert-subscribe/rules
func CreateAlertSubscribeRule(c *gin.Context) {
	var rule model.AlertSubscribeRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	rule.Metric = normalizeSubscribeMetric(rule.Metric)
	if rule.ContactGroupID > 0 {
		var cnt int64
		db.DB.Model(&model.AlertContactGroup{}).Where("id = ?", rule.ContactGroupID).Count(&cnt)
		if cnt == 0 {
			resp.BadRequest(c, "联系人组不存在")
			return
		}
	}
	rule.ID = 0
	if rule.Status == "" {
		rule.Status = "启用"
	}
	if rule.SilenceMinutes < 0 {
		rule.SilenceMinutes = 0
	}
	rule.TriggerCount = 0
	rule.LastTriggered = "—"
	if err := db.DB.Create(&rule).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	resp.OK(c, rule)
}

// PUT /api/monitor/alert-subscribe/rules/:id
func UpdateAlertSubscribeRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var payload struct {
		Name           string  `json:"name"`
		Metric         string  `json:"metric"`
		Operator       string  `json:"operator"`
		Threshold      float64 `json:"threshold"`
		Unit           string  `json:"unit"`
		Duration       int     `json:"duration"`
		Channels       string  `json:"channels"`
		Status         string  `json:"status"`
		ContactGroupID uint    `json:"contactGroupId"`
		SilenceMinutes int     `json:"silenceMinutes"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	payload.Metric = normalizeSubscribeMetric(payload.Metric)
	if payload.ContactGroupID > 0 {
		var cnt int64
		db.DB.Model(&model.AlertContactGroup{}).Where("id = ?", payload.ContactGroupID).Count(&cnt)
		if cnt == 0 {
			resp.BadRequest(c, "联系人组不存在")
			return
		}
	}
	if payload.SilenceMinutes < 0 {
		payload.SilenceMinutes = 0
	}
	if err := db.DB.Model(&model.AlertSubscribeRule{}).Where("id = ?", id).Updates(map[string]interface{}{
		"name":             payload.Name,
		"metric":           payload.Metric,
		"operator":         payload.Operator,
		"threshold":        payload.Threshold,
		"unit":             payload.Unit,
		"duration":         payload.Duration,
		"channels":         payload.Channels,
		"status":           payload.Status,
		"contact_group_id": payload.ContactGroupID,
		"silence_minutes":  payload.SilenceMinutes,
	}).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	var rule model.AlertSubscribeRule
	db.DB.First(&rule, id)
	resp.OK(c, rule)
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

func ensureBuiltinAlertSubscribeRules() {
	builtins := []model.AlertSubscribeRule{
		{Name: "上游可用率过低", Metric: "success_rate", Operator: "<", Threshold: 98, Unit: "%", Duration: 300, Channels: "邮件,WebHook", Status: "启用", LastTriggered: "—"},
		{Name: "SERVFAIL异常率", Metric: "servfail_rate", Operator: ">", Threshold: 2, Unit: "%", Duration: 300, Channels: "邮件,WebHook", Status: "启用", LastTriggered: "—"},
		{Name: "REFUSED异常率", Metric: "refused_rate", Operator: ">", Threshold: 1, Unit: "%", Duration: 300, Channels: "邮件,WebHook", Status: "启用", LastTriggered: "—"},
		{Name: "FORMERR异常率", Metric: "formerr_rate", Operator: ">", Threshold: 1, Unit: "%", Duration: 300, Channels: "邮件,WebHook", Status: "启用", LastTriggered: "—"},
		{Name: "域名流量突增", Metric: "domain_qps_spike_ratio", Operator: ">", Threshold: 300, Unit: "%", Duration: 300, Channels: "邮件,WebHook", Status: "启用", LastTriggered: "—"},
		{Name: "缓存退化", Metric: "cache_hit_drop_pct", Operator: ">", Threshold: 20, Unit: "%", Duration: 300, Channels: "邮件,WebHook", Status: "启用", LastTriggered: "—"},
		{Name: "P99响应延迟", Metric: "p99_latency", Operator: ">", Threshold: 800, Unit: "ms", Duration: 300, Channels: "邮件,WebHook", Status: "启用", LastTriggered: "—"},
		{Name: "DNSSEC失败率", Metric: "dnssec_failure_rate", Operator: ">", Threshold: 0.5, Unit: "%", Duration: 300, Channels: "邮件,WebHook", Status: "启用", LastTriggered: "—"},
		{Name: "证书30天内到期", Metric: "cert_expiring_30d_count", Operator: ">", Threshold: 0, Unit: "个", Duration: 300, Channels: "邮件,WebHook", Status: "启用", LastTriggered: "—"},
		{Name: "集群同步失败节点数", Metric: "cluster_sync_failed_count", Operator: ">", Threshold: 0, Unit: "个", Duration: 300, Channels: "邮件,WebHook", Status: "启用", LastTriggered: "—"},
		{Name: "通知死信积压", Metric: "notify_deadletter_15m_count", Operator: ">", Threshold: 0, Unit: "个", Duration: 300, Channels: "邮件,WebHook", Status: "启用", LastTriggered: "—"},
		{Name: "整体错误率过高", Metric: "error_rate", Operator: ">", Threshold: 5, Unit: "%", Duration: 300, Channels: "邮件,WebHook", Status: "启用", LastTriggered: "—"},
	}

	for _, r := range builtins {
		var cnt int64
		db.DB.Model(&model.AlertSubscribeRule{}).Where("name = ?", r.Name).Count(&cnt)
		if cnt > 0 {
			continue
		}
		r.TriggerCount = 0
		r.ContactGroupID = 0
		r.SilenceMinutes = 0
		db.DB.Create(&r)
	}
}

// DELETE /api/monitor/alert-subscribe/rules/:id
func DeleteAlertSubscribeRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Delete(&model.AlertSubscribeRule{}, id)
	resp.OK(c, gin.H{"success": true})
}

// PATCH /api/monitor/alert-subscribe/rules/:id/toggle
func ToggleAlertSubscribeRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req struct {
		Status string `json:"status"`
	}
	c.ShouldBindJSON(&req)
	db.DB.Model(&model.AlertSubscribeRule{}).Where("id = ?", id).Update("status", req.Status)
	resp.OK(c, gin.H{"success": true})
}

// PATCH /api/monitor/alert-subscribe/rules/batch
func BatchUpdateAlertSubscribeRules(c *gin.Context) {
	var req struct {
		IDs            []uint  `json:"ids"`
		Status         *string `json:"status"`
		Duration       *int    `json:"duration"`
		SilenceMinutes *int    `json:"silenceMinutes"`
		ContactGroupID *uint   `json:"contactGroupId"`
		Channels       *string `json:"channels"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}

	ids := make([]uint, 0, len(req.IDs))
	seen := map[uint]struct{}{}
	for _, id := range req.IDs {
		if id == 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		resp.BadRequest(c, "ids 不能为空")
		return
	}

	updates := map[string]interface{}{}
	if req.Status != nil {
		status := strings.TrimSpace(*req.Status)
		if status != "启用" && status != "禁用" {
			resp.BadRequest(c, "status 仅支持 启用/禁用")
			return
		}
		updates["status"] = status
	}
	if req.Duration != nil {
		if *req.Duration < 1 {
			resp.BadRequest(c, "duration 必须大于等于 1")
			return
		}
		updates["duration"] = *req.Duration
	}
	if req.SilenceMinutes != nil {
		sm := *req.SilenceMinutes
		if sm < 0 {
			sm = 0
		}
		updates["silence_minutes"] = sm
	}
	if req.ContactGroupID != nil {
		if *req.ContactGroupID > 0 {
			var cnt int64
			db.DB.Model(&model.AlertContactGroup{}).Where("id = ?", *req.ContactGroupID).Count(&cnt)
			if cnt == 0 {
				resp.BadRequest(c, "联系人组不存在")
				return
			}
		}
		updates["contact_group_id"] = *req.ContactGroupID
	}
	if req.Channels != nil {
		updates["channels"] = strings.TrimSpace(*req.Channels)
	}

	if len(updates) == 0 {
		resp.BadRequest(c, "至少提供一个可更新字段")
		return
	}

	if err := db.DB.Model(&model.AlertSubscribeRule{}).Where("id IN ?", ids).Updates(updates).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	resp.OK(c, gin.H{"success": true, "updated": len(ids)})
}

// GET /api/monitor/alert-subscribe/contact-groups
func ListAlertContactGroups(c *gin.Context) {
	var groups []model.AlertContactGroup
	db.DB.Order("created_at DESC").Find(&groups)
	if groups == nil {
		groups = []model.AlertContactGroup{}
	}
	resp.OK(c, groups)
}

// POST /api/monitor/alert-subscribe/contact-groups
func CreateAlertContactGroup(c *gin.Context) {
	var group model.AlertContactGroup
	if err := c.ShouldBindJSON(&group); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	group.ID = 0
	group.Name = strings.TrimSpace(group.Name)
	if group.Name == "" {
		resp.BadRequest(c, "联系人组名称不能为空")
		return
	}
	if group.Status == "" {
		group.Status = "启用"
	}
	if err := db.DB.Create(&group).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	resp.OK(c, group)
}

// PUT /api/monitor/alert-subscribe/contact-groups/:id
func UpdateAlertContactGroup(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var payload struct {
		Name          string `json:"name"`
		MemberUserIDs string `json:"memberUserIds"`
		Remark        string `json:"remark"`
		Status        string `json:"status"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	name := strings.TrimSpace(payload.Name)
	if name == "" {
		resp.BadRequest(c, "联系人组名称不能为空")
		return
	}
	if err := db.DB.Model(&model.AlertContactGroup{}).Where("id = ?", id).Updates(map[string]interface{}{
		"name":            name,
		"member_user_ids": payload.MemberUserIDs,
		"remark":          payload.Remark,
		"status":          payload.Status,
	}).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	var group model.AlertContactGroup
	db.DB.First(&group, id)
	resp.OK(c, group)
}

// DELETE /api/monitor/alert-subscribe/contact-groups/:id
func DeleteAlertContactGroup(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Delete(&model.AlertContactGroup{}, id)
	// Unbind rules referencing deleted groups to keep data consistent.
	db.DB.Model(&model.AlertSubscribeRule{}).Where("contact_group_id = ?", id).Update("contact_group_id", 0)
	resp.OK(c, gin.H{"success": true})
}

// GET /api/monitor/alert-subscribe/users
func ListAlertContactUsers(c *gin.Context) {
	includeDisabled := c.Query("includeDisabled") == "1"
	query := db.DB.Model(&model.User{})
	if !includeDisabled {
		query = query.Where("status = ?", "启用")
	}
	var users []model.User
	query.Order("created_at DESC").Find(&users)
	if users == nil {
		users = []model.User{}
	}
	resp.OK(c, users)
}

// GET /api/monitor/alert-subscribe/silence-rules
func ListAlertSilenceRules(c *gin.Context) {
	var rules []model.AlertSilenceRule
	db.DB.Order("created_at DESC").Find(&rules)
	if rules == nil {
		rules = []model.AlertSilenceRule{}
	}
	resp.OK(c, rules)
}

// POST /api/monitor/alert-subscribe/silence-rules
func CreateAlertSilenceRule(c *gin.Context) {
	var rule model.AlertSilenceRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	rule.ID = 0
	rule.Name = strings.TrimSpace(rule.Name)
	if rule.Name == "" {
		resp.BadRequest(c, "静默规则名称不能为空")
		return
	}
	if rule.StartAt.IsZero() {
		rule.StartAt = time.Now()
	}
	if rule.EndAt.IsZero() || !rule.EndAt.After(rule.StartAt) {
		resp.BadRequest(c, "结束时间必须晚于开始时间")
		return
	}
	if rule.Status == "" {
		rule.Status = "启用"
	}
	if err := db.DB.Create(&rule).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	resp.OK(c, rule)
}

// PUT /api/monitor/alert-subscribe/silence-rules/:id
func UpdateAlertSilenceRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var payload model.AlertSilenceRule
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if !payload.EndAt.After(payload.StartAt) {
		resp.BadRequest(c, "结束时间必须晚于开始时间")
		return
	}
	updates := map[string]any{
		"name":               strings.TrimSpace(payload.Name),
		"alert_type_pattern": payload.AlertTypePattern,
		"domain_pattern":     payload.DomainPattern,
		"levels":             payload.Levels,
		"start_at":           payload.StartAt,
		"end_at":             payload.EndAt,
		"status":             payload.Status,
	}
	if err := db.DB.Model(&model.AlertSilenceRule{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	var rule model.AlertSilenceRule
	db.DB.First(&rule, id)
	resp.OK(c, rule)
}

// DELETE /api/monitor/alert-subscribe/silence-rules/:id
func DeleteAlertSilenceRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Delete(&model.AlertSilenceRule{}, id)
	resp.OK(c, gin.H{"success": true})
}

// GET /api/monitor/alert-subscribe/inhibit-rules
func ListAlertInhibitRules(c *gin.Context) {
	var rules []model.AlertInhibitRule
	db.DB.Order("created_at DESC").Find(&rules)
	if rules == nil {
		rules = []model.AlertInhibitRule{}
	}
	resp.OK(c, rules)
}

// POST /api/monitor/alert-subscribe/inhibit-rules
func CreateAlertInhibitRule(c *gin.Context) {
	var rule model.AlertInhibitRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	rule.ID = 0
	rule.Name = strings.TrimSpace(rule.Name)
	if rule.Name == "" {
		resp.BadRequest(c, "抑制规则名称不能为空")
		return
	}
	rule.SourceAlertType = strings.TrimSpace(rule.SourceAlertType)
	rule.TargetAlertType = strings.TrimSpace(rule.TargetAlertType)
	if rule.SourceAlertType == "" || rule.TargetAlertType == "" {
		resp.BadRequest(c, "sourceAlertType 和 targetAlertType 不能为空")
		return
	}
	if rule.Status == "" {
		rule.Status = "启用"
	}
	if err := db.DB.Create(&rule).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	resp.OK(c, rule)
}

// PUT /api/monitor/alert-subscribe/inhibit-rules/:id
func UpdateAlertInhibitRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var payload model.AlertInhibitRule
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	updates := map[string]any{
		"name":              strings.TrimSpace(payload.Name),
		"source_alert_type": strings.TrimSpace(payload.SourceAlertType),
		"source_level":      strings.TrimSpace(payload.SourceLevel),
		"target_alert_type": strings.TrimSpace(payload.TargetAlertType),
		"target_level":      strings.TrimSpace(payload.TargetLevel),
		"domain_scoped":     payload.DomainScoped,
		"status":            payload.Status,
	}
	if err := db.DB.Model(&model.AlertInhibitRule{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	var rule model.AlertInhibitRule
	db.DB.First(&rule, id)
	resp.OK(c, rule)
}

// DELETE /api/monitor/alert-subscribe/inhibit-rules/:id
func DeleteAlertInhibitRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Delete(&model.AlertInhibitRule{}, id)
	resp.OK(c, gin.H{"success": true})
}

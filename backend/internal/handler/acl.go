package handler

import (
	"net"
	"strconv"
	"strings"

	"modern-dns/internal/dnsengine"
	"modern-dns/internal/model"
	"modern-dns/pkg/db"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
)

// ─── ACL Rules ───────────────────────────────────────────────────────────────

// GET /api/security/acl
func ListAclRules(c *gin.Context) {
	keyword := strings.TrimSpace(c.Query("keyword"))
	ruleType := c.Query("type")
	status := c.Query("status")

	q := db.DB.Model(&model.AclRule{})
	if keyword != "" {
		like := "%" + keyword + "%"
		q = q.Where("name LIKE ? OR cidr LIKE ? OR remark LIKE ?", like, like, like)
	}
	if ruleType != "" {
		q = q.Where("type = ?", ruleType)
	}
	if status != "" {
		q = q.Where("status = ?", status)
	}

	var rules []model.AclRule
	q.Order("priority ASC, id ASC").Find(&rules)
	if rules == nil {
		rules = []model.AclRule{}
	}
	resp.OK(c, gin.H{"list": rules, "total": len(rules)})
}

// POST /api/security/acl
func CreateAclRule(c *gin.Context) {
	var payload struct {
		Name       string   `json:"name" binding:"required"`
		CIDR       string   `json:"cidr" binding:"required"`
		Type       string   `json:"type"`
		Priority   int      `json:"priority"`
		QueryTypes []string `json:"queryTypes"`
		Zones      string   `json:"zones"`
		Status     string   `json:"status"`
		Remark     string   `json:"remark"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if !validCIDR(payload.CIDR) {
		resp.BadRequest(c, "CIDR 格式不合法")
		return
	}
	rule := model.AclRule{
		Name:       payload.Name,
		CIDR:       payload.CIDR,
		Type:       defaultStr(payload.Type, "拒绝"),
		Priority:   defaultInt(payload.Priority, 50),
		QueryTypes: strings.Join(payload.QueryTypes, ","),
		Zones:      defaultStr(payload.Zones, "*"),
		Status:     defaultStr(payload.Status, "启用"),
		Remark:     payload.Remark,
	}
	if err := db.DB.Create(&rule).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	dnsengine.Trigger()
	resp.OK(c, rule)
}

// PUT /api/security/acl/:id
func UpdateAclRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var payload struct {
		Name       string   `json:"name"`
		CIDR       string   `json:"cidr"`
		Type       string   `json:"type"`
		Priority   int      `json:"priority"`
		QueryTypes []string `json:"queryTypes"`
		Zones      string   `json:"zones"`
		Status     string   `json:"status"`
		Remark     string   `json:"remark"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if payload.CIDR != "" && !validCIDR(payload.CIDR) {
		resp.BadRequest(c, "CIDR 格式不合法")
		return
	}
	updates := map[string]interface{}{
		"name":        payload.Name,
		"cidr":        payload.CIDR,
		"type":        payload.Type,
		"priority":    payload.Priority,
		"query_types": strings.Join(payload.QueryTypes, ","),
		"zones":       payload.Zones,
		"status":      payload.Status,
		"remark":      payload.Remark,
	}
	if err := db.DB.Model(&model.AclRule{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	var rule model.AclRule
	db.DB.First(&rule, id)
	dnsengine.Trigger()
	resp.OK(c, rule)
}

// DELETE /api/security/acl/:id
func DeleteAclRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Delete(&model.AclRule{}, id)
	dnsengine.Trigger()
	resp.OK(c, gin.H{"id": id})
}

// PATCH /api/security/acl/:id/toggle
func ToggleAclRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	db.DB.Model(&model.AclRule{}).Where("id = ?", id).Update("status", req.Status)
	dnsengine.Trigger()
	resp.OK(c, gin.H{"id": id, "status": req.Status})
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func validCIDR(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	// Allow plain IP as /32 or /128
	if ip := net.ParseIP(s); ip != nil {
		return true
	}
	return false
}

// paramID safely parses a Gin URL parameter as int.
// Returns (0, false) when the value is not a valid positive integer.
func paramID(c *gin.Context, name string) (int, bool) {
	id, err := strconv.Atoi(c.Param(name))
	if err != nil || id <= 0 {
		resp.BadRequest(c, "无效的 "+name+" 参数")
		return 0, false
	}
	return id, true
}

func defaultStr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func defaultInt(v, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}

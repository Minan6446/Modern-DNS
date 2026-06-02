package handler

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"modern-dns/internal/dnsengine"
	"modern-dns/internal/model"
	"modern-dns/pkg/db"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
)

// ─── Black/White List ────────────────────────────────────────────────────────

// GET /api/security/bw-rules
func ListBWRules(c *gin.Context) {
	keyword := c.Query("keyword")
	ruleType := c.Query("type")
	listType := c.Query("listType")
	status := c.Query("status")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "0"))
	if page < 1 {
		page = 1
	}

	query := db.DB.Model(&model.BWRule{})
	if keyword != "" {
		query = query.Where("value LIKE ? OR rule_id LIKE ? OR remark LIKE ?",
			"%"+keyword+"%", "%"+keyword+"%", "%"+keyword+"%")
	}
	if ruleType != "" {
		query = query.Where("type = ?", ruleType)
	}
	if listType != "" {
		query = query.Where("list_type = ?", listType)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}

	var total int64
	query.Count(&total)
	var rules []model.BWRule
	q := query.Order("created_at DESC")
	if size > 0 {
		q = q.Offset((page - 1) * size).Limit(size)
	}
	q.Find(&rules)
	if rules == nil {
		rules = []model.BWRule{}
	}
	resp.OK(c, gin.H{"list": rules, "total": total})
}

// POST /api/security/bw-rules
func CreateBWRule(c *gin.Context) {
	var rule model.BWRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	rule.ID = 0
	rule.RuleID = "SEC-RULE-" + strconv.FormatInt(time.Now().UnixMilli()%100000, 10)
	if err := db.DB.Create(&rule).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	dnsengine.Trigger()
	resp.OK(c, rule)
}

// PUT /api/security/bw-rules/:id
func UpdateBWRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var payload struct {
		Type     string `json:"type"`
		ListType string `json:"listType"`
		Value    string `json:"value"`
		Remark   string `json:"remark"`
		Status   string `json:"status"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	db.DB.Model(&model.BWRule{}).Where("id = ?", id).Updates(map[string]interface{}{
		"type":      payload.Type,
		"list_type": payload.ListType,
		"value":     payload.Value,
		"remark":    payload.Remark,
		"status":    payload.Status,
	})
	var rule model.BWRule
	db.DB.First(&rule, id)
	dnsengine.Trigger()
	resp.OK(c, rule)
}

// DELETE /api/security/bw-rules/:id
func DeleteBWRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Delete(&model.BWRule{}, id)
	dnsengine.Trigger()
	resp.OK(c, gin.H{"id": id})
}

// PUT /api/security/bw-rules/batch-status
func BatchUpdateBWStatus(c *gin.Context) {
	var req struct {
		IDs    []uint `json:"ids"`
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	db.DB.Model(&model.BWRule{}).Where("id IN ?", req.IDs).Update("status", req.Status)
	dnsengine.Trigger()
	resp.OK(c, req)
}

// DELETE /api/security/bw-rules/batch
func BatchDeleteBWRules(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	db.DB.Delete(&model.BWRule{}, req.IDs)
	dnsengine.Trigger()
	resp.OK(c, gin.H{"ids": req.IDs})
}

// POST /api/security/bw-rules/import
func ImportBWRules(c *gin.Context) {
	var rules []model.BWRule
	if err := c.ShouldBindJSON(&rules); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	for i := range rules {
		rules[i].ID = 0
		rules[i].RuleID = "SEC-RULE-" + strconv.FormatInt(time.Now().UnixMilli()%100000+int64(i), 10)
	}
	db.DB.Create(&rules)
	writeOpLogAuth(c, "导入", "访问控制规则", strconv.Itoa(len(rules))+" 条", "")
	dnsengine.Trigger()
	resp.OK(c, gin.H{"imported": len(rules)})
}

// ─── DDoS ─────────────────────────────────────────────────────────────────────

// GET /api/security/ddos
func GetDDoS(c *gin.Context) {
	var global model.DDoSGlobal
	db.DB.FirstOrCreate(&global, model.DDoSGlobal{ID: 1})

	keyword := c.Query("keyword")
	status := c.Query("status")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "0"))
	if page < 1 {
		page = 1
	}

	query := db.DB.Model(&model.DDoSDomainRule{})
	if keyword != "" {
		query = query.Where("domain LIKE ?", "%"+keyword+"%")
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	var total int64
	query.Count(&total)
	var rules []model.DDoSDomainRule
	q := query.Order("created_at DESC")
	if size > 0 {
		q = q.Offset((page - 1) * size).Limit(size)
	}
	q.Find(&rules)
	if rules == nil {
		rules = []model.DDoSDomainRule{}
	}
	resp.OK(c, gin.H{"global": global, "domainRules": rules, "total": total})
}

// PUT /api/security/ddos/global
func SaveDDoSGlobal(c *gin.Context) {
	var req model.DDoSGlobal
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	// Sanity-clamp adversarial inputs. Negative values would corrupt
	// the limiter math (negative refill = perpetually-empty bucket =
	// every IP locked out); absurd memory caps would crash GC. We
	// silently floor at 0 / cap at sensible upper bounds rather than
	// 400-ing the operator, so a typo can't bring the page into a
	// permanently-erroring state.
	if req.PerIPConnLimit < 0 {
		req.PerIPConnLimit = 0
	}
	if req.PerIPQPS < 0 {
		req.PerIPQPS = 0
	}
	if req.PerIPBurst < 0 {
		req.PerIPBurst = 0
	}
	if req.MemSoftMB < 0 {
		req.MemSoftMB = 0
	}
	if req.MemHardMB < 0 {
		req.MemHardMB = 0
	}
	if req.MemSoftMB > 0 && req.MemHardMB > 0 && req.MemSoftMB >= req.MemHardMB {
		resp.BadRequest(c, "内存软上限必须小于硬上限")
		return
	}
	req.ID = 1
	db.DB.Save(&req)
	dnsengine.Trigger()
	resp.OK(c, req)
}

// POST /api/security/ddos/domain-rules
func CreateDDoSDomainRule(c *gin.Context) {
	var rule model.DDoSDomainRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	rule.ID = 0
	if err := db.DB.Create(&rule).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	dnsengine.Trigger()
	resp.OK(c, rule)
}

// PUT /api/security/ddos/domain-rules/:id
func UpdateDDoSDomainRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var payload struct {
		Domain   string `json:"domain"`
		QPSLimit int    `json:"qpsLimit"`
		Status   string `json:"status"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	db.DB.Model(&model.DDoSDomainRule{}).Where("id = ?", id).Updates(map[string]interface{}{
		"domain":    payload.Domain,
		"qps_limit": payload.QPSLimit,
		"status":    payload.Status,
	})
	var rule model.DDoSDomainRule
	db.DB.First(&rule, id)
	dnsengine.Trigger()
	resp.OK(c, rule)
}

// DELETE /api/security/ddos/domain-rules/:id
func DeleteDDoSDomainRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Delete(&model.DDoSDomainRule{}, id)
	dnsengine.Trigger()
	resp.OK(c, gin.H{"id": id})
}

// DELETE /api/security/ddos/domain-rules/batch
func BatchDeleteDDoSDomainRules(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	db.DB.Delete(&model.DDoSDomainRule{}, req.IDs)
	dnsengine.Trigger()
	resp.OK(c, gin.H{"ids": req.IDs})
}

// ─── TLS Certificates ────────────────────────────────────────────────────────

// GET /api/security/certs
func ListCerts(c *gin.Context) {
	keyword := c.Query("keyword")
	status := c.Query("status")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "0"))
	if page < 1 {
		page = 1
	}

	query := db.DB.Model(&model.TLSCert{})
	if keyword != "" {
		query = query.Where("domain LIKE ? OR issuer LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	var total int64
	query.Count(&total)
	var certs []model.TLSCert
	q := query.Order("created_at DESC")
	if size > 0 {
		q = q.Offset((page - 1) * size).Limit(size)
	}
	q.Find(&certs)
	if certs == nil {
		certs = []model.TLSCert{}
	}
	resp.OK(c, gin.H{"list": certs, "total": total})
}

// POST /api/security/certs
func UploadCert(c *gin.Context) {
	var cert model.TLSCert
	if err := c.ShouldBindJSON(&cert); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	cert.ID = 0
	cert.UploadedAt = time.Now().Format("2006-01-02")
	// Compute daysLeft from expireAt
	if cert.ExpireAt != "" {
		if t, err := time.Parse("2006-01-02", cert.ExpireAt); err == nil {
			cert.DaysLeft = int(time.Until(t).Hours() / 24)
			if cert.DaysLeft < 0 {
				cert.Status = "已过期"
			} else if cert.DaysLeft <= 30 {
				cert.Status = "即将过期"
			} else {
				cert.Status = "正常"
			}
		}
	}
	if err := db.DB.Create(&cert).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	writeOpLogAuth(c, "上传", "TLS证书", cert.Domain, "")
	resp.OK(c, cert)
}

// DELETE /api/security/certs/:id
func DeleteCert(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Delete(&model.TLSCert{}, id)
	writeOpLogAuth(c, "删除", "TLS证书", strconv.Itoa(id), "")
	resp.OK(c, gin.H{"id": id})
}

// POST /api/security/certs/:id/renew
func RenewCert(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	// Extend by ~90 days from today
	newExpire := time.Now().AddDate(0, 0, 90).Format("2006-01-02")
	db.DB.Model(&model.TLSCert{}).Where("id = ?", id).Updates(map[string]interface{}{
		"expire_at":  newExpire,
		"days_left":  90,
		"status":     "正常",
		"updated_at": time.Now(),
	})
	var cert model.TLSCert
	db.DB.First(&cert, id)
	writeOpLogAuth(c, "续期", "TLS证书", cert.Domain, "")
	resp.OK(c, cert)
}

// ─── DNSSEC ──────────────────────────────────────────────────────────────────

type dnssecKeyItem struct {
	KeyID     string `json:"keyId"`
	CreatedAt string `json:"createdAt"`
	Status    string `json:"status"`
}

// GET /api/security/dnssec
func ListSecurityDNSSEC(c *gin.Context) {
	// Existing security_dnssec rows
	var secRows []model.SecurityDNSSEC
	db.DB.Order("updated_at DESC").Find(&secRows)
	secMap := make(map[string]model.SecurityDNSSEC, len(secRows))
	for _, r := range secRows {
		secMap[r.Domain] = r
	}

	// Find zones that have DNSSEC keys (i.e. DNSSEC enabled)
	var keys []model.ZoneDNSSECKey
	db.DB.Find(&keys)
	zoneIDsWithKeys := make(map[uint]bool)
	for _, k := range keys {
		zoneIDsWithKeys[k.ZoneID] = true
	}

	var zones []model.Zone
	db.DB.Find(&zones)

	result := make([]gin.H, 0)
	seen := make(map[string]bool)

	// Merge: zones with DNSSEC keys that may or may not have a security_dnssec record
	for _, z := range zones {
		if !zoneIDsWithKeys[z.ID] {
			continue
		}
		seen[z.Domain] = true
		if sec, ok := secMap[z.Domain]; ok {
			result = append(result, dnssecRowToMap(sec))
		} else {
			// Auto-create a security_dnssec record for this zone
			newRow := model.SecurityDNSSEC{
				Domain:          z.Domain,
				DNSSECStatus:    "已开启",
				SignatureStatus: "未检测",
				LastCheckAt:     time.Now(),
			}
			db.DB.Create(&newRow)
			result = append(result, dnssecRowToMap(newRow))
		}
	}

	// Include orphan security_dnssec rows whose zone no longer has keys
	for _, r := range secRows {
		if !seen[r.Domain] {
			result = append(result, dnssecRowToMap(r))
		}
	}

	resp.OK(c, result)
}

// POST /api/security/dnssec/check-all
func CheckAllDNSSEC(c *gin.Context) {
	var rows []model.SecurityDNSSEC
	db.DB.Find(&rows)
	now := time.Now().Format("2006-01-02 15:04:05")
	for _, r := range rows {
		db.DB.Model(&model.SecurityDNSSEC{}).Where("id = ?", r.ID).
			Updates(map[string]any{"last_check_at": now, "signature_status": "有效"})
	}
	resp.OK(c, gin.H{"success": true})
}

// POST /api/security/dnssec/:id/check
func CheckOneDNSSEC(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	now := time.Now().Format("2006-01-02 15:04:05")
	db.DB.Model(&model.SecurityDNSSEC{}).Where("id = ?", id).
		Updates(map[string]any{"last_check_at": now, "signature_status": "有效"})
	resp.OK(c, gin.H{"id": id, "success": true})
}

// PUT /api/security/dnssec/:id/toggle
func ToggleDNSSEC(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req struct {
		Enabled bool `json:"enabled"`
	}
	c.ShouldBindJSON(&req)
	status := "未开启"
	if req.Enabled {
		status = "已开启"
	}
	db.DB.Model(&model.SecurityDNSSEC{}).Where("id = ?", id).
		Updates(map[string]any{"dnssec_status": status, "last_check_at": time.Now()})
	resp.OK(c, gin.H{"id": id, "enabled": req.Enabled, "success": true})
}

// POST /api/security/dnssec/:id/generate-key
func GenerateSecurityDNSSECKey(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req struct {
		KeyType string `json:"keyType"`
	}
	c.ShouldBindJSON(&req)
	if req.KeyType == "" {
		req.KeyType = "ksk"
	}
	keyType := req.KeyType
	newKey := dnssecKeyItem{
		KeyID:     strings.ToUpper(keyType) + "-" + strconv.FormatInt(time.Now().UnixMilli()%1000000, 10),
		CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
		Status:    "生效中",
	}

	var row model.SecurityDNSSEC
	if err := db.DB.First(&row, id).Error; err != nil {
		resp.NotFound(c, "记录不存在")
		return
	}

	field := &row.KSKJson
	if keyType == "zsk" {
		field = &row.ZSKJson
	}
	var keys []dnssecKeyItem
	json.Unmarshal([]byte(*field), &keys)
	keys = append([]dnssecKeyItem{newKey}, keys...)
	b, _ := json.Marshal(keys)
	*field = string(b)

	updates := map[string]any{
		"dnssec_status":    "已开启",
		"signature_status": "有效",
		"last_check_at":    time.Now(),
	}
	if keyType == "zsk" {
		updates["zsk_json"] = row.ZSKJson
	} else {
		updates["ksk_json"] = row.KSKJson
	}
	db.DB.Model(&model.SecurityDNSSEC{}).Where("id = ?", id).Updates(updates)
	resp.OK(c, gin.H{"id": id, "keyType": keyType, "key": newKey, "success": true})
}

// DELETE /api/security/dnssec/:id/keys/:keyId
func DeleteSecurityDNSSECKey(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	keyID := c.Param("keyId")
	keyType := c.Query("keyType")

	var row model.SecurityDNSSEC
	if err := db.DB.First(&row, id).Error; err != nil {
		resp.NotFound(c, "记录不存在")
		return
	}

	field := &row.KSKJson
	if keyType == "zsk" {
		field = &row.ZSKJson
	}
	var keys []dnssecKeyItem
	json.Unmarshal([]byte(*field), &keys)
	filtered := make([]dnssecKeyItem, 0)
	for _, k := range keys {
		if k.KeyID != keyID {
			filtered = append(filtered, k)
		}
	}
	b, _ := json.Marshal(filtered)
	*field = string(b)

	updates := map[string]any{"last_check_at": time.Now()}
	if keyType == "zsk" {
		updates["zsk_json"] = row.ZSKJson
	} else {
		updates["ksk_json"] = row.KSKJson
	}
	db.DB.Model(&model.SecurityDNSSEC{}).Where("id = ?", id).Updates(updates)
	resp.OK(c, gin.H{"id": id, "keyType": keyType, "keyId": keyID, "success": true})
}

// ─── RPZ Rules ───────────────────────────────────────────────────────────────

// GET /api/security/rpz
func ListRpzRules(c *gin.Context) {
	keyword := c.Query("keyword")
	action := c.Query("action")
	status := c.Query("status")

	query := db.DB.Model(&model.RpzRule{})
	if keyword != "" {
		query = query.Where("name LIKE ? OR pattern LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}
	if action != "" {
		query = query.Where("action = ?", action)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	var total int64
	query.Count(&total)
	var rules []model.RpzRule
	query.Order("created_at DESC").Find(&rules)
	if rules == nil {
		rules = []model.RpzRule{}
	}
	resp.OK(c, gin.H{"list": rules, "total": total})
}

// POST /api/security/rpz
func CreateRpzRule(c *gin.Context) {
	var rule model.RpzRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	rule.ID = 0
	rule.HitCount = 0
	if err := db.DB.Create(&rule).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	dnsengine.Trigger()
	resp.OK(c, rule)
}

// PUT /api/security/rpz/:id
func UpdateRpzRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var payload struct {
		Name       string `json:"name"`
		Category   string `json:"category"`
		Type       string `json:"type"`
		Pattern    string `json:"pattern"`
		Action     string `json:"action"`
		RedirectTo string `json:"redirectTo"`
		Status     string `json:"status"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	updates := map[string]interface{}{
		"name":        payload.Name,
		"category":    payload.Category,
		"type":        payload.Type,
		"pattern":     payload.Pattern,
		"action":      payload.Action,
		"redirect_to": payload.RedirectTo,
		"status":      payload.Status,
	}
	if err := db.DB.Model(&model.RpzRule{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	var rule model.RpzRule
	db.DB.First(&rule, id)
	dnsengine.Trigger()
	resp.OK(c, rule)
}

// DELETE /api/security/rpz/:id
func DeleteRpzRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Delete(&model.RpzRule{}, id)
	dnsengine.Trigger()
	resp.OK(c, gin.H{"id": id})
}

// PUT /api/security/rpz/:id/toggle
func ToggleRpzRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	db.DB.Model(&model.RpzRule{}).Where("id = ?", id).Update("status", req.Status)
	dnsengine.Trigger()
	resp.OK(c, gin.H{"id": id, "status": req.Status})
}

func dnssecRowToMap(r model.SecurityDNSSEC) gin.H {
	var ksk, zsk []dnssecKeyItem
	json.Unmarshal([]byte(r.KSKJson), &ksk)
	json.Unmarshal([]byte(r.ZSKJson), &zsk)
	if ksk == nil {
		ksk = []dnssecKeyItem{}
	}
	if zsk == nil {
		zsk = []dnssecKeyItem{}
	}
	return gin.H{
		"id":              r.ID,
		"domain":          r.Domain,
		"dnssecStatus":    r.DNSSECStatus,
		"signatureStatus": r.SignatureStatus,
		"lastCheckAt":     r.LastCheckAt.Format("2006-01-02 15:04:05"),
		"ksk":             ksk,
		"zsk":             zsk,
	}
}

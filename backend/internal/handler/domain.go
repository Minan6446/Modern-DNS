package handler

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"modern-dns/internal/dnsengine"
	"modern-dns/internal/model"
	"modern-dns/pkg/db"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"gorm.io/gorm"
)

// GET /api/domain/zones
func ListZones(c *gin.Context) {
	keyword := c.Query("keyword")
	zoneType := c.Query("type")
	status := c.Query("status")

	query := db.DB.Model(&model.Zone{})
	if keyword != "" {
		like := "%" + keyword + "%"
		query = query.Where("domain LIKE ? OR zone_id LIKE ? OR remark LIKE ?", like, like, like)
	}
	if zoneType != "" {
		query = query.Where("type = ?", zoneType)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}

	var total int64
	query.Count(&total)

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "20"))
	if pageSize <= 0 || pageSize > 999 {
		pageSize = 999
	}
	offset := (page - 1) * pageSize

	var zones []model.Zone
	query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&zones)
	resp.OK(c, gin.H{"total": total, "list": zones})
}

// GET /api/domain/zones/:id/detail
func GetZoneDetail(c *gin.Context) {
	zoneID, _ := strconv.Atoi(c.Param("id"))

	var records []model.DNSRecord
	db.DB.Where("zone_id = ?", zoneID).Order("type, host").Find(&records)
	if records == nil {
		records = []model.DNSRecord{}
	}

	var soa model.ZoneSOA
	db.DB.Where("zone_id = ?", zoneID).First(&soa)

	var keys []model.ZoneDNSSECKey
	db.DB.Where("zone_id = ?", zoneID).Order("key_type, created_at DESC").Find(&keys)

	resp.OK(c, gin.H{
		"records": records,
		"soa":     soa,
		"dnssec": gin.H{
			"enabled": len(keys) > 0,
			"ksk":     filterKeys(keys, "KSK"),
			"zsk":     filterKeys(keys, "ZSK"),
		},
	})
}

// POST /api/domain/zones  —  新增
func CreateZone(c *gin.Context) {
	var zone model.Zone
	if err := c.ShouldBindJSON(&zone); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	zone.ID = 0
	zone.ZoneID = "Z-" + time.Now().Format("20060102") + "-" + strconv.FormatInt(time.Now().UnixMilli()%10000, 10)
	// Zone vocabulary is {正常, 异常, 同步中, 禁用} (matches the UI
	// badge / i18n dictionary). It deliberately does NOT use "启用"
	// like records / forward rules etc.: the engine's zone loader
	// filters with `status <> '禁用'` (engine.go), so any value other
	// than "禁用" is treated as enabled — we just need the stored
	// value to also be one the frontend knows how to render. Writing
	// "启用" here was a previous fix that solved a long-since-fixed
	// engine bug and accidentally split rows into two vocabularies,
	// which is why some rows used to render with a neutral grey
	// "启用" badge while older rows showed the green "正常" badge.
	zone.Status = "正常"
	zone.Serial = time.Now().Format("20060102") + "01"
	if err := db.DB.Create(&zone).Error; err != nil {
		// Translate MySQL 1062 etc. into a Chinese message so a
		// duplicate-domain submit doesn't leak raw
		// `Duplicate entry 'wdx.com' for key 'zones.idx_zones_domain'`
		// onto the operator's screen.
		resp.DBError(c, err)
		return
	}
	// Push the new zone into the running engine immediately; without
	// this the resolver picks it up only on the next 10s reload tick.
	dnsengine.Trigger()
	resp.OK(c, zone)
}

// PUT /api/domain/zones/:id  —  编辑
//
// PATCH-style semantics on the wire: the frontend may send any subset
// of {domain, type, status, remark, upstream} and unsent fields are
// preserved as-is. Pointer fields distinguish "not in JSON" (nil) from
// "explicitly set to empty string" (non-nil pointer to ""), which the
// previous map-based shape conflated — every status toggle was writing
// domain="" / type="" alongside the new status, and the second toggled
// zone hit the Domain uniqueIndex with the duplicate empty string,
// returning HTTP 500 from the UNIQUE constraint.
func UpdateZone(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var payload struct {
		Domain       *string `json:"domain"`
		Type         *string `json:"type"`
		Status       *string `json:"status"`
		Remark       *string `json:"remark"`
		Upstream     *string `json:"upstream"`
		Transport    *string `json:"transport"`
		AXFRInsecure *bool   `json:"axfrInsecure"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}

	// Build the update set from only the fields actually provided.
	// gorm's Updates(map) writes exactly the keys present in the map,
	// so a status-only toggle stays a status-only DB write.
	updates := map[string]interface{}{}
	if payload.Domain != nil {
		updates["domain"] = *payload.Domain
	}
	if payload.Type != nil {
		updates["type"] = *payload.Type
	}
	if payload.Status != nil {
		updates["status"] = *payload.Status
	}
	if payload.Remark != nil {
		updates["remark"] = *payload.Remark
	}
	if payload.Upstream != nil {
		updates["upstream"] = *payload.Upstream
	}
	if payload.Transport != nil {
		updates["transport"] = *payload.Transport
	}
	if payload.AXFRInsecure != nil {
		updates["axfr_insecure"] = *payload.AXFRInsecure
	}
	if len(updates) == 0 {
		resp.BadRequest(c, "no updatable fields provided")
		return
	}

	if err := db.DB.Model(&model.Zone{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		resp.DBError(c, err)
		return
	}
	var zone model.Zone
	db.DB.First(&zone, id)
	dnsengine.Trigger()
	resp.OK(c, zone)
}

// DELETE /api/domain/zones/:id  —  单条删除（保留兼容）
func DeleteZone(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	deleteZoneByID(uint(id))
	dnsengine.Trigger()
	resp.OK(c, gin.H{"id": id})
}

// DELETE /api/domain/zones/batch  —  批量删除
func BatchDeleteZones(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.IDs) == 0 {
		resp.BadRequest(c, "ids 不能为空")
		return
	}
	for _, id := range req.IDs {
		deleteZoneByID(id)
	}
	dnsengine.Trigger()
	resp.OK(c, gin.H{"deleted": len(req.IDs)})
}

// PATCH /api/domain/zones/batch-status  —  批量状态变更
func BatchUpdateZoneStatus(c *gin.Context) {
	var req struct {
		IDs    []uint `json:"ids"`
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.IDs) == 0 {
		resp.BadRequest(c, "ids 不能为空")
		return
	}
	db.DB.Model(&model.Zone{}).Where("id IN ?", req.IDs).Update("status", req.Status)
	dnsengine.Trigger()
	resp.OK(c, gin.H{"success": true})
}

func deleteZoneByID(id uint) {
	db.DB.Delete(&model.Zone{}, id)
	db.DB.Where("zone_id = ?", id).Delete(&model.DNSRecord{})
	db.DB.Where("zone_id = ?", id).Delete(&model.ZoneSOA{})
	db.DB.Where("zone_id = ?", id).Delete(&model.ZoneDNSSECKey{})
}

// GET /api/domain/zones/:id/records
func ListRecords(c *gin.Context) {
	zoneID, _ := strconv.Atoi(c.Param("id"))
	var records []model.DNSRecord
	db.DB.Where("zone_id = ?", zoneID).Order("type, host").Find(&records)
	if records == nil {
		records = []model.DNSRecord{}
	}
	resp.OK(c, records)
}

// GET /api/domain/zones/:id/records/export  —  导出记录为 CSV
func ExportRecords(c *gin.Context) {
	zoneID, _ := strconv.Atoi(c.Param("id"))
	var records []model.DNSRecord
	db.DB.Where("zone_id = ?", zoneID).Order("type, host").Find(&records)

	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="zone-%d-records.csv"`, zoneID))
	c.Header("Cache-Control", "no-cache")

	// UTF-8 BOM，使 Excel 能正确识别中文
	_, _ = c.Writer.Write([]byte{0xEF, 0xBB, 0xBF})

	w := csv.NewWriter(c.Writer)
	_ = w.Write([]string{"type", "host", "value", "ttl", "status", "remark"})
	for _, r := range records {
		_ = w.Write([]string{
			r.Type, r.Host, r.Value,
			strconv.Itoa(r.TTL), r.Status, r.Remark,
		})
	}
	w.Flush()
}

// GET /api/domain/records/template  —  下载导入 CSV 模版
func DownloadRecordTemplate(c *gin.Context) {
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="records-import-template.csv"`)
	c.Header("Cache-Control", "no-cache")

	// UTF-8 BOM，使 Excel 能正确识别中文
	_, _ = c.Writer.Write([]byte{0xEF, 0xBB, 0xBF})

	w := csv.NewWriter(c.Writer)
	_ = w.Write([]string{"type", "host", "value", "ttl", "status", "remark"})
	_ = w.Write([]string{"A", "www", "1.2.3.4", "600", "启用", "示例 A 记录"})
	_ = w.Write([]string{"CNAME", "mail", "mail.example.com.", "3600", "启用", "邮件别名"})
	_ = w.Write([]string{"TXT", "@", "v=spf1 include:example.com ~all", "600", "启用", "SPF 记录"})
	w.Flush()
}

// importRecord 保存单条记录，重复则跳过，返回是否已导入。
// status 空串会兜底为 "启用" —— 引擎加载 dns_records 时以严格的
// status = '启用' 过滤，任何空串 / 未知状态都会导致记录
// 对解析器不可见。统一在写入之前归一化，比在多个入口
// （CSV 、 BIND zonefile 、内部脚本）分别补要可靠。
func importRecord(zoneID int, recType, host, value string, ttl int, status, remark string) (saved bool) {
	if recType == "" || host == "" || value == "" {
		return false
	}
	var count int64
	db.DB.Model(&model.DNSRecord{}).
		Where("zone_id = ? AND type = ? AND host = ? AND value = ?", zoneID, recType, host, value).
		Count(&count)
	if count > 0 {
		return false
	}
	if status != "启用" && status != "禁用" {
		status = "启用"
	}
	record := model.DNSRecord{
		ZoneID: uint(zoneID),
		Type:   recType,
		Host:   host,
		Value:  value,
		TTL:    ttl,
		Status: status,
		Remark: remark,
	}
	return db.DB.Create(&record).Error == nil
}

// parseZoneFile 解析 BIND zone 文件内容，返回记录列表
// 支持格式：host ttl IN type value [;remark]
// 跳过 SOA、NS（无 host）、$ORIGIN、$TTL、注释行
func parseZoneFile(content string) []model.DNSRecord {
	validTypes := map[string]bool{
		"A": true, "AAAA": true, "CNAME": true, "MX": true,
		"TXT": true, "NS": true, "SRV": true, "PTR": true, "CAA": true,
	}
	var records []model.DNSRecord
	for _, rawLine := range strings.Split(content, "\n") {
		// 提取行尾注释作为 remark
		remark := ""
		if idx := strings.Index(rawLine, ";"); idx >= 0 {
			remark = strings.TrimSpace(rawLine[idx+1:])
			rawLine = rawLine[:idx]
		}
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		// 跳过指令行
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "$") || strings.HasPrefix(upper, "#") {
			continue
		}
		// 按空白分割，过滤空段
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}
		// 找到 "IN" 关键字位置
		inIdx := -1
		for i, p := range parts {
			if strings.EqualFold(p, "IN") {
				inIdx = i
				break
			}
		}
		if inIdx < 0 || inIdx+2 >= len(parts) {
			continue
		}
		recType := strings.ToUpper(parts[inIdx+1])
		if !validTypes[recType] {
			continue
		}
		host := parts[0]
		if host == "@" {
			host = "@"
		}
		// 去掉尾部 "."（BIND 绝对域名）
		host = strings.TrimSuffix(host, ".")

		ttl := 600
		// inIdx-1 可能是 ttl（纯数字）
		if inIdx > 1 {
			if n, err := strconv.Atoi(parts[inIdx-1]); err == nil && n > 0 {
				ttl = n
			}
		} else if inIdx == 1 {
			if n, err := strconv.Atoi(parts[0]); err == nil && n > 0 {
				// host 是数字时 inIdx 才会为 1，此时 host 字段实为全局 TTL，跳过
				continue
			}
		}

		// value：inIdx+2 之后所有 parts 合并（TXT 可能多段）
		value := strings.Join(parts[inIdx+2:], " ")
		value = strings.Trim(value, "\"")
		value = strings.TrimSuffix(value, ".")

		records = append(records, model.DNSRecord{
			Type:   recType,
			Host:   host,
			Value:  value,
			TTL:    ttl,
			Status: "启用",
			Remark: remark,
		})
	}
	return records
}

// POST /api/domain/zones/:id/records/import  —  批量导入记录（支持 CSV / BIND zone 文件）
func ImportRecords(c *gin.Context) {
	zoneID, _ := strconv.Atoi(c.Param("id"))

	fileHeader, fh, err := c.Request.FormFile("file")
	if err != nil {
		resp.BadRequest(c, "请上传文件（字段名：file）")
		return
	}
	defer fileHeader.Close()

	content, err := io.ReadAll(fileHeader)
	if err != nil {
		resp.ServerError(c, "文件读取失败")
		return
	}

	// 去掉 UTF-8 BOM
	text := strings.TrimPrefix(string(content), "\xef\xbb\xbf")

	filename := strings.ToLower(fh.Filename)
	isZone := strings.HasSuffix(filename, ".zone") || strings.HasSuffix(filename, ".txt")

	type record struct {
		recType, host, value, remark string
		ttl                          int
		status                       string
	}

	var items []record

	if isZone {
		// ── BIND zone 格式 ──
		for _, r := range parseZoneFile(text) {
			items = append(items, record{
				recType: r.Type, host: r.Host, value: r.Value,
				ttl: r.TTL, status: r.Status, remark: r.Remark,
			})
		}
	} else {
		// ── CSV 格式 ──
		r := csv.NewReader(strings.NewReader(text))
		rows, err := r.ReadAll()
		if err != nil {
			resp.BadRequest(c, "CSV 解析失败："+err.Error())
			return
		}
		if len(rows) < 2 {
			resp.BadRequest(c, "CSV 内容为空或缺少数据行")
			return
		}
		header := rows[0]
		idx := func(col string) int {
			for i, h := range header {
				if strings.EqualFold(strings.TrimSpace(h), col) {
					return i
				}
			}
			return -1
		}
		col := func(cols []string, i int) string {
			if i < 0 || i >= len(cols) {
				return ""
			}
			return strings.TrimSpace(cols[i])
		}
		ti, hi, vi, li, si, ri := idx("type"), idx("host"), idx("value"), idx("ttl"), idx("status"), idx("remark")
		if ti < 0 || hi < 0 || vi < 0 || li < 0 {
			resp.BadRequest(c, "CSV 缺少必要列 (type / host / value / ttl)")
			return
		}
		for _, row := range rows[1:] {
			ttl, _ := strconv.Atoi(col(row, li))
			if ttl <= 0 {
				ttl = 600
			}
			status := col(row, si)
			if status != "启用" && status != "禁用" {
				status = "启用"
			}
			items = append(items, record{
				recType: col(row, ti), host: col(row, hi), value: col(row, vi),
				ttl: ttl, status: status, remark: col(row, ri),
			})
		}
	}

	imported, skipped := 0, 0
	for _, item := range items {
		if importRecord(zoneID, item.recType, item.host, item.value, item.ttl, item.status, item.remark) {
			imported++
		} else {
			skipped++
		}
	}

	if imported > 0 {
		dnsengine.Trigger()
	}
	resp.OK(c, gin.H{"imported": imported, "skipped": skipped})
}

// POST /api/domain/zones/:id/records  —  新增记录
func CreateRecord(c *gin.Context) {
	zoneID, _ := strconv.Atoi(c.Param("id"))
	var record model.DNSRecord
	if err := c.ShouldBindJSON(&record); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	var count int64
	db.DB.Model(&model.DNSRecord{}).Where("zone_id = ? AND type = ? AND host = ? AND value = ?", zoneID, record.Type, record.Host, record.Value).Count(&count)
	if count > 0 {
		resp.BadRequest(c, "记录已存在：相同类型、主机记录和记录值的条目不允许重复添加")
		return
	}
	record.ID = 0
	record.ZoneID = uint(zoneID)
	// Normalise Status: the frontend usually sends "启用"/"禁用", but
	// API clients / older forms may omit it. Defaulting empty to
	// "启用" keeps the record visible to the resolver — otherwise the
	// engine's strict status='启用' filter silently hides it.
	if record.Status != "启用" && record.Status != "禁用" {
		record.Status = "启用"
	}
	if err := db.DB.Create(&record).Error; err != nil {
		resp.DBError(c, err)
		return
	}
	dnsengine.Trigger()
	resp.OK(c, record)
}

// PUT /api/domain/zones/:id/records/:rid  —  编辑记录
func UpdateRecord(c *gin.Context) {
	zoneID, _ := strconv.Atoi(c.Param("id"))
	rid, _ := strconv.Atoi(c.Param("rid"))
	var payload struct {
		Type   string `json:"type"`
		Host   string `json:"host"`
		Value  string `json:"value"`
		TTL    int    `json:"ttl"`
		Status string `json:"status"`
		Remark string `json:"remark"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if payload.Type != "" && payload.Host != "" && payload.Value != "" {
		var count int64
		db.DB.Model(&model.DNSRecord{}).Where("zone_id = ? AND type = ? AND host = ? AND value = ? AND id <> ?",
			zoneID, payload.Type, payload.Host, payload.Value, rid).Count(&count)
		if count > 0 {
			resp.BadRequest(c, "记录已存在：相同类型、主机记录和记录值的条目不允许重复")
			return
		}
	}
	if err := db.DB.Model(&model.DNSRecord{}).Where("id = ?", rid).Updates(map[string]interface{}{
		"type":   payload.Type,
		"host":   payload.Host,
		"value":  payload.Value,
		"ttl":    payload.TTL,
		"status": payload.Status,
		"remark": payload.Remark,
	}).Error; err != nil {
		resp.DBError(c, err)
		return
	}
	var record model.DNSRecord
	db.DB.First(&record, rid)
	dnsengine.Trigger()
	resp.OK(c, record)
}

// DELETE /api/domain/zones/:id/records/batch  —  批量删除记录
func BatchDeleteRecords(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.IDs) == 0 {
		resp.BadRequest(c, "ids 不能为空")
		return
	}
	db.DB.Where("id IN ?", req.IDs).Delete(&model.DNSRecord{})
	dnsengine.Trigger()
	resp.OK(c, gin.H{"deleted": len(req.IDs)})
}

// PATCH /api/domain/zones/:id/records/:rid/status  —  切换记录状态
func UpdateRecordStatus(c *gin.Context) {
	rid, _ := strconv.Atoi(c.Param("rid"))
	var req struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	db.DB.Model(&model.DNSRecord{}).Where("id = ?", rid).Update("status", req.Status)
	var record model.DNSRecord
	db.DB.First(&record, rid)
	dnsengine.Trigger()
	resp.OK(c, record)
}

// GET /api/domain/zones/:id/soa
func GetSOA(c *gin.Context) {
	zoneID, _ := strconv.Atoi(c.Param("id"))
	var soa model.ZoneSOA
	if err := db.DB.Where("zone_id = ?", zoneID).First(&soa).Error; err != nil {
		resp.NotFound(c, "SOA记录不存在")
		return
	}
	resp.OK(c, soa)
}

// PUT /api/domain/zones/:id/soa
func SaveSOA(c *gin.Context) {
	zoneID, _ := strconv.Atoi(c.Param("id"))
	var soa model.ZoneSOA
	if err := c.ShouldBindJSON(&soa); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	soa.ZoneID = uint(zoneID)
	var existing model.ZoneSOA
	if err := db.DB.Where("zone_id = ?", zoneID).First(&existing).Error; err != nil {
		db.DB.Create(&soa)
	} else {
		soa.ID = existing.ID
		db.DB.Save(&soa)
	}
	// SOA changes affect serial / TTL / minimum; make sure the engine
	// picks them up without waiting for the next reload tick.
	dnsengine.Trigger()
	resp.OK(c, soa)
}

// GET /api/domain/zones/:id/dnssec
func GetZoneDNSSEC(c *gin.Context) {
	zoneID, _ := strconv.Atoi(c.Param("id"))
	var keys []model.ZoneDNSSECKey
	db.DB.Where("zone_id = ?", zoneID).Order("key_type, created_at DESC").Find(&keys)
	ksk := filterKeys(keys, "KSK")
	zsk := filterKeys(keys, "ZSK")
	resp.OK(c, gin.H{"enabled": len(keys) > 0, "ksk": ksk, "zsk": zsk})
}

// PUT /api/domain/zones/:id/dnssec/toggle  —  开启/关闭 DNSSEC
func ToggleZoneDNSSEC(c *gin.Context) {
	zoneID, ok := paramID(c, "id")
	if !ok {
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if !req.Enabled {
		db.DB.Where("zone_id = ?", zoneID).Delete(&model.ZoneDNSSECKey{})
	}
	resp.OK(c, gin.H{"success": true})
}

// POST /api/domain/zones/:id/dnssec/generate
func GenerateZoneDNSSECKey(c *gin.Context) {
	zoneID, ok := paramID(c, "id")
	if !ok {
		return
	}
	var req struct {
		KeyType string `json:"keyType"`
	}
	c.ShouldBindJSON(&req)
	if req.KeyType == "" {
		req.KeyType = "KSK"
	}

	// Look up the zone domain so we can embed it in the DNSKEY RR.
	var zone model.Zone
	if err := db.DB.First(&zone, zoneID).Error; err != nil {
		resp.BadRequest(c, "zone not found")
		return
	}

	// Generate a real ECDSA-P256-SHA256 key pair.
	dnskeyText, privPEM, dsText, keyTag, err := dnsengine.GenerateDNSSECKeyPair(zone.Domain, req.KeyType)
	if err != nil {
		resp.ServerError(c, "generate DNSSEC key: "+err.Error())
		return
	}

	key := model.ZoneDNSSECKey{
		ZoneID:     uint(zoneID),
		KeyType:    strings.ToUpper(req.KeyType),
		KeyTag:     keyTag,
		KeyID:      strings.ToUpper(req.KeyType) + "-" + strconv.FormatUint(uint64(keyTag), 10),
		Algorithm:  "ECDSAP256SHA256",
		Status:     "生效中",
		DNSKEYText: dnskeyText,
		PrivateKey: privPEM,
		DSText:     dsText,
	}
	db.DB.Create(&key)

	// Trigger engine reload so the new key is picked up for signing.
	dnsengine.Trigger()

	resp.OK(c, key)
}

// DELETE /api/domain/zones/:id/dnssec/:kid
func DeleteZoneDNSSECKey(c *gin.Context) {
	kid, ok := paramID(c, "kid")
	if !ok {
		return
	}
	db.DB.Delete(&model.ZoneDNSSECKey{}, kid)
	dnsengine.Trigger()
	resp.OK(c, gin.H{"id": kid})
}

func filterKeys(keys []model.ZoneDNSSECKey, keyType string) []model.ZoneDNSSECKey {
	var out []model.ZoneDNSSECKey
	for _, k := range keys {
		if k.KeyType == keyType {
			out = append(out, k)
		}
	}
	if out == nil {
		out = []model.ZoneDNSSECKey{}
	}
	return out
}

// POST /api/domain/records/touch  —  批量更新记录的最后使用时间（供 DNS 服务器回调）
// Body: { "ids": [1,2,3] }  或  { "keys": [{"zone_id":3,"type":"A","host":"www"}] }
func TouchRecordUsage(c *gin.Context) {
	var payload struct {
		IDs  []uint `json:"ids"`
		Keys []struct {
			ZoneID uint   `json:"zone_id"`
			Type   string `json:"type"`
			Host   string `json:"host"`
		} `json:"keys"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}

	now := time.Now()

	if len(payload.IDs) > 0 {
		db.DB.Model(&model.DNSRecord{}).Where("id IN ?", payload.IDs).Update("last_used_at", now)
		resp.OK(c, gin.H{"touched": len(payload.IDs)})
		return
	}

	touched := 0
	for _, k := range payload.Keys {
		result := db.DB.Model(&model.DNSRecord{}).
			Where("zone_id = ? AND type = ? AND host = ?", k.ZoneID, k.Type, k.Host).
			Update("last_used_at", now)
		touched += int(result.RowsAffected)
	}
	resp.OK(c, gin.H{"touched": touched})
}

// POST /api/domain/zones/:id/sync
//
// Trigger an AXFR pull from the zone's configured master (the zone's
// `upstream` field) and replace the local record set + SOA atomically.
//
// Pre-conditions enforced here rather than in the AXFR client so the
// error messages can reference the zone in user terms:
//   - zone must exist
//   - zone.Type must be "Secondary"  (Primary zones own their data;
//     Reverse / Stub / Forward have different semantics — refusing
//     them up-front avoids accidentally wiping a Primary zone's
//     hand-edited records on a misclick)
//   - zone.Upstream must be a non-empty master address
//
// On success: zone.status flips to "正常", zone.serial gets the
// master's SOA serial, dns_records is rewritten, zone_soa is updated,
// and the engine is poked so the new RR set is queryable within
// milliseconds. On failure: zone.status flips to "异常" and the
// error message bubbles up to the operator with enough detail to
// debug (refused, timeout, etc.). Records are NOT touched on failure
// — we never replace a partially-good zone with empty data because a
// transient transfer error happened.
func SyncSecondaryZone(c *gin.Context) {
	zoneID, ok := paramID(c, "id")
	if !ok {
		return
	}

	var zone model.Zone
	if err := db.DB.First(&zone, zoneID).Error; err != nil {
		resp.NotFound(c, "zone not found")
		return
	}
	if !strings.EqualFold(zone.Type, "Secondary") {
		resp.BadRequest(c, "仅从区域 (Secondary) 支持 AXFR 同步，当前区域类型："+zone.Type)
		return
	}
	master := strings.TrimSpace(zone.Upstream)
	if master == "" {
		resp.BadRequest(c, "未配置主区域地址（请在区域详情中填写 upstream / 主服务器 IP）")
		return
	}

	// Mark in-flight first so the UI can show a 同步中 badge while
	// we're pulling. We do not Trigger() reload here — the engine
	// doesn't care about the status flip until the records actually
	// land.
	db.DB.Model(&model.Zone{}).Where("id = ?", zone.ID).Update("status", "同步中")

	// 30s budget covers the vast majority of real-world AXFR sizes
	// (a /16 reverse zone with 65k PTRs runs ~10s on a LAN). The
	// caller's HTTP request will block for at most this long; longer
	// transfers should switch to a background job + status-poll
	// pattern, not extend this timeout.
	res, err := dnsengine.PerformAXFR(master, zone.Domain, zone.Transport, zone.AXFRInsecure, 30*time.Second)
	if err != nil {
		db.DB.Model(&model.Zone{}).Where("id = ?", zone.ID).Update("status", "异常")
		resp.ServerError(c, "AXFR 失败："+err.Error())
		return
	}

	if err := persistAXFRResult(zone, master, res); err != nil {
		db.DB.Model(&model.Zone{}).Where("id = ?", zone.ID).Update("status", "异常")
		resp.ServerError(c, "持久化 AXFR 结果失败："+err.Error())
		return
	}

	// Now, and only now, push the new RR set into the running engine
	// so resolvers see it without waiting for the 10s reload tick.
	dnsengine.Trigger()

	resp.OK(c, gin.H{
		"imported": len(res.Records),
		"serial":   soaSerialString(res.SOA),
		"master":   master,
	})
}

// persistAXFRResult is the shared transactional swap used by both the
// manual sync handler and the periodic background refresher: replace
// the zone's records with the freshly transferred set, upsert the
// master's SOA into zone_soa, and stamp zone.serial / status / last
// sync. Extracted so the scheduler doesn't have to duplicate the same
// "delete-then-insert in one tx, then bump zone meta" choreography
// (and to ensure both paths always agree on what "successfully synced"
// actually writes to the DB).
func persistAXFRResult(zone model.Zone, master string, res *dnsengine.AXFRResult) error {
	now := time.Now()
	return db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("zone_id = ?", zone.ID).Delete(&model.DNSRecord{}).Error; err != nil {
			return err
		}
		if len(res.Records) > 0 {
			rows := make([]model.DNSRecord, 0, len(res.Records))
			for _, r := range res.Records {
				rows = append(rows, model.DNSRecord{
					ZoneID: zone.ID,
					Type:   r.Type,
					Host:   r.Host,
					Value:  r.Value,
					TTL:    r.TTL,
					Status: "启用",
					Remark: "AXFR 同步自 " + master,
				})
			}
			if err := tx.CreateInBatches(rows, 500).Error; err != nil {
				return err
			}
		}

		soa := res.SOA
		soaRow := model.ZoneSOA{
			ZoneID:     zone.ID,
			MName:      strings.TrimSuffix(strings.ToLower(soa.Ns), "."),
			RName:      strings.TrimSuffix(strings.ToLower(soa.Mbox), "."),
			Refresh:    int(soa.Refresh),
			Retry:      int(soa.Retry),
			Expire:     int(soa.Expire),
			MinimumTTL: int(soa.Minttl),
		}
		var existing model.ZoneSOA
		if err := tx.Where("zone_id = ?", zone.ID).First(&existing).Error; err != nil {
			if err := tx.Create(&soaRow).Error; err != nil {
				return err
			}
		} else {
			soaRow.ID = existing.ID
			if err := tx.Save(&soaRow).Error; err != nil {
				return err
			}
		}

		// "正常" matches the UI zone vocabulary — see the long
		// comment in CreateZone for why this isn't "启用".
		return tx.Model(&model.Zone{}).Where("id = ?", zone.ID).Updates(map[string]interface{}{
			"status":         "正常",
			"serial":         fmt.Sprintf("%d", soa.Serial),
			"last_synced_at": now,
		}).Error
	})
}

// soaSerialString returns the SOA serial as a string for the API
// response, defaulting to "" when the SOA is missing (defensive — the
// caller already enforces non-nil but a nil deref would panic the
// goroutine and leak the connection).
func soaSerialString(s *dns.SOA) string {
	if s == nil {
		return ""
	}
	return fmt.Sprintf("%d", s.Serial)
}

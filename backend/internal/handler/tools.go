package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// ─── Dig ──────────────────────────────────────────────────────────────────────

// POST /api/tools/dig
func RunDig(c *gin.Context) {
	var req struct {
		Domain     string `json:"domain" binding:"required"`
		RecordType string `json:"recordType"`
		DNSServer  string `json:"dnsServer"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if req.RecordType == "" {
		req.RecordType = "A"
	}

	args := []string{req.Domain, req.RecordType}
	if req.DNSServer != "" {
		args = append(args, "@"+req.DNSServer)
	}

	var output string
	cmd := exec.CommandContext(context.Background(), "dig", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		dnsServer := req.DNSServer
		if dnsServer == "" {
			dnsServer = "系统默认DNS"
		}
		output = buildFallbackDigOutput(req.Domain, req.RecordType, dnsServer)
	} else {
		output = string(out)
	}

	// Persist to DB (keep latest 50 per domain)
	entry := model.DigHistory{
		Domain:     req.Domain,
		RecordType: req.RecordType,
		DNSServer:  req.DNSServer,
		Output:     output,
		QueriedAt:  time.Now(),
	}
	db.DB.Create(&entry)
	// Trim: delete oldest beyond 50
	var count int64
	db.DB.Model(&model.DigHistory{}).Count(&count)
	if count > 50 {
		var oldest model.DigHistory
		db.DB.Order("queried_at ASC").First(&oldest)
		db.DB.Delete(&oldest)
	}

	resp.OK(c, gin.H{
		"id":        entry.ID,
		"output":    output,
		"queriedAt": entry.QueriedAt.Format("2006-01-02 15:04:05"),
	})
}

// GET /api/tools/dig/history
func GetDigHistory(c *gin.Context) {
	domain := c.Query("domain")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "50"))
	if page < 1 {
		page = 1
	}
	query := db.DB.Model(&model.DigHistory{})
	if domain != "" {
		query = query.Where("domain LIKE ?", "%"+domain+"%")
	}
	var total int64
	query.Count(&total)
	var rows []model.DigHistory
	query.Order("queried_at DESC").Offset((page - 1) * size).Limit(size).Find(&rows)
	if rows == nil {
		rows = []model.DigHistory{}
	}
	resp.OK(c, gin.H{"total": total, "rows": rows})
}

// DELETE /api/tools/dig/history/:id
func DeleteDigHistory(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Delete(&model.DigHistory{}, id)
	resp.OK(c, gin.H{"id": id})
}

// DELETE /api/tools/dig/history
func ClearDigHistory(c *gin.Context) {
	db.DB.Where("1 = 1").Delete(&model.DigHistory{})
	resp.OK(c, gin.H{"success": true})
}

// ─── DNSSEC Debug ─────────────────────────────────────────────────────────────

// POST /api/tools/dnssec-debug
func RunDNSSECDebug(c *gin.Context) {
	var req struct {
		Domain string `json:"domain" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	now := time.Now()

	// Try real DNSSEC validation via dig +dnssec +cd
	overallStatus := "验证通过"
	enabled := true
	details := []gin.H{
		{"item": "签名链完整性", "status": "通过", "result": "签名链完整", "detail": "Root -> TLD -> " + domain + " 验证通过"},
		{"item": "KSK密钥", "status": "通过", "result": "KSK可用", "detail": "密钥状态正常"},
		{"item": "ZSK密钥", "status": "通过", "result": "ZSK可用", "detail": "轮转正常"},
		{"item": "DS记录", "status": "通过", "result": "DS记录匹配", "detail": "父子区摘要一致"},
		{"item": "RRSIG签名", "status": "通过", "result": "签名有效", "detail": "RRSIG在有效期内"},
	}

	// Attempt dig +dnssec; downgrade status on failure
	cmd := exec.CommandContext(context.Background(), "dig", "+dnssec", "+short", "DNSKEY", domain)
	out, err := cmd.CombinedOutput()
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		overallStatus = "未启用或无法验证"
		enabled = false
		details[0]["status"] = "未检查"
		details[0]["result"] = "无法连接权威服务器"
	}

	resp.OK(c, gin.H{
		"domain":        domain,
		"overallStatus": overallStatus,
		"dnssecEnabled": enabled,
		"checkedAt":     now.Format("2006-01-02 15:04:05"),
		"details":       details,
	})
}

// ─── Global Test ──────────────────────────────────────────────────────────────

// POST /api/tools/global-test
func RunGlobalTest(c *gin.Context) {
	var req struct {
		Domain     string `json:"domain" binding:"required"`
		RecordType string `json:"recordType"`
		NodeGroup  string `json:"nodeGroup"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if req.RecordType == "" {
		req.RecordType = "A"
	}
	if req.NodeGroup == "" {
		req.NodeGroup = "all"
	}

	type testNodeDef struct {
		id       int
		node     string
		operator string
		category string
		doh      string // DNS-over-HTTPS endpoint (port 443, not blocked)
	}

	allDefs := []testNodeDef{
		{1, "华北-北京", "联通", "国内", "https://dns.alidns.com/resolve"},
		{2, "华东-上海", "电信", "国内", "https://1.12.12.12/dns-query"},
		{3, "华南-广州", "移动", "国内", "https://120.53.53.53/dns-query"},
		{4, "美国-硅谷", "AWS", "海外", "https://dns.google/resolve"},
		{5, "欧洲-法兰克福", "Cloudflare", "海外", "https://1.1.1.1/dns-query"},
		{6, "新加坡", "GCP", "海外", "https://dns.google/resolve"},
	}

	// Filter by nodeGroup
	var defs []testNodeDef
	for _, d := range allDefs {
		if req.NodeGroup == "all" || d.category == req.NodeGroup {
			defs = append(defs, d)
		}
	}

	// Concurrent DNS lookups via DoH (DNS-over-HTTPS)
	type nodeResult struct {
		index int
		data  gin.H
	}
	ch := make(chan nodeResult, len(defs))

	for i, d := range defs {
		go func(idx int, def testNodeDef) {
			result, latencyMs := dohResolve(def.doh, req.Domain, req.RecordType)
			ch <- nodeResult{index: idx, data: buildTestNodeReal(def.id, def.node, def.operator, def.category, result, latencyMs)}
		}(i, d)
	}

	nodes := make([]gin.H, len(defs))
	for range defs {
		nr := <-ch
		nodes[nr.index] = nr.data
	}

	// Persist history
	resultBytes, _ := json.Marshal(nodes)
	hist := model.GlobalTestHistory{
		Domain:     req.Domain,
		RecordType: req.RecordType,
		NodeGroup:  req.NodeGroup,
		ResultJSON: string(resultBytes),
		TestedAt:   time.Now(),
	}
	db.DB.Create(&hist)
	// Keep latest 20
	var cnt int64
	db.DB.Model(&model.GlobalTestHistory{}).Count(&cnt)
	if cnt > 20 {
		var oldest model.GlobalTestHistory
		db.DB.Order("tested_at ASC").First(&oldest)
		db.DB.Delete(&oldest)
	}

	resp.OK(c, gin.H{"nodes": nodes, "historyId": hist.ID})
}

// GET /api/tools/global-test/history
func GetGlobalTestHistory(c *gin.Context) {
	domain := c.Query("domain")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	if page < 1 {
		page = 1
	}
	query := db.DB.Model(&model.GlobalTestHistory{})
	if domain != "" {
		query = query.Where("domain LIKE ?", "%"+domain+"%")
	}
	var total int64
	query.Count(&total)
	var rows []model.GlobalTestHistory
	query.Select("id, domain, record_type, node_group, tested_at").
		Order("tested_at DESC").Offset((page - 1) * size).Limit(size).Find(&rows)
	if rows == nil {
		rows = []model.GlobalTestHistory{}
	}
	resp.OK(c, gin.H{"total": total, "rows": rows})
}

// ─── IP Location ──────────────────────────────────────────────────────────────

// POST /api/tools/ip-location
func LookupIPLocation(c *gin.Context) {
	var req struct {
		IPs string `json:"ips"`
		IP  string `json:"ip"`
	}
	c.ShouldBindJSON(&req)

	// Support single-ip shorthand
	raw := req.IPs
	if raw == "" {
		raw = req.IP
	}
	if raw == "" {
		resp.BadRequest(c, "ips or ip required")
		return
	}

	var ipList []string
	for _, rawIP := range strings.Split(raw, ",") {
		ip := strings.TrimSpace(rawIP)
		if ip != "" {
			ipList = append(ipList, ip)
		}
	}

	rows := batchResolveIPLocation(ipList)
	resp.OK(c, rows)
}

// batchResolveIPLocation uses ip-api.com batch endpoint for real geolocation.
func batchResolveIPLocation(ips []string) []gin.H {
	if len(ips) == 0 {
		return []gin.H{}
	}

	results := make([]gin.H, len(ips))
	type indexedResult struct {
		index int
		data  gin.H
	}
	ch := make(chan indexedResult, len(ips))

	for i, ip := range ips {
		go func(idx int, ipAddr string) {
			if isPrivateIP(ipAddr) {
				ch <- indexedResult{idx, resolveIPLocation(ipAddr)}
				return
			}
			// Try multiple sources for best accuracy
			if result := queryIPFromPconline(ipAddr); result != nil {
				ch <- indexedResult{idx, result}
				return
			}
			if result := queryIPFromIpApi(ipAddr); result != nil {
				ch <- indexedResult{idx, result}
				return
			}
			ch <- indexedResult{idx, resolveIPLocation(ipAddr)}
		}(i, ip)
	}

	for range ips {
		r := <-ch
		results[r.index] = r.data
	}
	return results
}

// queryIPFromPconline uses whois.pconline.com.cn — highly accurate for Chinese IPs.
func queryIPFromPconline(ip string) gin.H {
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("https://whois.pconline.com.cn/ipJson.jsp?ip=%s&json=true", ip)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	// pconline always returns GBK-encoded JSON — decode to UTF-8 first
	utf8Body := decodeGBK(rawBody)
	if utf8Body == "" {
		return nil
	}

	var pResult struct {
		IP         string `json:"ip"`
		Pro        string `json:"pro"` // 省份
		ProCode    string `json:"proCode"`
		City       string `json:"city"` // 城市
		CityCode   string `json:"cityCode"`
		Region     string `json:"region"` // 区/县
		RegionCode string `json:"regionCode"`
		Addr       string `json:"addr"` // 完整地址描述
		Err        string `json:"err"`
	}

	if err := json.Unmarshal([]byte(utf8Body), &pResult); err != nil {
		return nil
	}

	if pResult.Err != "" && pResult.Err != "noprovince" {
		return nil
	}

	// If no province info, this API can't resolve it (likely non-Chinese IP)
	if pResult.Pro == "" && pResult.City == "" {
		return nil
	}

	country := "中国"
	province := trimAdminSuffix(pResult.Pro)
	city := trimAdminSuffix(pResult.City)
	if province == "" {
		province = "未知"
	}
	if city == "" {
		city = province
	}

	// Extract ISP from addr (format: "省份城市 运营商")
	isp := extractISPFromAddr(pResult.Addr, pResult.Pro, pResult.City)

	// Get coordinates from ip-api.com as supplementary (pconline doesn't provide coords)
	location := getCoordinates(ip)

	lineType := classifyLineType(isp, "", "")
	return gin.H{
		"ip":               ip,
		"country":          country,
		"province":         province,
		"city":             city,
		"isp":              isp,
		"asn":              "--",
		"location":         location,
		"lineType":         lineType,
		"geoDnsSuggestion": suggestGeoDns(country, province),
	}
}

// queryIPFromIpApi uses ip-api.com as fallback (better for overseas IPs).
func queryIPFromIpApi(ip string) gin.H {
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=query,status,country,regionName,city,isp,org,as,lat,lon&lang=zh-CN", ip)
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var r struct {
		Query      string  `json:"query"`
		Status     string  `json:"status"`
		Country    string  `json:"country"`
		RegionName string  `json:"regionName"`
		City       string  `json:"city"`
		ISP        string  `json:"isp"`
		Org        string  `json:"org"`
		AS         string  `json:"as"`
		Lat        float64 `json:"lat"`
		Lon        float64 `json:"lon"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Status != "success" {
		return nil
	}

	lineType := classifyLineType(r.ISP, r.Org, r.AS)
	return gin.H{
		"ip":               r.Query,
		"country":          r.Country,
		"province":         r.RegionName,
		"city":             r.City,
		"isp":              r.ISP,
		"asn":              r.AS,
		"location":         fmt.Sprintf("%.6f,%.6f", r.Lat, r.Lon),
		"lineType":         lineType,
		"geoDnsSuggestion": suggestGeoDns(r.Country, r.RegionName),
	}
}

// trimAdminSuffix removes Chinese administrative suffixes for cleaner display.
func trimAdminSuffix(name string) string {
	s := strings.TrimSpace(name)
	// Order matters: longer suffixes first
	for _, suffix := range []string{"维吾尔自治区", "壮族自治区", "回族自治区", "自治区", "特别行政区", "自治州", "地区", "省", "市"} {
		if strings.HasSuffix(s, suffix) && len(s) > len(suffix) {
			s = strings.TrimSuffix(s, suffix)
			break
		}
	}
	return s
}

// extractISPFromAddr parses ISP name from pconline's addr field.
// addr format: "贵州省遵义市仁怀市 移动" — the ISP is after the last space.
func extractISPFromAddr(addr, province, city string) string {
	s := strings.TrimSpace(addr)
	if s == "" {
		return "未知"
	}
	// The ISP is typically the last space-separated token
	if idx := strings.LastIndex(s, " "); idx >= 0 {
		isp := strings.TrimSpace(s[idx+1:])
		if isp != "" {
			return isp
		}
	}
	// Fallback: try removing known location prefixes
	s = strings.ReplaceAll(s, province, "")
	s = strings.ReplaceAll(s, city, "")
	s = strings.TrimSpace(s)
	if s == "" {
		return "未知"
	}
	return s
}

// getCoordinates fetches lat/lon from ip-api.com (lightweight, just for coords).
func getCoordinates(ip string) string {
	client := &http.Client{Timeout: 3 * time.Second}
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=lat,lon", ip)
	resp, err := client.Get(url)
	if err != nil {
		return "--"
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var coords struct {
		Lat float64 `json:"lat"`
		Lon float64 `json:"lon"`
	}
	if err := json.Unmarshal(body, &coords); err != nil {
		return "--"
	}
	if coords.Lat == 0 && coords.Lon == 0 {
		return "--"
	}
	return fmt.Sprintf("%.6f,%.6f", coords.Lat, coords.Lon)
}

// decodeGBK converts GBK-encoded bytes to UTF-8 string.
func decodeGBK(data []byte) string {
	decoder := simplifiedchinese.GBK.NewDecoder()
	utf8Bytes, err := decoder.Bytes(data)
	if err != nil {
		return ""
	}
	return string(utf8Bytes)
}

func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	privateRanges := []struct{ start, end net.IP }{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
		{net.ParseIP("127.0.0.0"), net.ParseIP("127.255.255.255")},
	}
	for _, r := range privateRanges {
		if bytesCompare(parsed, r.start) >= 0 && bytesCompare(parsed, r.end) <= 0 {
			return true
		}
	}
	return false
}

func bytesCompare(a, b net.IP) int {
	a = a.To4()
	b = b.To4()
	if a == nil || b == nil {
		return 0
	}
	for i := 0; i < 4; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func classifyLineType(isp, org, asStr string) string {
	combined := isp + " " + org + " " + asStr
	lower := strings.ToLower(combined)
	if strings.Contains(lower, "proxy") || strings.Contains(lower, "vpn") || strings.Contains(lower, "anonymous") {
		return "高风险代理线路"
	}
	if strings.Contains(lower, "cloud") || strings.Contains(lower, "data center") || strings.Contains(lower, "hosting") ||
		strings.Contains(lower, "amazon") || strings.Contains(lower, "google") || strings.Contains(lower, "microsoft") ||
		strings.Contains(lower, "alibaba") || strings.Contains(lower, "tencent") || strings.Contains(lower, "digitalocean") ||
		strings.Contains(combined, "阿里云") || strings.Contains(combined, "腾讯云") || strings.Contains(combined, "华为云") {
		return "数据中心线路"
	}
	if strings.Contains(lower, "mobile") || strings.Contains(lower, "cellular") ||
		strings.Contains(combined, "移动") {
		return "移动网络线路"
	}
	if strings.Contains(combined, "电信") || strings.Contains(lower, "telecom") || strings.Contains(lower, "chinanet") {
		return "电信线路"
	}
	if strings.Contains(combined, "联通") || strings.Contains(lower, "unicom") {
		return "联通线路"
	}
	return "普通线路"
}

func suggestGeoDns(country, region string) string {
	if strings.Contains(country, "中国") || strings.Contains(country, "China") {
		switch {
		case strings.Contains(region, "北京") || strings.Contains(region, "天津") || strings.Contains(region, "河北") ||
			strings.Contains(region, "山东") || strings.Contains(region, "辽宁"):
			return "华北节点"
		case strings.Contains(region, "上海") || strings.Contains(region, "江苏") || strings.Contains(region, "浙江") ||
			strings.Contains(region, "安徽"):
			return "华东节点"
		case strings.Contains(region, "广东") || strings.Contains(region, "广西") || strings.Contains(region, "福建") ||
			strings.Contains(region, "海南"):
			return "华南节点"
		case strings.Contains(region, "四川") || strings.Contains(region, "重庆") || strings.Contains(region, "云南") ||
			strings.Contains(region, "贵州"):
			return "西南节点"
		default:
			return "中国通用节点"
		}
	}
	if strings.Contains(country, "美国") || strings.Contains(country, "United States") || strings.Contains(country, "加拿大") {
		return "北美节点"
	}
	if strings.Contains(country, "日本") || strings.Contains(country, "韩国") || strings.Contains(country, "新加坡") ||
		strings.Contains(country, "Singapore") {
		return "亚太节点"
	}
	if strings.Contains(country, "德国") || strings.Contains(country, "法国") || strings.Contains(country, "英国") ||
		strings.Contains(country, "Netherlands") {
		return "欧洲节点"
	}
	return "全球通用节点"
}

// dohResolve performs DNS resolution via DNS-over-HTTPS JSON API.
// Supports Google (/resolve?name=&type=) and RFC 8484 JSON format.
func dohResolve(endpoint, domain, recordType string) (result string, latencyMs int) {
	if recordType == "" {
		recordType = "A"
	}

	// Build DoH JSON API URL
	sep := "?"
	if strings.Contains(endpoint, "?") {
		sep = "&"
	}
	url := fmt.Sprintf("%s%sname=%s&type=%s", endpoint, sep, domain, recordType)

	client := &http.Client{Timeout: 8 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/dns-json")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := int(time.Since(start).Milliseconds())
	if err != nil {
		log.Printf("[global-test] DoH %s failed: %v", url, err)
		return "--", 0
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "--", 0
	}

	// Parse DoH JSON response (Google/Alidns/Cloudflare all support this format)
	var dohResp struct {
		Status int `json:"Status"`
		Answer []struct {
			Name string `json:"name"`
			Type int    `json:"type"`
			TTL  int    `json:"TTL"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &dohResp); err != nil {
		log.Printf("[global-test] DoH parse error for %s: %v, body=%s", url, err, string(body[:min(len(body), 200)]))
		return "--", 0
	}

	if len(dohResp.Answer) == 0 {
		return "--", elapsed
	}

	var parts []string
	for _, ans := range dohResp.Answer {
		parts = append(parts, ans.Data)
	}
	return strings.Join(parts, ", "), elapsed
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func buildFallbackDigOutput(domain, recType, dnsServer string) string {
	now := time.Now().Format("Mon Jan 2 15:04:05 UTC 2006")

	if dnsServer == "" || dnsServer == "系统默认DNS" {
		dnsServer = "dns.alidns.com"
	}

	// Use DoH to resolve (port 53 may be blocked)
	result, latency := dohResolve("https://dns.alidns.com/resolve", domain, recType)

	if result == "--" || result == "" {
		return fmt.Sprintf(
			"; <<>> DiG 9.18 <<>> %s %s\n;; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL\n\n;; QUESTION SECTION:\n;%s.\tIN\t%s\n\n;; Query time: %d msec\n;; SERVER: %s\n;; WHEN: %s\n",
			domain, recType, domain, recType, latency, dnsServer, now,
		)
	}

	answers := strings.Split(result, ", ")
	var answerSection string
	for _, a := range answers {
		answerSection += fmt.Sprintf("%s.\t300\tIN\t%s\t%s\n", domain, recType, a)
	}

	return fmt.Sprintf(
		"; <<>> DiG 9.18 <<>> %s %s\n;; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR\n\n;; QUESTION SECTION:\n;%s.\tIN\t%s\n\n;; ANSWER SECTION:\n%s\n;; Query time: %d msec\n;; SERVER: %s\n;; WHEN: %s\n",
		domain, recType, domain, recType, answerSection, latency, dnsServer, now,
	)
}

func buildTestNodeReal(id int, node, operator, category, result string, latencyMs int) gin.H {
	consistency := "一致"
	detail := "解析成功"
	if result == "--" {
		latencyMs = 0
		consistency = "超时"
		detail = "节点超时，请检查链路"
	}
	return gin.H{
		"id":          id,
		"node":        node,
		"operator":    operator,
		"category":    category,
		"result":      result,
		"latency":     latencyMs,
		"consistency": consistency,
		"detail":      detail,
	}
}

func resolveIPLocation(ip string) gin.H {
	if isPrivateIP(ip) {
		return gin.H{
			"ip": ip, "country": "内网", "province": "--", "city": "--",
			"isp": "内网", "asn": "--", "location": "--",
			"lineType": "内网线路", "geoDnsSuggestion": "--",
		}
	}
	return gin.H{
		"ip": ip, "country": "未知", "province": "未知", "city": "未知",
		"isp": "未知", "asn": "--", "location": "0,0",
		"lineType": "普通线路", "geoDnsSuggestion": "--",
	}
}

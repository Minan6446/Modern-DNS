package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"modern-dns/internal/dnsengine"
	"modern-dns/internal/model"
	"modern-dns/pkg/db"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
)

// GET /api/cache/strategy
func GetCacheStrategy(c *gin.Context) {
	var cfg model.CacheGlobalStrategy
	db.DB.FirstOrCreate(&cfg, model.CacheGlobalStrategy{ID: 1})
	keyword := c.Query("keyword")
	status := c.Query("status")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "0")) // 0 = no paging
	if page < 1 {
		page = 1
	}

	query := db.DB.Model(&model.CacheDomainRule{})
	if keyword != "" {
		query = query.Where("domain LIKE ?", "%"+keyword+"%")
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	var total int64
	query.Count(&total)
	var rules []model.CacheDomainRule
	q := query.Order("created_at DESC")
	if size > 0 {
		q = q.Offset((page - 1) * size).Limit(size)
	}
	q.Find(&rules)
	if rules == nil {
		rules = []model.CacheDomainRule{}
	}
	resp.OK(c, gin.H{
		"global":      cfg,
		"domainRules": rules,
		"total":       total,
	})
}

// PUT /api/cache/strategy/global
func SaveCacheGlobalStrategy(c *gin.Context) {
	var req model.CacheGlobalStrategy
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	req.ID = 1
	db.DB.Save(&req)
	writeOpLogAuth(c, "配置", "缓存策略", "保存全局缓存策略", "")
	dnsengine.Trigger()
	resp.OK(c, req)
}

// POST /api/cache/strategy/domain-rules
func CreateCacheDomainRule(c *gin.Context) {
	var rule model.CacheDomainRule
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

// PUT /api/cache/strategy/domain-rules/:id
func UpdateCacheDomainRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var payload struct {
		Domain       string `json:"domain"`
		CustomTTL    int    `json:"customTtl"`
		CustomRetain int    `json:"customRetain"`
		Status       string `json:"status"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	updates := map[string]interface{}{
		"domain":        payload.Domain,
		"custom_ttl":    payload.CustomTTL,
		"custom_retain": payload.CustomRetain,
		"status":        payload.Status,
	}
	if err := db.DB.Model(&model.CacheDomainRule{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	var rule model.CacheDomainRule
	db.DB.First(&rule, id)
	dnsengine.Trigger()
	resp.OK(c, rule)
}

// DELETE /api/cache/strategy/domain-rules/:id
func DeleteCacheDomainRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Delete(&model.CacheDomainRule{}, id)
	dnsengine.Trigger()
	resp.OK(c, gin.H{"id": id})
}

// DELETE /api/cache/strategy/domain-rules/batch
func BatchDeleteCacheDomainRules(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	db.DB.Delete(&model.CacheDomainRule{}, req.IDs)
	dnsengine.Trigger()
	resp.OK(c, gin.H{"ids": req.IDs})
}

// GET /api/cache/entries
// Returns a paged list of live cache entries from Redis
func GetCacheEntries(c *gin.Context) {
	if db.RDBCache == nil {
		resp.OK(c, []gin.H{})
		return
	}
	pattern := c.DefaultQuery("pattern", "dns:cache:*")
	var cursor uint64
	var keys []string
	for {
		batch, nextCursor, err := db.RDBCache.Scan(context.Background(), cursor, pattern, 100).Result()
		if err != nil {
			break
		}
		keys = append(keys, batch...)
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	var entries []gin.H
	for _, key := range keys {
		ttl, _ := db.RDBCache.TTL(context.Background(), key).Result()
		val, _ := db.RDBCache.HGetAll(context.Background(), key).Result()
		ttlRemaining := int(ttl.Seconds())
		ttlOriginal, _ := strconv.Atoi(val["ttlOriginal"])
		if ttlOriginal <= 0 {
			ttlOriginal = ttlRemaining
		}
		entries = append(entries, gin.H{
			"cacheId":      key,
			"domain":       val["domain"],
			"recordType":   val["recordType"],
			"recordValue":  val["recordValue"],
			"ttlRemaining": ttlRemaining,
			"ttlOriginal":  ttlOriginal,
			"source":       val["source"],
			"cacheTime":    val["cacheTime"],
			"updatedAt":    val["cacheTime"],
		})
	}
	if entries == nil {
		entries = []gin.H{}
	}
	resp.OK(c, entries)
}

// clearCacheRequest is the wire shape accepted by POST /api/cache/clear.
//
// Two distinct call shapes are supported on the same endpoint so the
// 「缓存浏览」row-level "clear this entry" buttons (which already pass
// raw Redis keys via IDs) keep working unchanged, while「手动清理」
// gains a richer scope-based contract:
//
//  1. Row-level:   {"ids":["dns:cache:..."]}                — legacy
//  2. Scope-level: {"scope":"all|expired|domain","domains":"a.com,b.com",
//     "timeRange":["2026-05-01 00:00:00","2026-05-11 00:00:00"],
//     "preview":true}
//
// `Preview=true` runs the SCAN + filter without DEL'ing anything and
// without writing a CacheClearLog row — used by the dialog's "preview"
// step so the operator sees an authoritative count from Redis instead
// of the frontend's locally-cached `entries` snapshot (which can be
// stale by minutes).
type clearCacheRequest struct {
	IDs       []string `json:"ids"`
	Domain    string   `json:"domain"` // legacy, single-domain shape
	Scope     string   `json:"scope"`  // "all" | "expired" | "domain"
	Domains   string   `json:"domains"`
	TimeRange []string `json:"timeRange"`
	Preview   bool     `json:"preview"`
}

// POST /api/cache/clear
func ClearCache(c *gin.Context) {
	var req clearCacheRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Tolerate empty / malformed bodies — the legacy "clear all"
		// call sometimes posts no body at all. Treat as scope=all.
		req = clearCacheRequest{}
	}

	if db.RDBCache == nil {
		// Without Redis we have no cache to clear, but we still
		// return success so the UI can complete its own flow. The
		// log row is skipped because there's nothing to record.
		resp.OK(c, gin.H{
			"clearedCount": 0,
			"clearedAt":    time.Now().Format("2006-01-02 15:04:05"),
			"scope":        normaliseScope(req),
			"preview":      req.Preview,
		})
		return
	}

	keys, err := selectClearKeys(c.Request.Context(), &req)
	if err != nil {
		resp.ServerError(c, err.Error())
		return
	}

	cleared := 0
	if !req.Preview {
		for _, k := range keys {
			if db.RDBCache.Del(c.Request.Context(), k).Val() > 0 {
				cleared++
			}
		}
	} else {
		// In preview mode we only count what would match; we never
		// delete. Returning len(keys) keeps the UI's "本次将清理 N 条"
		// honest even when some keys would have already auto-expired
		// between SCAN and DEL.
		cleared = len(keys)
	}

	scope := normaliseScope(req)
	scopeLabel := buildScopeLabel(scope, &req)

	// A zero-match real clear is a no-op — refuse to pollute either
	// the audit trail or the「清理历史」panel with rows that record
	// "cleared 0 items". Frontend's preview step already shows the
	// "本次将清理 0 条" warning, but a determined operator might
	// still click 确认清理; this guard makes that path benign.
	if !req.Preview && cleared > 0 {
		// Audit + UI history. Both writes are best-effort: a failure
		// to record the log must not propagate as a 500 to the user
		// — they did successfully clear the cache, the bookkeeping is
		// secondary.
		writeOpLogAuth(c, "清除", "DNS缓存",
			fmt.Sprintf("手动清理 %s（%d 条）", scopeLabel, cleared), "")

		detail, _ := json.Marshal(map[string]any{
			"scope":     scope,
			"domains":   req.Domains,
			"timeRange": req.TimeRange,
		})
		start, end := "", ""
		if len(req.TimeRange) >= 1 {
			start = req.TimeRange[0]
		}
		if len(req.TimeRange) >= 2 {
			end = req.TimeRange[1]
		}
		log := model.CacheClearLog{
			Scope:        scope,
			ScopeLabel:   scopeLabel,
			Domains:      req.Domains,
			TimeStart:    start,
			TimeEnd:      end,
			ClearedCount: cleared,
			Operator:     actorUsername(c),
			IP:           c.ClientIP(),
			Detail:       string(detail),
		}
		if err := db.DB.Create(&log).Error; err != nil {
			// Don't fail the request — log to server log only.
			fmt.Printf("[cache-clear] failed to persist clear log: %v\n", err)
		}
	}

	resp.OK(c, gin.H{
		"clearedCount": cleared,
		"clearedAt":    time.Now().Format("2006-01-02 15:04:05"),
		"scope":        scope,
		"scopeLabel":   scopeLabel,
		"preview":      req.Preview,
	})
}

// normaliseScope canonicalises whichever request shape we got into a
// single scope tag the rest of the pipeline can switch on. The legacy
// `ids` and `domain` fields take precedence for backwards compat: a
// caller that passed `ids` is by definition asking for a row-level
// clear regardless of what they put in `scope`.
func normaliseScope(r clearCacheRequest) string {
	switch {
	case len(r.IDs) > 0:
		return "ids"
	case r.Domain != "":
		return "domain"
	}
	switch strings.ToLower(strings.TrimSpace(r.Scope)) {
	case "expired":
		return "expired"
	case "domain":
		return "domain"
	case "", "all":
		return "all"
	}
	return "all"
}

// buildScopeLabel renders a human-readable Chinese summary of the
// purge for both the operator log and the「清理历史」list. Kept here
// so the wire payload of POST /clear stays small (frontend doesn't
// have to round-trip a label) and the table reads consistently no
// matter who issued the call.
func buildScopeLabel(scope string, r *clearCacheRequest) string {
	switch scope {
	case "ids":
		return fmt.Sprintf("精确清理 %d 条", len(r.IDs))
	case "expired":
		return "已过期缓存"
	case "domain":
		domains := r.Domain
		if r.Domains != "" {
			domains = r.Domains
		}
		domains = strings.TrimSpace(domains)
		if domains == "" {
			return "按域名清理"
		}
		return fmt.Sprintf("按域名清理：%s", domains)
	case "all":
		return "全部缓存"
	}
	return scope
}

// selectClearKeys walks the Redis cache namespace once and returns
// only the keys that match the requested scope. The walk uses SCAN
// (cursored, non-blocking) so a long-running clear can't stall the
// query path the way KEYS would on a hot Redis. Each match is
// further filtered by the optional time-range against the cached
// `cacheTime` hash field — that's the same field GetCacheEntries
// surfaces, so "I cleared everything from May 1–8" matches what the
// operator saw in the table.
func selectClearKeys(ctx context.Context, r *clearCacheRequest) ([]string, error) {
	// Row-level: caller already knows the keys, just return them.
	if len(r.IDs) > 0 {
		return r.IDs, nil
	}

	scope := normaliseScope(*r)
	domainMatches := splitCSV(r.Domains)
	if r.Domain != "" {
		domainMatches = append(domainMatches, r.Domain)
	}

	// Pre-compute the time-range bounds once.
	var tStart, tEnd time.Time
	hasTimeFilter := false
	if len(r.TimeRange) == 2 && r.TimeRange[0] != "" && r.TimeRange[1] != "" {
		s, errS := time.Parse("2006-01-02 15:04:05", r.TimeRange[0])
		e, errE := time.Parse("2006-01-02 15:04:05", r.TimeRange[1])
		if errS == nil && errE == nil {
			tStart, tEnd = s, e
			hasTimeFilter = true
		}
	}

	matched := make([]string, 0, 256)
	var cursor uint64
	for {
		batch, next, err := db.RDBCache.Scan(ctx, cursor, "dns:cache:*", 200).Result()
		if err != nil {
			return nil, fmt.Errorf("scan redis cache: %w", err)
		}
		for _, key := range batch {
			if !keyMatchesScope(ctx, key, scope, domainMatches, hasTimeFilter, tStart, tEnd) {
				continue
			}
			matched = append(matched, key)
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return matched, nil
}

// keyMatchesScope decides whether a single Redis cache key satisfies
// the scope+filter combination. `expired` is interpreted as "TTL has
// already elapsed but the key is still around" — Redis usually evicts
// these on its own, so this set is mostly empty in practice; we keep
// the branch so an operator can still flush the residue after a
// pathological GC stall.
func keyMatchesScope(
	ctx context.Context,
	key, scope string,
	domains []string,
	hasTimeFilter bool,
	tStart, tEnd time.Time,
) bool {
	switch scope {
	case "expired":
		ttl, err := db.RDBCache.TTL(ctx, key).Result()
		if err != nil {
			return false
		}
		// TTL == -2 → key gone, -1 → no expiry. We only care about
		// "expired but lingering" which Redis exposes as TTL <= 0 on
		// keys that did have an expiry set at write time.
		if ttl > 0 {
			return false
		}
	case "domain":
		dom, _ := db.RDBCache.HGet(ctx, key, "domain").Result()
		if dom == "" {
			return false
		}
		if !anySubstring(dom, domains) {
			return false
		}
	case "all":
		// no scope-specific filter
	default:
		return false
	}

	if hasTimeFilter {
		ts, _ := db.RDBCache.HGet(ctx, key, "cacheTime").Result()
		if ts == "" {
			return false
		}
		t, err := time.Parse("2006-01-02 15:04:05", ts)
		if err != nil {
			return false
		}
		if t.Before(tStart) || t.After(tEnd) {
			return false
		}
	}
	return true
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ';'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func anySubstring(haystack string, needles []string) bool {
	if len(needles) == 0 {
		return false
	}
	h := strings.ToLower(haystack)
	for _, n := range needles {
		if strings.Contains(h, n) {
			return true
		}
	}
	return false
}

// GET /api/cache/clear/logs?limit=N
// Returns the most recent purge-log rows for the「清理历史」panel.
// Default limit 50, clamped to [1, 500] so a malicious caller can't
// make us serialise the full history table.
func GetCacheClearLogs(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit < 1 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	var rows []model.CacheClearLog
	if err := db.DB.Order("created_at DESC").Limit(limit).Find(&rows).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	if rows == nil {
		rows = []model.CacheClearLog{}
	}
	resp.OK(c, rows)
}

// DELETE /api/cache/clear/logs
// Truncates the purge-log table. Used by the「清空」button on the
// 「清理历史」panel; we keep audit trail in operation_logs separately,
// so this is purely a UI-state reset.
func PurgeCacheClearLogs(c *gin.Context) {
	if err := db.DB.Where("1=1").Delete(&model.CacheClearLog{}).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	writeOpLogAuth(c, "清除", "DNS缓存", "清空清理历史", "")
	resp.OK(c, gin.H{"cleared": true})
}

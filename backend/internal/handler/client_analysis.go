package handler

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// GET /api/monitor/client-analysis
func GetClientAnalysis(c *gin.Context) {
	timeRange := c.DefaultQuery("range", "1d")
	keyword := c.Query("keyword")
	region := c.Query("region")

	now := time.Now()
	var since time.Time
	switch timeRange {
	case "1h":
		since = now.Add(-1 * time.Hour)
	case "7d":
		since = now.AddDate(0, 0, -6)
	default:
		since = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	}

	base := db.DB.Model(&model.QueryLog{}).Where("created_at >= ?", since)
	if keyword != "" {
		base = base.Where("source_ip LIKE ? OR domain LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}
	if region != "" {
		base = base.Where("region = ?", region)
	}

	// ── Top clients ──
	type clientRow struct {
		IP            string  `json:"ip"`
		Region        string  `json:"region"`
		QueryCount    int64   `json:"queryCount"`
		NxdomainCount int64   `json:"nxdomainCount"`
		ErrorRate     float64 `json:"errorRate"`
		TopDomain     string  `json:"topDomain"`
		LastSeen      string  `json:"lastSeen"`
	}

	var raws []rawClient
	base.Session(&gorm.Session{}).
		Select(`source_ip,
			COALESCE(region, '') as region,
			COUNT(*) as cnt,
			SUM(CASE WHEN rcode = 'NXDOMAIN' THEN 1 ELSE 0 END) as nx_cnt,
			SUM(CASE WHEN response_status != '成功' THEN 1 ELSE 0 END) as err_cnt,
			MAX(created_at) as last_seen`).
		Group("source_ip, region").
		Order("cnt DESC").
		Limit(100).
		Scan(&raws)

	// Bulk fetch top-domain for every IP in raws using a single window-style
	// aggregate query, instead of N+1 separate Pluck calls.
	topDomainMap := bulkTopDomain(raws, since)

	var clients []clientRow
	for _, r := range raws {
		errRate := 0.0
		if r.Cnt > 0 {
			errRate = math.Round(float64(r.ErrCnt)/float64(r.Cnt)*1000) / 10
		}
		clients = append(clients, clientRow{
			IP:            r.SourceIP,
			Region:        r.Region,
			QueryCount:    r.Cnt,
			NxdomainCount: r.NxCnt,
			ErrorRate:     errRate,
			TopDomain:     topDomainMap[r.SourceIP],
			LastSeen:      r.LastSeen.Format("2006-01-02 15:04"),
		})
	}
	if clients == nil {
		clients = []clientRow{}
	}

	// ── Trend data ── single SQL query per range using a CASE bucket index.
	trend := buildTrend(timeRange, now)

	// ── Distribution: region, record type, ISP ──
	type nameVal struct {
		Name  string `json:"name"`
		Value int64  `json:"value"`
	}

	var geoDist []nameVal
	db.DB.Model(&model.QueryLog{}).Where("created_at >= ?", since).
		Select("COALESCE(region, '未知') as name, COUNT(*) as value").
		Group("region").Order("value DESC").Scan(&geoDist)
	if geoDist == nil {
		geoDist = []nameVal{}
	}

	var typeDist []nameVal
	db.DB.Model(&model.QueryLog{}).Where("created_at >= ?", since).
		Select("record_type as name, COUNT(*) as value").
		Group("record_type").Order("value DESC").Scan(&typeDist)
	if typeDist == nil {
		typeDist = []nameVal{}
	}

	resp.OK(c, gin.H{
		"clients":  clients,
		"trend":    trend,
		"geoDist":  geoDist,
		"typeDist": typeDist,
	})
}

// bulkTopDomain returns a single source_ip→most-queried-domain map computed in
// one SQL query, avoiding the previous N+1 Pluck-per-IP pattern.
func bulkTopDomain(raws []rawClient, since time.Time) map[string]string {
	result := make(map[string]string, len(raws))
	if len(raws) == 0 {
		return result
	}
	ips := make([]string, 0, len(raws))
	for _, r := range raws {
		ips = append(ips, r.SourceIP)
	}

	type row struct {
		SourceIP string `gorm:"column:source_ip"`
		Domain   string `gorm:"column:domain"`
		Cnt      int64  `gorm:"column:cnt"`
	}
	var rows []row
	db.DB.Model(&model.QueryLog{}).
		Select("source_ip, domain, COUNT(*) AS cnt").
		Where("source_ip IN ? AND created_at >= ?", ips, since).
		Group("source_ip, domain").
		Scan(&rows)

	// In Go, keep the highest-count domain per IP — still cheap because we
	// already capped clients at 100 distinct IPs.
	best := make(map[string]int64, len(raws))
	for _, r := range rows {
		if r.Cnt > best[r.SourceIP] {
			best[r.SourceIP] = r.Cnt
			result[r.SourceIP] = r.Domain
		}
	}
	return result
}

// rawClient is shared across helpers so callers don't need to redefine it.
type rawClient struct {
	SourceIP string
	Region   string
	Cnt      int64
	NxCnt    int64
	ErrCnt   int64
	LastSeen time.Time
}

// trendPoint mirrors the JSON shape returned to the dashboard.
type trendPoint struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

// buildTrend produces a per-bucket query count using a single SQL aggregation.
func buildTrend(timeRange string, now time.Time) []trendPoint {
	type window struct {
		label string
		start time.Time
		end   time.Time
	}
	var windows []window

	switch timeRange {
	case "1h":
		for i := 11; i >= 0; i-- {
			t := now.Add(-time.Duration(i) * 5 * time.Minute)
			start := t.Truncate(5 * time.Minute)
			end := start.Add(5 * time.Minute)
			windows = append(windows, window{label: start.Format("15:04"), start: start, end: end})
		}
	case "7d":
		for i := 6; i >= 0; i-- {
			d := now.AddDate(0, 0, -i)
			start := time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, d.Location())
			end := start.AddDate(0, 0, 1)
			windows = append(windows, window{label: start.Format("01-02"), start: start, end: end})
		}
	default: // "1d"
		for h := 0; h < 24; h++ {
			start := time.Date(now.Year(), now.Month(), now.Day(), h, 0, 0, 0, now.Location())
			end := start.Add(time.Hour)
			windows = append(windows, window{label: fmt.Sprintf("%02d:00", h), start: start, end: end})
		}
	}
	if len(windows) == 0 {
		return []trendPoint{}
	}

	var sb strings.Builder
	args := make([]interface{}, 0, len(windows)*2)
	sb.WriteString("(CASE ")
	for i, w := range windows {
		sb.WriteString("WHEN created_at >= ? AND created_at < ? THEN ")
		sb.WriteString(strconv.Itoa(i))
		sb.WriteString(" ")
		args = append(args, w.start, w.end)
	}
	sb.WriteString("ELSE -1 END)")

	var rows []struct {
		Idx int   `gorm:"column:bucket_idx"`
		Cnt int64 `gorm:"column:cnt"`
	}
	db.DB.Model(&model.QueryLog{}).
		Select(sb.String()+" AS bucket_idx, COUNT(*) AS cnt", args...).
		Where("created_at >= ?", windows[0].start).
		Group("bucket_idx").
		Scan(&rows)

	counts := make([]int64, len(windows))
	for _, r := range rows {
		if r.Idx >= 0 && r.Idx < len(counts) {
			counts[r.Idx] = r.Cnt
		}
	}
	out := make([]trendPoint, len(windows))
	for i, w := range windows {
		out[i] = trendPoint{Label: w.label, Count: counts[i]}
	}
	return out
}

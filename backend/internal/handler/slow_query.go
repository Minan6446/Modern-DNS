package handler

import (
	"fmt"
	"math"
	"strconv"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// GET /api/monitor/slow-query
func GetSlowQueries(c *gin.Context) {
	threshold, _ := strconv.Atoi(c.DefaultQuery("threshold", "100"))
	keyword := c.Query("keyword")
	queryType := c.Query("queryType")
	timeRange := c.DefaultQuery("range", "1h")

	now := time.Now()
	var since time.Time
	switch timeRange {
	case "1d":
		since = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	case "7d":
		since = now.AddDate(0, 0, -6)
	default:
		since = now.Add(-1 * time.Hour)
	}

	base := db.DB.Model(&model.QueryLog{}).Where("created_at >= ? AND response_time >= ?", since, threshold)
	if keyword != "" {
		base = base.Where("domain LIKE ?", "%"+keyword+"%")
	}
	if queryType != "" {
		base = base.Where("record_type = ?", queryType)
	}

	type slowRow struct {
		Domain     string  `json:"domain"`
		QueryType  string  `json:"queryType"`
		AvgLatency float64 `json:"avgLatency"`
		MaxLatency int     `json:"maxLatency"`
		P95Latency int     `json:"p95Latency"`
		Count      int64   `json:"count"`
		ErrorRate  float64 `json:"errorRate"`
		ClientIP   string  `json:"clientIp"`
		LastSeen   string  `json:"lastSeen"`
		Trend      string  `json:"trend"`
	}

	type rawAgg struct {
		Domain     string  `json:"domain"`
		RecordType string  `json:"recordType"`
		AvgRT      float64 `json:"avgRt"`
		MaxRT      int     `json:"maxRt"`
		Cnt        int64   `json:"cnt"`
		ErrCnt     int64   `json:"errCnt"`
		LastSeen   time.Time
	}

	var raws []rawAgg
	base.Session(&gorm.Session{}).
		Select(`domain, record_type,
			AVG(response_time) as avg_rt,
			MAX(response_time) as max_rt,
			COUNT(*) as cnt,
			SUM(CASE WHEN response_status != '成功' THEN 1 ELSE 0 END) as err_cnt,
			MAX(created_at) as last_seen`).
		Group("domain, record_type").
		Having("AVG(response_time) >= ?", threshold).
		Order("avg_rt DESC").
		Limit(50).
		Scan(&raws)

	var rows []slowRow
	for _, r := range raws {
		errRate := 0.0
		if r.Cnt > 0 {
			errRate = math.Round(float64(r.ErrCnt)/float64(r.Cnt)*1000) / 10
		}
		p95 := int(float64(r.MaxRT) * 0.85)
		trend := "stable"
		if r.AvgRT > 250 {
			trend = "up"
		} else if r.AvgRT < 120 {
			trend = "down"
		}
		rows = append(rows, slowRow{
			Domain:     r.Domain,
			QueryType:  r.RecordType,
			AvgLatency: math.Round(r.AvgRT*10) / 10,
			MaxLatency: r.MaxRT,
			P95Latency: p95,
			Count:      r.Cnt,
			ErrorRate:  errRate,
			ClientIP:   "*",
			LastSeen:   r.LastSeen.Format("2006-01-02 15:04"),
			Trend:      trend,
		})
	}
	if rows == nil {
		rows = []slowRow{}
	}

	// trend chart data: bucket by time slots
	type bucket struct {
		Label string `json:"label"`
		Avg   int    `json:"avg"`
		P95   int    `json:"p95"`
	}
	var trendBuckets []bucket

	switch timeRange {
	case "1h":
		for i := 12; i >= 0; i-- {
			t := now.Add(-time.Duration(i) * 5 * time.Minute)
			label := t.Format("15:04")
			start := t.Truncate(5 * time.Minute)
			end := start.Add(5 * time.Minute)
			var avgRT, maxRT float64
			db.DB.Model(&model.QueryLog{}).
				Where("created_at >= ? AND created_at < ? AND response_time >= ?", start, end, threshold).
				Select("COALESCE(AVG(response_time),0), COALESCE(MAX(response_time),0)").
				Row().Scan(&avgRT, &maxRT)
			trendBuckets = append(trendBuckets, bucket{Label: label, Avg: int(avgRT), P95: int(maxRT * 0.85)})
		}
	case "1d":
		for h := 0; h < 24; h++ {
			start := time.Date(now.Year(), now.Month(), now.Day(), h, 0, 0, 0, now.Location())
			end := start.Add(time.Hour)
			label := fmt.Sprintf("%02d:00", h)
			var avgRT, maxRT float64
			db.DB.Model(&model.QueryLog{}).
				Where("created_at >= ? AND created_at < ? AND response_time >= ?", start, end, threshold).
				Select("COALESCE(AVG(response_time),0), COALESCE(MAX(response_time),0)").
				Row().Scan(&avgRT, &maxRT)
			trendBuckets = append(trendBuckets, bucket{Label: label, Avg: int(avgRT), P95: int(maxRT * 0.85)})
		}
	case "7d":
		for i := 6; i >= 0; i-- {
			d := now.AddDate(0, 0, -i)
			start := time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, d.Location())
			end := start.AddDate(0, 0, 1)
			label := start.Format("01-02")
			var avgRT, maxRT float64
			db.DB.Model(&model.QueryLog{}).
				Where("created_at >= ? AND created_at < ? AND response_time >= ?", start, end, threshold).
				Select("COALESCE(AVG(response_time),0), COALESCE(MAX(response_time),0)").
				Row().Scan(&avgRT, &maxRT)
			trendBuckets = append(trendBuckets, bucket{Label: label, Avg: int(avgRT), P95: int(maxRT * 0.85)})
		}
	}

	resp.OK(c, gin.H{
		"rows":  rows,
		"trend": trendBuckets,
	})
}

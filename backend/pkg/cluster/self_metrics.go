package cluster

import (
	"context"
	"log"
	"runtime"
	"sync"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"
)

// StartSelfMetricsSampler boots a goroutine that periodically refreshes the
// local primary's NodeRuntime entry with measurements taken from this process
// and the query_logs table. Without it, Get(selfID) returns zero CPU/Mem/QPS
// so the cluster overview shows the primary as a dead-looking node despite
// it actively serving traffic.
//
// Metrics produced:
//
//   - mem_usage : runtime.MemStats.HeapInuse / Sys × 100 — a stdlib-friendly
//     proxy for "Go heap pressure". This is NOT host RSS / total RAM; that
//     would need /proc parsing on Linux or syscalls on Windows. Operators
//     who need true OS metrics should swap in gopsutil at this seam.
//   - qps      : COUNT(*) FROM query_logs WHERE created_at >= now-60s, /60.
//     Approximate but cheap; the DNS engine doesn't expose an in-memory
//     counter today.
//   - cpu_usage: left at 0 (stdlib has no portable per-process CPU time).
//
// Returns immediately; the goroutine respects ctx cancellation.
func StartSelfMetricsSampler(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	go runSelfSampler(ctx, interval)
}

var sampleOnce sync.Once

func runSelfSampler(ctx context.Context, interval time.Duration) {
	sampleOnce.Do(func() { log.Printf("[cluster-self] metrics sampler started (every %s)", interval) })
	t := time.NewTicker(interval)
	defer t.Stop()
	// First sample immediately so the UI doesn't show all-zeros for the
	// first interval after boot.
	sampleAndPublish()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sampleAndPublish()
		}
	}
}

func sampleAndPublish() {
	if SelfID() == "" {
		return // cluster not initialised yet
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	mem := 0
	if ms.Sys > 0 {
		mem = int(ms.HeapInuse * 100 / ms.Sys)
		if mem > 100 {
			mem = 100
		}
	}

	qps := approximateQPS()
	UpdateSelfMetrics(0, mem, qps)
}

// approximateQPS counts query_logs rows in the last 60 seconds and divides
// by 60. We cap the lookback at one minute to keep the COUNT cheap and the
// number responsive to real traffic shifts. A failed query (e.g. table not
// yet migrated) returns 0 so the sampler never panics.
func approximateQPS() int {
	if db.DB == nil {
		return 0
	}
	cutoff := time.Now().Add(-60 * time.Second)
	var cnt int64
	if err := db.DB.Model(&model.QueryLog{}).
		Where("created_at >= ?", cutoff).
		Count(&cnt).Error; err != nil {
		return 0
	}
	return int(cnt / 60)
}

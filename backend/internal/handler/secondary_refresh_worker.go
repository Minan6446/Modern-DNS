package handler

// Periodic refresher for Secondary zones.
//
// What this does
// ──────────────
// A single long-running goroutine wakes up every `tickInterval`,
// queries the DB for every zone whose type == "Secondary" and whose
// `last_synced_at + SOA.Refresh` is in the past (or whose
// last_synced_at is NULL, i.e. never synced), and runs a full AXFR
// against the configured master. On success it stamps last_synced_at;
// on failure it flips status to "异常" but keeps the previously
// transferred records intact (no half-empty zones — same contract as
// the manual SyncSecondaryZone handler).
//
// Why a worker rather than a per-zone goroutine
// ─────────────────────────────────────────────
// Spawning one goroutine per Secondary zone scales linearly with the
// zone count and makes graceful shutdown awkward (each goroutine
// needs its own ticker + done channel). One global worker with a
// bounded concurrency semaphore caps the AXFR fan-out regardless of
// how many zones the operator adds, and the single ticker is trivial
// to cancel via the rootCtx wired in from main.go.
//
// Concurrency cap
// ───────────────
// `axfrConcurrency` limits how many AXFRs run in parallel. AXFR is
// network-bound and the master often rate-limits transfers, so the
// cap protects both us (memory pressure when many large zones tick
// simultaneously) and the master (avoid getting throttled / blocked).
//
// Why we re-read zones inside the loop
// ────────────────────────────────────
// Operators can edit a zone's master / transport / insecure flag
// while the worker is running. Re-querying on every tick (instead
// of caching the zone list at startup) ensures changes take effect
// no later than the next tick without an explicit restart.

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"modern-dns/internal/dnsengine"
	"modern-dns/internal/model"
	"modern-dns/pkg/db"
)

const (
	// tickInterval is the cadence at which we re-evaluate which
	// Secondary zones are due for refresh. 1 minute is small enough
	// that a zone with a 60-second SOA.Refresh still tracks the
	// master closely, and large enough that the DB scan stays cheap
	// even with thousands of zones.
	secondaryRefreshTick = time.Minute

	// axfrConcurrency caps concurrent in-flight AXFRs. 4 is a
	// conservative default that keeps memory bounded on a 1 GB box
	// while still letting a backlog drain in reasonable time. Tune
	// upward only if you've measured the master / network can take
	// it; lower numbers do NOT improve correctness.
	axfrConcurrency = 4

	// fallbackRefresh is used when zone_soa has no row yet (the
	// zone was created in the UI but has never been synced
	// successfully). Without this guard a brand-new Secondary
	// would never get its first AXFR scheduled because the
	// "now > last_synced_at + refresh" predicate would compare
	// against refresh=0.
	fallbackRefresh = 3600 * time.Second

	// minRefresh clamps abusively low SOA.Refresh values (e.g.
	// a misconfigured master with refresh=1) so we don't melt
	// the network or the master. 60s is the smallest interval
	// you would ever reasonably want for a Secondary zone.
	minRefresh = 60 * time.Second

	// axfrCallTimeout is the per-transfer budget. Generous
	// because large zones (PTR /16, big TLDs) legitimately take
	// tens of seconds; we still want a hard ceiling so a stuck
	// connection can't pin a worker slot forever.
	axfrCallTimeout = 30 * time.Second
)

var (
	secondaryRefreshOnce sync.Once
	secondaryRefreshStop func()
)

// StartSecondaryRefreshWorker launches the periodic refresher. Safe
// to call exactly once during process startup (sync.Once guards
// against duplicate launches if a future refactor calls it again).
// The worker exits cleanly when ctx is cancelled.
func StartSecondaryRefreshWorker(ctx context.Context) {
	secondaryRefreshOnce.Do(func() {
		workerCtx, cancel := context.WithCancel(ctx)
		secondaryRefreshStop = cancel
		go runSecondaryRefreshLoop(workerCtx)
	})
}

// StopSecondaryRefreshWorker cancels the worker. Calling Stop before
// Start is a no-op; calling it twice is also a no-op (the second
// cancel() on the same ctx is harmless).
func StopSecondaryRefreshWorker() {
	if secondaryRefreshStop != nil {
		secondaryRefreshStop()
	}
}

func runSecondaryRefreshLoop(ctx context.Context) {
	log.Printf("[secondary-refresh] worker started (tick=%s, concurrency=%d)", secondaryRefreshTick, axfrConcurrency)

	// Run an initial pass immediately so a process restart picks
	// up due zones without waiting a full tick. Operators are
	// often surprised when "I restarted and my zones look stale
	// for a minute"; this removes that confusion.
	refreshDueSecondaryZones(ctx)

	ticker := time.NewTicker(secondaryRefreshTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("[secondary-refresh] worker stopped")
			return
		case <-ticker.C:
			refreshDueSecondaryZones(ctx)
		}
	}
}

func refreshDueSecondaryZones(ctx context.Context) {
	// We deliberately read ALL Secondary zones and filter the
	// "is it due?" predicate in Go rather than SQL. The join with
	// zone_soa would need an OUTER JOIN to handle the never-synced
	// case, and the predicate involves date arithmetic across two
	// columns from two tables — the SQL gets verbose and the
	// in-memory filter is fine while we have <10k zones.
	var zones []model.Zone
	if err := db.DB.Where("type = ?", "Secondary").Find(&zones).Error; err != nil {
		log.Printf("[secondary-refresh] failed to list zones: %v", err)
		return
	}
	if len(zones) == 0 {
		return
	}

	// Load every SOA row we need in a single query (avoids the
	// classic N+1 — one SELECT per zone — which would dominate
	// the tick budget at scale).
	ids := make([]uint, 0, len(zones))
	for _, z := range zones {
		ids = append(ids, z.ID)
	}
	var soaRows []model.ZoneSOA
	db.DB.Where("zone_id IN ?", ids).Find(&soaRows)
	soaByZone := make(map[uint]model.ZoneSOA, len(soaRows))
	for _, s := range soaRows {
		soaByZone[s.ZoneID] = s
	}

	now := time.Now()
	sem := make(chan struct{}, axfrConcurrency)
	var wg sync.WaitGroup

	for _, z := range zones {
		if !isDueForRefresh(z, soaByZone[z.ID], now) {
			continue
		}
		// Snapshot the zone into the goroutine — `z` is the loop
		// variable and would otherwise be captured by reference.
		z := z
		wg.Add(1)
		sem <- struct{}{} // acquire slot (blocks on full semaphore)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			runZoneRefresh(ctx, z)
		}()
	}
	wg.Wait()
}

// isDueForRefresh decides whether a zone should be re-transferred
// on this tick. A zone is due when:
//
//   - it has never been synced (last_synced_at is NULL); OR
//   - its master upstream is non-empty AND the configured SOA
//     refresh interval has elapsed since the last successful sync.
//
// Zones with no master configured (upstream empty AND SOA.MName also
// empty) are skipped entirely — we have nothing to ask. The fallback
// to SOA.MName matches the manual-sync handler's behaviour and lets
// operators get away without filling in "upstream" if the zone's
// authoritative NS already lists the master.
func isDueForRefresh(z model.Zone, soa model.ZoneSOA, now time.Time) bool {
	master := strings.TrimSpace(z.Upstream)
	if master == "" {
		master = strings.TrimSpace(soa.MName)
	}
	if master == "" {
		return false
	}
	if z.LastSyncedAt == nil {
		return true
	}
	refresh := time.Duration(soa.Refresh) * time.Second
	if refresh < minRefresh {
		// Either zone_soa has no row yet (Refresh==0) or the
		// master is misconfigured; both cases collapse onto the
		// safe fallback.
		if refresh == 0 {
			refresh = fallbackRefresh
		} else {
			refresh = minRefresh
		}
	}
	return now.Sub(*z.LastSyncedAt) >= refresh
}

func runZoneRefresh(ctx context.Context, z model.Zone) {
	// Bail early if the context was cancelled while this goroutine
	// was queued on the semaphore.
	if ctx.Err() != nil {
		return
	}

	master := strings.TrimSpace(z.Upstream)
	if master == "" {
		// Mirror the handler's SOA.MName fallback so the scheduler
		// and the manual sync make identical decisions.
		var soa model.ZoneSOA
		if err := db.DB.Where("zone_id = ?", z.ID).First(&soa).Error; err == nil {
			master = strings.TrimSpace(soa.MName)
		}
	}
	if master == "" {
		// Should not happen because isDueForRefresh filtered these,
		// but defensive against a race where another goroutine
		// cleared upstream between the predicate and now.
		return
	}

	res, err := dnsengine.PerformAXFR(master, z.Domain, z.Transport, z.AXFRInsecure, axfrCallTimeout)
	if err != nil {
		// We deliberately do NOT spam the log on every failed tick;
		// once per cycle is enough to diagnose, and flipping status
		// to "异常" already surfaces the failure in the UI. If the
		// operator wants per-attempt detail, the audit log /
		// metrics path is the right place — this loop is hot.
		db.DB.Model(&model.Zone{}).Where("id = ?", z.ID).Update("status", "异常")
		log.Printf("[secondary-refresh] zone=%s master=%s transport=%s: AXFR failed: %v", z.Domain, master, z.Transport, err)
		return
	}

	if err := persistAXFRResult(z, master, res); err != nil {
		db.DB.Model(&model.Zone{}).Where("id = ?", z.ID).Update("status", "异常")
		log.Printf("[secondary-refresh] zone=%s persist failed: %v", z.Domain, err)
		return
	}

	// Same as the manual handler: tell the resolver to reload so
	// queries see the new RR set before the next 10s reload tick.
	dnsengine.Trigger()
}

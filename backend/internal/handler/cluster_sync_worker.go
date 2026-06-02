package handler

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"
)

// ─── Cluster sync background worker ──────────────────────────────────────
//
// Two responsibilities, both polled on the same 30-second ticker so they
// share one goroutine and one DB transaction window:
//
//   1. Retry tick — find ClusterConfigSync rows whose sync_status='异常'
//      AND next_retry_at <= now, then re-push the latest snapshot. The
//      retry budget is enforced inside pushSnapshotToNodes via
//      retry_count + retryBackoff. When budget is exhausted the row is
//      left at 异常 with a zero next_retry_at so we stop touching it.
//
//   2. Auto-sync tick — if cluster_settings.config_refresh_sec > 0 AND
//      the last successful push for any node is older than that window,
//      push the current snapshot to all pending secondaries. This wires
//      up the previously-stored-but-unused ConfigRefreshSec setting.
//
// The worker is idempotent: starting it twice no-ops, stop+start cleanly
// rebinds. Lifecycle is bound to a context owned by main.go.

const clusterSyncTickInterval = 30 * time.Second

var (
	clusterSyncMu     sync.Mutex
	clusterSyncCancel context.CancelFunc
)

// StartClusterSyncWorker boots the retry + auto-sync loop. Idempotent.
func StartClusterSyncWorker(parent context.Context) {
	clusterSyncMu.Lock()
	defer clusterSyncMu.Unlock()
	if clusterSyncCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	clusterSyncCancel = cancel
	go clusterSyncLoop(ctx)
	log.Printf("[cluster-sync] worker started (tick=%s)", clusterSyncTickInterval)
}

// StopClusterSyncWorker tears the worker down. Safe to call repeatedly.
func StopClusterSyncWorker() {
	clusterSyncMu.Lock()
	defer clusterSyncMu.Unlock()
	if clusterSyncCancel == nil {
		return
	}
	clusterSyncCancel()
	clusterSyncCancel = nil
}

func clusterSyncLoop(ctx context.Context) {
	// Settle delay so the rest of the boot sequence finishes (DB migrate,
	// secondaries register, etc.) before we touch sync state.
	select {
	case <-ctx.Done():
		return
	case <-time.After(20 * time.Second):
	}
	t := time.NewTicker(clusterSyncTickInterval)
	defer t.Stop()
	for {
		runRetryTick()
		runAutoSyncTick()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// runRetryTick walks the rows scheduled for retry whose next_retry_at has
// arrived, and re-pushes a fresh snapshot. The retry budget itself is
// enforced inside pushSnapshotToNodes/recordPushFailure.
func runRetryTick() {
	now := time.Now()
	var rows []model.ClusterConfigSync
	if err := db.DB.
		Where("sync_status = ? AND retry_count > 0 AND retry_count <= ? AND next_retry_at > ? AND next_retry_at <= ?",
			"异常", len(retryBackoff), time.Time{}, now).
		Find(&rows).Error; err != nil {
		return
	}
	if len(rows) == 0 {
		return
	}

	// Collect the target nodes; skip ones whose URL is empty (secondary
	// hasn't handshaked) — there's nothing to retry until they do.
	ids := make([]uint, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.NodeID)
	}
	var nodes []model.ClusterNode
	db.DB.Where("id IN ? AND role = ? AND url <> ''", ids, "从节点").Find(&nodes)
	if len(nodes) == 0 {
		return
	}

	snap := buildAndStampSnapshot()
	res := pushSnapshotToNodes(&snap, nodes, "retry", "system")
	log.Printf("[cluster-sync] retry tick: version=%s targets=%d success=%d failed=%d",
		snap.Version, len(nodes), res.Success, res.Failed)
}

// runAutoSyncTick fires when cluster_settings.config_refresh_sec is set and
// at least one secondary has a stale config_version (older than the refresh
// window since its last_sync_at). We don't re-push when everything is in
// sync, so this is cheap for healthy clusters.
func runAutoSyncTick() {
	var s model.ClusterSettings
	if err := db.DB.First(&s, 1).Error; err != nil {
		return
	}
	if s.ConfigRefreshSec <= 0 || !s.Initialized {
		return
	}

	cutoff := time.Now().Add(-time.Duration(s.ConfigRefreshSec) * time.Second)
	var stale []model.ClusterNode
	// Stale = secondary whose latest sync row is older than the refresh
	// window OR whose status is not "已同步" (covers waiting / never-synced).
	db.DB.Table("cluster_nodes AS n").
		Joins("JOIN cluster_config_sync AS s ON s.node_id = n.id").
		Where("n.role = ? AND n.url <> '' AND (s.sync_status <> ? OR s.last_sync_at < ?)",
			"从节点", "已同步", cutoff).
		Find(&stale)
	if len(stale) == 0 {
		return
	}

	snap := buildAndStampSnapshot()
	res := pushSnapshotToNodes(&snap, stale, "auto", "system")
	log.Printf("[cluster-sync] auto tick: version=%s refresh=%ds targets=%d success=%d failed=%d",
		snap.Version, s.ConfigRefreshSec, len(stale), res.Success, res.Failed)

	// One audit log entry per cycle so the operation log shows that the
	// scheduler did work, not just the per-node detail in sync history.
	if res.Success > 0 || res.Failed > 0 {
		writeOpLog(nil, "system", "自动同步", "集群",
			fmt.Sprintf("version=%s success=%d failed=%d", snap.Version, res.Success, res.Failed), "")
	}
}

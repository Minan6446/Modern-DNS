// Package scheduler runs the periodic chores driven by SystemConfig:
//
//   - Auto-backup at the configured cycle (daily/weekly/monthly), gated by
//     SystemConfig.AutoBackup.
//   - Backup retention: delete backup rows + files older than
//     SystemConfig.BackupRetentionDays.
//   - Operation-log retention: delete operation_logs rows older than
//     SystemConfig.LogRetentionDays.
//
// The scheduler is a single goroutine ticking every minute; each tick re-
// reads SystemConfig so operator changes take effect at the next minute
// boundary without restart. State is recovered from the DB on every tick
// (we don't keep an in-memory "last run" timestamp), which means crashing
// mid-cycle is harmless.
package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/backup"
	"modern-dns/pkg/db"
)

const (
	// tickInterval is how often the loop wakes. One minute keeps log volume
	// low while still giving fine-grained reaction to config changes.
	tickInterval = 1 * time.Minute
	// firstTickDelay lets the rest of the boot sequence (router, DNS engine,
	// migrations) settle before we touch the DB.
	firstTickDelay = 30 * time.Second
)

var (
	mu      sync.Mutex
	cancel  context.CancelFunc
	running bool
)

// Start launches the scheduler goroutine. Idempotent: a second call is a
// no-op while the first instance is still running. Stop must be called to
// fully tear it down before a fresh Start can rebind.
func Start() {
	mu.Lock()
	defer mu.Unlock()
	if running {
		return
	}
	ctx, cncl := context.WithCancel(context.Background())
	cancel = cncl
	running = true
	go loop(ctx)
	log.Printf("[scheduler] started (tick=%s)", tickInterval)
}

// Stop signals the goroutine to exit. Safe to call multiple times.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if !running {
		return
	}
	cancel()
	running = false
}

func loop(ctx context.Context) {
	// Brief settle delay so the rest of the boot sequence finishes first.
	select {
	case <-ctx.Done():
		return
	case <-time.After(firstTickDelay):
	}
	tick()

	t := time.NewTicker(tickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

func tick() {
	var cfg model.SystemConfig
	if err := db.DB.First(&cfg, 1).Error; err != nil {
		// No config row yet — bootstrap is incomplete, just skip this tick.
		return
	}
	now := time.Now()
	runAutoBackup(&cfg, now)
	cleanExpiredBackups(&cfg, now)
	cleanExpiredOperationLogs(&cfg, now)
}

// ─── Auto-backup ─────────────────────────────────────────────────────────

// runAutoBackup creates a fresh BK-AUTO-* backup if AutoBackup is on AND
// the most recent BK-AUTO-* row is older than the configured cycle. We
// use the DB row as the source of truth for "last auto backup at" so the
// scheduler is stateless across process restarts.
func runAutoBackup(cfg *model.SystemConfig, now time.Time) {
	if !cfg.AutoBackup {
		return
	}
	interval := cycleInterval(cfg.BackupCycle)
	if interval == 0 {
		return
	}

	var last model.Backup
	err := db.DB.Where("backup_id LIKE ?", "BK-AUTO-%").
		Order("backup_time DESC").
		First(&last).Error
	if err == nil && now.Sub(last.BackupTime) < interval {
		return
	}

	scope := []string{"系统配置", "域名解析", "黑白名单", "安全规则"}
	backupID := fmt.Sprintf("BK-AUTO-%d", now.UnixMilli())

	filePath, fileSize, stats, expErr := backup.Export(backupID, scope)
	if expErr != nil {
		log.Printf("[scheduler] auto backup failed: %v", expErr)
		return
	}
	if len(stats.WarnedTables) > 0 {
		log.Printf("[scheduler] auto backup completed with %d warned table(s): %v",
			len(stats.WarnedTables), stats.WarnedTables)
	}

	scopeJSON, _ := json.Marshal(scope)
	rec := model.Backup{
		BackupID:    backupID,
		BackupScope: model.JSON(scopeJSON),
		BackupTime:  now,
		FileSize:    fileSize,
		Format:      "JSON",
		FileName:    filepath.Base(filePath),
	}
	if err := db.DB.Create(&rec).Error; err != nil {
		log.Printf("[scheduler] auto backup row insert failed: %v", err)
		// File on disk is orphaned; best-effort cleanup so the next run
		// doesn't pile up garbage.
		_ = os.Remove(filePath)
		return
	}
	log.Printf("[scheduler] auto backup created: %s (%s)", backupID, fileSize)
}

func cycleInterval(cycle string) time.Duration {
	switch strings.ToLower(strings.TrimSpace(cycle)) {
	case "daily", "每日", "day":
		return 24 * time.Hour
	case "weekly", "每周", "week":
		return 7 * 24 * time.Hour
	case "monthly", "每月", "month":
		return 30 * 24 * time.Hour
	}
	return 0
}

// ─── Retention cleanup ───────────────────────────────────────────────────

func cleanExpiredBackups(cfg *model.SystemConfig, now time.Time) {
	if cfg.BackupRetentionDays <= 0 {
		return
	}
	cutoff := now.Add(-time.Duration(cfg.BackupRetentionDays) * 24 * time.Hour)

	var stale []model.Backup
	if err := db.DB.Where("backup_time < ?", cutoff).Find(&stale).Error; err != nil {
		return
	}
	if len(stale) == 0 {
		return
	}
	for _, b := range stale {
		// Best-effort file removal — DB row is the canonical record, so
		// even if the file is missing or unreadable we still drop the row.
		_ = os.Remove(backup.FilePath(b.FileName))
		db.DB.Delete(&model.Backup{}, b.ID)
	}
	log.Printf("[scheduler] purged %d expired backup(s) older than %d day(s)",
		len(stale), cfg.BackupRetentionDays)
}

func cleanExpiredOperationLogs(cfg *model.SystemConfig, now time.Time) {
	if cfg.LogRetentionDays <= 0 {
		return
	}
	cutoff := now.Add(-time.Duration(cfg.LogRetentionDays) * 24 * time.Hour)

	res := db.DB.Where("created_at < ?", cutoff).Delete(&model.OperationLog{})
	if res.Error != nil {
		log.Printf("[scheduler] purge operation_logs failed: %v", res.Error)
		return
	}
	if res.RowsAffected > 0 {
		log.Printf("[scheduler] purged %d operation_log row(s) older than %d day(s)",
			res.RowsAffected, cfg.LogRetentionDays)
	}
}

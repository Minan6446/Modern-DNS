package main

import (
	"fmt"
	"log"

	"modern-dns/config"
	"modern-dns/pkg/db"
)

func main() {
	config.Init()
	db.InitMySQL()

	sqls := []string{
		// ── Missing tables ───────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS acl_rules (
			id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			name        VARCHAR(128) NOT NULL DEFAULT '',
			cidr        VARCHAR(64)  NOT NULL DEFAULT '',
			type        VARCHAR(16)  NOT NULL DEFAULT '允许',
			priority    INT          NOT NULL DEFAULT 0,
			query_types VARCHAR(255) NOT NULL DEFAULT '',
			zones       VARCHAR(512) NOT NULL DEFAULT '',
			hit_count   INT          NOT NULL DEFAULT 0,
			status      VARCHAR(16)  NOT NULL DEFAULT '启用',
			remark      VARCHAR(512) NOT NULL DEFAULT '',
			created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS rpz_rules (
			id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			name        VARCHAR(128) NOT NULL DEFAULT '',
			category    VARCHAR(64)  NOT NULL DEFAULT '',
			type        VARCHAR(32)  NOT NULL DEFAULT '',
			pattern     VARCHAR(255) NOT NULL DEFAULT '',
			action      VARCHAR(32)  NOT NULL DEFAULT '',
			redirect_to VARCHAR(255) NOT NULL DEFAULT '',
			hit_count   INT          NOT NULL DEFAULT 0,
			status      VARCHAR(16)  NOT NULL DEFAULT '启用',
			created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS monitor_latency_rule (
			id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			threshold_ms  INT        NOT NULL DEFAULT 500,
			period_sec    INT        NOT NULL DEFAULT 60,
			enabled       TINYINT(1) NOT NULL DEFAULT 0,
			updated_at    DATETIME   NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS monitor_cache_hit_rule (
			id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			min_hit_percent INT        NOT NULL DEFAULT 50,
			period_sec      INT        NOT NULL DEFAULT 300,
			enabled         TINYINT(1) NOT NULL DEFAULT 0,
			updated_at      DATETIME   NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS cluster_settings (
			id                     BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			initialized            TINYINT(1)   NOT NULL DEFAULT 0,
			cluster_domain         VARCHAR(255) NOT NULL DEFAULT '',
			primary_ips            VARCHAR(512) NOT NULL DEFAULT '',
			api_token              VARCHAR(255) NOT NULL DEFAULT '',
			heartbeat_interval_sec INT          NOT NULL DEFAULT 5,
			config_refresh_sec     INT          NOT NULL DEFAULT 60,
			config_version         VARCHAR(64)  NOT NULL DEFAULT '',
			updated_at             DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		) ENGINE=InnoDB`,
		// ── Seed rows for singleton tables ───────────────────────────
		`INSERT IGNORE INTO monitor_latency_rule (id) VALUES (1)`,
		`INSERT IGNORE INTO monitor_cache_hit_rule (id) VALUES (1)`,
	}

	// ── Drop runtime-only / duplicated columns from cluster tables ───
	// Live metrics moved to in-memory pkg/cluster/runtime; node identity is
	// owned by cluster_nodes and joined into cluster_config_sync at read.
	dropCols := []struct {
		table string
		col   string
	}{
		{"cluster_nodes", "status"},
		{"cluster_nodes", "state"},
		{"cluster_nodes", "cpu_usage"},
		{"cluster_nodes", "mem_usage"},
		{"cluster_nodes", "qps"},
		{"cluster_nodes", "sync_lag"},
		{"cluster_nodes", "up_since"},
		{"cluster_nodes", "last_heartbeat"},
		{"cluster_nodes", "last_seen"},
		{"cluster_config_sync", "node_name"},
		{"cluster_config_sync", "node_ip"},
		{"cluster_config_sync", "node_role"},
		{"cluster_config_sync", "zone"},
	}

	for _, sql := range sqls {
		if err := db.DB.Exec(sql).Error; err != nil {
			log.Printf("[migrate] error: %v", err)
		} else {
			fmt.Println("[migrate] OK")
		}
	}

	// Drop legacy index idx_status on cluster_nodes if it survives the column
	// drop (MySQL keeps the index when it covers status only).
	dropIndexes := []struct {
		table string
		index string
	}{
		{"cluster_nodes", "idx_status"},
	}
	for _, di := range dropIndexes {
		var count int64
		db.DB.Raw("SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ?", di.table, di.index).Scan(&count)
		if count > 0 {
			if err := db.DB.Exec(fmt.Sprintf("ALTER TABLE %s DROP INDEX %s", di.table, di.index)).Error; err != nil {
				log.Printf("[migrate] drop index %s.%s error: %v", di.table, di.index, err)
			} else {
				fmt.Printf("[migrate] dropped index %s.%s\n", di.table, di.index)
			}
		}
	}

	for _, dc := range dropCols {
		var count int64
		db.DB.Raw("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?", dc.table, dc.col).Scan(&count)
		if count > 0 {
			if err := db.DB.Exec(fmt.Sprintf("ALTER TABLE %s DROP COLUMN %s", dc.table, dc.col)).Error; err != nil {
				log.Printf("[migrate] drop %s.%s error: %v", dc.table, dc.col, err)
			} else {
				fmt.Printf("[migrate] dropped %s.%s\n", dc.table, dc.col)
			}
		}
	}

	// ── system_config: idempotently add new columns introduced by the
	// General Settings expansion. Old installs only had 6 fields; everything
	// else (ECS/DoH/DoT/MFA/IP whitelist/session/lockout/log/maintenance/
	// branding) had no DB backing and silently dropped on save.
	addCols := []struct{ table, col, ddl string }{
		{"system_config", "backup_storage_type", "VARCHAR(16) NOT NULL DEFAULT 'local'"},
		{"system_config", "backup_storage_path", "VARCHAR(512) NOT NULL DEFAULT ''"},
		{"system_config", "default_ttl", "INT NOT NULL DEFAULT 3600"},
		{"system_config", "negative_cache_ttl", "INT NOT NULL DEFAULT 300"},
		{"system_config", "ecs_enabled", "TINYINT(1) NOT NULL DEFAULT 0"},
		{"system_config", "doh_enabled", "TINYINT(1) NOT NULL DEFAULT 0"},
		{"system_config", "dot_enabled", "TINYINT(1) NOT NULL DEFAULT 0"},
		{"system_config", "login_timeout_minutes", "INT NOT NULL DEFAULT 30"},
		{"system_config", "login_max_failures", "INT NOT NULL DEFAULT 5"},
		{"system_config", "login_lock_minutes", "INT NOT NULL DEFAULT 15"},
		{"system_config", "mfa_required", "TINYINT(1) NOT NULL DEFAULT 0"},
		{"system_config", "ip_whitelist", "TEXT"},
		{"system_config", "log_retention_days", "INT NOT NULL DEFAULT 90"},
		{"system_config", "log_level", "VARCHAR(16) NOT NULL DEFAULT 'INFO'"},
		{"system_config", "log_export_format", "VARCHAR(16) NOT NULL DEFAULT 'csv'"},
		{"system_config", "global_qps_threshold", "INT NOT NULL DEFAULT 10000"},
		{"system_config", "maintenance_enabled", "TINYINT(1) NOT NULL DEFAULT 0"},
		{"system_config", "maintenance_window", "VARCHAR(64) NOT NULL DEFAULT ''"},
		// Branding columns (system_title / logo_url / theme_color)
		// removed in the 2026-05 cleanup; intentionally not re-added so
		// fresh installs skip them. Existing installs keep their
		// columns harmlessly because GORM no longer maps the fields.
		// PasswordChangedAt drives PwdExpireDays enforcement (2026-05).
		// NULL for pre-existing rows is treated as "never expired" so
		// the upgrade doesn't lock every operator out at once; they'll
		// get an expiry timestamp the next time they change their
		// password (or the admin resets it).
		{"users", "password_changed_at", "DATETIME NULL"},
		{"users", "email", "VARCHAR(128) NOT NULL DEFAULT ''"},
		{"users", "phone", "VARCHAR(32) NOT NULL DEFAULT ''"},
		{"users", "department", "VARCHAR(128) NOT NULL DEFAULT ''"},
		// dns_records.created_at retro-added so the dashboard
		// resource-trend chart can bucket records by creation time.
		// Pre-existing rows backfill to CURRENT_TIMESTAMP, which
		// puts every legacy record in "today's" bucket; that's an
		// acceptable visual artifact compared to the previous bug
		// (the line was a flat plateau equal to the lifetime total).
		{"dns_records", "created_at", "DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP"},
	}
	for _, ac := range addCols {
		var count int64
		db.DB.Raw("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?", ac.table, ac.col).Scan(&count)
		if count == 0 {
			if err := db.DB.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", ac.table, ac.col, ac.ddl)).Error; err != nil {
				log.Printf("[migrate] add %s.%s error: %v", ac.table, ac.col, err)
			} else {
				fmt.Printf("[migrate] added %s.%s\n", ac.table, ac.col)
			}
		}
	}

	fmt.Println("[migrate] done")
}

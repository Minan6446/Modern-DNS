package backup

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"

	"gorm.io/gorm"
)

// Dir is the directory where backup files are stored.
var Dir = "./backups"

// ─── Backup file format ──────────────────────────────────────────────────────

type File struct {
	Version     int                    `json:"version"`
	BackupID    string                 `json:"backupId"`
	BackupTime  string                 `json:"backupTime"`
	BackupScope []string               `json:"backupScope"`
	Data        map[string]interface{} `json:"data"`
}

// ─── Scope → table mapping ──────────────────────────────────────────────────

// scopeTables returns the list of table keys included in a given scope.
func scopeTables(scope string) []string {
	switch scope {
	case "系统配置":
		return []string{"system_config", "notice_config", "forward_global", "ddos_global", "cache_global_strategy"}
	case "域名解析":
		return []string{"zones", "dns_records", "zone_soa", "zone_dnssec"}
	case "黑白名单":
		return []string{"bw_rules"}
	case "安全规则":
		return []string{"acl_rules", "rpz_rules", "ddos_domain_rules", "tls_certs"}
	}
	return nil
}

// AllScopes returns all scopes that the given backup file contains data for.
func AllScopes(bf *File) []string {
	all := []string{"系统配置", "域名解析", "黑白名单", "安全规则"}
	var found []string
	for _, s := range all {
		for _, tbl := range scopeTables(s) {
			if rows, ok := bf.Data[tbl]; ok {
				if arr, isArr := rows.([]interface{}); isArr && len(arr) > 0 {
					found = append(found, s)
					break
				}
			}
		}
	}
	if len(found) == 0 {
		// If we cannot detect scope from data, fall back to the file's declared scope
		return bf.BackupScope
	}
	return found
}

// ─── Export ──────────────────────────────────────────────────────────────────

// ExportStats summarises a successful backup so the caller can surface
// per-table row counts + failures to the operator instead of just a
// pass/fail boolean. Returned alongside the file path and size.
type ExportStats struct {
	Tables       map[string]int    `json:"tables"` // table → row count
	TotalRows    int               `json:"totalRows"`
	WarnedTables map[string]string `json:"warnedTables,omitempty"` // table → error message
}

// Export reads DB tables for the given scopes and writes a JSON backup
// file. Returns the file path, human-readable size, and per-table stats.
//
// Per-table errors are *recorded* in stats.WarnedTables but never abort
// the whole export: an empty / corrupt sub-table shouldn't keep the
// operator from creating a backup of every other healthy module. The
// resulting backup file still includes valid tables, and the audit log
// can show which tables were skipped so the operator can investigate.
//
// Errors only escape this function for unrecoverable failures: scope
// validation, filesystem write, or JSON marshalling of the wrapper
// itself.
func Export(backupID string, scopes []string) (filePath, fileSize string, stats ExportStats, err error) {
	if len(scopes) == 0 {
		err = fmt.Errorf("backup scope is empty")
		return
	}

	// Validate every scope up front — better to fail loudly than to
	// silently emit an empty file because of a typo'd scope name.
	for _, s := range scopes {
		if scopeTables(s) == nil {
			err = fmt.Errorf("unknown backup scope: %s", s)
			return
		}
	}

	if err = os.MkdirAll(Dir, 0755); err != nil {
		return
	}

	stats = ExportStats{
		Tables:       map[string]int{},
		WarnedTables: map[string]string{},
	}

	data := make(map[string]interface{})
	seen := make(map[string]struct{}) // dedupe tables shared across scopes
	for _, scope := range scopes {
		for _, tbl := range scopeTables(scope) {
			if _, dup := seen[tbl]; dup {
				continue
			}
			seen[tbl] = struct{}{}

			rows, e := readTable(tbl)
			if e != nil {
				log.Printf("[backup] warn: read table %s: %v", tbl, e)
				stats.WarnedTables[tbl] = e.Error()
				// Still record the table key with an empty slice so a
				// downstream restore knows the scope was attempted.
				data[tbl] = []interface{}{}
				continue
			}
			data[tbl] = rows
			stats.Tables[tbl] = rowCount(rows)
			stats.TotalRows += stats.Tables[tbl]
		}
	}

	bf := File{
		Version:     1,
		BackupID:    backupID,
		BackupTime:  time.Now().Format(time.RFC3339),
		BackupScope: scopes,
		Data:        data,
	}

	raw, err := json.MarshalIndent(bf, "", "  ")
	if err != nil {
		return
	}

	fileName := fmt.Sprintf("%s.json", backupID)
	filePath = filepath.Join(Dir, fileName)
	if err = os.WriteFile(filePath, raw, 0644); err != nil {
		return
	}

	fileSize = humanSize(int64(len(raw)))
	return
}

// rowCount counts entries in a slice returned by readTable. Used by
// Export to populate ExportStats.Tables. Falls back to 0 when the data
// isn't a slice (shouldn't happen given readTable's contract, but cheap
// to be defensive).
func rowCount(v interface{}) int {
	switch x := v.(type) {
	case []model.SystemConfig:
		return len(x)
	case []model.NoticeConfig:
		return len(x)
	case []model.ForwardGlobal:
		return len(x)
	case []model.DDoSGlobal:
		return len(x)
	case []model.CacheGlobalStrategy:
		return len(x)
	case []model.Zone:
		return len(x)
	case []model.DNSRecord:
		return len(x)
	case []model.ZoneSOA:
		return len(x)
	case []model.ZoneDNSSECKey:
		return len(x)
	case []model.BWRule:
		return len(x)
	case []model.AclRule:
		return len(x)
	case []model.RpzRule:
		return len(x)
	case []model.DDoSDomainRule:
		return len(x)
	case []model.TLSCert:
		return len(x)
	}
	return 0
}

// ─── Import (restore) ───────────────────────────────────────────────────────

// Restore reads a backup file and restores selected scopes into the DB
// inside a transaction.
func Restore(filePath string, scopes []string) error {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read backup file: %w", err)
	}

	var bf File
	if err := json.Unmarshal(raw, &bf); err != nil {
		return fmt.Errorf("parse backup file: %w", err)
	}

	return db.DB.Transaction(func(tx *gorm.DB) error {
		for _, scope := range scopes {
			for _, tbl := range scopeTables(scope) {
				rows, ok := bf.Data[tbl]
				if !ok {
					continue
				}
				if err := restoreTable(tx, tbl, rows); err != nil {
					return fmt.Errorf("restore %s: %w", tbl, err)
				}
			}
		}
		return nil
	})
}

// ParseFile reads and parses a backup JSON file, returning scope info.
func ParseFile(filePath string) (*File, error) {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var bf File
	if err := json.Unmarshal(raw, &bf); err != nil {
		return nil, err
	}
	return &bf, nil
}

// FilePath returns the expected file path for a given backup file name.
func FilePath(fileName string) string {
	return filepath.Join(Dir, fileName)
}

// ─── Table read helpers ─────────────────────────────────────────────────────

func readTable(tbl string) (interface{}, error) {
	switch tbl {
	case "system_config":
		var rows []model.SystemConfig
		return rows, db.DB.Find(&rows).Error
	case "notice_config":
		var rows []model.NoticeConfig
		return rows, db.DB.Find(&rows).Error
	case "forward_global":
		var rows []model.ForwardGlobal
		return rows, db.DB.Find(&rows).Error
	case "ddos_global":
		var rows []model.DDoSGlobal
		return rows, db.DB.Find(&rows).Error
	case "cache_global_strategy":
		var rows []model.CacheGlobalStrategy
		return rows, db.DB.Find(&rows).Error
	case "zones":
		var rows []model.Zone
		return rows, db.DB.Find(&rows).Error
	case "dns_records":
		var rows []model.DNSRecord
		return rows, db.DB.Find(&rows).Error
	case "zone_soa":
		var rows []model.ZoneSOA
		return rows, db.DB.Find(&rows).Error
	case "zone_dnssec":
		var rows []model.ZoneDNSSECKey
		return rows, db.DB.Find(&rows).Error
	case "bw_rules":
		var rows []model.BWRule
		return rows, db.DB.Find(&rows).Error
	case "acl_rules":
		var rows []model.AclRule
		return rows, db.DB.Find(&rows).Error
	case "rpz_rules":
		var rows []model.RpzRule
		return rows, db.DB.Find(&rows).Error
	case "ddos_domain_rules":
		var rows []model.DDoSDomainRule
		return rows, db.DB.Find(&rows).Error
	case "tls_certs":
		var rows []model.TLSCert
		return rows, db.DB.Find(&rows).Error
	default:
		return nil, fmt.Errorf("unknown table %s", tbl)
	}
}

// ─── Table restore helpers ──────────────────────────────────────────────────

func restoreTable(tx *gorm.DB, tbl string, raw interface{}) error {
	// Re-marshal then unmarshal into concrete slices
	b, err := json.Marshal(raw)
	if err != nil {
		return err
	}

	switch tbl {
	case "system_config":
		var rows []model.SystemConfig
		if err := json.Unmarshal(b, &rows); err != nil {
			return err
		}
		tx.Where("1=1").Delete(&model.SystemConfig{})
		for i := range rows {
			tx.Create(&rows[i])
		}
	case "notice_config":
		var rows []model.NoticeConfig
		if err := json.Unmarshal(b, &rows); err != nil {
			return err
		}
		tx.Where("1=1").Delete(&model.NoticeConfig{})
		for i := range rows {
			tx.Create(&rows[i])
		}
	case "forward_global":
		var rows []model.ForwardGlobal
		if err := json.Unmarshal(b, &rows); err != nil {
			return err
		}
		tx.Where("1=1").Delete(&model.ForwardGlobal{})
		for i := range rows {
			tx.Create(&rows[i])
		}
	case "ddos_global":
		var rows []model.DDoSGlobal
		if err := json.Unmarshal(b, &rows); err != nil {
			return err
		}
		tx.Where("1=1").Delete(&model.DDoSGlobal{})
		for i := range rows {
			tx.Create(&rows[i])
		}
	case "cache_global_strategy":
		var rows []model.CacheGlobalStrategy
		if err := json.Unmarshal(b, &rows); err != nil {
			return err
		}
		tx.Where("1=1").Delete(&model.CacheGlobalStrategy{})
		for i := range rows {
			tx.Create(&rows[i])
		}
	case "zones":
		var rows []model.Zone
		if err := json.Unmarshal(b, &rows); err != nil {
			return err
		}
		tx.Where("1=1").Delete(&model.Zone{})
		for i := range rows {
			tx.Create(&rows[i])
		}
	case "dns_records":
		var rows []model.DNSRecord
		if err := json.Unmarshal(b, &rows); err != nil {
			return err
		}
		tx.Where("1=1").Delete(&model.DNSRecord{})
		for i := range rows {
			tx.Create(&rows[i])
		}
	case "zone_soa":
		var rows []model.ZoneSOA
		if err := json.Unmarshal(b, &rows); err != nil {
			return err
		}
		tx.Where("1=1").Delete(&model.ZoneSOA{})
		for i := range rows {
			tx.Create(&rows[i])
		}
	case "zone_dnssec":
		var rows []model.ZoneDNSSECKey
		if err := json.Unmarshal(b, &rows); err != nil {
			return err
		}
		tx.Where("1=1").Delete(&model.ZoneDNSSECKey{})
		for i := range rows {
			tx.Create(&rows[i])
		}
	case "bw_rules":
		var rows []model.BWRule
		if err := json.Unmarshal(b, &rows); err != nil {
			return err
		}
		tx.Where("1=1").Delete(&model.BWRule{})
		for i := range rows {
			tx.Create(&rows[i])
		}
	case "acl_rules":
		var rows []model.AclRule
		if err := json.Unmarshal(b, &rows); err != nil {
			return err
		}
		tx.Where("1=1").Delete(&model.AclRule{})
		for i := range rows {
			tx.Create(&rows[i])
		}
	case "rpz_rules":
		var rows []model.RpzRule
		if err := json.Unmarshal(b, &rows); err != nil {
			return err
		}
		tx.Where("1=1").Delete(&model.RpzRule{})
		for i := range rows {
			tx.Create(&rows[i])
		}
	case "ddos_domain_rules":
		var rows []model.DDoSDomainRule
		if err := json.Unmarshal(b, &rows); err != nil {
			return err
		}
		tx.Where("1=1").Delete(&model.DDoSDomainRule{})
		for i := range rows {
			tx.Create(&rows[i])
		}
	case "tls_certs":
		var rows []model.TLSCert
		if err := json.Unmarshal(b, &rows); err != nil {
			return err
		}
		tx.Where("1=1").Delete(&model.TLSCert{})
		for i := range rows {
			tx.Create(&rows[i])
		}
	default:
		return fmt.Errorf("unknown table %s", tbl)
	}
	return nil
}

// ─── Utility ────────────────────────────────────────────────────────────────

func humanSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1fGB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.1fMB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1fKB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}

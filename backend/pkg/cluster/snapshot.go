package cluster

import (
	"modern-dns/internal/model"
	"modern-dns/pkg/db"
	"reflect"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ConfigSnapshot is the unit of work for cluster sync. The primary builds it
// from the live database and pushes it to every secondary; secondaries replace
// their local rows with the snapshot, then trigger an engine reload.
//
// Tables included are exactly those the DNS engine reads during request
// handling (zones, records, forward + LB, cache strategy, ACL, BW, RPZ, DDoS).
// User accounts, audit logs, monitor history, etc. stay node-local on purpose.
type ConfigSnapshot struct {
	Version string `json:"version"`

	// Forwarding plane
	ForwardGlobal  model.ForwardGlobal   `json:"forwardGlobal"`
	ForwardServers []model.ForwardServer `json:"forwardServers"`
	ForwardRules   []model.ForwardRule   `json:"forwardRules"`
	LbGroups       []model.LbGroup       `json:"lbGroups"`
	LbServers      []model.LbServer      `json:"lbServers"`

	// Authoritative plane
	Zones      []model.Zone      `json:"zones"`
	DNSRecords []model.DNSRecord `json:"dnsRecords"`

	// Cache plane
	CacheGlobal      model.CacheGlobalStrategy `json:"cacheGlobal"`
	CacheDomainRules []model.CacheDomainRule   `json:"cacheDomainRules"`

	// Security plane
	BWRules         []model.BWRule         `json:"bwRules"`
	RpzRules        []model.RpzRule        `json:"rpzRules"`
	AclRules        []model.AclRule        `json:"aclRules"`
	DDoSGlobal      model.DDoSGlobal       `json:"ddosGlobal"`
	DDoSDomainRules []model.DDoSDomainRule `json:"ddosDomainRules"`
}

// BuildSnapshot reads the current state of every syncable table into one
// ConfigSnapshot. Returned errors are best-effort: missing or empty tables
// are tolerated so that a brand-new master can still produce a sync.
func BuildSnapshot(version string) ConfigSnapshot {
	snap := ConfigSnapshot{Version: version}

	db.DB.FirstOrCreate(&snap.ForwardGlobal, model.ForwardGlobal{ID: 1})
	db.DB.Find(&snap.ForwardServers)
	db.DB.Find(&snap.ForwardRules)
	db.DB.Find(&snap.LbGroups)
	db.DB.Find(&snap.LbServers)

	db.DB.Find(&snap.Zones)
	db.DB.Find(&snap.DNSRecords)

	db.DB.FirstOrCreate(&snap.CacheGlobal, model.CacheGlobalStrategy{ID: 1})
	db.DB.Find(&snap.CacheDomainRules)

	db.DB.Find(&snap.BWRules)
	db.DB.Find(&snap.RpzRules)
	db.DB.Find(&snap.AclRules)
	db.DB.FirstOrCreate(&snap.DDoSGlobal, model.DDoSGlobal{ID: 1})
	db.DB.Find(&snap.DDoSDomainRules)

	return snap
}

// ApplySnapshot replaces every syncable table with the contents of the
// snapshot using a merge strategy: rows present in the snapshot are
// upserted; rows absent from the snapshot are deleted. This is atomic
// per-table within the outer transaction and never leaves a table
// temporarily empty mid-sync.
func ApplySnapshot(snap *ConfigSnapshot) error {
	return db.DB.Transaction(func(tx *gorm.DB) error {
		// Forwarding plane
		if err := mergeTable(tx, &model.ForwardServer{}, snap.ForwardServers); err != nil {
			return err
		}
		if err := mergeTable(tx, &model.ForwardRule{}, snap.ForwardRules); err != nil {
			return err
		}
		if err := mergeTable(tx, &model.LbGroup{}, snap.LbGroups); err != nil {
			return err
		}
		if err := mergeTable(tx, &model.LbServer{}, snap.LbServers); err != nil {
			return err
		}
		// Authoritative plane
		if err := mergeTable(tx, &model.Zone{}, snap.Zones); err != nil {
			return err
		}
		if err := mergeTable(tx, &model.DNSRecord{}, snap.DNSRecords); err != nil {
			return err
		}
		// Cache plane
		if err := mergeTable(tx, &model.CacheDomainRule{}, snap.CacheDomainRules); err != nil {
			return err
		}
		// Security plane
		if err := mergeTable(tx, &model.BWRule{}, snap.BWRules); err != nil {
			return err
		}
		if err := mergeTable(tx, &model.RpzRule{}, snap.RpzRules); err != nil {
			return err
		}
		if err := mergeTable(tx, &model.AclRule{}, snap.AclRules); err != nil {
			return err
		}
		if err := mergeTable(tx, &model.DDoSDomainRule{}, snap.DDoSDomainRules); err != nil {
			return err
		}

		// Singletons (id = 1) — upsert in place
		fg := snap.ForwardGlobal
		fg.ID = 1
		if err := tx.Save(&fg).Error; err != nil {
			return err
		}
		cg := snap.CacheGlobal
		cg.ID = 1
		if err := tx.Save(&cg).Error; err != nil {
			return err
		}
		dg := snap.DDoSGlobal
		dg.ID = 1
		if err := tx.Save(&dg).Error; err != nil {
			return err
		}
		return nil
	})
}

// mergeTable reconciles the target table with the supplied rows.
// Strategy:
//  1. DELETE rows whose IDs are not present in the snapshot.
//  2. Bulk-upsert the snapshot rows (INSERT … ON DUPLICATE KEY UPDATE).
//
// This keeps existing rows visible for the entire duration.
func mergeTable[T any](tx *gorm.DB, modelPtr interface{}, rows []T) error {
	ids := collectIDs(rows)

	if len(ids) == 0 {
		// Empty snapshot → truncate the table.
		return tx.Where("1 = 1").Delete(modelPtr).Error
	}

	// Remove rows the primary no longer carries.
	if err := tx.Where("id NOT IN ?", ids).Delete(modelPtr).Error; err != nil {
		return err
	}

	// Upsert in one bulk statement so existing rows are never briefly missing.
	if len(rows) > 0 {
		return tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&rows).Error
	}
	return nil
}

// collectIDs extracts every uint ID from a slice of structs (or *structs)
// using reflection. All syncable models have a uint primary key named "ID".
func collectIDs[T any](rows []T) []uint {
	ids := make([]uint, 0, len(rows))
	for i := range rows {
		rv := reflect.ValueOf(rows[i])
		if rv.Kind() == reflect.Ptr {
			rv = rv.Elem()
		}
		if f := rv.FieldByName("ID"); f.IsValid() && f.Kind() == reflect.Uint {
			ids = append(ids, uint(f.Uint()))
		}
	}
	return ids
}

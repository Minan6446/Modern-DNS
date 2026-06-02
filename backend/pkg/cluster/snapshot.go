package cluster

import (
	"modern-dns/internal/model"
	"modern-dns/pkg/db"

	"gorm.io/gorm"
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
// snapshot. It is destructive on purpose — the primary is the only source of
// truth. Wrapped in a transaction so partial application never happens.
func ApplySnapshot(snap *ConfigSnapshot) error {
	return db.DB.Transaction(func(tx *gorm.DB) error {
		// Forwarding plane
		if err := replaceTable(tx, &model.ForwardServer{}, snap.ForwardServers); err != nil {
			return err
		}
		if err := replaceTable(tx, &model.ForwardRule{}, snap.ForwardRules); err != nil {
			return err
		}
		if err := replaceTable(tx, &model.LbGroup{}, snap.LbGroups); err != nil {
			return err
		}
		if err := replaceTable(tx, &model.LbServer{}, snap.LbServers); err != nil {
			return err
		}
		// Authoritative plane
		if err := replaceTable(tx, &model.Zone{}, snap.Zones); err != nil {
			return err
		}
		if err := replaceTable(tx, &model.DNSRecord{}, snap.DNSRecords); err != nil {
			return err
		}
		// Cache plane
		if err := replaceTable(tx, &model.CacheDomainRule{}, snap.CacheDomainRules); err != nil {
			return err
		}
		// Security plane
		if err := replaceTable(tx, &model.BWRule{}, snap.BWRules); err != nil {
			return err
		}
		if err := replaceTable(tx, &model.RpzRule{}, snap.RpzRules); err != nil {
			return err
		}
		if err := replaceTable(tx, &model.AclRule{}, snap.AclRules); err != nil {
			return err
		}
		if err := replaceTable(tx, &model.DDoSDomainRule{}, snap.DDoSDomainRules); err != nil {
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

// replaceTable wipes every row of the model's table and inserts the supplied
// slice. Safe even when the slice is empty (effectively a truncate).
func replaceTable[T any](tx *gorm.DB, modelPtr interface{}, rows []T) error {
	if err := tx.Where("1 = 1").Delete(modelPtr).Error; err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	return tx.Create(&rows).Error
}

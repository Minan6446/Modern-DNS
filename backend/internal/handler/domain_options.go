package handler

// Per-zone「区域选项」persistence.
//
// What this serves
// ────────────────
// The zone-list page exposes a 4-tab dialog (查询访问 / 区域传输 /
// 变更通知 / 动态更新) where operators pick policies for each zone.
// This file is the storage + validation layer behind it. The DNS
// engine does NOT yet consult these rows on the hot path — wiring
// that up (B / D in the design doc) is a separate body of work.
// For now the data round-trips correctly: the operator's choices
// survive page reloads and process restarts.
//
// Why GET returns defaults on miss
// ────────────────────────────────
// A brand-new zone has no row in zone_options. Rather than 404'ing,
// GET synthesises a default object the frontend can hydrate the
// dialog with — the operator's first save then upserts the row.
// This keeps the dialog's open / save lifecycle simple (no special
// "no record" branch) and gives every zone a deterministic baseline.
//
// Why we validate enum-shaped strings here, not as DB CHECK
// ─────────────────────────────────────────────────────────
// SQLite (used by tests) doesn't enforce CHECK constraints the same
// way MySQL does across versions, and we want one source of truth
// for the legal mode set. Each tab's whitelist of modes lives in the
// `*ModeAllowed` maps below; adding a new mode is one slice
// modification — no migration required.

import (
	"strconv"
	"strings"

	"modern-dns/internal/dnsengine"
	"modern-dns/internal/model"
	"modern-dns/pkg/db"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
)

// Mode whitelists — must stay in sync with the frontend ts unions
// (QueryAccessMode / TransferMode / NotifyMode / DynUpdateMode in
// `views/domain/ZoneListPage.vue`). Drift here will manifest as a
// 400 from the validator below, so it's a load-bearing contract.
var (
	queryModesAllowed    = map[string]struct{}{"deny": {}, "allow": {}, "private": {}, "ns-only": {}, "acl": {}, "ns-acl": {}}
	transferModesAllowed = map[string]struct{}{"deny": {}, "allow": {}, "ns-only": {}, "acl": {}}
	notifyModesAllowed   = map[string]struct{}{"none": {}, "ns": {}, "custom": {}}
	dynModesAllowed      = map[string]struct{}{"deny": {}, "allow": {}, "private": {}, "acl": {}}
)

// recordTypesAllowed is the set of DNS record types we accept in
// `dyn_allow_types`. Keeping this small + explicit (rather than
// taking anything) protects the dynamic-update path from operators
// pasting random strings that would later parse as garbage.
var recordTypesAllowed = map[string]struct{}{
	"A": {}, "AAAA": {}, "CNAME": {}, "MX": {}, "TXT": {},
	"SRV": {}, "PTR": {}, "NS": {}, "CAA": {}, "SOA": {},
}

// defaultZoneOptions returns the synthesised baseline for a zone
// that has never saved its options. Mirrors the frontend's
// `openZoneOptions` reset defaults so the dialog UI looks the same
// whether the operator first opens it before or after a save.
func defaultZoneOptions(zoneID uint) model.ZoneOptions {
	return model.ZoneOptions{
		ZoneID:          zoneID,
		QueryMode:       "allow",
		TransferMode:    "deny",
		NotifyMode:      "none",
		NotifyOnChange:  true,
		DynMode:         "deny",
		DynTSIGRequired: true,
		DynAllowTypes:   "A,AAAA",
	}
}

// GET /api/domain/zones/:id/options
//
// Returns the persisted options or the synthesised default — never
// a 404. Operators have no way to "create" an options row through
// the UI separately from a save, so a missing row is just "you
// haven't customised this zone yet".
func GetZoneOptions(c *gin.Context) {
	zoneID, _ := strconv.Atoi(c.Param("id"))
	if zoneID <= 0 {
		resp.BadRequest(c, "invalid zone id")
		return
	}

	// Ensure the zone actually exists so the frontend doesn't get a
	// silent "options for nothing" payload. Cheap — primary-key lookup.
	var zone model.Zone
	if err := db.DB.First(&zone, zoneID).Error; err != nil {
		resp.NotFound(c, "zone not found")
		return
	}

	var opts model.ZoneOptions
	if err := db.DB.Where("zone_id = ?", zoneID).First(&opts).Error; err != nil {
		// Not found → return defaults (id=0 indicates not-yet-saved).
		opts = defaultZoneOptions(uint(zoneID))
	}
	resp.OK(c, opts)
}

// PUT /api/domain/zones/:id/options
//
// Upsert: row may or may not exist on entry. Validates the mode
// strings + dyn_allow_types before writing so a bad payload doesn't
// silently land bogus data the engine would later choke on.
//
// On success we Trigger() the engine so a future enforcement layer
// (B in the design doc) reads the new ACL within milliseconds; the
// resolver itself is a no-op for now.
func SaveZoneOptions(c *gin.Context) {
	zoneID, _ := strconv.Atoi(c.Param("id"))
	if zoneID <= 0 {
		resp.BadRequest(c, "invalid zone id")
		return
	}

	var zone model.Zone
	if err := db.DB.First(&zone, zoneID).Error; err != nil {
		resp.NotFound(c, "zone not found")
		return
	}

	var payload model.ZoneOptions
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, "请求体格式错误："+err.Error())
		return
	}

	if msg := validateZoneOptions(&payload); msg != "" {
		resp.BadRequest(c, msg)
		return
	}

	payload.ZoneID = uint(zoneID)

	// Upsert by (zone_id) — the table's uniqueIndex on zone_id
	// guarantees there's at most one row to find.
	var existing model.ZoneOptions
	if err := db.DB.Where("zone_id = ?", zoneID).First(&existing).Error; err != nil {
		if err := db.DB.Create(&payload).Error; err != nil {
			resp.DBError(c, err)
			return
		}
	} else {
		payload.ID = existing.ID
		// Save (vs Updates(map)) is fine here because we validated
		// every field and the model has no read-only columns.
		if err := db.DB.Save(&payload).Error; err != nil {
			resp.DBError(c, err)
			return
		}
	}

	dnsengine.Trigger()
	resp.OK(c, payload)
}

// validateZoneOptions returns an empty string when the payload is
// acceptable, or a Chinese operator-facing error message otherwise.
// We split the legality check from the handler body so unit tests
// can target it without spinning up gin.
//
// Why we normalise on the way in
// ───────────────────────────────
// `DynAllowTypes` arrives as the operator's free-form string. We:
//  1. uppercase each token (DNS RR types are case-insensitive but
//     the engine matches exact strings),
//  2. drop empties produced by trailing commas,
//  3. reject anything outside the allowlist with a useful message,
//  4. re-join with a single comma so the stored value is canonical
//     and trivially splittable later.
//
// Trim is applied to the ACL / target text fields as well so we
// don't store leading/trailing whitespace that some textareas add.
func validateZoneOptions(o *model.ZoneOptions) string {
	if _, ok := queryModesAllowed[o.QueryMode]; !ok {
		return "查询访问模式取值非法：" + o.QueryMode
	}
	if _, ok := transferModesAllowed[o.TransferMode]; !ok {
		return "区域传输模式取值非法：" + o.TransferMode
	}
	if _, ok := notifyModesAllowed[o.NotifyMode]; !ok {
		return "变更通知模式取值非法：" + o.NotifyMode
	}
	if _, ok := dynModesAllowed[o.DynMode]; !ok {
		return "动态更新模式取值非法：" + o.DynMode
	}

	// Canonicalise DynAllowTypes. We deliberately accept JSON input
	// in either form ("A,AAAA" or "a, aaaa") so an API client doesn't
	// have to know our exact storage format.
	if msg, normalised := normaliseAllowTypes(o.DynAllowTypes); msg != "" {
		return msg
	} else {
		o.DynAllowTypes = normalised
	}

	o.QueryACL = strings.TrimSpace(o.QueryACL)
	o.TransferACL = strings.TrimSpace(o.TransferACL)
	o.NotifyTargets = strings.TrimSpace(o.NotifyTargets)
	o.DynACL = strings.TrimSpace(o.DynACL)
	return ""
}

func normaliseAllowTypes(raw string) (errMsg, normalised string) {
	parts := strings.Split(raw, ",")
	cleaned := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		t := strings.ToUpper(strings.TrimSpace(p))
		if t == "" {
			continue
		}
		if _, ok := recordTypesAllowed[t]; !ok {
			return "动态更新允许的记录类型 '" + t + "' 不在支持列表中", ""
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		cleaned = append(cleaned, t)
	}
	if len(cleaned) == 0 {
		// Default to the common pair when the operator left the
		// field blank — same as the frontend's reset state, keeps
		// the round-trip symmetric.
		return "", "A,AAAA"
	}
	return "", strings.Join(cleaned, ",")
}

package model

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// ─── JSON column helper ───────────────────────────────────────────────────────

type JSON json.RawMessage

func (j JSON) Value() (driver.Value, error) {
	if len(j) == 0 {
		return "null", nil
	}
	return string(j), nil
}

// Scan accepts every shape a SQL driver might return for a JSON-bearing
// column:
//
//   - []byte  — MySQL, Postgres
//   - string  — SQLite (modernc.org/sqlite returns TEXT as string)
//   - nil     — column was NULL (we map to an empty JSON value, equivalent
//     to "null", so downstream MarshalJSON stays valid)
//
// Anything else falls back to "null" rather than returning an error,
// because a Scan failure here used to leave the buffer in a half-valid
// state that would later trip MarshalJSON during a backup with the
// classic `invalid character '\u0000' looking for beginning of value`
// error. We also strip leading/trailing NUL bytes that occasionally
// sneak in via legacy SQLite rows.
func (j *JSON) Scan(value any) error {
	if value == nil {
		*j = nil
		return nil
	}
	var raw []byte
	switch v := value.(type) {
	case []byte:
		raw = append([]byte(nil), v...)
	case string:
		raw = []byte(v)
	default:
		return fmt.Errorf("cannot scan type %T into JSON", value)
	}
	// Trim spurious whitespace + control bytes (especially \x00 trailing
	// padding from very old SQLite blobs migrated in from other tools).
	raw = trimJSONFrame(raw)
	if len(raw) == 0 || !json.Valid(raw) {
		// Don't propagate the error — corrupt JSON in one row shouldn't
		// nuke a list query or a backup export. Treat as null.
		*j = nil
		return nil
	}
	*j = JSON(raw)
	return nil
}

// trimJSONFrame strips ASCII whitespace and NUL padding from both ends of
// the byte slice. Doesn't touch interior content, so anything that's
// actually JSON survives byte-for-byte.
func trimJSONFrame(b []byte) []byte {
	for len(b) > 0 {
		switch b[0] {
		case ' ', '\t', '\n', '\r', 0x00:
			b = b[1:]
		default:
			goto trail
		}
	}
trail:
	for len(b) > 0 {
		switch b[len(b)-1] {
		case ' ', '\t', '\n', '\r', 0x00:
			b = b[:len(b)-1]
		default:
			return b
		}
	}
	return b
}

func (j JSON) MarshalJSON() ([]byte, error) {
	// Defensive validation: a row hand-edited via SQL or migrated in from
	// another system may contain garbage that survived Scan (e.g. when an
	// older build of this code accepted unparsed bytes). Returning "null"
	// is preferable to taking down a list query / backup export.
	if len(j) == 0 || !json.Valid(j) {
		return []byte("null"), nil
	}
	return j, nil
}

func (j *JSON) UnmarshalJSON(data []byte) error {
	*j = JSON(data)
	return nil
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

type Role struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `gorm:"size:64;uniqueIndex" json:"name"`
	Remark    string    `gorm:"size:255" json:"remark"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (Role) TableName() string { return "roles" }

type User struct {
	ID          uint   `gorm:"primaryKey" json:"id"`
	Username    string `gorm:"size:64;uniqueIndex" json:"username"`
	Password    string `gorm:"size:255" json:"-"`
	RealName    string `gorm:"size:64" json:"realName"`
	Email       string `gorm:"size:128" json:"email"`
	Phone       string `gorm:"size:32" json:"phone"`
	Department  string `gorm:"size:128" json:"department"`
	RoleID      uint   `json:"roleId"`
	RoleName    string `gorm:"size:64" json:"roleName"`
	Status      string `gorm:"size:16" json:"status"`
	TOTPSecret  string `gorm:"column:totp_secret" json:"-"`
	TOTPEnabled bool   `gorm:"column:totp_enabled" json:"totpEnabled"`
	// PasswordChangedAt drives PwdExpireDays enforcement: the login
	// path compares now() − this timestamp against
	// SystemConfig.PwdExpireDays and refuses to issue an access token
	// when the password is past its expiry. Set by SaveUser /
	// ResetUserPassword / ChangePassword whenever Password is mutated.
	// Nullable — pre-2026-05 rows leave it zero, in which case we
	// treat the password as not-yet-expired (operator hasn't opted
	// into rotation).
	PasswordChangedAt time.Time `gorm:"column:password_changed_at" json:"passwordChangedAt"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

func (User) TableName() string { return "users" }

type RolePermission struct {
	ID         uint   `gorm:"primaryKey" json:"id"`
	RoleID     uint   `gorm:"uniqueIndex:uk_role_perm" json:"roleId"`
	Permission string `gorm:"size:64;uniqueIndex:uk_role_perm" json:"permission"`
}

func (RolePermission) TableName() string { return "role_permissions" }

type OperationLog struct {
	ID           uint   `gorm:"primaryKey" json:"id"`
	LogID        string `gorm:"size:64" json:"logId"`
	Operator     string `gorm:"size:64" json:"operator"`
	OperatorRole string `gorm:"size:64" json:"operatorRole"`
	ActionType   string `gorm:"size:64" json:"actionType"`
	Action       string `gorm:"size:128" json:"action"`
	Module       string `gorm:"size:64" json:"module"`
	Target       string `gorm:"size:255" json:"target"`
	Content      string `gorm:"size:512" json:"content"`
	IP           string `gorm:"size:64" json:"clientIp"`
	Result       string `gorm:"size:32" json:"result"`
	Duration     int    `json:"duration"`
	Before       string `gorm:"type:text" json:"before"`
	After        string `gorm:"type:text" json:"after"`
	Detail       string `gorm:"type:text" json:"detail"`
	// StepUp records the second-factor proof presented by the operator
	// for sensitive operations: "totp" or "password" when the route was
	// gated by middleware.SensitiveConfirm and the operator passed; empty
	// otherwise. Used by audit reports to flag which destructive actions
	// were performed under elevated assurance.
	StepUp    string    `gorm:"size:16" json:"stepUp,omitempty"`
	CreatedAt time.Time `json:"time"`
}

func (OperationLog) TableName() string { return "operation_logs" }

// ─── Dashboard ───────────────────────────────────────────────────────────────

type AlertRule struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	RuleID    string    `gorm:"size:64;uniqueIndex" json:"ruleId"`
	RuleName  string    `gorm:"size:128" json:"ruleName"`
	AlertType string    `gorm:"size:64" json:"alertType"`
	Level     string    `gorm:"size:32" json:"level"`
	Channel   string    `gorm:"size:64" json:"channel"`
	Target    string    `gorm:"size:255" json:"target"`
	Threshold int       `json:"threshold"`
	Status    string    `gorm:"size:16" json:"status"`
	Remark    string    `gorm:"size:512" json:"remark"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (AlertRule) TableName() string { return "alert_rules" }

type AlertEvent struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	Level          string    `gorm:"size:32" json:"level"`
	Type           string    `gorm:"size:64" json:"type"`
	Domain         string    `gorm:"size:255" json:"domain"`
	Content        string    `gorm:"size:512" json:"content"`
	SuppressType   string    `gorm:"size:32" json:"suppressType"`
	SuppressReason string    `gorm:"size:255" json:"suppressReason"`
	Status         string    `gorm:"size:32" json:"status"`
	IsRead         bool      `json:"read"`
	TriggeredAt    time.Time `json:"triggeredAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

func (AlertEvent) TableName() string { return "alert_events" }

type AlertAuditLog struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Operator  string    `gorm:"size:64" json:"operator"`
	Action    string    `gorm:"size:128" json:"action"`
	Target    string    `gorm:"size:255" json:"target"`
	Result    string    `gorm:"size:32" json:"result"`
	CreatedAt time.Time `json:"time"`
}

func (AlertAuditLog) TableName() string { return "alert_audit_logs" }

type DomainHealth struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Domain       string    `gorm:"size:255;uniqueIndex" json:"domain"`
	Status       string    `gorm:"size:32" json:"status"`
	Availability string    `gorm:"size:16" json:"availability"`
	CheckIP      string    `gorm:"size:64" json:"checkIp"`
	CheckedAt    time.Time `json:"checkedAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

func (DomainHealth) TableName() string { return "domain_health" }

// ─── Domain ──────────────────────────────────────────────────────────────────

type Zone struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	ZoneID   string `gorm:"size:64;uniqueIndex" json:"zoneId"`
	Domain   string `gorm:"size:255;uniqueIndex" json:"domain"`
	Type     string `gorm:"size:32" json:"type"`
	Status   string `gorm:"size:32" json:"status"`
	Remark   string `gorm:"size:255" json:"remark"`
	Upstream string `gorm:"size:255" json:"upstream"`
	// Transport is the wire protocol used for AXFR / IXFR pulls when
	// this zone is type=Secondary or Stub. Empty / "tcp" is the
	// classical 53/TCP transfer (RFC 1995); "tls" is XFR-over-TLS
	// (RFC 9103, port 853); "quic" is reserved for future
	// XFR-over-QUIC support and currently surfaces a clear
	// "not yet implemented" error from the AXFR client. Ignored for
	// Primary / Forward / Reverse zones.
	Transport string `gorm:"size:16;default:'tcp'" json:"transport"`
	// AXFRInsecure disables TLS verification when Transport == "tls" or
	// "quic". This is intentionally a per-zone knob (not a global one)
	// because a deployment commonly mixes a few self-signed lab masters
	// with production masters that have valid CA chains; a single
	// global flag would force operators to choose between security and
	// usability. Default false → strict verification.
	AXFRInsecure bool `gorm:"column:axfr_insecure;default:false" json:"axfrInsecure"`
	// LastSyncedAt records when the most recent successful AXFR (or
	// SOA-only refresh that decided no new transfer was needed)
	// completed. Drives the periodic-refresh scheduler — a NULL /
	// zero value means "never synced, refresh ASAP".
	LastSyncedAt *time.Time `json:"lastSyncedAt,omitempty"`
	Serial       string     `gorm:"size:32" json:"serial"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`
}

func (Zone) TableName() string { return "zones" }

type DNSRecord struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	ZoneID     uint       `json:"zoneId"`
	Type       string     `gorm:"size:16" json:"type"`
	Host       string     `gorm:"size:255" json:"host"`
	Value      string     `gorm:"size:512" json:"value"`
	TTL        int        `json:"ttl"`
	Status     string     `gorm:"size:16" json:"status"`
	Remark     string     `gorm:"size:255" json:"remark"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	// CreatedAt drives the dashboard "记录增长趋势" series — without
	// it the resource-usage chart had no way to bucket records by
	// when they were added, so it fell back to repeating the
	// lifetime total in every bucket (the line was a flat plateau).
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (DNSRecord) TableName() string { return "dns_records" }

type ZoneSOA struct {
	ID         uint   `gorm:"primaryKey" json:"id"`
	ZoneID     uint   `gorm:"uniqueIndex" json:"zoneId"`
	MName      string `gorm:"size:255" json:"mname"`
	RName      string `gorm:"size:255" json:"rname"`
	Refresh    int    `json:"refresh"`
	Retry      int    `json:"retry"`
	Expire     int    `json:"expire"`
	MinimumTTL int    `json:"minimumTtl"`
}

func (ZoneSOA) TableName() string { return "zone_soa" }

type ZoneDNSSECKey struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	ZoneID     uint      `gorm:"uniqueIndex:uk_zone_key" json:"zoneId"`
	KeyType    string    `gorm:"size:16" json:"keyType"`                       // "KSK" | "ZSK"
	KeyTag     uint16    `json:"keyTag"`                                       // DNSKEY key-tag
	KeyID      string    `gorm:"size:64;uniqueIndex:uk_zone_key" json:"keyId"` // display identifier
	Algorithm  string    `gorm:"size:64" json:"algorithm"`                     // e.g. "ECDSAP256SHA256"
	Status     string    `gorm:"size:32" json:"status"`                        // "启用" | "禁用"
	DNSKEYText string    `gorm:"type:text" json:"-"`                           // full DNSKEY RR as text
	PrivateKey string    `gorm:"type:text" json:"-"`                           // private key in miekg string format
	DSText     string    `gorm:"type:text" json:"ds"`                          // DS record as text (KSK only)
	CreatedAt  time.Time `json:"createdAt"`
}

func (ZoneDNSSECKey) TableName() string { return "zone_dnssec" }

// ZoneOptions persists the per-zone server-side policy controls
// surfaced by the「区域选项」dialog: who can query, who can pull AXFR,
// who gets notified on changes, and who may run dynamic updates.
//
// Storage shape
// ─────────────
// One row per zone (ZoneID has a UNIQUE index). The ACL / target /
// allow-types columns are free-form `TEXT` because operators paste in
// CIDR / IP / hostname lists separated by newlines or commas — we keep
// the raw text in the DB and split / re-join in Go when the engine
// actually evaluates a rule. Storing pre-parsed forms (e.g. one row
// per CIDR) would force a join on every query path, which the engine
// can't afford on the hot path.
//
// Mode columns are short strings rather than enums so adding a new
// mode in code does not require a schema migration. The handler layer
// is the single source of truth for the legal value set.
//
// Why a separate table (not extra columns on `zones`)
// ───────────────────────────────────────────────────
// The options data is conceptually optional and rarely accessed by
// the hot resolver path (only on query/transfer/update gates), while
// `zones` is read on every reload. Keeping it out of `zones` keeps
// that hot table narrow and lets us add fields here without touching
// the engine zone loader.
type ZoneOptions struct {
	ID              uint   `gorm:"primaryKey" json:"id"`
	ZoneID          uint   `gorm:"uniqueIndex" json:"zoneId"`
	QueryMode       string `gorm:"size:16;default:'allow'" json:"queryMode"`
	QueryACL        string `gorm:"type:text" json:"queryAcl"`
	TransferMode    string `gorm:"size:16;default:'deny'" json:"transferMode"`
	TransferACL     string `gorm:"type:text" json:"transferAcl"`
	NotifyMode      string `gorm:"size:16;default:'none'" json:"notifyMode"`
	NotifyTargets   string `gorm:"type:text" json:"notifyTargets"`
	NotifyOnChange  bool   `gorm:"default:true" json:"notifyOnChange"`
	DynMode         string `gorm:"size:16;default:'deny'" json:"dynMode"`
	DynACL          string `gorm:"type:text" json:"dynAcl"`
	DynTSIGRequired bool   `gorm:"default:true" json:"dynTsigRequired"`
	// DynAllowTypes is a comma-separated list of RR types the dynamic
	// update path will accept (e.g. "A,AAAA,TXT"). Stored flat so we
	// can reuse the column for both display and engine matching
	// without an extra normalised-types table.
	DynAllowTypes string    `gorm:"size:255;default:'A,AAAA'" json:"dynAllowTypes"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

func (ZoneOptions) TableName() string { return "zone_options" }

// ─── Forward ─────────────────────────────────────────────────────────────────

type ForwardGlobal struct {
	ID               uint   `gorm:"primaryKey" json:"id"`
	Enabled          bool   `json:"enabled"`
	PublicDNS        string `gorm:"size:64" json:"publicDns"`
	PublicDNSEnabled bool   `json:"publicDnsEnabled"`
	PublicDNSCustom  string `gorm:"size:255" json:"publicDnsCustom"`
	Timeout          int    `json:"timeout"`
	Retries          int    `json:"retries"`
	Strategy         string `gorm:"size:32" json:"strategy"`
	// LbGroupID, when non-nil and pointing at an enabled LbGroup, makes
	// the resolver pick a single upstream from that group's per-pick
	// algorithm (round-robin / weighted / least-latency / …) instead
	// of the flat ForwardServer list. nil → keep the legacy behaviour.
	LbGroupID *uint `json:"lbGroupId"`
}

func (ForwardGlobal) TableName() string { return "forward_global" }

type ForwardServer struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `gorm:"size:128" json:"name"`
	Address   string    `gorm:"size:255" json:"address"`
	Port      int       `json:"port"`
	Protocol  string    `gorm:"size:16" json:"protocol"`
	Priority  int       `json:"priority"`
	Status    string    `gorm:"size:16" json:"status"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (ForwardServer) TableName() string { return "forward_servers" }

type ForwardRule struct {
	ID           uint   `gorm:"primaryKey" json:"id"`
	RuleID       string `gorm:"size:64;uniqueIndex" json:"ruleId"`
	Domains      string `gorm:"type:text" json:"domains"`
	UpstreamID   uint   `json:"upstreamId"`
	UpstreamName string `gorm:"size:255" json:"upstreamName"`
	// LbGroupID, when non-nil and enabled, takes precedence over
	// UpstreamID — matches against the LbGroup's pick algorithm so a
	// rule can fan out across a pool of upstreams. UpstreamID is kept
	// as the fallback / legacy column so existing rules keep working.
	LbGroupID *uint  `json:"lbGroupId"`
	Priority  int    `json:"priority"`
	Status    string `gorm:"size:16" json:"status"`
	// Protocol overrides the global UpstreamProtocolOrder for queries
	// that match this rule. Empty = inherit (legacy). Recognised
	// values: udp / tcp / dot / doh / doq. doq is currently surfaced
	// from the UI but the engine returns a clear "not yet
	// implemented" error rather than silently downgrading.
	Protocol  string    `gorm:"size:16" json:"protocol"`
	Remark    string    `gorm:"size:255" json:"remark"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (ForwardRule) TableName() string { return "forward_rules" }

// ─── Cache ───────────────────────────────────────────────────────────────────

type CacheGlobalStrategy struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	TTLMax       int       `json:"ttlMax"`
	MinRetain    int       `json:"minRetain"`
	AutoCleanup  bool      `json:"autoCleanup"`
	CleanupCycle string    `gorm:"size:32" json:"cleanupCycle"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

func (CacheGlobalStrategy) TableName() string { return "cache_global_strategy" }

type CacheDomainRule struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Domain       string    `gorm:"size:255;uniqueIndex" json:"domain"`
	CustomTTL    int       `json:"customTtl"`
	CustomRetain int       `json:"customRetain"`
	Status       string    `gorm:"size:16" json:"status"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

func (CacheDomainRule) TableName() string { return "cache_domain_rules" }

// CacheClearLog records every successful manual purge so the
// 「手动清理」tab's "清理历史" panel survives page reloads and node
// restarts (the previous in-memory store lost everything on F5).
//
// We deliberately keep this separate from operation_logs even though
// every purge also writes one there: operation_logs is an audit trail
// keyed off of operator identity, whereas this table is a UI-facing
// timeline keyed off of scope/count and shown to anyone who opens the
// cache page. Joining the two would force the UI to filter on
// `module = 'DNS缓存'` and reconstruct the count from a free-text
// `content` field, which is brittle.
//
// `Detail` carries the wire payload (domains, timeRange) as JSON so
// future UI work can re-run a previous purge without re-typing the
// scope. Stored as a string column to avoid a JSON-typed column that
// would break on MySQL < 5.7 / MariaDB.
type CacheClearLog struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Scope        string    `gorm:"size:32;index" json:"scope"`
	ScopeLabel   string    `gorm:"size:128" json:"scopeLabel"`
	Domains      string    `gorm:"type:text" json:"domains"`
	TimeStart    string    `gorm:"size:32" json:"timeStart"`
	TimeEnd      string    `gorm:"size:32" json:"timeEnd"`
	ClearedCount int       `json:"clearedCount"`
	Operator     string    `gorm:"size:64" json:"operator"`
	IP           string    `gorm:"size:64" json:"clientIp"`
	Detail       string    `gorm:"type:text" json:"detail"`
	CreatedAt    time.Time `json:"time"`
}

func (CacheClearLog) TableName() string { return "cache_clear_logs" }

// ─── Security ─────────────────────────────────────────────────────────────────

type BWRule struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	RuleID    string    `gorm:"size:64;uniqueIndex" json:"ruleId"`
	Type      string    `gorm:"size:16" json:"type"`
	ListType  string    `gorm:"size:16" json:"listType"`
	Value     string    `gorm:"size:255" json:"value"`
	Remark    string    `gorm:"size:255" json:"remark"`
	Status    string    `gorm:"size:16" json:"status"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (BWRule) TableName() string { return "bw_rules" }

type DDoSGlobal struct {
	ID         uint `gorm:"primaryKey" json:"id"`
	Enabled    bool `json:"enabled"`
	QPSLimit   int  `json:"qpsLimit"`
	CurrentQPS int  `json:"currentQps"`
	// PerIPConnLimit caps simultaneous in-flight queries per source IP.
	// Set 0 to disable. Stored even when enforcement is plumbed-in
	// later — schema fronts the operator UI today and the engine can
	// adopt the bound without a follow-up migration.
	PerIPConnLimit int `json:"perIpConnLimit"`
	// MemSoftMB / MemHardMB tune Go runtime memory pressure responses
	// so a flood that bloats cache + connection tables can't OOM the
	// host. Hard maps to debug.SetMemoryLimit; soft is a logging /
	// shedding watermark consulted by the engine's GC ticker.
	MemSoftMB int `json:"memSoftMb"`
	MemHardMB int `json:"memHardMb"`
	// PerIPQPS / PerIPBurst express the access-control "每 IP 限流"
	// policy: sustained queries-per-second + burst bucket size for a
	// single client IP. Disabled when either is 0. The existing
	// QPSLimit field is retained for backward compat as the legacy
	// global-per-IP cap; this pair adds an optional tighter shaped
	// bucket for surge protection.
	PerIPQPS   int       `json:"perIpQps"`
	PerIPBurst int       `json:"perIpBurst"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

func (DDoSGlobal) TableName() string { return "ddos_global" }

type DDoSDomainRule struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Domain    string    `gorm:"size:255;uniqueIndex" json:"domain"`
	QPSLimit  int       `json:"qpsLimit"`
	Status    string    `gorm:"size:16" json:"status"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (DDoSDomainRule) TableName() string { return "ddos_domain_rules" }

type SecurityDNSSEC struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	Domain          string    `gorm:"size:255;uniqueIndex" json:"domain"`
	DNSSECStatus    string    `gorm:"size:32" json:"dnssecStatus"`
	SignatureStatus string    `gorm:"size:32" json:"signatureStatus"`
	LastCheckAt     time.Time `json:"lastCheckAt"`
	KSKJson         string    `gorm:"type:text" json:"-"`
	ZSKJson         string    `gorm:"type:text" json:"-"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

func (SecurityDNSSEC) TableName() string { return "security_dnssec" }

type TLSCert struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Domain      string    `gorm:"size:255" json:"domain"`
	CertType    string    `gorm:"size:16" json:"type"`
	Issuer      string    `gorm:"size:128" json:"issuer"`
	ExpireAt    string    `gorm:"size:32" json:"expireAt"`
	DaysLeft    int       `json:"daysLeft"`
	Status      string    `gorm:"size:32" json:"status"`
	Fingerprint string    `gorm:"size:128" json:"fingerprint"`
	UploadedAt  string    `gorm:"size:32" json:"uploadedAt"`
	CertContent string    `gorm:"type:text" json:"-"`
	KeyContent  string    `gorm:"type:text" json:"-"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func (TLSCert) TableName() string { return "tls_certs" }

type AclRule struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	Name       string    `gorm:"size:128" json:"name"`
	CIDR       string    `gorm:"column:cidr;size:64" json:"cidr"`
	Type       string    `gorm:"size:16" json:"type"` // "允许" | "拒绝"
	Priority   int       `json:"priority"`            // smaller wins
	QueryTypes string    `gorm:"size:255" json:"queryTypes"`
	Zones      string    `gorm:"size:512" json:"zones"`
	HitCount   int       `json:"hitCount"`
	Status     string    `gorm:"size:16" json:"status"` // "启用" | "禁用"
	Remark     string    `gorm:"size:512" json:"remark"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

func (AclRule) TableName() string { return "acl_rules" }

type RpzRule struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	Name       string    `gorm:"size:128" json:"name"`
	Category   string    `gorm:"size:64" json:"category"`
	Type       string    `gorm:"size:32" json:"type"`
	Pattern    string    `gorm:"size:255" json:"pattern"`
	Action     string    `gorm:"size:32" json:"action"`
	RedirectTo string    `gorm:"size:255" json:"redirectTo"`
	HitCount   int       `json:"hitCount"`
	Status     string    `gorm:"size:16" json:"status"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

func (RpzRule) TableName() string { return "rpz_rules" }

// ─── Monitor ─────────────────────────────────────────────────────────────────

type QueryLog struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	QueryID         string    `gorm:"size:64" json:"queryId"`
	Domain          string    `gorm:"size:255;index:idx_qlog_domain_time,priority:1" json:"domain"`
	RecordType      string    `gorm:"size:16" json:"recordType"`
	SourceIP        string    `gorm:"size:64;index:idx_qlog_ip_time,priority:1" json:"sourceIp"`
	Region          string    `gorm:"size:64" json:"region"`
	ResponseStatus  string    `gorm:"size:32;index" json:"responseStatus"`
	ResponseTime    int       `json:"responseTime"`
	RCode           string    `gorm:"size:32;index" json:"rcode"`
	TransactionID   string    `gorm:"size:64" json:"transactionId"`
	RequestPayload  string    `gorm:"type:text" json:"requestPayload"`
	ResponsePayload string    `gorm:"type:text" json:"responsePayload"`
	CreatedAt       time.Time `gorm:"index:idx_qlog_created;index:idx_qlog_domain_time,priority:2;index:idx_qlog_ip_time,priority:2" json:"time"`
}

func (QueryLog) TableName() string { return "query_logs" }

type MonitorQPSRule struct {
	ID                     uint      `gorm:"primaryKey" json:"id"`
	GlobalThresholdPercent int       `json:"globalThresholdPercent"`
	DomainThresholdPercent int       `json:"domainThresholdPercent"`
	PeriodSec              int       `json:"periodSec"`
	Enabled                bool      `json:"enabled"`
	UpdatedAt              time.Time `json:"updatedAt"`
}

func (MonitorQPSRule) TableName() string { return "monitor_qps_rule" }

type MonitorNXDomainRule struct {
	ID               uint      `gorm:"primaryKey" json:"id"`
	ThresholdPercent int       `json:"thresholdPercent"`
	PeriodSec        int       `json:"periodSec"`
	Enabled          bool      `json:"enabled"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

func (MonitorNXDomainRule) TableName() string { return "monitor_nxdomain_rule" }

type MonitorLatencyRule struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	ThresholdMs int       `json:"thresholdMs"`
	PeriodSec   int       `json:"periodSec"`
	Enabled     bool      `json:"enabled"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func (MonitorLatencyRule) TableName() string { return "monitor_latency_rule" }

type MonitorCacheHitRule struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	MinHitPercent int       `json:"minHitPercent"`
	PeriodSec     int       `json:"periodSec"`
	Enabled       bool      `json:"enabled"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

func (MonitorCacheHitRule) TableName() string { return "monitor_cache_hit_rule" }

type MonitorRuleHistory struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	RuleID       string    `gorm:"size:64" json:"ruleId"`
	RuleType     string    `gorm:"size:64" json:"ruleType"`
	Content      string    `gorm:"size:512" json:"content"`
	HandleStatus string    `gorm:"size:32" json:"handleStatus"`
	TriggerAt    time.Time `json:"triggerAt"`
}

func (MonitorRuleHistory) TableName() string { return "monitor_rule_history" }

// ─── Tools ────────────────────────────────────────────────────────────────────

type DigHistory struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	Domain     string    `gorm:"size:255" json:"domain"`
	RecordType string    `gorm:"size:16" json:"recordType"`
	DNSServer  string    `gorm:"size:255" json:"dnsServer"`
	Output     string    `gorm:"type:text" json:"output"`
	QueriedAt  time.Time `json:"queriedAt"`
}

func (DigHistory) TableName() string { return "dig_history" }

type GlobalTestHistory struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	Domain     string    `gorm:"size:255" json:"domain"`
	RecordType string    `gorm:"size:16" json:"recordType"`
	NodeGroup  string    `gorm:"size:64" json:"nodeGroup"`
	ResultJSON string    `gorm:"type:text" json:"-"`
	TestedAt   time.Time `json:"testedAt"`
}

func (GlobalTestHistory) TableName() string { return "global_test_history" }

// ─── Cluster ──────────────────────────────────────────────────────────────────

// ClusterNode persists only the static identity and configuration of a
// cluster member. All live metrics (status, state, CPU/Mem/QPS, heartbeat
// timestamps) are tracked in pkg/cluster.Runtime and merged into API
// responses on the fly — never stored to MySQL.
type ClusterNode struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	NodeID      string    `gorm:"column:node_id;size:64;index" json:"nodeId"` // stable UUID assigned on join
	Name        string    `gorm:"size:128" json:"name"`
	IP          string    `gorm:"size:64" json:"ip"`
	IPAddresses string    `gorm:"column:ip_addresses;size:512" json:"ipAddresses"` // CSV
	URL         string    `gorm:"column:url;size:255" json:"url"`
	Port        int       `json:"port"`
	Role        string    `gorm:"size:32" json:"role"`
	Zone        string    `gorm:"size:64" json:"zone"`
	Version     string    `gorm:"size:32" json:"version"`
	Certificate string    `gorm:"type:text" json:"-"`
	JoinedAt    time.Time `json:"joinedAt"`

	// Drained operationally removes the node from sync rotation without
	// deleting it. Used during planned maintenance: the secondary keeps
	// running but the primary skips it for snapshot pushes and the
	// operator can safely take it offline. Toggled via the drain /
	// undrain endpoints. Composes cleanly with the runtime state machine
	// (online / offline / unreachable) instead of replacing it.
	Drained bool `gorm:"default:false" json:"drained"`
}

func (ClusterNode) TableName() string { return "cluster_nodes" }

// ClusterSettings is the singleton (id=1) holding cluster-wide configuration.
type ClusterSettings struct {
	ID                   uint      `gorm:"primaryKey" json:"id"`
	Initialized          bool      `json:"initialized"`
	ClusterDomain        string    `gorm:"size:255" json:"clusterDomain"`
	PrimaryIPs           string    `gorm:"column:primary_ips;size:512" json:"primaryIps"` // CSV
	APIToken             string    `gorm:"column:api_token;size:255" json:"-"`            // never returned to clients
	HeartbeatIntervalSec int       `gorm:"column:heartbeat_interval_sec" json:"heartbeatIntervalSec"`
	ConfigRefreshSec     int       `gorm:"column:config_refresh_sec" json:"configRefreshSec"`
	ConfigVersion        string    `gorm:"column:config_version;size:64" json:"configVersion"`
	UpdatedAt            time.Time `json:"updatedAt"`
}

func (ClusterSettings) TableName() string { return "cluster_settings" }

// ClusterConfigSync stores the latest sync attempt facts per node. Node
// identity (name/ip/role/zone) is intentionally NOT duplicated here; the
// list endpoint joins cluster_nodes by node_id to enrich the response.
type ClusterConfigSync struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	NodeID        uint      `gorm:"index" json:"nodeId"` // FK → cluster_nodes.id
	ConfigVersion string    `gorm:"size:64" json:"configVersion"`
	MasterVersion string    `gorm:"size:64" json:"masterVersion"`
	SyncStatus    string    `gorm:"size:32" json:"syncStatus"`
	LastSyncAt    time.Time `json:"lastSyncAt"`
	DiffCount     int       `json:"diffCount"`
	DiffDetail    string    `gorm:"type:text" json:"-"`

	// Retry bookkeeping for the scheduler-driven exponential backoff. When a
	// push fails the scheduler bumps RetryCount and stamps NextRetryAt; the
	// retry tick picks up rows whose NextRetryAt has passed.
	RetryCount  int       `gorm:"column:retry_count;default:0" json:"retryCount"`
	NextRetryAt time.Time `gorm:"column:next_retry_at" json:"nextRetryAt"`
}

func (ClusterConfigSync) TableName() string { return "cluster_config_sync" }

// ClusterSyncHistory is the per-push audit trail behind the "同步历史" tab.
// Every config push (manual single-node, manual all-pending, scheduled retry,
// or scheduled auto-sync) appends one row here so operators can answer
// "what changed at 14:32?" without grepping operation_logs.
type ClusterSyncHistory struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Version      string    `gorm:"size:64;index" json:"version"`
	StartedAt    time.Time `gorm:"index" json:"startedAt"`
	FinishedAt   time.Time `json:"finishedAt"`
	TotalNodes   int       `json:"totalNodes"`
	SuccessCount int       `json:"successCount"`
	FailedCount  int       `json:"failedCount"`
	Trigger      string    `gorm:"size:32" json:"trigger"` // "manual" / "manual-all" / "auto" / "retry"
	TriggeredBy  string    `gorm:"size:64" json:"triggeredBy"`
	Notes        string    `gorm:"type:text" json:"notes"` // JSON of []pushItem for drill-down
}

func (ClusterSyncHistory) TableName() string { return "cluster_sync_history" }

// ─── Setting ─────────────────────────────────────────────────────────────────

type SystemConfig struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	Timezone string `gorm:"size:64" json:"timezone"`
	Language string `gorm:"size:16" json:"language"`

	// ── Backup ─────────────────────────────────────
	AutoBackup          bool   `json:"autoBackup"`
	BackupCycle         string `gorm:"size:32" json:"backupCycle"`
	BackupRetentionDays int    `json:"backupRetentionDays"`
	BackupStorageType   string `gorm:"size:16;default:'local'" json:"backupStorageType"`
	BackupStoragePath   string `gorm:"size:512" json:"backupStoragePath"`

	// ── DNS policy ─────────────────────────────────
	DNSSECGlobal     bool `json:"dnssecGlobal"`
	DefaultTTL       int  `gorm:"default:3600" json:"defaultTtl"`
	NegativeCacheTTL int  `gorm:"default:300" json:"negativeCacheTtl"`
	ECSEnabled       bool `json:"ecsEnabled"`
	DoHEnabled       bool `json:"dohEnabled"`
	DoTEnabled       bool `json:"dotEnabled"`

	// TTL clamp: any record / forwarder response with a TTL outside
	// [MinTTL, MaxTTL] is rewritten to the boundary before the answer
	// is cached or sent. Avoids upstreams that hand back absurd values
	// (negative, multi-day, zero) from poisoning local caches.
	MinTTL int `gorm:"default:0" json:"minTtl"`
	MaxTTL int `gorm:"default:0" json:"maxTtl"`

	// Upstream protocol preference. `UpstreamProtocolOrder` is a
	// comma-separated list drawn from {doh,dot,udp,tcp} in the order
	// the forwarder should attempt; the first entry that succeeds
	// wins. UpstreamTimeoutMs gates each individual attempt.
	UpstreamProtocolOrder string `gorm:"size:64;default:'udp,tcp'" json:"upstreamProtocolOrder"`
	UpstreamTimeoutMs     int    `gorm:"default:2000" json:"upstreamTimeoutMs"`
	// DoHPreferGET routes queryDoH through HTTP GET (RFC 8484 §4.1.1
	// base64url) instead of POST. Useful in corporate / lab networks
	// where an HTTP proxy strips POST application/dns-message bodies.
	// POST → GET fallback also kicks in automatically on certain 4xx
	// responses, but operators can pin GET-first when they know the
	// environment requires it.
	DoHPreferGET bool `gorm:"column:doh_prefer_get;default:false" json:"dohPreferGet"`

	// ECS prefix length when ECSEnabled. We send the client's source
	// /24 (v4) or /64 (v6) by default; setting these to 0 disables
	// the per-family override (defaults are then 24 / 56).
	ECSPrefixV4 int `gorm:"default:24" json:"ecsPrefixV4"`
	ECSPrefixV6 int `gorm:"default:56" json:"ecsPrefixV6"`

	// RFC 8467 response padding for DoH/DoT. When enabled, we pad the
	// response to a power-of-two-aligned length to defeat traffic
	// analysis. Block size 128 is the RFC recommendation; 0 disables.
	DNSPaddingEnabled bool `gorm:"column:dns_padding_enabled" json:"dnsPaddingEnabled"`
	DNSPaddingBlock   int  `gorm:"column:dns_padding_block;default:128" json:"dnsPaddingBlock"`

	// ── Security & access ──────────────────────────
	LoginTimeoutMinutes int    `gorm:"default:30" json:"loginTimeoutMinutes"`
	LoginMaxFailures    int    `gorm:"default:5" json:"loginMaxFailures"`
	LoginLockMinutes    int    `gorm:"default:15" json:"loginLockMinutes"`
	MFARequired         bool   `gorm:"column:mfa_required" json:"mfaRequired"`
	IPWhitelist         string `gorm:"type:text" json:"ipWhitelist"`

	// Password policy. Enforced at user-create / password-change time
	// in handler/setting.go. Zeroes mean "no requirement"; the user
	// helper resolveLoginPolicy() in handler/auth.go applies sensible
	// fallbacks so an empty config never weakens the default policy
	// below the Modern-DNS baseline.
	PwdMinLength       int  `gorm:"default:8" json:"pwdMinLength"`
	PwdRequireUpper    bool `gorm:"default:true" json:"pwdRequireUpper"`
	PwdRequireLower    bool `gorm:"default:true" json:"pwdRequireLower"`
	PwdRequireDigit    bool `gorm:"default:true" json:"pwdRequireDigit"`
	PwdRequireSymbol   bool `gorm:"default:false" json:"pwdRequireSymbol"`
	PwdExpireDays      int  `gorm:"default:0" json:"pwdExpireDays"`      // 0 = never expire
	MaxConcurrentLogin int  `gorm:"default:0" json:"maxConcurrentLogin"` // 0 = unlimited

	// SessionLegacyGraceDays is the soft-deadline for accepting JWTs
	// minted before the MaxConcurrentLogin upgrade (i.e. tokens with
	// no Sid claim). After this many days from the token's IssuedAt,
	// sid-less tokens are rejected so an indefinitely-stashed legacy
	// JWT can't bypass session enforcement forever. Default 7 is long
	// enough that all live sessions will have rotated through refresh
	// at least once. 0 disables the soft-deadline (accept indefinitely
	// — only useful during a long phased rollout).
	SessionLegacyGraceDays int `gorm:"default:7" json:"sessionLegacyGraceDays"`

	// ── DB connection pool ─────────────────────────
	// Live-tunable. Applied on save via db.ApplyPoolFromSystemConfig
	// so operators can adjust pool sizing under load without restart.
	// Zero on any field means "keep the current value".
	DBMaxOpenConns       int `gorm:"default:100" json:"dbMaxOpenConns"`
	DBMaxIdleConns       int `gorm:"default:50" json:"dbMaxIdleConns"`
	DBConnMaxLifetimeMin int `gorm:"default:10" json:"dbConnMaxLifetimeMin"`
	DBConnMaxIdleMin     int `gorm:"default:5" json:"dbConnMaxIdleMin"`

	// ── NTP time sync ──────────────────────────────
	// Comma / newline-separated list of NTP server hostnames; the
	// poller picks the first reachable one each cycle. Drift and
	// last-sync timestamps are written back from the poller goroutine
	// (see pkg/sysmon/ntp.go) so the UI can render the current state
	// without a separate health endpoint.
	NTPEnabled       bool      `gorm:"column:ntp_enabled;default:true" json:"ntpEnabled"`
	NTPServers       string    `gorm:"type:text;column:ntp_servers" json:"ntpServers"`
	NTPCheckInterval int       `gorm:"column:ntp_check_interval;default:300" json:"ntpCheckIntervalSec"`
	NTPLastSync      time.Time `gorm:"column:ntp_last_sync" json:"ntpLastSync"`
	NTPLastDriftMs   int64     `gorm:"column:ntp_last_drift_ms" json:"ntpLastDriftMs"`
	NTPLastError     string    `gorm:"size:255;column:ntp_last_error" json:"ntpLastError"`

	// ── Logs & maintenance ─────────────────────────
	LogRetentionDays int    `gorm:"default:90" json:"logRetentionDays"`
	LogLevel         string `gorm:"size:16;default:'INFO'" json:"logLevel"`
	LogExportFormat  string `gorm:"size:16;default:'csv'" json:"logExportFormat"`
	// SyslogEnabled / SyslogServer drive the optional syslog forwarder.
	// Stored on SystemConfig (rather than a dedicated table) because
	// they're singletons just like the rest of the operation-log knobs.
	// SyslogServer is "host:port" form; the actual push pipeline reads
	// these on every config save and reconnects.
	SyslogEnabled bool   `gorm:"column:syslog_enabled" json:"syslogEnabled"`
	SyslogServer  string `gorm:"size:128;column:syslog_server" json:"syslogServer"`
	// GlobalQPSThreshold removed in 2026-05 cleanup. The DB column
	// global_qps_threshold is intentionally retained (see migrations/
	// schema.sql + cmd/migrate) so existing rows / backup imports stay
	// compatible, but no Go code path reads or writes it. Real QPS
	// limiting is owned by ddos_global.qps_limit (pkg/ddos), surfaced
	// in the UI under 「安全中心 → DDoS 防护」.
	MaintenanceEnabled bool   `json:"maintenanceEnabled"`
	MaintenanceWindow  string `gorm:"size:64" json:"maintenanceWindow"`

	// Branding fields (system_title / logo_url / theme_color) were
	// removed in the 2026-05 cleanup. Existing rows keep the columns in
	// MySQL but the model no longer maps them, so GORM ignores them on
	// read/write. Old backups can still be deserialised because
	// json.Unmarshal silently drops unknown keys.

	UpdatedAt time.Time `json:"updatedAt"`
}

func (SystemConfig) TableName() string { return "system_config" }

type Backup struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	BackupID    string    `gorm:"size:64;uniqueIndex" json:"backupId"`
	BackupScope JSON      `json:"backupScope"`
	BackupTime  time.Time `json:"backupTime"`
	FileSize    string    `gorm:"size:32" json:"fileSize"`
	Format      string    `gorm:"size:16" json:"format"`
	FileName    string    `gorm:"size:255" json:"fileName"`
}

func (Backup) TableName() string { return "backups" }

type NoticeConfig struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	Channel    string    `gorm:"size:32;uniqueIndex" json:"channel"`
	Enabled    bool      `json:"enabled"`
	ConfigJSON JSON      `json:"config"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

func (NoticeConfig) TableName() string { return "notice_config" }

// NoticeTemplate stores per-channel rendering overrides. A row exists
// only when the operator has explicitly customised the template — the
// default text/template strings live alongside the renderer in
// pkg/notify/template_defaults.go and are used whenever the channel has
// no row here. This keeps DB clean (8 rows max) and makes "reset to
// default" a single DELETE rather than a re-seed dance.
type NoticeTemplate struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Channel   string    `gorm:"size:32;uniqueIndex" json:"channel"`
	Subject   string    `gorm:"size:512" json:"subject"`
	Body      string    `gorm:"type:mediumtext" json:"body"`
	UpdatedAt time.Time `json:"updatedAt"`
	UpdatedBy uint      `json:"updatedBy"`
}

func (NoticeTemplate) TableName() string { return "notice_templates" }

// AlertNotifyDeadLetter stores final-failed async notification jobs for
// operator replay / forensic inspection.
type AlertNotifyDeadLetter struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Channel   string    `gorm:"size:32;index" json:"channel"`
	Level     string    `gorm:"size:32" json:"level"`
	AlertType string    `gorm:"size:64;index" json:"alertType"`
	Domain    string    `gorm:"size:255;index" json:"domain"`
	Title     string    `gorm:"size:255" json:"title"`
	Message   string    `gorm:"type:mediumtext" json:"message"`
	Error     string    `gorm:"type:text" json:"error"`
	Attempts  int       `json:"attempts"`
	IsTest    bool      `gorm:"index" json:"isTest"`
	CreatedAt time.Time `gorm:"index" json:"createdAt"`
}

func (AlertNotifyDeadLetter) TableName() string { return "alert_notify_dead_letters" }

type ApiKey struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	Name       string    `gorm:"size:128" json:"name"`
	Prefix     string    `gorm:"size:32" json:"prefix"`
	KeyHash    string    `gorm:"size:255" json:"-"`
	Scope      JSON      `json:"scope"`
	CreatedBy  string    `gorm:"size:64" json:"createdBy"`
	ExpiresAt  string    `gorm:"size:32" json:"expiresAt"`
	Status     string    `gorm:"size:16" json:"status"`
	LastUsedAt string    `gorm:"size:32" json:"lastUsedAt"`
	CreatedAt  time.Time `json:"createdAt"`
}

func (ApiKey) TableName() string { return "api_keys" }

// ─── Load Balance ────────────────────────────────────────────────────────────

type LbGroup struct {
	ID                  uint      `gorm:"primaryKey" json:"id"`
	Name                string    `gorm:"size:128" json:"name"`
	Algorithm           string    `gorm:"size:32" json:"algorithm"`
	HealthCheckInterval int       `json:"healthCheckInterval"`
	Status              string    `gorm:"size:16" json:"status"`
	CreatedAt           time.Time `json:"createdAt"`
	UpdatedAt           time.Time `json:"updatedAt"`
}

func (LbGroup) TableName() string { return "lb_groups" }

type LbServer struct {
	ID          uint    `gorm:"primaryKey" json:"id"`
	GroupID     uint    `json:"groupId"`
	Name        string  `gorm:"size:128" json:"name"`
	Address     string  `gorm:"size:255" json:"address"`
	Port        int     `json:"port"`
	Protocol    string  `gorm:"size:16" json:"protocol"`
	Weight      int     `json:"weight"`
	MaxConns    int     `json:"maxConns"`
	Latency     int     `json:"latency"`
	SuccessRate float64 `json:"successRate"`
	Status      string  `gorm:"size:16" json:"status"`
	Enabled     bool    `json:"enabled"`
	// LastError captures the most-recent probe failure reason — empty
	// string when the last probe succeeded. Surfaced in the LB
	// management UI so the operator doesn't have to grep server logs
	// to figure out *why* an upstream is in 异常 status (TLS handshake
	// vs HTTP 4xx vs DNS truncation each need different remediation).
	LastError string    `gorm:"size:255;column:last_error" json:"lastError"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (LbServer) TableName() string { return "lb_servers" }

// ─── Alert Subscribe ─────────────────────────────────────────────────────────

type AlertSubscribeRule struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	Name           string    `gorm:"size:128" json:"name"`
	Metric         string    `gorm:"size:32" json:"metric"`
	Operator       string    `gorm:"size:4" json:"operator"`
	Threshold      float64   `json:"threshold"`
	Unit           string    `gorm:"size:16" json:"unit"`
	Duration       int       `json:"duration"`
	Channels       string    `gorm:"size:255" json:"channels"`
	ContactGroupID uint      `gorm:"column:contact_group_id;default:0" json:"contactGroupId"`
	SilenceMinutes int       `gorm:"column:silence_minutes;default:0" json:"silenceMinutes"`
	Status         string    `gorm:"size:16" json:"status"`
	TriggerCount   int       `json:"triggerCount"`
	LastTriggered  string    `gorm:"size:32" json:"lastTriggered"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

func (AlertSubscribeRule) TableName() string { return "alert_subscribe_rules" }

type AlertContactGroup struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	Name          string    `gorm:"size:128" json:"name"`
	MemberUserIDs string    `gorm:"column:member_user_ids;type:text" json:"memberUserIds"`
	Remark        string    `gorm:"size:255" json:"remark"`
	Status        string    `gorm:"size:16" json:"status"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

func (AlertContactGroup) TableName() string { return "alert_contact_groups" }

// AlertSilenceRule mutes matching alerts within a configured time window.
type AlertSilenceRule struct {
	ID               uint      `gorm:"primaryKey" json:"id"`
	Name             string    `gorm:"size:128" json:"name"`
	AlertTypePattern string    `gorm:"column:alert_type_pattern;size:128" json:"alertTypePattern"`
	DomainPattern    string    `gorm:"column:domain_pattern;size:255" json:"domainPattern"`
	Levels           string    `gorm:"size:128" json:"levels"`
	StartAt          time.Time `gorm:"index" json:"startAt"`
	EndAt            time.Time `gorm:"index" json:"endAt"`
	Status           string    `gorm:"size:16;index" json:"status"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

func (AlertSilenceRule) TableName() string { return "alert_silence_rules" }

// AlertInhibitRule suppresses target alerts while matching source alerts are firing.
type AlertInhibitRule struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	Name            string    `gorm:"size:128" json:"name"`
	SourceAlertType string    `gorm:"column:source_alert_type;size:128;index" json:"sourceAlertType"`
	SourceLevel     string    `gorm:"column:source_level;size:32" json:"sourceLevel"`
	TargetAlertType string    `gorm:"column:target_alert_type;size:128;index" json:"targetAlertType"`
	TargetLevel     string    `gorm:"column:target_level;size:32" json:"targetLevel"`
	DomainScoped    bool      `gorm:"column:domain_scoped;default:false" json:"domainScoped"`
	Status          string    `gorm:"size:16;index" json:"status"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

func (AlertInhibitRule) TableName() string { return "alert_inhibit_rules" }

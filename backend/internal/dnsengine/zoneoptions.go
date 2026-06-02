package dnsengine

// Per-zone server-side policy gating: query access + zone-transfer
// access. The persistence layer (model.ZoneOptions / table
// `zone_options`) is shared with the「区域选项」frontend dialog; this
// file is the engine-side view of those rows compiled into runtime
// matchers and consulted on every query / AXFR.
//
// The mode strings are kept identical to what the frontend dialog
// emits so the audit trail (DB row → wire behaviour) is one-to-one.
//
// Default-when-no-row policy
// ──────────────────────────
// A zone with NO zone_options row is the most common shape (every
// freshly-created zone, every legacy zone). The engine MUST keep
// answering queries for those — anything else would be a regression
// the moment an operator upgrades. So:
//
//   query   → allow when zd.Options == nil (legacy / freshly-created)
//   transfer→ deny  when zd.Options == nil (BIND-style safe default)
//
// Operators who want stricter query gating must explicitly pick a
// non-allow mode in the dialog; until they do, the resolver behaves
// exactly as it did before this feature shipped.

import (
	"net"
	"strings"

	"modern-dns/internal/model"
	"modern-dns/pkg/acl"

	"github.com/miekg/dns"
)

// zoneOptions is the engine's compiled view of a model.ZoneOptions
// row. We compile both ACL textareas at reload time so the hot path
// (Match) does no string parsing. nsAddrs is pre-computed from the
// zone's NS records + their A/AAAA glue so "ns-only" / "ns-acl"
// modes don't have to walk the record slice on every query.
type zoneOptions struct {
	queryMode       string
	queryMatcher    *acl.Matcher
	transferMode    string
	transferMatcher *acl.Matcher
}

// compileZoneOptions converts a model.ZoneOptions row into the
// engine's runtime view. Mode strings are lower-cased so the gate
// helpers can do straight switches.
func compileZoneOptions(o *model.ZoneOptions) *zoneOptions {
	if o == nil {
		return nil
	}
	return &zoneOptions{
		queryMode:       strings.ToLower(strings.TrimSpace(o.QueryMode)),
		queryMatcher:    acl.Compile(o.QueryACL),
		transferMode:    strings.ToLower(strings.TrimSpace(o.TransferMode)),
		transferMatcher: acl.Compile(o.TransferACL),
	}
}

// gateQuery returns true when clientIP is allowed to query zd. A
// nil zd or nil Options means "legacy default — allow", matching
// the pre-feature behaviour. ip == nil (e.g. unparseable remote
// address) is treated as untrusted and only allowed when the mode
// itself is "allow".
func gateQuery(zd *zoneData, ip net.IP) bool {
	if zd == nil || zd.Options == nil {
		return true
	}
	o := zd.Options
	switch o.queryMode {
	case "", "allow":
		return true
	case "deny":
		return false
	case "private":
		return ipIsPrivate(ip)
	case "ns-only":
		return matchesZoneNS(zd, ip)
	case "acl":
		// An empty ACL with mode=acl means "deny everyone": the
		// operator picked ACL but listed nobody, so honour that
		// literal intent. See pkg/acl package doc.
		return ip != nil && o.queryMatcher.Match(ip)
	case "ns-acl":
		if matchesZoneNS(zd, ip) {
			return true
		}
		return ip != nil && o.queryMatcher.Match(ip)
	}
	// Unknown mode: be conservative but don't break legacy traffic
	// — fall back to allow so a typo in the DB doesn't black-hole
	// the zone. The frontend validates modes, so this branch is
	// hit only by hand-edits / bad migrations.
	return true
}

// gateTransfer returns true when clientIP is allowed to AXFR / IXFR
// zd. Default (no row) is DENY — BIND's historical safe default,
// and the only sane choice given how much data a transfer leaks.
func gateTransfer(zd *zoneData, ip net.IP) bool {
	if zd == nil || zd.Options == nil {
		return false
	}
	o := zd.Options
	switch o.transferMode {
	case "allow":
		return true
	case "", "deny":
		return false
	case "ns-only":
		return matchesZoneNS(zd, ip)
	case "acl":
		return ip != nil && o.transferMatcher.Match(ip)
	}
	return false
}

// ipIsPrivate is the "private" mode predicate. We mirror the same
// approximation as acl.matchMacro("localnets") so the two paths
// agree on what "internal" means.
func ipIsPrivate(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate()
}

// matchesZoneNS returns true when ip equals the address of one of
// the zone's NS records, looked up via in-zone A/AAAA glue. NS
// targets that point outside the zone are ignored — we cannot
// resolve them safely from here without risking a recursion loop
// (the resolver itself is what's gating the lookup).
//
// This is best-effort by design: operators who run NS on hosts
// without in-zone glue should pick the "acl" / "ns-acl" mode and
// list the addresses explicitly.
func matchesZoneNS(zd *zoneData, ip net.IP) bool {
	if zd == nil || ip == nil {
		return false
	}
	// Collect NS targets at the zone apex.
	var nsTargets []string
	for _, rec := range zd.Records {
		if !strings.EqualFold(rec.Type, "NS") {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(rec.Host))
		if host != "@" && host != "" {
			// Only apex NS records define the zone's authoritative
			// servers; sub-zone delegations (host != "@") describe
			// children, not us.
			continue
		}
		t := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rec.Value), "."))
		if t != "" {
			nsTargets = append(nsTargets, t)
		}
	}
	if len(nsTargets) == 0 {
		return false
	}

	zoneFQDN := strings.ToLower(strings.TrimSuffix(zd.Zone.Domain, "."))
	for _, target := range nsTargets {
		// Map NS target back to the in-zone host label so we can
		// look it up against zd.Records — same scheme as
		// resolveLocalWithZone uses for incoming queries.
		var hostLabel string
		switch {
		case target == zoneFQDN:
			hostLabel = "@"
		case strings.HasSuffix(target, "."+zoneFQDN):
			hostLabel = strings.TrimSuffix(target, "."+zoneFQDN)
		default:
			// External NS target (e.g. ns1.example.net for example.com).
			// Skip — we can't resolve it without recursion.
			continue
		}
		for _, rec := range zd.Records {
			if !strings.EqualFold(rec.Host, hostLabel) {
				continue
			}
			t := strings.ToUpper(rec.Type)
			if t != "A" && t != "AAAA" {
				continue
			}
			if recIP := net.ParseIP(strings.TrimSpace(rec.Value)); recIP != nil && recIP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// findMatchingZone returns the zoneData whose apex covers qName, or
// nil. Same matching rule as resolveLocalWithZone — longest-prefix
// would be more correct, but the current resolver does first-match
// over the slice and we want the gates to agree with it byte-for-byte.
//
// Caller must hold e.mu (read lock is fine).
func (e *Engine) findMatchingZone(qName string) *zoneData {
	for i := range e.zones {
		zd := &e.zones[i]
		zoneFQDN := dns.Fqdn(strings.ToLower(zd.Zone.Domain))
		if dns.IsSubDomain(zoneFQDN, qName) {
			return zd
		}
	}
	return nil
}

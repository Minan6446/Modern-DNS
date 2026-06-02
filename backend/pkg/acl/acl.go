// Package acl is the Go counterpart of the frontend's
// `utils/aclParser.ts`: a tiny BIND-style ACL parser + first-match
// IP matcher used by the DNS engine to gate per-zone Query / AXFR
// access. The two implementations MUST agree on what "valid" and
// "matches" mean — operators paste the same text in either side.
//
// Why a Go re-implementation (instead of, say, server-side rule eval)
// ───────────────────────────────────────────────────────────────────
// The matcher runs on every query that hits a zone with a non-trivial
// query-mode. That's the resolver's hot path; we cannot afford an
// HTTP round-trip, JSON parse, or even a regex compile per match.
// We compile the rule list once per engine reload into a flat slice
// of pre-parsed Entries, and Match() does a linear walk with cheap
// `net.IP` comparisons. Linear walk is fine: real ACLs are tens of
// lines, the L1 cache eats them whole, and "first match wins"
// requires order preservation anyway.
//
// What's NOT here on purpose
// ──────────────────────────
//   - Hostname resolution. The TS parser accepts hostnames as a
//     shape — we keep that here too for parity, but the matcher
//     does NOT resolve them. Callers either pre-resolve before
//     compiling, or — current behaviour — a hostname entry is a
//     no-op at match time. This is the safe default: a stale cached
//     A record let into an ACL is a security footgun.
//   - The `localnets` macro doesn't enumerate real interface
//     networks; we approximate it as RFC 1918 + loopback + link-local
//     + ULA. That covers what operators actually mean by "let
//     anything inside come in" in 99% of deployments without making
//     the package depend on the host's network stack.
//
// Default-deny when empty
// ───────────────────────
// Compile("") returns a Matcher whose Empty() reports true. Callers
// decide what an empty ACL means in *their* mode — for `query_mode =
// 'acl'` an empty list MUST default-deny (refusing all queries is
// what an operator who picks "ACL" with no entries plainly intends);
// for `query_mode = 'allow'` the matcher isn't consulted at all.
package acl

import (
	"net"
	"strings"
)

// Kind enumerates the form a single ACL line resolved into. The Go
// names are intentionally identical to the TS `AclLineKind` strings
// modulo case so future parity tests can compare textually.
type Kind int

const (
	KindUnknown Kind = iota
	KindEmpty
	KindComment
	KindMacro
	KindIPv4
	KindIPv4CIDR
	KindIPv6
	KindIPv6CIDR
	KindHostname
)

// Entry is one parsed, compiled ACL line. The matcher walks a slice
// of these in order; the field that's used depends on Kind.
type Entry struct {
	Negated bool
	Kind    Kind
	// Net is set for KindIPv4 / KindIPv4CIDR / KindIPv6 / KindIPv6CIDR.
	// Bare addresses are normalised to a /32 (IPv4) or /128 (IPv6)
	// IPNet so the same `Contains` call works for all four.
	Net *net.IPNet
	// Macro is set for KindMacro.
	Macro string
	// Hostname is set for KindHostname. Stored but never matched —
	// see package doc for rationale.
	Hostname string
	// LineNumber is 1-based, useful when callers want to surface
	// "your rule on line 5 doesn't match" in the UI.
	LineNumber int
	// Raw is the original text exactly as it arrived (for debug logs).
	Raw string
	// Error is the parse failure reason, empty when the line parsed.
	// Invalid lines still appear in the slice (so line numbers stay
	// stable) but are skipped at match time.
	Error string
}

// Matcher is the compiled form of an ACL textarea. Safe for
// concurrent reads; build a fresh Matcher to modify.
type Matcher struct {
	entries  []Entry
	hasValid bool
}

// Empty returns true when the source text yielded no usable entries
// (all blank / comments / parse errors). The DNS engine treats this
// as "default deny" — see the package doc.
func (m *Matcher) Empty() bool {
	if m == nil {
		return true
	}
	return !m.hasValid
}

// Entries returns the parsed entry slice for inspection / debug.
// The returned slice is a copy header but shares the backing array;
// callers MUST NOT mutate it.
func (m *Matcher) Entries() []Entry {
	if m == nil {
		return nil
	}
	return m.entries
}

// Match implements BIND's first-match-wins semantics:
//
//	walk entries top-to-bottom
//	  on first matching entry:
//	    return !entry.Negated
//	if nothing matched:
//	    return false  (default deny)
//
// A nil ip never matches. A nil/empty matcher returns false (the
// caller should have checked Empty() first if the mode wants a
// different default).
func (m *Matcher) Match(ip net.IP) bool {
	if m == nil || ip == nil || len(m.entries) == 0 {
		return false
	}
	for _, e := range m.entries {
		if !entryMatches(e, ip) {
			continue
		}
		return !e.Negated
	}
	return false
}

func entryMatches(e Entry, ip net.IP) bool {
	switch e.Kind {
	case KindMacro:
		return matchMacro(e.Macro, ip)
	case KindIPv4, KindIPv4CIDR, KindIPv6, KindIPv6CIDR:
		if e.Net == nil {
			return false
		}
		return e.Net.Contains(ip)
	case KindHostname:
		// Intentional no-op — see package doc.
		return false
	default:
		return false
	}
}

// matchMacro decides whether a macro keyword applies to ip. The set
// of supported keywords mirrors the TS parser's `ACL_MACROS`.
func matchMacro(macro string, ip net.IP) bool {
	switch macro {
	case "any":
		return true
	case "none":
		return false
	case "localhost":
		return ip.IsLoopback()
	case "localnets":
		// Approximation — see package doc for why this isn't a true
		// interface walk. Returns true for any address an operator
		// would intuitively consider "local" without requiring a
		// hand-written CIDR list.
		return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate()
	}
	return false
}

// Compile parses textarea content into a Matcher.
//
// Line separators: `\r\n`, `\n`, and `\r` are all accepted, matching
// the TS parser exactly so paste from any OS works identically.
//
// Invalid lines do NOT cause Compile to fail — they're stored as
// Entry{Kind: KindUnknown, Error: "..."} in the result so callers
// can surface them, but they don't poison the matcher: their
// containing slot is simply skipped at match time.
func Compile(text string) *Matcher {
	m := &Matcher{}
	if text == "" {
		return m
	}
	// Normalise CRLF / CR to LF first to keep the split simple.
	t := strings.ReplaceAll(text, "\r\n", "\n")
	t = strings.ReplaceAll(t, "\r", "\n")
	lines := strings.Split(t, "\n")
	m.entries = make([]Entry, 0, len(lines))
	for i, raw := range lines {
		ent := parseLine(raw, i+1)
		m.entries = append(m.entries, ent)
		if ent.Error == "" && ent.Kind != KindEmpty && ent.Kind != KindComment {
			m.hasValid = true
		}
	}
	return m
}

// parseLine mirrors `parseAclLine` in aclParser.ts. Keep diffs in
// sync — there's a parity test in acl_test.go that flags drift.
func parseLine(raw string, lineNo int) Entry {
	ent := Entry{Raw: raw, LineNumber: lineNo}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		ent.Kind = KindEmpty
		return ent
	}
	if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
		ent.Kind = KindComment
		return ent
	}

	if strings.HasPrefix(trimmed, "!") {
		ent.Negated = true
		trimmed = strings.TrimSpace(trimmed[1:])
		if trimmed == "" {
			ent.Error = `negation prefix "!" must be followed by an address`
			return ent
		}
	}

	lower := strings.ToLower(trimmed)
	if isMacro(lower) {
		ent.Kind = KindMacro
		ent.Macro = lower
		return ent
	}

	// CIDR first — `net.ParseCIDR` accepts both v4 and v6 forms.
	if ipnet, err := parseCIDR(trimmed); err == nil {
		ent.Net = ipnet
		if ip4 := ipnet.IP.To4(); ip4 != nil && len(ipnet.Mask) == net.IPv4len {
			ent.Kind = KindIPv4CIDR
		} else {
			ent.Kind = KindIPv6CIDR
		}
		return ent
	}

	// Bare IP — wrap in a /32 or /128 so Match's IPNet.Contains works.
	if ip := net.ParseIP(trimmed); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			ent.Net = &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
			ent.Kind = KindIPv4
		} else {
			ent.Net = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			ent.Kind = KindIPv6
		}
		return ent
	}

	if isHostname(trimmed) {
		ent.Kind = KindHostname
		ent.Hostname = strings.TrimSuffix(strings.ToLower(trimmed), ".")
		return ent
	}

	ent.Error = `not a valid IP / CIDR / hostname / macro: "` + trimmed + `"`
	return ent
}

// parseCIDR is `net.ParseCIDR` minus the host-bits-cleared address.
// The Go stdlib happily zeroes them; we want the same so callers can
// `Contains` without surprises. Wrapped here so the parseLine code
// reads cleanly.
func parseCIDR(s string) (*net.IPNet, error) {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	return ipnet, nil
}

func isMacro(lower string) bool {
	switch lower {
	case "any", "none", "localhost", "localnets":
		return true
	}
	return false
}

// isHostname mirrors the TS `isHostname` exactly: ≥ 2 labels of
// 1-63 chars [A-Za-z0-9-] not starting/ending with '-', total ≤ 253,
// and at least one alphabetic character anywhere (to reject things
// like `256.0.0.1` that already failed the IPv4 path).
func isHostname(value string) bool {
	if len(value) > 253 {
		return false
	}
	v := strings.TrimSuffix(value, ".")
	if v == "" {
		return false
	}
	labels := strings.Split(v, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !validHostnameLabel(l) {
			return false
		}
	}
	hasAlpha := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			hasAlpha = true
			break
		}
	}
	return hasAlpha
}

func validHostnameLabel(l string) bool {
	if l == "" || len(l) > 63 {
		return false
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return false
		}
	}
	return true
}

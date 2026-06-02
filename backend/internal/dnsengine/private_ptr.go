// private_ptr.go short-circuits PTR queries that fall under reserved /
// private IP space (RFC 1918, link-local, loopback, ULA, …) so they
// never reach the public-internet upstream pool.
//
// Why bother:
//   - Public recursive resolvers (8.8.8.8, 1.1.1.1, 114.114.114.114, …)
//     do not — and cannot — answer reverse lookups for 10.0.0.0/8 or
//     192.168.0.0/16. They typically just drop or return SERVFAIL after
//     several seconds. That delay drives every "nslookup hangs on
//     startup, then says timed out" report we see, because Windows
//     nslookup blocks on a server-IP PTR before issuing the user's
//     real query (default 4 retries × 2s = 8s of dead air).
//   - Returning NXDOMAIN immediately is exactly what an authoritative
//     server for the reserved blocks (per RFC 6303 / IANA AS112) would
//     do, so this is fully spec-compliant — we just inline the same
//     answer rather than asking AS112 about it.
//
// Local PTR zones still win: this short-circuit lives AFTER the local-
// zone lookup step, so an operator who has actually populated a
// reverse zone (e.g. 1.168.192.in-addr.arpa with PTRs for their LAN)
// keeps full control. The short-circuit only fires when nobody owns
// the name locally.
package dnsengine

import "strings"

// privateReverseSuffixes lists the FQDN suffixes (each with a trailing
// dot, lowercase) that should be answered with NXDOMAIN locally.
//
// Coverage:
//   - IPv4 RFC 1918:  10/8, 172.16/12, 192.168/16
//   - IPv4 link-local 169.254/16  (RFC 3927)
//   - IPv4 loopback   127/8
//   - IPv4 CGNAT      100.64/10   (RFC 6598) — partial: covers the /10
//                     by listing the eight /16 prefixes that fall under
//                     it. Cheaper than special-casing the /10 boundary.
//   - IPv6 loopback   ::1
//   - IPv6 link-local fe80::/10 (4 nibble-prefixes)
//   - IPv6 ULA        fc00::/7   (2 nibble-prefixes: c.f / d.f)
//
// Entries are checked with simple suffix match against a normalised
// qName (lowercase, trailing dot). The suffix list is small and stable
// so a linear scan is fine — far below the cost of a single forwarded
// UDP query.
var privateReverseSuffixes = func() []string {
	out := []string{
		// IPv4
		"10.in-addr.arpa.",
		"168.192.in-addr.arpa.",
		"254.169.in-addr.arpa.",
		"127.in-addr.arpa.",
		// IPv6
		"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.", // ::
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.", // ::1
		// fe80::/10 — first 10 bits cover four nibble-aligned /12s
		"8.e.f.ip6.arpa.",
		"9.e.f.ip6.arpa.",
		"a.e.f.ip6.arpa.",
		"b.e.f.ip6.arpa.",
		// fc00::/7 — first 7 bits cover c.f / d.f
		"c.f.ip6.arpa.",
		"d.f.ip6.arpa.",
	}
	// 172.16.0.0/12 → 16.172 … 31.172 in-addr.arpa (16 contiguous /16s)
	for i := 16; i <= 31; i++ {
		out = append(out, itoa(i)+".172.in-addr.arpa.")
	}
	// 100.64.0.0/10 → 64.100 … 127.100 in-addr.arpa (CGNAT). Listing
	// the 64 /16 leaves keeps the suffix-match contract simple.
	for i := 64; i <= 127; i++ {
		out = append(out, itoa(i)+".100.in-addr.arpa.")
	}
	return out
}()

// isPrivateReverseName reports whether qName falls under a reserved
// reverse-DNS zone that public resolvers cannot answer. qName is
// expected to be a fully-qualified, lowercased name (the engine's
// pipeline already normalises to that shape via dns.Fqdn + ToLower).
func isPrivateReverseName(qName string) bool {
	// Cheap pre-filter: every match ends in either ".in-addr.arpa." or
	// ".ip6.arpa." — bail out before the linear scan otherwise.
	if !strings.HasSuffix(qName, ".in-addr.arpa.") && !strings.HasSuffix(qName, ".ip6.arpa.") {
		return false
	}
	for _, suf := range privateReverseSuffixes {
		// Exact match (rare, when client queries the apex itself) or
		// a sub-zone within one of the reserved blocks.
		if qName == suf || strings.HasSuffix(qName, "."+suf) {
			return true
		}
	}
	return false
}

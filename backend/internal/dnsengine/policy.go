package dnsengine

import (
	"net"
	"strings"

	"modern-dns/internal/model"

	"github.com/miekg/dns"
)

// PolicyDecision is the outcome of evaluating BW / RPZ policies.
type PolicyDecision int

const (
	PolicyPass     PolicyDecision = iota // continue pipeline
	PolicyAllow                          // explicit white-list bypass (skip RPZ + DDoS)
	PolicyBlock                          // refuse / NXDOMAIN
	PolicyRedirect                       // synthesize answer using RedirectTo
)

// PolicyResult describes the matched rule context.
type PolicyResult struct {
	Decision   PolicyDecision
	Source     string // "bw" / "rpz"
	RuleID     uint
	RuleLabel  string // human-readable label written into query log
	RedirectTo string // for PolicyRedirect (A/AAAA literal)
	BlockRcode int    // dns.RcodeNameError or dns.RcodeRefused
}

// compiledBW is a pre-parsed black/white list rule, ready for fast matching.
type compiledBW struct {
	id        uint
	listType  string // "黑名单" | "白名单"
	matchType string // "domain" | "ip" | "cidr"
	domain    string // lower-case, no trailing dot, may be wildcard
	ipNet     *net.IPNet
	ip        net.IP
	label     string
}

// compiledRPZ is a pre-parsed RPZ rule.
type compiledRPZ struct {
	id         uint
	matchType  string // "exact" | "suffix" | "regex" (regex not supported yet)
	pattern    string // lower-case
	action     string // "block" | "redirect" | "passthru"
	redirectTo string
	label      string
}

// PolicySet bundles the compiled rule caches.
type PolicySet struct {
	bw  []compiledBW
	rpz []compiledRPZ
	acl []compiledACL
}

// compiledACL is a pre-parsed source-IP access rule, sorted by priority.
type compiledACL struct {
	id       uint
	name     string
	priority int
	allow    bool // true = "允许", false = "拒绝"
	ipNet    *net.IPNet
	ip       net.IP
	zones    []string // lower-case domain suffixes; "*" means any
	qtypes   []string // empty means any
}

// compileAclRules turns DB rows into a fast-matchable slice (sorted by priority).
func compileAclRules(rules []model.AclRule) []compiledACL {
	out := make([]compiledACL, 0, len(rules))
	for _, r := range rules {
		if r.Status != "启用" {
			continue
		}
		c := compiledACL{
			id:       r.ID,
			name:     r.Name,
			priority: r.Priority,
			allow:    r.Type == "允许",
			zones:    splitTrim(r.Zones),
			qtypes:   splitTrim(r.QueryTypes),
		}
		val := strings.TrimSpace(r.CIDR)
		if _, ipNet, err := net.ParseCIDR(val); err == nil {
			c.ipNet = ipNet
		} else if ip := net.ParseIP(val); ip != nil {
			c.ip = ip
		} else {
			continue
		}
		out = append(out, c)
	}
	// stable insertion order = creation order; sort ascending priority
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && out[j-1].priority > out[j].priority {
			out[j-1], out[j] = out[j], out[j-1]
			j--
		}
	}
	return out
}

func splitTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// evaluateACL checks the inbound query against the source-IP ACL rules.
// Higher-priority (smaller) rules evaluated first. Returns Allow/Block/Pass:
//   - explicit allow rule match → PolicyAllow (still subject to BW/RPZ/limit)
//   - explicit deny rule match → PolicyBlock with REFUSED
//   - no match → PolicyPass
func (p *PolicySet) evaluateACL(qName string, qType uint16, clientIP net.IP) PolicyResult {
	if len(p.acl) == 0 || clientIP == nil {
		return PolicyResult{Decision: PolicyPass}
	}
	domain := strings.ToLower(strings.TrimSuffix(qName, "."))
	qtypeStr := strings.ToUpper(dnsTypeToString(qType))

	for _, c := range p.acl {
		if !aclIPMatches(c, clientIP) {
			continue
		}
		if !aclZoneMatches(c.zones, domain) {
			continue
		}
		if !aclQtypeMatches(c.qtypes, qtypeStr) {
			continue
		}
		if c.allow {
			return PolicyResult{Decision: PolicyAllow, Source: "acl", RuleID: c.id, RuleLabel: c.name}
		}
		return PolicyResult{
			Decision:   PolicyBlock,
			Source:     "acl",
			RuleID:     c.id,
			RuleLabel:  c.name,
			BlockRcode: dns.RcodeRefused,
		}
	}
	return PolicyResult{Decision: PolicyPass}
}

func aclIPMatches(c compiledACL, clientIP net.IP) bool {
	if c.ipNet != nil {
		return c.ipNet.Contains(clientIP)
	}
	if c.ip != nil {
		return c.ip.Equal(clientIP)
	}
	return false
}

func aclZoneMatches(zones []string, domain string) bool {
	if len(zones) == 0 {
		return true
	}
	for _, z := range zones {
		if z == "*" || z == "" {
			return true
		}
		if domain == z || strings.HasSuffix(domain, "."+z) {
			return true
		}
	}
	return false
}

func aclQtypeMatches(qtypes []string, qtype string) bool {
	if len(qtypes) == 0 {
		return true
	}
	for _, q := range qtypes {
		if strings.EqualFold(q, "any") || strings.EqualFold(q, qtype) {
			return true
		}
	}
	return false
}

func dnsTypeToString(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return ""
}

// compileBWRules turns DB rows into a fast-matchable slice.
func compileBWRules(rules []model.BWRule) []compiledBW {
	out := make([]compiledBW, 0, len(rules))
	for _, r := range rules {
		if r.Status != "启用" {
			continue
		}
		val := strings.TrimSpace(r.Value)
		if val == "" {
			continue
		}
		c := compiledBW{
			id:       r.ID,
			listType: r.ListType,
			label:    r.RuleID,
		}
		// Try CIDR first
		if _, ipNet, err := net.ParseCIDR(val); err == nil {
			c.matchType = "cidr"
			c.ipNet = ipNet
		} else if ip := net.ParseIP(val); ip != nil {
			c.matchType = "ip"
			c.ip = ip
		} else {
			c.matchType = "domain"
			c.domain = strings.ToLower(strings.TrimSuffix(val, "."))
		}
		out = append(out, c)
	}
	return out
}

// compileRpzRules turns DB rows into the matching slice.
func compileRpzRules(rules []model.RpzRule) []compiledRPZ {
	out := make([]compiledRPZ, 0, len(rules))
	for _, r := range rules {
		if r.Status != "启用" {
			continue
		}
		pattern := strings.ToLower(strings.TrimSpace(r.Pattern))
		if pattern == "" {
			continue
		}
		mt := strings.ToLower(strings.TrimSpace(r.Type))
		switch mt {
		case "exact", "精确", "精确匹配":
			mt = "exact"
		case "regex", "正则":
			mt = "regex"
		default:
			mt = "suffix"
		}
		// support leading "*." for wildcard
		pattern = strings.TrimSuffix(pattern, ".")
		pattern = strings.TrimPrefix(pattern, "*.")
		out = append(out, compiledRPZ{
			id:         r.ID,
			matchType:  mt,
			pattern:    pattern,
			action:     normalizeRpzAction(r.Action),
			redirectTo: strings.TrimSpace(r.RedirectTo),
			label:      r.Name,
		})
	}
	return out
}

func normalizeRpzAction(action string) string {
	a := strings.ToLower(strings.TrimSpace(action))
	switch a {
	case "block", "屏蔽", "拦截", "deny":
		return "block"
	case "redirect", "重定向":
		return "redirect"
	case "passthru", "passthrough", "放行", "allow":
		return "passthru"
	}
	return "block"
}

// evaluateBW checks the request against the BW set.
// Order: explicit white-list match wins (PolicyAllow), otherwise any black-list match → PolicyBlock.
func (p *PolicySet) evaluateBW(qName string, clientIP net.IP) PolicyResult {
	if len(p.bw) == 0 {
		return PolicyResult{Decision: PolicyPass}
	}
	domain := strings.ToLower(strings.TrimSuffix(qName, "."))

	// First pass: white-list
	for _, c := range p.bw {
		if c.listType != "白名单" {
			continue
		}
		if bwMatch(c, domain, clientIP) {
			return PolicyResult{Decision: PolicyAllow, Source: "bw", RuleID: c.id, RuleLabel: c.label}
		}
	}
	// Second pass: black-list
	for _, c := range p.bw {
		if c.listType != "黑名单" {
			continue
		}
		if bwMatch(c, domain, clientIP) {
			return PolicyResult{
				Decision:   PolicyBlock,
				Source:     "bw",
				RuleID:     c.id,
				RuleLabel:  c.label,
				BlockRcode: dns.RcodeRefused,
			}
		}
	}
	return PolicyResult{Decision: PolicyPass}
}

func bwMatch(c compiledBW, domain string, clientIP net.IP) bool {
	switch c.matchType {
	case "ip":
		return clientIP != nil && c.ip.Equal(clientIP)
	case "cidr":
		return clientIP != nil && c.ipNet.Contains(clientIP)
	case "domain":
		return domainMatches(c.domain, domain)
	}
	return false
}

// evaluateRPZ checks the query name against the RPZ set.
func (p *PolicySet) evaluateRPZ(qName string) PolicyResult {
	if len(p.rpz) == 0 {
		return PolicyResult{Decision: PolicyPass}
	}
	domain := strings.ToLower(strings.TrimSuffix(qName, "."))
	for _, c := range p.rpz {
		hit := false
		switch c.matchType {
		case "exact":
			hit = domain == c.pattern
		case "suffix":
			hit = domainMatches(c.pattern, domain)
		case "regex":
			// not implemented yet — fallback to suffix
			hit = domainMatches(c.pattern, domain)
		}
		if !hit {
			continue
		}
		switch c.action {
		case "passthru":
			return PolicyResult{Decision: PolicyAllow, Source: "rpz", RuleID: c.id, RuleLabel: c.label}
		case "redirect":
			if c.redirectTo == "" {
				return PolicyResult{
					Decision:   PolicyBlock,
					Source:     "rpz",
					RuleID:     c.id,
					RuleLabel:  c.label,
					BlockRcode: dns.RcodeNameError,
				}
			}
			return PolicyResult{
				Decision:   PolicyRedirect,
				Source:     "rpz",
				RuleID:     c.id,
				RuleLabel:  c.label,
				RedirectTo: c.redirectTo,
			}
		default: // block
			return PolicyResult{
				Decision:   PolicyBlock,
				Source:     "rpz",
				RuleID:     c.id,
				RuleLabel:  c.label,
				BlockRcode: dns.RcodeNameError,
			}
		}
	}
	return PolicyResult{Decision: PolicyPass}
}

// domainMatches returns true when target equals pattern or is a sub-domain of pattern.
func domainMatches(pattern, target string) bool {
	if pattern == "" || target == "" {
		return false
	}
	if pattern == target {
		return true
	}
	return strings.HasSuffix(target, "."+pattern)
}

// buildRedirectAnswer synthesizes A/AAAA records for a redirect action.
// Returns nil when target is not an IP literal compatible with the query type.
func buildRedirectAnswer(qName string, qType uint16, target string, ttl uint32) []dns.RR {
	ip := net.ParseIP(strings.TrimSpace(target))
	if ip == nil {
		// non-IP redirect target → emit a CNAME for any query type
		rr, err := dns.NewRR(qName + " " + itoa(int(ttl)) + " IN CNAME " + dns.Fqdn(target))
		if err != nil {
			return nil
		}
		return []dns.RR{rr}
	}
	if v4 := ip.To4(); v4 != nil {
		if qType == dns.TypeA || qType == dns.TypeANY {
			rr, _ := dns.NewRR(qName + " " + itoa(int(ttl)) + " IN A " + v4.String())
			if rr != nil {
				return []dns.RR{rr}
			}
		}
		return nil
	}
	if qType == dns.TypeAAAA || qType == dns.TypeANY {
		rr, _ := dns.NewRR(qName + " " + itoa(int(ttl)) + " IN AAAA " + ip.String())
		if rr != nil {
			return []dns.RR{rr}
		}
	}
	return nil
}

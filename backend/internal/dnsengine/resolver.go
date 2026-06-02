package dnsengine

import (
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// resolveLocal checks local zone records for an authoritative answer.
// Returns the answer RRs and whether a match was found.
func (e *Engine) resolveLocal(qName string, qType uint16) ([]dns.RR, bool) {
	answers, found, _ := e.resolveLocalWithZone(qName, qType)
	return answers, found
}

// resolveLocalWithZone is like resolveLocal but also returns the matching
// zoneData pointer, which the DNSSEC signing code needs.
func (e *Engine) resolveLocalWithZone(qName string, qType uint16) ([]dns.RR, bool, *zoneData) {
	// qName is already lower-cased and FQDN (trailing dot)
	for i := range e.zones {
		zd := &e.zones[i]
		zoneFQDN := dns.Fqdn(strings.ToLower(zd.Zone.Domain))
		if !dns.IsSubDomain(zoneFQDN, qName) {
			continue
		}

		// DNSKEY query at zone apex — answered by DNSSEC key material
		if qType == dns.TypeDNSKEY && qName == zoneFQDN && zd.DNSSEC != nil {
			return nil, true, zd // answers will be filled by the engine (DNSKEY RRs)
		}

		// Determine the host label relative to zone
		// e.g. qName="www.example.com." zone="example.com." → host="www"
		// e.g. qName="example.com." zone="example.com." → host="@"
		var hostLabel string
		if qName == zoneFQDN {
			hostLabel = "@"
		} else {
			hostLabel = strings.TrimSuffix(qName, "."+zoneFQDN)
		}

		var answers []dns.RR
		for _, rec := range zd.Records {
			recHost := strings.ToLower(rec.Host)
			recType := strings.ToUpper(rec.Type)

			if recHost != hostLabel {
				continue
			}

			if !typeMatches(recType, qType) {
				continue
			}

			rr := buildRR(qName, recType, rec.Value, uint32(rec.TTL))
			if rr != nil {
				answers = append(answers, rr)
			}
		}

		if len(answers) > 0 {
			return answers, true, zd
		}

		// Zone matched but no record found → authoritative NXDOMAIN could be
		// returned, but we let the pipeline continue to forwarding so that
		// sub-domains not in local zones can still be resolved externally.
	}
	return nil, false, nil
}

// matchConditionRule finds the first conditional forwarding rule whose
// domain pattern matches the query name. Returns the upstream address
// to forward to (resolved either via the rule's LbGroupID — preferred
// when set — or its legacy UpstreamID), or "" if nothing matches.
//
// LbGroupID takes precedence: a rule that points at an LB group fans
// out across the group's pick algorithm (RR / weighted / least-latency)
// per query. Falling back to UpstreamID keeps every rule that pre-dates
// the LB integration working unchanged.
// matchConditionRule returns (upstreamAddr, forcedProto). forcedProto
// is the rule's Protocol column when set — empty means "inherit the
// global UpstreamProtocolOrder".
func (e *Engine) matchConditionRule(qName string) (string, string) {
	for _, rule := range e.rules {
		domains := strings.Split(rule.Domains, ",")
		for _, d := range domains {
			d = strings.TrimSpace(strings.ToLower(d))
			if d == "" {
				continue
			}
			pattern := dns.Fqdn(d)
			// Exact match or sub-domain match
			if qName == pattern || dns.IsSubDomain(pattern, qName) {
				// Prefer the LB group when the rule binds one — this
				// is what makes the LB page actually do work for
				// conditional traffic.
				if rule.LbGroupID != nil && *rule.LbGroupID > 0 {
					if addr := e.pickLbGroupAddr(*rule.LbGroupID); addr != "" {
						return addr, rule.Protocol
					}
					// Group missing or every server unhealthy → fall
					// through to the legacy single-server upstream so
					// the rule still resolves something rather than
					// silently breaking.
				}
				// Legacy path: single ForwardServer by ID.
				for _, s := range e.servers {
					if s.ID == rule.UpstreamID {
						return net.JoinHostPort(s.Address, itoa(s.Port)), rule.Protocol
					}
				}
			}
		}
	}
	return "", ""
}

// pickLbGroupAddr resolves an LB group ID to a single "host:port" by
// running the group's configured pick algorithm. Returns "" when the
// group is unknown to the engine cache (e.g. created since last reload
// or disabled) or the group has no healthy servers — callers fall
// back to their legacy upstream path in that case.
//
// Caller must already hold e.mu (read or write); we do not lock here
// because both call sites already hold the engine lock when they
// look up rules / globalCfg.
func (e *Engine) pickLbGroupAddr(groupID uint) string {
	for _, g := range e.lbGroups {
		if g.Group.ID != groupID {
			continue
		}
		return globalLBPicker.pickServer(g)
	}
	return ""
}

// typeMatches checks if a record type string matches the DNS query type.
func typeMatches(recType string, qType uint16) bool {
	switch recType {
	case "A":
		return qType == dns.TypeA
	case "AAAA":
		return qType == dns.TypeAAAA
	case "CNAME":
		return qType == dns.TypeCNAME || qType == dns.TypeA || qType == dns.TypeAAAA
	case "MX":
		return qType == dns.TypeMX
	case "TXT":
		return qType == dns.TypeTXT
	case "NS":
		return qType == dns.TypeNS
	case "SRV":
		return qType == dns.TypeSRV
	case "CAA":
		return qType == dns.TypeCAA
	case "PTR":
		return qType == dns.TypePTR
	case "SOA":
		return qType == dns.TypeSOA
	}
	return false
}

// buildRR constructs a dns.RR from record data.
func buildRR(name, recType, value string, ttl uint32) dns.RR {
	// Build a zone-file line and let miekg parse it
	var line string
	switch recType {
	case "A":
		line = name + " " + itoa(int(ttl)) + " IN A " + value
	case "AAAA":
		line = name + " " + itoa(int(ttl)) + " IN AAAA " + value
	case "CNAME":
		line = name + " " + itoa(int(ttl)) + " IN CNAME " + dns.Fqdn(value)
	case "MX":
		// value format: "10 mail.example.com" or just "mail.example.com"
		parts := strings.Fields(value)
		if len(parts) == 1 {
			line = name + " " + itoa(int(ttl)) + " IN MX 10 " + dns.Fqdn(parts[0])
		} else {
			line = name + " " + itoa(int(ttl)) + " IN MX " + parts[0] + " " + dns.Fqdn(parts[1])
		}
	case "TXT":
		line = name + " " + itoa(int(ttl)) + " IN TXT \"" + value + "\""
	case "NS":
		line = name + " " + itoa(int(ttl)) + " IN NS " + dns.Fqdn(value)
	case "SRV":
		line = name + " " + itoa(int(ttl)) + " IN SRV " + value
	case "CAA":
		line = name + " " + itoa(int(ttl)) + " IN CAA " + value
	case "PTR":
		line = name + " " + itoa(int(ttl)) + " IN PTR " + dns.Fqdn(value)
	default:
		return nil
	}

	rr, err := dns.NewRR(line)
	if err != nil {
		return nil
	}
	return rr
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

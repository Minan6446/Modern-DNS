package dnsengine

// Server-side AXFR (and IXFR-falls-back-to-AXFR) handler.
//
// Why we serve transfer at all
// ────────────────────────────
// The engine is authoritative for any zone it loads from local
// records, so secondaries — whether external BIND/Knot installs or
// our own peer instance running secondary_refresh_worker — need a
// way to pull the data. Refusing every AXFR would force operators
// onto out-of-band sync (rsync, sql dumps) which defeats the point
// of running a DNS server.
//
// Why "single-message" AXFR
// ─────────────────────────
// RFC 5936 allows multi-message AXFR; the streaming form is needed
// only when the answer doesn't fit one TCP frame (~ 65 535 bytes
// after compression, comfortably > 5 000 records). Modern-DNS zones
// are operator-curated and very rarely cross that threshold; the
// few that do can be split into sub-zones with no behaviour change.
// Single-message keeps the wire path small and avoids wrestling
// miekg's dns.Transfer.Out helper, which expects a manual envelope
// loop and ties us to a private response writer surface.
//
// What we don't do
// ────────────────
//  - True IXFR. RFC 1995 incremental transfer requires us to keep
//    a per-zone change journal; we don't have one. We answer IXFR
//    by falling back to a full AXFR, which every well-behaved
//    secondary handles transparently (it's the BIND default when
//    the server replies with a single SOA != the asked-for serial,
//    or with the full AXFR envelope, which is what we do).
//  - TSIG. Authentication is IP-based via the transfer ACL — same
//    threat model as the rest of this server.

import (
	"strconv"
	"strings"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"

	"github.com/miekg/dns"
)

// handleZoneTransfer serves AXFR / IXFR. Caller has already verified
// q.Qtype is TypeAXFR or TypeIXFR. Always writes a response (success
// envelope or REFUSED) and returns; never falls through to the
// regular query pipeline.
func (e *Engine) handleZoneTransfer(w dns.ResponseWriter, r *dns.Msg) {
	q := r.Question[0]
	qName := strings.ToLower(q.Name)

	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Authoritative = true

	clientIP := remoteClientIP(w.RemoteAddr())

	e.mu.RLock()
	zd := e.findMatchingZone(qName)
	// We only serve transfer for an EXACT apex match. Asking for
	// AXFR sub.example.com when example.com is the loaded zone is a
	// configuration error on the secondary's side — REFUSED keeps
	// the contract clear.
	if zd != nil {
		zoneFQDN := dns.Fqdn(strings.ToLower(zd.Zone.Domain))
		if zoneFQDN != qName {
			zd = nil
		}
	}
	allowed := gateTransfer(zd, clientIP)
	e.mu.RUnlock()

	if zd == nil || !allowed {
		resp.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(resp)
		return
	}

	// Build the AXFR envelope: SOA + all records + SOA.
	soa := buildSOAForZone(zd)
	if soa == nil {
		// Without an SOA we'd be sending a malformed AXFR; refuse
		// rather than feed the secondary a broken zone.
		resp.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(resp)
		return
	}

	answer := make([]dns.RR, 0, len(zd.Records)+2)
	answer = append(answer, soa)
	zoneFQDN := dns.Fqdn(strings.ToLower(zd.Zone.Domain))
	for _, rec := range zd.Records {
		// Translate the in-DB host label back to an FQDN, same
		// scheme as resolveLocalWithZone uses on the lookup side.
		host := strings.ToLower(strings.TrimSpace(rec.Host))
		var fqdn string
		if host == "@" || host == "" {
			fqdn = zoneFQDN
		} else {
			fqdn = host + "." + zoneFQDN
		}
		// Skip apex SOA stored as a record — the SOA we just
		// emitted is authoritative; emitting the record-table copy
		// too would duplicate the envelope opener.
		if strings.EqualFold(rec.Type, "SOA") {
			continue
		}
		if rr := buildRR(fqdn, strings.ToUpper(rec.Type), rec.Value, uint32(rec.TTL)); rr != nil {
			answer = append(answer, rr)
		}
	}
	answer = append(answer, soa)
	resp.Answer = answer

	_ = w.WriteMsg(resp)
}

// buildSOAForZone fetches the per-zone SOA row and the zone's serial,
// composing a dns.SOA RR suitable for AXFR / SOA-query responses.
// Returns nil when no SOA row exists — the caller treats that as a
// hard error (a zone without an SOA is unservable).
//
// We hit the DB instead of caching because (a) SOA changes are rare
// but matter (the serial bumps on every record edit) and (b) the
// row is tiny — a single PK lookup, comfortably below the noise floor
// even at handler-thread call rate.
func buildSOAForZone(zd *zoneData) *dns.SOA {
	if zd == nil {
		return nil
	}
	var soa model.ZoneSOA
	if err := db.DB.Where("zone_id = ?", zd.Zone.ID).First(&soa).Error; err != nil {
		return nil
	}

	zoneFQDN := dns.Fqdn(strings.ToLower(zd.Zone.Domain))
	mname := dns.Fqdn(strings.TrimSpace(soa.MName))
	if mname == "." {
		mname = zoneFQDN
	}
	rname := dns.Fqdn(strings.TrimSpace(soa.RName))
	if rname == "." {
		rname = "hostmaster." + zoneFQDN
	}

	// The serial is stored as a string on Zone (operators write it
	// in YYYYMMDDNN form). Anything unparseable falls back to 1
	// rather than refusing service — secondaries treat any change
	// as fresh, so a sane non-zero default still works.
	serial := uint32(1)
	if v, err := strconv.ParseUint(strings.TrimSpace(zd.Zone.Serial), 10, 32); err == nil && v > 0 {
		serial = uint32(v)
	}

	// Defaults track common BIND-ish values when the SOA row leaves
	// them at zero. These match what NewSOAFromAXFR would synthesise
	// for an upstream that didn't override them.
	refresh := uint32(soa.Refresh)
	if refresh == 0 {
		refresh = 3600
	}
	retry := uint32(soa.Retry)
	if retry == 0 {
		retry = 900
	}
	expire := uint32(soa.Expire)
	if expire == 0 {
		expire = 604800
	}
	minTTL := uint32(soa.MinimumTTL)
	if minTTL == 0 {
		minTTL = 3600
	}

	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   zoneFQDN,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    minTTL,
		},
		Ns:      mname,
		Mbox:    rname,
		Serial:  serial,
		Refresh: refresh,
		Retry:   retry,
		Expire:  expire,
		Minttl:  minTTL,
	}
}

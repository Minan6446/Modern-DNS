// response_policy.go applies operator-tunable response transformations
// (TTL clamp + RFC 8467 padding) immediately before the engine writes
// the message back to the client. We deliberately keep this isolated
// from policy.go (which handles BW/RPZ/ACL *blocking*) so the
// "transform what we send" code path is reviewable independently from
// the "decide whether to send" code path.
//
// Why read system_config on every query rather than caching the values
// at the Engine struct? The whole row is one int-only fetch and the
// query handler is not the bottleneck of a Modern-DNS deployment;
// keeping the read here avoids a cache-invalidation bug where the
// operator changes the clamp in the UI but the engine keeps using the
// stale value because nobody remembered to call e.reload().
package dnsengine

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"

	"github.com/miekg/dns"
)

// cachedResponsePolicy is refreshed at most once a second; that's plenty
// fine for an operator-driven knob (the panel's save button is the only
// way the value changes) and keeps the QPS path allocation-free.
type cachedResponsePolicy struct {
	minTTL        uint32
	maxTTL        uint32
	paddingEnable bool
	paddingBlock  uint16
	// ECS injection. Outbound forwarder queries get an EDNS0_SUBNET
	// option built from the client's source IP truncated to the per-
	// family prefix length below, giving CDN/GeoDNS upstreams enough
	// locality to route well without leaking the client's full address.
	ecsEnabled  bool
	ecsPrefixV4 uint8
	ecsPrefixV6 uint8
}

var (
	respPolMu     sync.RWMutex
	respPolCached cachedResponsePolicy
	respPolTS     atomic.Int64 // unix-nanos of last refresh
)

const respPolicyTTL = 1 * time.Second

// invalidateResponsePolicy resets the cache stamp so the next call to
// loadResponsePolicy() re-reads from MySQL. Called by the settings
// save path so an operator's change to TTL clamp / ECS / padding
// flips behaviour the moment the save completes (the 1-second TTL
// would otherwise let the old value linger up to a full second
// after the click).
func invalidateResponsePolicy() {
	respPolTS.Store(0)
}

// InvalidatePolicies busts both the response- and upstream-policy
// caches in one call. Exposed for the handler package to call after
// any SystemConfig save without coupling to the cache internals of
// either file. Cheap (two atomic stores) — safe to call from any
// HTTP handler hot path.
func InvalidatePolicies() {
	invalidateResponsePolicy()
	invalidateUpstreamPolicy()
}

func loadResponsePolicy() cachedResponsePolicy {
	now := time.Now().UnixNano()
	last := respPolTS.Load()
	if last != 0 && time.Duration(now-last) < respPolicyTTL {
		respPolMu.RLock()
		v := respPolCached
		respPolMu.RUnlock()
		return v
	}

	var cfg model.SystemConfig
	if db.DB == nil {
		// engine boot may briefly precede DB init in tests
		return cachedResponsePolicy{}
	}
	if err := db.DB.First(&cfg, 1).Error; err != nil {
		return cachedResponsePolicy{}
	}

	v := cachedResponsePolicy{
		minTTL:        clampUint32(cfg.MinTTL),
		maxTTL:        clampUint32(cfg.MaxTTL),
		paddingEnable: cfg.DNSPaddingEnabled,
		paddingBlock:  uint16(cfg.DNSPaddingBlock),
		ecsEnabled:    cfg.ECSEnabled,
		ecsPrefixV4:   clampPrefix(cfg.ECSPrefixV4, 32, 24),
		ecsPrefixV6:   clampPrefix(cfg.ECSPrefixV6, 128, 56),
	}
	respPolMu.Lock()
	respPolCached = v
	respPolMu.Unlock()
	respPolTS.Store(now)
	return v
}

func clampUint32(v int) uint32 {
	if v < 0 {
		return 0
	}
	if v > int(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(v)
}

// clampPrefix bounds an operator-supplied prefix length into the legal
// range for its address family, with `def` as the documented sane
// default when the operator left the field at zero. We treat 0 as
// "use the documented default" (24 / 56) rather than "send /0" because
// /0 is meaningless ECS — it discloses no locality and just inflates
// the OPT RR.
func clampPrefix(v int, max int, def uint8) uint8 {
	if v <= 0 {
		return def
	}
	if v > max {
		return uint8(max)
	}
	return uint8(v)
}

// injectECS adds an EDNS0_SUBNET option to the outbound query when ECS
// is enabled in system_config. Safe on a request that already carries
// an OPT RR — we re-use it; otherwise we synthesise one. We also
// guard against private / loopback / multicast source addresses since
// forwarding those upstream tells external resolvers nothing useful
// (and may even leak internal topology).
//
// Returns the (possibly mutated) request unchanged when ECS is off or
// the client IP is unsuitable, so call sites can use it unconditionally.
func injectECS(r *dns.Msg, clientIP net.IP) *dns.Msg {
	if r == nil || clientIP == nil {
		return r
	}
	pol := loadResponsePolicy()
	if !pol.ecsEnabled {
		return r
	}
	if !ecsEligibleIP(clientIP) {
		return r
	}

	// Deep-clone so the original request retained by serveDNS for
	// logging is not mutated. Only allocates when ECS is on (the
	// short-circuits above are the hot path on most deployments).
	r = r.Copy()

	opt := r.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096}}
		r.Extra = append(r.Extra, opt)
	}
	// Strip any client-supplied subnet option; we own the field on
	// outbound forwards. Repeated EDNS0_SUBNET would be undefined.
	filtered := opt.Option[:0]
	for _, o := range opt.Option {
		if _, isSub := o.(*dns.EDNS0_SUBNET); !isSub {
			filtered = append(filtered, o)
		}
	}
	opt.Option = filtered

	sub := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, SourceScope: 0}
	if v4 := clientIP.To4(); v4 != nil {
		sub.Family = 1
		sub.SourceNetmask = pol.ecsPrefixV4
		sub.Address = maskedIP(v4, int(pol.ecsPrefixV4), 32)
	} else {
		sub.Family = 2
		sub.SourceNetmask = pol.ecsPrefixV6
		sub.Address = maskedIP(clientIP.To16(), int(pol.ecsPrefixV6), 128)
	}
	opt.Option = append(opt.Option, sub)
	return r
}

// ecsEligibleIP returns true when the client IP is a global unicast
// address worth forwarding upstream. Loopback / private / link-local
// / multicast / unspecified all fail this check — sending those bits
// upstream is at best useless, at worst leaks internal topology.
func ecsEligibleIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() {
		return false
	}
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip.IsPrivate() {
		return false
	}
	return true
}

// maskedIP zeros out bits below `prefix` so we ship only the network
// portion. Both v4 and v6 collapse to the same byte-bit math.
func maskedIP(ip net.IP, prefix, totalBits int) net.IP {
	if prefix <= 0 {
		return nil
	}
	if prefix > totalBits {
		prefix = totalBits
	}
	mask := net.CIDRMask(prefix, totalBits)
	out := make(net.IP, len(ip))
	for i := range ip {
		out[i] = ip[i] & mask[i]
	}
	return out
}

// applyResponsePolicies rewrites in-place. It's safe to call with a nil
// or empty msg; the helper short-circuits before touching anything.
//
// The padding is conditional on the original query carrying an OPT
// record (i.e. the client speaks EDNS0). Naked UDP queries with no
// EDNS0 must not get padded — we'd just be inflating UDP datagrams
// that the client is going to discard anyway. RFC 8467 specifically
// scopes padding to "DNS-over-TLS / DNS-over-HTTPS" but accepting any
// EDNS-aware client is harmless.
func applyResponsePolicies(msg *dns.Msg, w dns.ResponseWriter) {
	if msg == nil {
		return
	}
	pol := loadResponsePolicy()

	// ── TTL clamp on every RR section ──
	if pol.minTTL > 0 || pol.maxTTL > 0 {
		clampSection(msg.Answer, pol.minTTL, pol.maxTTL)
		clampSection(msg.Ns, pol.minTTL, pol.maxTTL)
		clampSection(msg.Extra, pol.minTTL, pol.maxTTL)
	}

	// ── RFC 8467 padding ──
	if pol.paddingEnable && pol.paddingBlock > 0 && msg.IsEdns0() != nil {
		applyPadding(msg, int(pol.paddingBlock))
		paddingInboundMetric.Add(1)
	}
}

func clampSection(rrs []dns.RR, minTTL, maxTTL uint32) {
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		// Skip OPT — its TTL field encodes flags (DO bit, EDNS version),
		// not a duration; rewriting it would corrupt the response.
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		t := rr.Header().Ttl
		if minTTL > 0 && t < minTTL {
			rr.Header().Ttl = minTTL
		} else if maxTTL > 0 && t > maxTTL {
			rr.Header().Ttl = maxTTL
		}
	}
}

// applyPadding pads the DNS response so its on-wire length is a
// multiple of `block`. The padding is carried as an EDNS0 Padding
// option (RFC 7830) inside the OPT RR. We compute the deficit by
// serialising the message once, then build the OPT option with that
// many zero bytes — the second serialise will land on a block
// boundary because the OPT framing overhead is constant.
func applyPadding(msg *dns.Msg, block int) {
	opt := msg.IsEdns0()
	if opt == nil {
		return
	}
	// Drop any pre-existing padding option so re-padding is idempotent.
	filtered := opt.Option[:0]
	for _, o := range opt.Option {
		if _, isPad := o.(*dns.EDNS0_PADDING); !isPad {
			filtered = append(filtered, o)
		}
	}
	opt.Option = filtered

	wire, err := msg.Pack()
	if err != nil {
		return
	}
	// 4 bytes is the EDNS0 option header (option-code + option-length)
	// that wraps the actual padding bytes.
	const optionOverhead = 4
	current := len(wire) + optionOverhead
	target := ((current + block - 1) / block) * block
	padBytes := target - current
	if padBytes < 0 {
		padBytes = 0
	}
	pad := &dns.EDNS0_PADDING{Padding: make([]byte, padBytes)}
	opt.Option = append(opt.Option, pad)
}

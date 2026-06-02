// upstream_policy.go reads SystemConfig.UpstreamProtocolOrder and
// UpstreamTimeoutMs into a per-second cache so the forwarder hot path
// doesn't hit MySQL on every query. Mirrors the design of
// response_policy.go (same TTL constant, same lock pattern).
//
// The protocol order is parsed once on cache refresh into a sanitised
// []protocol slice; unknown tokens are dropped silently so a typo in
// the operator's config never wedges the forwarder. If the resulting
// list is empty (e.g. the operator wiped the field) we fall back to
// the conservative ["udp", "tcp"] default \u2014 the same behaviour the
// hard-coded forwarder had before this knob existed.
package dnsengine

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"
)

// protocol is the set of upstream transports the forwarder knows how
// to speak. The DoH/DoT entries lean on per-protocol port defaults
// when an upstream is given as bare host (or host:53) \u2014 see
// resolveUpstreamFor* in forwarder.go.
type protocol string

const (
	protoUDP protocol = "udp"
	protoTCP protocol = "tcp"
	protoDoT protocol = "dot"
	protoDoH protocol = "doh"
)

type cachedUpstreamPolicy struct {
	order     []protocol
	timeoutMs int
	// dohPreferGET asks queryDoH to use HTTP GET (base64url-encoded
	// query in URL) instead of POST. Some corporate proxies / app-layer
	// gateways block POST application/dns-message but pass GET; this
	// knob lets operators in those environments switch without a
	// rebuild. Default false (POST) — POST avoids URL length limits
	// and is what every public DoH provider documents first.
	dohPreferGET bool
}

var (
	upPolMu     sync.RWMutex
	upPolCached cachedUpstreamPolicy
	upPolTS     atomic.Int64
)

const upPolicyTTL = 1 * time.Second

// loadUpstreamPolicy returns the current order + per-attempt timeout.
// Same caching contract as loadResponsePolicy(): at most one DB read
// per second, fresh after every operator save (the timeout is so
// short the cache effectively just absorbs query bursts).
func loadUpstreamPolicy() cachedUpstreamPolicy {
	now := time.Now().UnixNano()
	last := upPolTS.Load()
	if last != 0 && time.Duration(now-last) < upPolicyTTL {
		upPolMu.RLock()
		v := upPolCached
		upPolMu.RUnlock()
		return v
	}

	v := cachedUpstreamPolicy{
		order:     []protocol{protoUDP, protoTCP},
		timeoutMs: 2000,
	}
	if db.DB != nil {
		var cfg model.SystemConfig
		if err := db.DB.First(&cfg, 1).Error; err == nil {
			if parsed := parseProtocolOrder(cfg.UpstreamProtocolOrder); len(parsed) > 0 {
				v.order = parsed
			}
			if cfg.UpstreamTimeoutMs > 0 {
				v.timeoutMs = cfg.UpstreamTimeoutMs
			}
			v.dohPreferGET = cfg.DoHPreferGET
		}
	}

	upPolMu.Lock()
	upPolCached = v
	upPolMu.Unlock()
	upPolTS.Store(now)
	return v
}

// parseProtocolOrder accepts the comma-separated string the operator
// stores in SystemConfig.UpstreamProtocolOrder. Whitespace around each
// token is trimmed, case is normalised, unknown tokens are dropped
// (better to silently degrade than to wedge the forwarder), and
// duplicates are de-duplicated so a typo like "udp,UDP,tcp" doesn't
// cause us to retry UDP twice in a row.
func parseProtocolOrder(raw string) []protocol {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	seen := map[protocol]bool{}
	out := make([]protocol, 0, 4)
	for _, t := range strings.Split(raw, ",") {
		p := protocol(strings.ToLower(strings.TrimSpace(t)))
		switch p {
		case protoUDP, protoTCP, protoDoT, protoDoH:
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// invalidateUpstreamPolicy is exposed so the settings save handler
// could bust the cache after an operator change for sub-second
// pickup; currently unused because the 1-second TTL is already short
// enough for interactive use, but kept as a hook for future hot-
// reload semantics.
func invalidateUpstreamPolicy() {
	upPolTS.Store(0)
}

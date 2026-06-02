package dnsengine

import (
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"modern-dns/internal/model"

	"github.com/miekg/dns"
)

// forward sends the query to the list of upstreams using the global
// strategy + the operator-configured upstream protocol order (DoH /
// DoT / UDP / TCP, see SystemConfig.UpstreamProtocolOrder). For each
// retry attempt we walk every (protocol, upstream) pair until one
// succeeds; the first protocol gets first crack at the first
// upstream, etc. Failure of one (proto, upstream) only logs locally
// and falls through to the next combination.
//
// Per-attempt timeout: there are three nested budgets here that have
// to coexist:
//
//   - SystemConfig.UpstreamTimeoutMs   — per (proto, upstream) try
//   - forward_global.Timeout           — overall query budget (used
//     as a ceiling so a slow
//     proto×upstream cartesian
//     product can't outrun the
//     client's wait-for-answer)
//   - forward_global.Retries           — number of full passes
//
// When UpstreamTimeoutMs > forward_global.Timeout we clamp to the
// outer budget so a misconfiguration can't stall the engine for
// minutes per query.
func (e *Engine) forward(r *dns.Msg, upstreams []string) (*dns.Msg, error) {
	return e.forwardWith(r, upstreams, "")
}

// forwardWith is the same as forward but lets the caller pin the
// transport protocol used for every (proto, upstream) attempt — used
// by conditional forwarding rules whose Protocol column overrides the
// global UpstreamProtocolOrder. An empty forcedProto means "fall back
// to the global policy", preserving the legacy behaviour.
//
// `forcedProto` accepts the same lower-case tokens as
// SystemConfig.UpstreamProtocolOrder: udp / tcp / dot / doh. The
// special token "doq" is recognised but currently surfaces a clear
// "not yet implemented" error from this function rather than silently
// downgrading to a working protocol — operators see *why* the rule
// stopped working when they pick an unimplemented transport.
func (e *Engine) forwardWith(r *dns.Msg, upstreams []string, forcedProto string) (*dns.Msg, error) {
	e.mu.RLock()
	totalTimeout := time.Duration(e.globalCfg.Timeout) * time.Second
	retries := e.globalCfg.Retries
	strategy := e.globalCfg.Strategy
	e.mu.RUnlock()

	if totalTimeout <= 0 {
		totalTimeout = 5 * time.Second
	}
	if retries <= 0 {
		retries = 1
	}

	pol := loadUpstreamPolicy()
	perAttempt := time.Duration(pol.timeoutMs) * time.Millisecond
	if perAttempt <= 0 {
		perAttempt = 2 * time.Second
	}
	if perAttempt > totalTimeout {
		perAttempt = totalTimeout
	}

	// Per-rule override path — pin a single protocol so the rule
	// behaves exactly as the operator picked it from the UI. We
	// reject unknown / not-yet-implemented tokens up-front so the
	// failure mode is "rule errors out" rather than "rule silently
	// downgrades to UDP".
	var protos []protocol
	switch strings.ToLower(strings.TrimSpace(forcedProto)) {
	case "":
		protos = pol.order
	case string(protoUDP):
		protos = []protocol{protoUDP}
	case string(protoTCP):
		protos = []protocol{protoTCP}
	case string(protoDoT), "tls":
		protos = []protocol{protoDoT}
	case string(protoDoH), "https":
		protos = []protocol{protoDoH}
	case "doq", "quic":
		return nil, fmt.Errorf("DoQ (DNS-over-QUIC) 暂未实现 — 请在条件转发规则中改用 UDP / TCP / DoT / DoH")
	default:
		// Unknown token — fall back to the global policy rather
		// than wedging the rule. Logged once per resolve.
		protos = pol.order
	}
	if len(protos) == 0 {
		protos = []protocol{protoUDP, protoTCP}
	}

	ordered := orderUpstreams(upstreams, strategy)

	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		for _, p := range protos {
			for _, addr := range ordered {
				resp, err := dispatchProto(p, r, addr, perAttempt)
				if err == nil && resp != nil {
					return resp, nil
				}
				lastErr = err
			}
		}
	}
	return nil, lastErr
}

// orderUpstreams reorders the upstream list based on the strategy.
func orderUpstreams(upstreams []string, strategy string) []string {
	if len(upstreams) <= 1 {
		return upstreams
	}

	result := make([]string, len(upstreams))
	copy(result, upstreams)

	switch strategy {
	case "random", "随机":
		rand.Shuffle(len(result), func(i, j int) { result[i], result[j] = result[j], result[i] })
	case "round-robin", "轮询":
		idx := int(rrCounter.Add(1)) % len(result)
		// Rotate so that the next server is first
		rotated := make([]string, len(result))
		for i := range result {
			rotated[i] = result[(idx+i)%len(result)]
		}
		return rotated
	// "priority" / "优先级" – keep the original priority order (default)
	default:
		// no reorder
	}
	return result
}

var rrCounter atomic.Int64

// ─── LB group–based forwarding ──────────────────────────────────────────────

// lbPicker holds per-group state used by the dispatch algorithms. The
// previous implementation kept a single global rrIndex shared across
// every group, which meant adding a server to group A would visibly
// shift the rotation in unrelated group B — surprising and hard to
// debug. State is now keyed by group ID so groups are isolated, and
// the SWRR (Smooth Weighted Round Robin) algorithm avoids the
// per-pick allocation that the naive expand-the-weighted-list
// approach incurred on every query.
type lbPicker struct {
	mu sync.Mutex
	// rr tracks the next round-robin index for each group ID.
	rr map[uint]int
	// swrrCurrent tracks per-server "current weight" inside each
	// group for the SWRR algorithm (Nginx-style smooth weighted
	// round robin: each pick increments every server's current by
	// its configured weight, picks the max, and decrements that
	// max by the total weight). Distribution converges to weight
	// ratio without bursty runs of identical picks.
	swrrCurrent map[uint]map[uint]int
}

var globalLBPicker = &lbPicker{
	rr:          make(map[uint]int),
	swrrCurrent: make(map[uint]map[uint]int),
}

// healthyServers filters out disabled / "异常" / "禁用" / never-probed
// rows. We deliberately accept "检测中" — a freshly-added server should
// still receive at least some traffic so its first probe and its first
// real query happen close together (ops gets immediate signal); the
// alternative blackhole until the first probe completes is worse for
// rollouts. If every server is unhealthy we fall back to the original
// list rather than returning empty: returning "" upstream would 503
// the client, while picking a known-bad server at least gives the
// resolver fallback chain a chance.
func healthyServers(servers []model.LbServer) []model.LbServer {
	out := make([]model.LbServer, 0, len(servers))
	for _, s := range servers {
		if !s.Enabled {
			continue
		}
		if s.Status == "异常" || s.Status == "禁用" {
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return servers
	}
	return out
}

// pickServer selects a server address from the LB group data.
func (p *lbPicker) pickServer(g lbGroupData) string {
	servers := healthyServers(g.Servers)
	if len(servers) == 0 {
		return ""
	}

	switch g.Group.Algorithm {
	case "加权轮询":
		return p.weightedRoundRobin(g.Group.ID, servers)
	case "最小延迟":
		return p.leastLatency(servers)
	case "随机":
		return p.randomPick(servers)
	case "IP哈希":
		// Without client IP context here, fall back to plain RR.
		// Real IP-hash dispatch belongs at the serveDNS layer
		// where the ResponseWriter exposes RemoteAddr.
		return p.roundRobin(g.Group.ID, servers)
	default: // "轮询"
		return p.roundRobin(g.Group.ID, servers)
	}
}

func (p *lbPicker) roundRobin(groupID uint, servers []model.LbServer) string {
	p.mu.Lock()
	idx := p.rr[groupID] % len(servers)
	p.rr[groupID] = idx + 1
	p.mu.Unlock()
	s := servers[idx]
	return s.Address + ":" + itoa(s.Port)
}

// weightedRoundRobin picks a server using the smooth-weighted variant
// (a la Nginx). Compared to the original "expand weights into a slice
// and round-robin it" approach this is O(N) per pick with zero
// allocations, and produces a smoother distribution: weights {5, 1, 1}
// yield A,A,B,A,C,A,A instead of A,A,A,A,A,B,C.
func (p *lbPicker) weightedRoundRobin(groupID uint, servers []model.LbServer) string {
	totalWeight := 0
	for _, s := range servers {
		w := s.Weight
		if w <= 0 {
			w = 1
		}
		totalWeight += w
	}
	if totalWeight == 0 {
		return servers[0].Address + ":" + itoa(servers[0].Port)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	cur, ok := p.swrrCurrent[groupID]
	if !ok {
		cur = make(map[uint]int, len(servers))
		p.swrrCurrent[groupID] = cur
	}

	bestIdx := 0
	bestScore := math.MinInt
	// Increment each server's current by its weight; track the max.
	for i, s := range servers {
		w := s.Weight
		if w <= 0 {
			w = 1
		}
		cur[s.ID] += w
		if cur[s.ID] > bestScore {
			bestScore = cur[s.ID]
			bestIdx = i
		}
	}
	// Decrement the winner by total so the others "catch up" next pick.
	cur[servers[bestIdx].ID] -= totalWeight

	s := servers[bestIdx]
	return s.Address + ":" + itoa(s.Port)
}

// leastLatency picks the server with the lowest measured latency,
// ignoring rows that haven't been probed yet (latency == 0). The
// original implementation treated 0 as "infinitely fast", so a
// freshly-added server would always win until its first probe ran.
func (p *lbPicker) leastLatency(servers []model.LbServer) string {
	bestIdx := -1
	bestLatency := math.MaxInt
	for i, s := range servers {
		if s.Latency <= 0 {
			continue // never-probed; skip to avoid divide-by-luck
		}
		if s.Latency < bestLatency {
			bestLatency = s.Latency
			bestIdx = i
		}
	}
	if bestIdx < 0 {
		// Nothing has been probed yet — fall back to first.
		bestIdx = 0
	}
	s := servers[bestIdx]
	return s.Address + ":" + itoa(s.Port)
}

func (p *lbPicker) randomPick(servers []model.LbServer) string {
	s := servers[rand.Intn(len(servers))]
	return s.Address + ":" + itoa(s.Port)
}

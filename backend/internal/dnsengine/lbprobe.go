package dnsengine

import (
	"log"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"

	"github.com/miekg/dns"
)

// lbProbeQuery is the canary used to test reachability of an LB server.
// We query "." NS (root nameservers) with RD=1 because:
//
//  1. Every recursive resolver answers it from cache in <50ms — the
//     root NS RRset is one of the most cached records on the planet.
//  2. RD=1 is required: most public recursive resolvers (119.6.6.6,
//     223.5.5.5, 8.8.8.8, 114.114.114.114, …) silently drop queries
//     with RD=0 because they have nothing authoritative to serve.
//     The original probe used RD=0 against an "*.invalid" name, which
//     manifested as 2 s timeouts on every query and made every server
//     look 异常 even when DNS was perfectly functional.
//  3. The answer is small (a few NS RRs, no DNSSEC chain) so even a
//     bandwidth-constrained probe path fits in one UDP packet.
//
// We accept *any* RCODE (NOERROR / SERVFAIL / REFUSED) as "alive" —
// the goal is to detect "the server speaks DNS" rather than "the
// server resolves correctly", since policy filtering is a different
// concern than reachability.
const lbProbeQuery = "."

// probeConcurrency caps how many servers we probe in parallel inside a
// single tick. The goal isn't max throughput — it's bounding the total
// time a slow group can hold up the loop. With 8 workers and a 2s probe
// timeout, even 64 dead servers finish a tick in ~16s instead of ~128s.
const probeConcurrency = 8

// probeStateCacheTTL is how long we keep the "last persisted state" in
// memory so we can suppress UPDATE statements that would write the
// same row back to MySQL. The TTL is generous because we deliberately
// re-write at least once an hour even on no-op so the row stays
// "warm" for ops queries that filter on updated_at.
const probeStateCacheTTL = 1 * time.Hour

// lbProbeStats holds rolling success accounting per server ID.
type lbProbeStats struct {
	mu      sync.Mutex
	success map[uint]int
	total   map[uint]int
	// last is the last state that was actually persisted to MySQL
	// for each server ID. We compare freshly-probed values against
	// this to skip UPDATE statements when nothing meaningful changed
	// — the original implementation wrote on every tick, which on
	// systems with 4+ unreachable servers showed up as repeated
	// "SLOW SQL >= 1s" warnings against lb_servers under contention.
	last map[uint]lbWriteState
}

type lbWriteState struct {
	status      string
	latency     int64
	successRate float64
	lastError   string
	at          time.Time
}

func newLbProbeStats() *lbProbeStats {
	return &lbProbeStats{
		success: make(map[uint]int),
		total:   make(map[uint]int),
		last:    make(map[uint]lbWriteState),
	}
}

// record updates rolling counts (last 20 probes) and returns the success rate %.
func (s *lbProbeStats) record(id uint, ok bool) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total[id]++
	if ok {
		s.success[id]++
	}
	if s.total[id] > 20 {
		// halve to keep a moving window without unbounded growth
		s.total[id] /= 2
		s.success[id] /= 2
	}
	if s.total[id] == 0 {
		return 0
	}
	return float64(s.success[id]) / float64(s.total[id]) * 100
}

// shouldPersist returns whether the freshly-probed state is meaningfully
// different from what we last wrote — i.e. status/lastError changed,
// success-rate moved by >=1pp, latency moved by >=10ms (jitter window),
// or the cached entry is older than probeStateCacheTTL. The function
// also updates the cache when it returns true so the next call sees
// the new baseline.
func (s *lbProbeStats) shouldPersist(id uint, next lbWriteState) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.last[id]
	if !ok || time.Since(prev.at) > probeStateCacheTTL {
		next.at = time.Now()
		s.last[id] = next
		return true
	}
	if prev.status != next.status || prev.lastError != next.lastError {
		next.at = time.Now()
		s.last[id] = next
		return true
	}
	if math.Abs(prev.successRate-next.successRate) >= 1.0 {
		next.at = prev.at
		next.at = time.Now()
		s.last[id] = next
		return true
	}
	if absInt64(prev.latency-next.latency) >= 10 {
		next.at = time.Now()
		s.last[id] = next
		return true
	}
	return false
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// lbProbeLoop launches one goroutine per LB group, each running on its
// own configured HealthCheckInterval ticker, and reloads the schedule
// whenever groups are added/removed. The previous single-loop design
// applied min(interval) globally and probed every server sequentially,
// so a 5s group + a 60s group + a slow upstream meant the 5s group
// effectively ran at 5+timeout×count cadence. The per-group design
// scales independently and probes within a group concurrently.
func (e *Engine) lbProbeLoop() {
	stats := newLbProbeStats()
	const reloadInterval = 30 * time.Second

	type groupRunner struct {
		cancel chan struct{}
		gen    uint64 // last-seen group fingerprint to detect interval changes
	}
	runners := map[uint]*groupRunner{}
	defer func() {
		for _, r := range runners {
			close(r.cancel)
		}
	}()

	tick := time.NewTicker(reloadInterval)
	defer tick.Stop()

	reload := func() {
		var groups []model.LbGroup
		if err := db.DB.Find(&groups).Error; err != nil {
			// Optional table missing on older deployments — back off
			// silently; the next reload tick retries.
			return
		}

		seen := make(map[uint]struct{}, len(groups))
		for _, g := range groups {
			seen[g.ID] = struct{}{}
			interval := time.Duration(g.HealthCheckInterval) * time.Second
			if interval < 5*time.Second {
				interval = 30 * time.Second
			}
			fp := uint64(interval / time.Second)

			if r, ok := runners[g.ID]; ok && r.gen == fp {
				continue // unchanged
			}
			if r, ok := runners[g.ID]; ok {
				close(r.cancel)
			}
			cancel := make(chan struct{})
			runners[g.ID] = &groupRunner{cancel: cancel, gen: fp}
			go runGroupProbeLoop(g.ID, interval, cancel, e.stopCh, stats)
		}
		// Stop runners for groups that disappeared.
		for id, r := range runners {
			if _, ok := seen[id]; !ok {
				close(r.cancel)
				delete(runners, id)
			}
		}
	}

	reload()
	for {
		select {
		case <-e.stopCh:
			return
		case <-tick.C:
			reload()
		}
	}
}

// runGroupProbeLoop is the per-group scheduler. It probes every enabled
// server in the group on each tick, in parallel up to probeConcurrency.
func runGroupProbeLoop(groupID uint, interval time.Duration, cancel, stopCh chan struct{}, stats *lbProbeStats) {
	t := time.NewTicker(interval)
	defer t.Stop()

	runOnce := func() {
		var servers []model.LbServer
		if err := db.DB.Where("group_id = ? AND enabled = ?", groupID, true).Find(&servers).Error; err != nil {
			return
		}
		probeMany(servers, stats)
	}

	runOnce() // immediate first pass instead of waiting one full interval
	for {
		select {
		case <-stopCh:
			return
		case <-cancel:
			return
		case <-t.C:
			runOnce()
		}
	}
}

// probeMany fans out probes across a worker pool capped at probeConcurrency
// and waits for all of them to finish. Returning serially keeps the caller's
// scheduling simple while still bounding tail latency on slow upstreams.
func probeMany(servers []model.LbServer, stats *lbProbeStats) {
	if len(servers) == 0 {
		return
	}
	workers := probeConcurrency
	if workers > len(servers) {
		workers = len(servers)
	}
	// Buffer the channel so all jobs are enqueued instantly; workers then
	// race to consume them. Without a buffer, each send waits for a worker
	// to be scheduled, which can serialize under high load.
	jobs := make(chan model.LbServer, len(servers))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range jobs {
				probeOne(s, stats)
			}
		}()
	}
	for _, s := range servers {
		jobs <- s
	}
	close(jobs)
	wg.Wait()
}

// ProbeServers runs a one-shot probe of the supplied servers and persists
// the resulting latency / status / success_rate values. Intended to be called
// by the LbHealthCheck HTTP handler when an operator clicks "立即探测".
// Probes are parallelized; the caller blocks until all complete.
func ProbeServers(servers []model.LbServer) {
	stats := newLbProbeStats()
	probeMany(servers, stats)
}

// resolveProbeProto translates the operator-configured per-server
// protocol string ("UDP" / "tcp" / "DoT" / "doh", any case) into the
// internal protocol enum used by dispatchProto. Empty / unknown
// values fall back to UDP — the historical default — so the probe
// loop can never panic on a typo'd row.
func resolveProbeProto(raw string) protocol {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "tcp":
		return protoTCP
	case "dot", "tcp-tls", "tls":
		return protoDoT
	case "doh", "https":
		return protoDoH
	default:
		return protoUDP
	}
}

// probeOne sends a single canary DNS query to the server using its
// configured protocol and persists latency / success-rate / status /
// last-error. Probing matches the actual transport so a DoH-only
// upstream behind a UDP-blocked firewall doesn't spuriously read as
// "healthy" because the historic UDP probe happened to pass.
//
// Persistence is suppressed when nothing changed materially — see
// shouldPersist — so a bank of 数百 stable servers no longer hammers
// MySQL with O(N/tick) writes that show up as SLOW SQL warnings under
// pool contention.
func probeOne(s model.LbServer, stats *lbProbeStats) {
	const probeTimeout = 2 * time.Second

	msg := new(dns.Msg)
	msg.SetQuestion(lbProbeQuery, dns.TypeNS)
	msg.RecursionDesired = true
	// Advertise EDNS0 with a 4096-byte buffer so DoH/DoT upstreams
	// don't downgrade us to TCP for a tiny response. Some servers
	// also use OPT presence as a "real client, not scanner" signal.
	msg.SetEdns0(4096, false)

	// dispatchProto's per-protocol clients each apply their own port
	// default, so we hand them just the host + port from the row
	// rather than coercing into a transport-specific URL up front.
	host := s.Address
	if s.Port > 0 {
		host = net.JoinHostPort(s.Address, strconv.Itoa(s.Port))
	}

	start := time.Now()
	_, err := dispatchProto(resolveProbeProto(s.Protocol), msg, host, probeTimeout)
	latency := time.Since(start).Milliseconds()

	ok := err == nil
	successRate := stats.record(s.ID, ok)

	status := "异常"
	lastError := ""
	if ok {
		status = "健康"
	} else {
		// Truncate to fit last_error VARCHAR(255). Errors carrying
		// full TLS handshake dumps would otherwise overflow the
		// column on MySQL strict mode.
		lastError = err.Error()
		if len(lastError) > 250 {
			lastError = lastError[:250] + "…"
		}
	}

	next := lbWriteState{
		status:      status,
		latency:     latency,
		successRate: successRate,
		lastError:   lastError,
	}
	if !stats.shouldPersist(s.ID, next) {
		return
	}

	updates := map[string]interface{}{
		"status":       status,
		"latency":      latency,
		"success_rate": successRate,
		"last_error":   lastError,
	}
	if err := db.DB.Model(&model.LbServer{}).Where("id = ?", s.ID).Updates(updates).Error; err != nil {
		log.Printf("[lb-probe] failed to update server %d: %v", s.ID, err)
	}
}

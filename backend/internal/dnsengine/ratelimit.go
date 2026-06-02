package dnsengine

import (
	"strings"
	"sync"
	"time"

	"modern-dns/internal/model"
)

// rateLimiter implements per-IP and per-domain token-bucket throttling.
//
// Two scopes are supported:
//   - global: bucket keyed by client IP, cap = DDoSGlobal.QPSLimit, refill = cap tokens/sec
//   - domain: bucket keyed by (clientIP|domain) pair when a DDoSDomainRule matches.
//
// A bucket holds at most `cap` tokens; one token is taken per query.
// The bucket refills proportionally to elapsed time.
type rateLimiter struct {
	mu sync.Mutex

	globalEnabled bool
	globalLimit   int

	// perIPQPS / perIPBurst implement the access-control "每 IP 限流"
	// surge bucket: refill = perIPQPS tokens/sec, cap = perIPBurst.
	// Both must be >0 to engage; this is independent of globalLimit
	// (which is a uniform cap = refill bucket retained for backward
	// compatibility with the existing 全局 QPS slider).
	perIPQPS   int
	perIPBurst int

	// perIPConnLimit caps simultaneous in-flight queries per source
	// IP. 0 disables. Tracked independently from token-bucket QPS so
	// a slow-recursive client that keeps connections open cannot
	// exhaust the engine's goroutine / FD budget without also
	// breaching its QPS quota.
	perIPConnLimit int
	inflight       map[string]int

	// domainLimits holds (lower-case domain → qps limit) for enabled rules.
	domainLimits map[string]int

	// buckets keyed by scope+key:
	//   "g:<ip>"           — legacy per-IP global QPS bucket
	//   "p:<ip>"           — per-IP shaped bucket (qps + burst)
	//   "d:<ip>|<domain>"  — per-IP per-domain bucket
	buckets map[string]*bucket
}

type bucket struct {
	tokens    float64
	cap       float64
	refill    float64 // tokens per second
	updatedAt time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		domainLimits: make(map[string]int),
		buckets:      make(map[string]*bucket),
		inflight:     make(map[string]int),
	}
}

// AcquireConn reserves an in-flight connection slot for clientIP.
// Returns false when perIPConnLimit is already saturated; otherwise
// increments the counter and the caller MUST pair the call with
// ReleaseConn (defer) once the query is done. A 0 limit means
// "unlimited" — we still increment so observability tooling could
// expose the gauge later, but the gate always passes.
func (l *rateLimiter) AcquireConn(clientIP string) bool {
	if clientIP == "" {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cur := l.inflight[clientIP]
	if l.perIPConnLimit > 0 && cur >= l.perIPConnLimit {
		return false
	}
	l.inflight[clientIP] = cur + 1
	return true
}

// ReleaseConn balances an AcquireConn that returned true. Must be
// called exactly once per successful Acquire to avoid leaking the
// inflight gauge upward; an unbalanced release is a no-op below 0
// rather than a panic so a stray defer can't crash the engine.
func (l *rateLimiter) ReleaseConn(clientIP string) {
	if clientIP == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cur := l.inflight[clientIP]
	if cur <= 1 {
		delete(l.inflight, clientIP)
		return
	}
	l.inflight[clientIP] = cur - 1
}

// reload re-compiles rules from DB rows.
func (l *rateLimiter) reload(global model.DDoSGlobal, domainRules []model.DDoSDomainRule) {
	domains := make(map[string]int, len(domainRules))
	for _, r := range domainRules {
		if r.Status != "启用" || r.QPSLimit <= 0 {
			continue
		}
		domains[strings.ToLower(strings.TrimSpace(r.Domain))] = r.QPSLimit
	}

	l.mu.Lock()
	l.globalEnabled = global.Enabled && global.QPSLimit > 0
	l.globalLimit = global.QPSLimit
	l.perIPQPS = global.PerIPQPS
	l.perIPBurst = global.PerIPBurst
	l.perIPConnLimit = global.PerIPConnLimit
	l.domainLimits = domains
	// Wipe stale buckets so new limits take effect immediately.
	// Inflight is intentionally NOT cleared — those counters track
	// real goroutines holding connections right now; resetting would
	// double-credit slots and let a flooder open 2× the cap.
	l.buckets = make(map[string]*bucket)
	l.mu.Unlock()
}

// allow returns (allowed, scope, label).
//   - scope is "global" / "domain" / "" depending on which bucket fired.
//   - label is the matched rule descriptor for query-log diagnostics.
func (l *rateLimiter) allow(clientIP, qName string) (bool, string, string) {
	if clientIP == "" {
		return true, "", ""
	}

	domain := strings.ToLower(strings.TrimSuffix(qName, "."))

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	// Per-domain bucket (most specific first)
	if limit, label := l.matchDomainLimitLocked(domain); limit > 0 {
		key := "d:" + clientIP + "|" + label
		if !takeTokenLocked(l.buckets, key, limit, now) {
			return false, "domain", label
		}
	}

	// Global per-IP bucket (legacy uniform cap = refill).
	if l.globalEnabled {
		key := "g:" + clientIP
		if !takeTokenLocked(l.buckets, key, l.globalLimit, now) {
			return false, "global", "global-qps"
		}
	}

	// Per-IP shaped bucket (访问控制 → 每 IP 限流). Engages only when
	// both knobs are configured nonzero. We check it AFTER the global
	// bucket so a tightly-tuned shaped bucket can deny what the
	// coarser global cap would let through.
	if l.perIPQPS > 0 && l.perIPBurst > 0 {
		key := "p:" + clientIP
		if !takeShapedTokenLocked(l.buckets, key, l.perIPQPS, l.perIPBurst, now) {
			return false, "perip", "per-ip-qps"
		}
	}
	return true, "", ""
}

// matchDomainLimitLocked returns the most specific matching limit (longest suffix).
func (l *rateLimiter) matchDomainLimitLocked(domain string) (int, string) {
	bestLen := -1
	bestLimit := 0
	bestLabel := ""
	for d, limit := range l.domainLimits {
		if d == "" {
			continue
		}
		if domain == d || strings.HasSuffix(domain, "."+d) {
			if len(d) > bestLen {
				bestLen = len(d)
				bestLimit = limit
				bestLabel = d
			}
		}
	}
	return bestLimit, bestLabel
}

// gcStale removes buckets that have not been touched for over 60 seconds.
// Called periodically from the engine's reloadLoop or a dedicated goroutine.
func (l *rateLimiter) gcStale() {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-60 * time.Second)
	for k, b := range l.buckets {
		if b.updatedAt.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}

// takeTokenLocked refills then consumes a single token from the named bucket.
// Caller must hold the limiter mutex.
func takeTokenLocked(buckets map[string]*bucket, key string, limit int, now time.Time) bool {
	b := buckets[key]
	if b == nil {
		b = &bucket{
			tokens:    float64(limit),
			cap:       float64(limit),
			refill:    float64(limit),
			updatedAt: now,
		}
		buckets[key] = b
	} else {
		// In case the limit changed since the bucket was created.
		b.cap = float64(limit)
		b.refill = float64(limit)
		elapsed := now.Sub(b.updatedAt).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * b.refill
			if b.tokens > b.cap {
				b.tokens = b.cap
			}
			b.updatedAt = now
		}
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
}

// takeShapedTokenLocked is takeTokenLocked's asymmetric cousin: cap
// (= burst) and refill (= sustained QPS) decouple, modelling a leaky-
// bucket where a client can spend `burst` tokens immediately but is
// then refilled at `qps` tokens/sec. Used for the per-IP "QPS / 突发
// 桶大小" knobs surfaced on the access-control page.
func takeShapedTokenLocked(buckets map[string]*bucket, key string, qps, burst int, now time.Time) bool {
	b := buckets[key]
	if b == nil {
		b = &bucket{
			tokens:    float64(burst),
			cap:       float64(burst),
			refill:    float64(qps),
			updatedAt: now,
		}
		buckets[key] = b
	} else {
		// Reflect live config changes without forcing a flush.
		b.cap = float64(burst)
		b.refill = float64(qps)
		elapsed := now.Sub(b.updatedAt).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * b.refill
			if b.tokens > b.cap {
				b.tokens = b.cap
			}
			b.updatedAt = now
		}
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
}

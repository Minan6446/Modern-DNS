package dnsengine

import (
	"container/list"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"

	"github.com/miekg/dns"
)

// dnsCache implements a two-tier DNS answer cache:
//   - L1: in-process LRU keyed by "qname|qtype" → packed dns.Msg
//   - L2: Redis hash under "dns:cache:<id>" with TTL, used for cross-instance
//     visibility and powering the "Domain Cache" page.
//
// Both tiers respect the same TTL. Negative answers (NXDOMAIN / empty) use a
// shorter negative TTL governed by the cache strategy.
type dnsCache struct {
	mu       sync.Mutex
	maxSize  int
	items    map[string]*list.Element
	order    *list.List // most-recent at front
	strategy cacheStrategy
}

type cacheEntry struct {
	key       string
	answer    []dns.RR
	rcode     int
	expiresAt time.Time
	source    string // "本地" / "递归解析" / "缓存"
	domain    string
	qtype     string
}

// cacheStrategy is a snapshot of CacheGlobalStrategy + per-domain rules.
type cacheStrategy struct {
	enabled     bool
	ttlMaxSec   int
	negativeTTL int
	domainRules map[string]int // suffix → custom TTL seconds
	autoCleanup bool
}

func newDNSCache(maxSize int) *dnsCache {
	if maxSize <= 0 {
		maxSize = 4096
	}
	return &dnsCache{
		maxSize: maxSize,
		items:   make(map[string]*list.Element),
		order:   list.New(),
	}
}

// reload re-snapshots the strategy from the DB models.
func (c *dnsCache) reload(global model.CacheGlobalStrategy, rules []model.CacheDomainRule) {
	domains := make(map[string]int, len(rules))
	for _, r := range rules {
		if r.Status != "启用" || r.CustomTTL <= 0 {
			continue
		}
		domains[strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Domain), "."))] = r.CustomTTL
	}
	negTTL := global.MinRetain
	if negTTL <= 0 {
		negTTL = 60
	}
	ttlMax := global.TTLMax
	if ttlMax <= 0 {
		ttlMax = 3600
	}

	c.mu.Lock()
	c.strategy = cacheStrategy{
		enabled:     true, // engine-driven; UI toggles via per-domain rule status
		ttlMaxSec:   ttlMax,
		negativeTTL: negTTL,
		domainRules: domains,
		autoCleanup: global.AutoCleanup,
	}
	c.mu.Unlock()
}

// cacheKey builds the lookup key from query name + qtype.
func cacheKey(qName string, qType uint16) string {
	return strings.ToLower(strings.TrimSuffix(qName, ".")) + "|" + dns.TypeToString[qType]
}

// lookup returns a cached message ready to be served, if not expired.
func (c *dnsCache) lookup(qName string, qType uint16) (*dns.Msg, bool) {
	key := cacheKey(qName, qType)

	c.mu.Lock()
	el, ok := c.items[key]
	if !ok {
		c.mu.Unlock()
		return nil, false
	}
	entry := el.Value.(*cacheEntry)
	if time.Now().After(entry.expiresAt) {
		c.order.Remove(el)
		delete(c.items, key)
		c.mu.Unlock()
		return nil, false
	}
	c.order.MoveToFront(el)
	rrs := append([]dns.RR(nil), entry.answer...)
	rcode := entry.rcode
	c.mu.Unlock()

	resp := new(dns.Msg)
	resp.Answer = rrs
	resp.Rcode = rcode
	return resp, true
}

// store inserts an answer into both LRU and Redis. Returns the chosen TTL.
func (c *dnsCache) store(qName string, qType uint16, answer []dns.RR, rcode int, source string) int {
	key := cacheKey(qName, qType)
	domain := strings.ToLower(strings.TrimSuffix(qName, "."))
	qtypeStr := dns.TypeToString[qType]
	if qtypeStr == "" {
		qtypeStr = fmt.Sprintf("TYPE%d", qType)
	}

	c.mu.Lock()
	strat := c.strategy
	c.mu.Unlock()

	ttl := computeTTL(answer, rcode, strat, domain)
	if ttl <= 0 {
		return 0
	}

	entry := &cacheEntry{
		key:       key,
		answer:    append([]dns.RR(nil), answer...),
		rcode:     rcode,
		expiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
		source:    source,
		domain:    domain,
		qtype:     qtypeStr,
	}

	c.mu.Lock()
	if el, ok := c.items[key]; ok {
		el.Value = entry
		c.order.MoveToFront(el)
	} else {
		el := c.order.PushFront(entry)
		c.items[key] = el
		// evict
		for c.order.Len() > c.maxSize {
			oldest := c.order.Back()
			if oldest == nil {
				break
			}
			c.order.Remove(oldest)
			delete(c.items, oldest.Value.(*cacheEntry).key)
		}
	}
	c.mu.Unlock()

	go writeCacheToRedis(entry, ttl)
	return ttl
}

// purge removes a single key (used after explicit cache clear from UI).
func (c *dnsCache) purge(qName string, qType uint16) {
	key := cacheKey(qName, qType)
	c.mu.Lock()
	if el, ok := c.items[key]; ok {
		c.order.Remove(el)
		delete(c.items, key)
	}
	c.mu.Unlock()
}

// computeTTL chooses the cache lifetime based on strategy defaults and
// per-domain overrides.
//
// Negative-cache policy (per RFC 2308 + practical hardening):
//   - NXDOMAIN  → cache for negativeTTL.  Authoritative "doesn't exist" is
//     stable, caching it cuts useless upstream traffic.
//   - NODATA    → cache for negativeTTL.  Same reasoning.
//   - REFUSED   → DO NOT cache. REFUSED means "this upstream is unwilling to
//     answer you right now" — almost always a transient policy /
//     ACL / rate-limit issue. Caching it would freeze a flap into
//     a 60s outage for every client. Each query gets a fresh try
//     (which may pick a different upstream via LB / strategy).
//   - SERVFAIL  → DO NOT cache. Indicates upstream malfunction; same reasoning
//     as REFUSED. Some recursive resolvers do micro-cache SERVFAIL
//     (5s) to dampen storms — we trade that resilience knob for
//     the much more common operator pain of "my DNS is down for
//     a minute every time an upstream hiccups."
//   - any other non-Success rcode (NOTIMP, FORMERR, …) → don't cache; rare
//     enough that aggressive retry is the safer default.
func computeTTL(answer []dns.RR, rcode int, strat cacheStrategy, domain string) int {
	switch rcode {
	case dns.RcodeRefused, dns.RcodeServerFailure:
		return 0
	case dns.RcodeNameError:
		return strat.negativeTTL
	case dns.RcodeSuccess:
		if len(answer) == 0 {
			return strat.negativeTTL
		}
		// fall through to the positive-TTL path below
	default:
		return 0
	}
	// Take the smallest RR TTL as the upper bound (RFC 1035)
	rrTTL := int(^uint32(0) >> 1)
	for _, rr := range answer {
		if t := int(rr.Header().Ttl); t > 0 && t < rrTTL {
			rrTTL = t
		}
	}
	if rrTTL == int(^uint32(0)>>1) {
		rrTTL = 300
	}
	// Per-domain override (longest suffix wins)
	bestLen := -1
	bestTTL := 0
	for d, t := range strat.domainRules {
		if d == "" {
			continue
		}
		if domain == d || strings.HasSuffix(domain, "."+d) {
			if len(d) > bestLen {
				bestLen = len(d)
				bestTTL = t
			}
		}
	}
	if bestTTL > 0 {
		return bestTTL
	}
	// Global cache TTL is the operator-selected baseline TTL for positive
	// records. We keep RR parsing above for compatibility fallback only.
	if strat.ttlMaxSec > 0 {
		return strat.ttlMaxSec
	}
	return rrTTL
}

// writeCacheToRedis persists a compact view of the entry for the cache page.
func writeCacheToRedis(entry *cacheEntry, ttl int) {
	if db.RDBCache == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	key := "dns:cache:" + shortHash(entry.key)
	value := ""
	if len(entry.answer) > 0 {
		// First answer's RR rendered without the leading "name TTL IN type "
		parts := strings.SplitN(entry.answer[0].String(), "\t", 5)
		if len(parts) == 5 {
			value = parts[4]
		} else {
			value = entry.answer[0].String()
		}
	} else {
		value = dns.RcodeToString[entry.rcode]
	}

	_ = db.RDBCache.HSet(ctx, key, map[string]interface{}{
		"domain":      entry.domain,
		"recordType":  entry.qtype,
		"recordValue": value,
		"source":      entry.source,
		"cacheTime":   time.Now().Format("2006-01-02 15:04:05"),
		"ttlOriginal": ttl,
	}).Err()
	_ = db.RDBCache.Expire(ctx, key, time.Duration(ttl)*time.Second).Err()
}

func shortHash(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:8])
}

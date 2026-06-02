package dnsengine

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"

	"github.com/miekg/dns"
)

// ── Package-level singleton for handler-side reload triggers ──────────────────

var (
	gEngineMu sync.RWMutex
	gEngine   *Engine
)

// Trigger requests an immediate config reload of the running engine.
// Safe to call from HTTP handlers; no-op if the engine is not started.
func Trigger() {
	gEngineMu.RLock()
	e := gEngine
	gEngineMu.RUnlock()
	if e != nil {
		e.Reload()
	}
}

// SetPolicyBypassFor temporarily disables BW / RPZ / DDoS enforcement for the
// supplied duration (cluster spec: TemporaryDisableBlockingAsync). After the
// timer fires, the bypass clears automatically. Calling again resets the
// expiry to the new value.
//
// Safe to call from HTTP handlers; no-op if the engine is not started.
func SetPolicyBypassFor(d time.Duration) {
	gEngineMu.RLock()
	e := gEngine
	gEngineMu.RUnlock()
	if e == nil {
		return
	}
	until := time.Now().Add(d).UnixNano()
	e.policyBypassUntil.Store(until)
}

// PolicyBypassActive reports whether the engine is currently in
// "temporary disable blocking" mode.
func (e *Engine) PolicyBypassActive() bool {
	until := e.policyBypassUntil.Load()
	if until == 0 {
		return false
	}
	if time.Now().UnixNano() >= until {
		e.policyBypassUntil.Store(0)
		return false
	}
	return true
}

// MetricsSnapshot exposes counters for dashboard reporting.
type MetricsSnapshot struct {
	Queries     int64 `json:"queries"`
	Blocked     int64 `json:"blocked"`
	RateLimited int64 `json:"rateLimited"`
	CacheHits   int64 `json:"cacheHits"`
	Forwarded   int64 `json:"forwarded"`
	LocalHits   int64 `json:"localHits"`
	// PaddingApplied counts queries / responses that received an
	// EDNS0 Padding option (RFC 7830). Inbound = padding added to
	// the response we send back to clients; Outbound = padding
	// added to the query we send to a DoH/DoT upstream. Counted
	// separately because the operator can enable padding without
	// having any encrypted-channel upstreams (so Outbound stays 0)
	// and vice-versa during phased rollouts.
	PaddingInbound  int64 `json:"paddingInbound"`
	PaddingOutbound int64 `json:"paddingOutbound"`
}

// Snapshot returns the current engine metrics.
func Snapshot() MetricsSnapshot {
	gEngineMu.RLock()
	e := gEngine
	gEngineMu.RUnlock()
	if e == nil {
		return MetricsSnapshot{}
	}
	return MetricsSnapshot{
		Queries:         e.metricQueries.Load(),
		Blocked:         e.metricBlocked.Load(),
		RateLimited:     e.metricRateLimited.Load(),
		CacheHits:       e.metricCacheHits.Load(),
		Forwarded:       e.metricForwarded.Load(),
		LocalHits:       e.metricLocalHits.Load(),
		PaddingInbound:  paddingInboundMetric.Load(),
		PaddingOutbound: paddingOutboundMetric.Load(),
	}
}

// Padding counters live as package-level atomics because the apply
// functions are pkg-level (not Engine methods) and we want them to
// keep working in unit tests that stand up no Engine. The Snapshot
// function above pulls them into the per-Engine MetricsSnapshot for
// dashboard reporting.
var (
	paddingInboundMetric  atomic.Int64
	paddingOutboundMetric atomic.Int64
)

// Engine is the core DNS server that listens on UDP+TCP and delegates
// resolution through the pipeline:
//  1. Local zone lookup (authoritative records from DB)
//  2. Conditional forwarding (domain-match rules → specific upstream)
//  3. Global forwarding (fallback to configured upstream servers)
type Engine struct {
	cfg EngineConfig

	udpServer *dns.Server
	tcpServer *dns.Server
	dotServer *dns.Server  // DNS-over-TLS (port 853)
	dohServer *http.Server // DNS-over-HTTPS (port 443)

	// cached config – refreshed periodically
	mu        sync.RWMutex
	globalCfg model.ForwardGlobal
	servers   []model.ForwardServer
	rules     []model.ForwardRule
	zones     []zoneData
	lbGroups  []lbGroupData
	policy    PolicySet
	limiter   *rateLimiter
	cache     *dnsCache
	// forwarderMap was removed in 2026-05 alongside the per-upstream
	// Forwarder struct. The new dispatch path (proto_clients.go) is
	// stateless — each query opens a transient client because the
	// per-attempt budget (UpstreamTimeoutMs) is much shorter than
	// the cost of cache eviction would amortise away.

	lbLoadErrLogged bool

	// reload coordination
	reloadCh chan struct{}

	// runtime metrics (atomics, no lock required)
	metricQueries     atomic.Int64
	metricBlocked     atomic.Int64
	metricRateLimited atomic.Int64
	metricCacheHits   atomic.Int64
	metricForwarded   atomic.Int64
	metricLocalHits   atomic.Int64

	// temporary policy-bypass deadline (UnixNano); 0 means not active
	policyBypassUntil atomic.Int64

	// RPZ hit aggregation buffer. Query path only appends counters in-memory,
	// and a background flusher periodically batches DB writes.
	rpzHitMu     sync.Mutex
	rpzHitDeltas map[uint]int64

	stopOnce sync.Once
	stopCh   chan struct{}
}

// EngineConfig carries all DNS-related configuration from config.yaml.
type EngineConfig struct {
	ListenAddr string
	DoTPort    string // e.g. "853"
	DoHPort    string // e.g. "443"
	CertFile   string // TLS cert PEM path (shared DoT+DoH)
	KeyFile    string // TLS key  PEM path
}

type zoneData struct {
	Zone    model.Zone
	Records []model.DNSRecord
	DNSSEC  *zoneDNSSEC // nil when DNSSEC not enabled for this zone
	// Options is the compiled per-zone access-control view. nil
	// means the zone has no zone_options row (the legacy default
	// for every freshly-created or pre-feature zone) — gate*
	// helpers treat that as "allow queries, deny transfer".
	Options *zoneOptions
}

type lbGroupData struct {
	Group   model.LbGroup
	Servers []model.LbServer
}

// New creates a new DNS engine.
func New(cfg EngineConfig) *Engine {
	return &Engine{
		cfg:          cfg,
		limiter:      newRateLimiter(),
		cache:        newDNSCache(8192),
		reloadCh:     make(chan struct{}, 1),
		rpzHitDeltas: make(map[uint]int64),
		stopCh:       make(chan struct{}),
	}
}

// Start launches the DNS server on UDP and TCP, and begins periodic config reload.
func (e *Engine) Start() error {
	e.reloadConfig()
	go e.reloadLoop()
	go e.lbProbeLoop()
	go e.rpzHitFlushLoop()

	gEngineMu.Lock()
	gEngine = e
	gEngineMu.Unlock()

	handler := dns.HandlerFunc(e.serveDNS)

	e.udpServer = &dns.Server{
		Addr:    e.cfg.ListenAddr,
		Net:     "udp",
		Handler: handler,
	}
	e.tcpServer = &dns.Server{
		Addr:    e.cfg.ListenAddr,
		Net:     "tcp",
		Handler: handler,
	}

	errCh := make(chan error, 2)
	go func() {
		log.Printf("[dns-engine] UDP listening on %s", e.cfg.ListenAddr)
		if err := e.udpServer.ListenAndServe(); err != nil {
			errCh <- fmt.Errorf("udp: %w", err)
		}
	}()
	go func() {
		log.Printf("[dns-engine] TCP listening on %s", e.cfg.ListenAddr)
		if err := e.tcpServer.ListenAndServe(); err != nil {
			errCh <- fmt.Errorf("tcp: %w", err)
		}
	}()

	// ── DoT (DNS-over-TLS, port 853) ──
	if e.cfg.CertFile != "" && e.cfg.KeyFile != "" && e.cfg.DoTPort != "" {
		e.startDoT(handler)
	}

	// ── DoH (DNS-over-HTTPS, port 443) ──
	if e.cfg.CertFile != "" && e.cfg.KeyFile != "" && e.cfg.DoHPort != "" {
		e.startDoH()
	}

	// Wait a tiny bit to catch immediate bind errors
	select {
	case err := <-errCh:
		return err
	case <-time.After(200 * time.Millisecond):
		return nil
	}
}

// Stop gracefully shuts down all servers.
func (e *Engine) Stop() {
	e.stopOnce.Do(func() {
		close(e.stopCh)
		e.flushRPZHitDeltas()
		if e.udpServer != nil {
			e.udpServer.Shutdown()
		}
		if e.tcpServer != nil {
			e.tcpServer.Shutdown()
		}
		if e.dotServer != nil {
			e.dotServer.Shutdown()
		}
		if e.dohServer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			e.dohServer.Shutdown(ctx)
		}
		gEngineMu.Lock()
		if gEngine == e {
			gEngine = nil
		}
		gEngineMu.Unlock()
	})
}

// ── DoT startup ──────────────────────────────────────────────────────────────

func (e *Engine) startDoT(handler dns.Handler) {
	cert, err := tls.LoadX509KeyPair(e.cfg.CertFile, e.cfg.KeyFile)
	if err != nil {
		log.Printf("[dns-engine] DoT: load TLS cert failed: %v (skipping)", err)
		return
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	addr := ":" + e.cfg.DoTPort
	e.dotServer = &dns.Server{
		Addr:      addr,
		Net:       "tcp-tls",
		TLSConfig: tlsCfg,
		Handler:   handler,
	}

	go func() {
		log.Printf("[dns-engine] DoT listening on %s", addr)
		if err := e.dotServer.ListenAndServe(); err != nil {
			log.Printf("[dns-engine] DoT stopped: %v", err)
		}
	}()
}

// ── DoH startup ──────────────────────────────────────────────────────────────

func (e *Engine) startDoH() {
	cert, err := tls.LoadX509KeyPair(e.cfg.CertFile, e.cfg.KeyFile)
	if err != nil {
		log.Printf("[dns-engine] DoH: load TLS cert failed: %v (skipping)", err)
		return
	}

	addr := ":" + e.cfg.DoHPort
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", e.handleDoH)

	e.dohServer = &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("[dns-engine] DoH listening on %s", addr)
		if err := e.dohServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("[dns-engine] DoH stopped: %v", err)
		}
	}()
}

// Reload coalesces an asynchronous config reload request.
// Multiple calls within a short window collapse into a single reload, so
// handlers can call Reload() liberally on every CRUD without flooding the DB.
func (e *Engine) Reload() {
	select {
	case e.reloadCh <- struct{}{}:
	default:
	}
}

// reloadLoop periodically reloads config from database, and also responds to
// asynchronous Reload() requests from handlers.
func (e *Engine) reloadLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			e.reloadConfig()
		case <-e.reloadCh:
			e.reloadConfig()
		case <-e.stopCh:
			return
		}
	}
}

// reloadConfig fetches all forwarding configuration from the database.
// Errors on individual queries are logged once and do not block other sections.
func (e *Engine) reloadConfig() {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Global forward config (reset struct to avoid duplicate WHERE from previous ID)
	e.globalCfg = model.ForwardGlobal{}
	db.DB.FirstOrCreate(&e.globalCfg, model.ForwardGlobal{ID: 1})

	// Forward servers (ordered by priority)
	db.DB.Order("priority").Where("status = ?", "启用").Find(&e.servers)

	// Conditional forward rules (ordered by priority, enabled only)
	db.DB.Order("priority").Where("status = ?", "启用").Find(&e.rules)

	// Local zones + records (single SQL for all records, then group in memory)
	//
	// Status filter is defensive: historically CreateZone wrote "正常"
	// while every other table uses "启用", which caused every freshly
	// created zone to be invisible to the resolver. The handler bug
	// has been fixed, but existing databases still contain "正常" rows
	// that would silently stop resolving after an upgrade. Treating
	// anything other than the explicit "禁用" sentinel as enabled keeps
	// those legacy zones working without forcing a manual DB migration.
	var zones []model.Zone
	db.DB.Where("status IS NULL OR status <> ?", "禁用").Find(&zones)
	e.zones = make([]zoneData, 0, len(zones))
	if len(zones) > 0 {
		zoneIDs := make([]uint, 0, len(zones))
		for _, z := range zones {
			zoneIDs = append(zoneIDs, z.ID)
		}
		var allRecords []model.DNSRecord
		db.DB.Where("zone_id IN ? AND status = ?", zoneIDs, "启用").Find(&allRecords)
		recordsByZone := make(map[uint][]model.DNSRecord, len(zones))
		for _, r := range allRecords {
			recordsByZone[r.ZoneID] = append(recordsByZone[r.ZoneID], r)
		}

		// DNSSEC keys per zone
		var allDNSSECKeys []model.ZoneDNSSECKey
		db.DB.Where("zone_id IN ? AND status = ?", zoneIDs, "生效中").Find(&allDNSSECKeys)
		keysByZone := make(map[uint][]model.ZoneDNSSECKey, len(zones))
		for _, k := range allDNSSECKeys {
			keysByZone[k.ZoneID] = append(keysByZone[k.ZoneID], k)
		}

		// Per-zone options (query / transfer ACLs). Load all rows in
		// a single SELECT; zones without a row keep zd.Options = nil
		// and inherit the legacy default in the gate helpers.
		var allOpts []model.ZoneOptions
		db.DB.Where("zone_id IN ?", zoneIDs).Find(&allOpts)
		optsByZone := make(map[uint]*zoneOptions, len(allOpts))
		for i := range allOpts {
			optsByZone[allOpts[i].ZoneID] = compileZoneOptions(&allOpts[i])
		}

		for _, z := range zones {
			zd := zoneData{Zone: z, Records: recordsByZone[z.ID], Options: optsByZone[z.ID]}
			if keys := keysByZone[z.ID]; len(keys) > 0 {
				sec := &zoneDNSSEC{}
				for _, k := range keys {
					kp := parseDNSKEY(k.DNSKEYText, k.PrivateKey)
					if kp == nil {
						continue
					}
					sec.DNSKEYRRs = append(sec.DNSKEYRRs, kp.DNSKEY)
					switch strings.ToUpper(k.KeyType) {
					case "KSK":
						sec.KSK = append(sec.KSK, kp)
					case "ZSK":
						sec.ZSK = append(sec.ZSK, kp)
					}
				}
				if len(sec.KSK) > 0 || len(sec.ZSK) > 0 {
					zd.DNSSEC = sec
				}
			}
			e.zones = append(e.zones, zd)
		}
	}

	// LB groups + servers (optional tables, tolerate missing)
	var lbGroups []model.LbGroup
	if err := db.DB.Where("status = ?", "启用").Find(&lbGroups).Error; err == nil {
		e.lbLoadErrLogged = false
		e.lbGroups = make([]lbGroupData, 0, len(lbGroups))
		for _, g := range lbGroups {
			var servers []model.LbServer
			db.DB.Where("group_id = ? AND enabled = ?", g.ID, true).Find(&servers)
			e.lbGroups = append(e.lbGroups, lbGroupData{Group: g, Servers: servers})
		}
	} else if !e.lbLoadErrLogged {
		log.Printf("[dns-engine] skipping lb_groups: %v", err)
		e.lbLoadErrLogged = true
	}

	// Security policies: ACL + BW + RPZ
	var aclRules []model.AclRule
	db.DB.Find(&aclRules)
	var bwRules []model.BWRule
	db.DB.Find(&bwRules)
	var rpzRules []model.RpzRule
	db.DB.Find(&rpzRules)
	e.policy = PolicySet{
		acl: compileAclRules(aclRules),
		bw:  compileBWRules(bwRules),
		rpz: compileRpzRules(rpzRules),
	}

	// DDoS rate limits
	var ddosGlobal model.DDoSGlobal
	db.DB.FirstOrCreate(&ddosGlobal, model.DDoSGlobal{ID: 1})
	var ddosDomain []model.DDoSDomainRule
	db.DB.Find(&ddosDomain)
	e.limiter.reload(ddosGlobal, ddosDomain)

	// Apply Go-runtime memory hard cap so a flood-driven cache /
	// connection-table bloat triggers GC pressure long before the
	// host OOM-kills us. SetMemoryLimit is a soft target — Go will
	// shed allocation throughput as it approaches it. 0 means "off"
	// per debug.SetMemoryLimit's own contract; we forward that
	// directly so operators can disable the cap without code change.
	if ddosGlobal.MemHardMB > 0 {
		debug.SetMemoryLimit(int64(ddosGlobal.MemHardMB) * 1024 * 1024)
	} else {
		debug.SetMemoryLimit(-1)
	}

	// Cache strategy
	var cacheGlobal model.CacheGlobalStrategy
	db.DB.FirstOrCreate(&cacheGlobal, model.CacheGlobalStrategy{ID: 1})
	var cacheRules []model.CacheDomainRule
	db.DB.Find(&cacheRules)
	e.cache.reload(cacheGlobal, cacheRules)

	// Housekeeping: remove stale rate-limiter buckets to prevent memory leak
	if e.limiter != nil {
		e.limiter.gcStale()
	}
}

// serveDNS is the main handler invoked for every incoming DNS query.
func (e *Engine) serveDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	q := r.Question[0]
	qName := strings.ToLower(q.Name)
	start := time.Now()
	e.metricQueries.Add(1)

	// ── Pre-pipeline: zone transfer (AXFR / IXFR) ──
	// Transfer is gated separately from the regular query path: it
	// has its own ACL (zone_options.transfer_acl), a different
	// safe-default (deny on no row), and a wholly different reply
	// shape (multi-RR envelope vs single answer). Handle it in a
	// dedicated path before any other policy / cache / forward
	// machinery runs, so an AXFR never accidentally hits the
	// upstream forwarders or the L1 cache.
	if q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR {
		e.handleZoneTransfer(w, r)
		return
	}

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = false
	msg.RecursionAvailable = true

	var rcode int
	var status string
	var answered bool
	var bypassPolicy bool
	var rpzHitRuleID uint

	clientIP := remoteClientIP(w.RemoteAddr())

	// ── Pipeline Step 0a: ACL (source IP / CIDR allow-deny) ──
	e.mu.RLock()
	policy := e.policy
	limiter := e.limiter
	cache := e.cache
	e.mu.RUnlock()

	// ── Pipeline Step 0: Per-IP connection cap ──
	// Gate before any policy evaluation so a flooder cannot burn CPU
	// on ACL/BW/RPZ regex evaluation while already over its concurrent-
	// query budget. Refused queries are still query-logged (the deferred
	// writeQueryLog at the end of this function captures status), so
	// operators can spot saturating clients in audit. Acquire is a
	// no-op when the operator has not configured a limit.
	clientIPStr := ""
	if clientIP != nil {
		clientIPStr = clientIP.String()
	}
	if limiter != nil {
		if !limiter.AcquireConn(clientIPStr) {
			msg.Rcode = dns.RcodeRefused
			rcode = dns.RcodeRefused
			status = "CONN_LIMITED"
			answered = true
			e.metricRateLimited.Add(1)
		} else {
			defer limiter.ReleaseConn(clientIPStr)
		}
	}

	// Cluster-wide temporary disable: skip ACL/BW/RPZ/limit but still resolve.
	if e.PolicyBypassActive() {
		bypassPolicy = true
	}

	if !bypassPolicy {
		if res := policy.evaluateACL(qName, q.Qtype, clientIP); res.Decision != PolicyPass {
			switch res.Decision {
			case PolicyAllow:
				bypassPolicy = true
			case PolicyBlock:
				msg.Rcode = res.BlockRcode
				rcode = res.BlockRcode
				status = "BLOCKED"
				answered = true
				e.metricBlocked.Add(1)
			}
		}
	}

	// ── Pipeline Step 0b: BW (white-list bypass / black-list block) ──
	if !answered && !bypassPolicy {
		if res := policy.evaluateBW(qName, clientIP); res.Decision != PolicyPass {
			switch res.Decision {
			case PolicyAllow:
				bypassPolicy = true
			case PolicyBlock:
				msg.Rcode = res.BlockRcode
				rcode = res.BlockRcode
				status = "BLOCKED"
				answered = true
				e.metricBlocked.Add(1)
			}
		}
	}

	// ── Pipeline Step 1: RPZ (block / redirect / passthru) ──
	if !answered && !bypassPolicy {
		if res := policy.evaluateRPZ(qName); res.Decision != PolicyPass {
			if res.RuleID > 0 {
				rpzHitRuleID = res.RuleID
			}
			switch res.Decision {
			case PolicyAllow:
				bypassPolicy = true
			case PolicyBlock:
				msg.Rcode = res.BlockRcode
				rcode = res.BlockRcode
				status = "BLOCKED"
				answered = true
				e.metricBlocked.Add(1)
			case PolicyRedirect:
				if rrs := buildRedirectAnswer(qName, q.Qtype, res.RedirectTo, 60); len(rrs) > 0 {
					msg.Authoritative = true
					msg.Answer = rrs
					rcode = dns.RcodeSuccess
					status = "REDIRECT"
					answered = true
					e.metricBlocked.Add(1)
				} else {
					msg.Rcode = dns.RcodeNameError
					rcode = dns.RcodeNameError
					status = "BLOCKED"
					answered = true
					e.metricBlocked.Add(1)
				}
			}
		}
	}

	// ── Pipeline Step 2: DDoS rate limit ──
	if !answered && !bypassPolicy && limiter != nil {
		if allowed, _, _ := limiter.allow(clientIP.String(), qName); !allowed {
			msg.Rcode = dns.RcodeRefused
			rcode = dns.RcodeRefused
			status = "RATE_LIMITED"
			answered = true
			e.metricRateLimited.Add(1)
		}
	}

	// ── Pipeline Step 2.5: Cache lookup (skip on white-list bypass to avoid stale) ──
	if !answered && cache != nil {
		if cached, ok := cache.lookup(qName, q.Qtype); ok {
			msg.Answer = cached.Answer
			msg.Rcode = cached.Rcode
			rcode = cached.Rcode
			status = "CACHED"
			answered = true
			e.metricCacheHits.Add(1)
		}
	}

	// ── Pipeline Step 3: Local Zone Lookup ──
	if !answered {
		e.mu.RLock()
		// Per-zone query ACL: refuse before resolving when the
		// matched zone has a non-allow query mode and the source
		// IP doesn't satisfy it. We REFUSED rather than NXDOMAIN
		// so the client doesn't cache a negative result and can
		// retry once the operator widens the ACL.
		zoneForGate := e.findMatchingZone(qName)
		queryAllowed := gateQuery(zoneForGate, clientIP)
		var localAnswer []dns.RR
		var found bool
		var matchedZone *zoneData
		if queryAllowed {
			localAnswer, found, matchedZone = e.resolveLocalWithZone(qName, q.Qtype)
		}
		e.mu.RUnlock()

		if !queryAllowed {
			msg.Authoritative = true
			msg.Rcode = dns.RcodeRefused
			rcode = dns.RcodeRefused
			status = "REFUSED"
			answered = true
			e.metricBlocked.Add(1)
		}

		if found {
			msg.Authoritative = true
			msg.Answer = localAnswer
			answered = true
			rcode = dns.RcodeSuccess
			status = "成功"
			e.metricLocalHits.Add(1)

			// DNSSEC: sign the answer RR set with ZSK when zone has keys
			// and the client indicated DNSSEC-OK (DO bit).
			wantDNSSEC := r.IsEdns0() != nil && r.IsEdns0().Do()
			if wantDNSSEC && matchedZone != nil && matchedZone.DNSSEC != nil {
				sec := matchedZone.DNSSEC
				if q.Qtype == dns.TypeDNSKEY {
					// Return DNSKEY RRs signed by KSK
					msg.Answer = append(msg.Answer, sec.DNSKEYRRs...)
					if len(sec.KSK) > 0 {
						if rrsig := signDNSKEYSet(sec.DNSKEYRRs, matchedZone.Zone.Domain, sec.KSK[0]); rrsig != nil {
							msg.Answer = append(msg.Answer, rrsig)
						}
					}
				} else if len(localAnswer) > 0 && len(sec.ZSK) > 0 {
					// Sign data RRset with ZSK
					if rrsig := signRRSet(localAnswer, matchedZone.Zone.Domain, sec.ZSK[0]); rrsig != nil {
						msg.Answer = append(msg.Answer, rrsig)
					}
				}
				// Set EDNS0 in response with DO bit
				e.ensureEDNS0(msg)
			}
		}
	}

	// ── Pipeline Step 3.5: Private-range reverse short-circuit ──
	// PTR queries for RFC 1918 / link-local / loopback / ULA blocks
	// that nobody answered locally are responded with NXDOMAIN right
	// here, instead of being relayed to public resolvers (which would
	// either drop them or eventually SERVFAIL — exactly the source
	// of the multi-second nslookup hang on first contact).
	//
	// Authoritative bit is set so caching resolvers along the way
	// trust the answer; we also cache it ourselves with the existing
	// negative-TTL machinery so subsequent identical queries are
	// served from L1 without re-running this check.
	if !answered && q.Qtype == dns.TypePTR && isPrivateReverseName(qName) {
		msg.Authoritative = true
		msg.Rcode = dns.RcodeNameError
		rcode = dns.RcodeNameError
		status = "NXDOMAIN"
		answered = true
		e.metricLocalHits.Add(1)
		if cache != nil && !bypassPolicy {
			cache.store(qName, q.Qtype, nil, dns.RcodeNameError, "本地")
		}
	}

	// ── Pipeline Step 4: Conditional Forwarding ──
	if !answered {
		e.mu.RLock()
		condUpstream, condProto := e.matchConditionRule(qName)
		e.mu.RUnlock()

		if condUpstream != "" {
			// ECS is best-effort: when disabled or the source IP isn't
			// eligible (private / loopback) injectECS returns r unchanged,
			// so the no-op path is allocation-free.
			fwdReq := injectECS(r, clientIP)
			// condProto, when non-empty, pins the wire protocol the
			// operator picked for this rule (UDP / TCP / DoT / DoH /
			// DoQ). Empty falls back to the global UpstreamProtocolOrder.
			resp, err := e.forwardWith(fwdReq, []string{condUpstream}, condProto)
			if err == nil && resp != nil {
				msg = resp
				msg.Id = r.Id
				answered = true
				rcode = resp.Rcode
				status = rcodeToStatus(rcode)
				e.metricForwarded.Add(1)
				if cache != nil && !bypassPolicy {
					cache.store(qName, q.Qtype, resp.Answer, resp.Rcode, "递归解析")
				}
			}
		}
	}

	// ── Pipeline Step 5: Global Forwarding ──
	if !answered {
		e.mu.RLock()
		enabled := e.globalCfg.Enabled
		// LbGroupID, when set on the global config, takes precedence
		// over the flat ForwardServer list — pick a single address
		// from the group's algorithm and forward to it. This is the
		// only call path that actually exercises the LB page's
		// algorithm/health-check work for "default" traffic; the
		// flat list path stays as the legacy / fallback shape.
		var upstreams []string
		if e.globalCfg.LbGroupID != nil && *e.globalCfg.LbGroupID > 0 {
			if addr := e.pickLbGroupAddr(*e.globalCfg.LbGroupID); addr != "" {
				upstreams = []string{addr}
			}
		}
		if len(upstreams) == 0 {
			upstreams = e.getGlobalUpstreams()
		}
		e.mu.RUnlock()

		if enabled && len(upstreams) > 0 {
			fwdReq := injectECS(r, clientIP)
			resp, err := e.forward(fwdReq, upstreams)
			if err == nil && resp != nil {
				msg = resp
				msg.Id = r.Id
				answered = true
				rcode = resp.Rcode
				status = rcodeToStatus(rcode)
				e.metricForwarded.Add(1)
				if cache != nil && !bypassPolicy {
					cache.store(qName, q.Qtype, resp.Answer, resp.Rcode, "递归解析")
				}
			}
		}
	}

	if !answered {
		msg.Rcode = dns.RcodeServerFailure
		rcode = dns.RcodeServerFailure
		status = "SERVFAIL"
	}

	// Apply TTL clamp + optional RFC 8467 padding from system_config.
	// Reading the config on every query is fine — the row is tiny and
	// the clamp helper caches the parsed values per-call.
	applyResponsePolicies(msg, w)

	w.WriteMsg(msg)
	elapsed := time.Since(start)

	// ── Async: write query log ──
	go e.writeQueryLog(q, w.RemoteAddr().String(), rcode, status, elapsed, r, msg, rpzHitRuleID)
}

// remoteClientIP extracts the IP component from a net.Addr (UDP or TCP).
func remoteClientIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

// getGlobalUpstreams builds the list of upstream addresses from config.
func (e *Engine) getGlobalUpstreams() []string {
	var upstreams []string
	for _, s := range e.servers {
		addr := fmt.Sprintf("%s:%d", s.Address, s.Port)
		upstreams = append(upstreams, addr)
	}
	return upstreams
}

// ensureEDNS0 adds an OPT pseudo-RR with the DO flag to the response
// so DNSSEC-aware resolvers know the answer carries RRSIG data.
func (e *Engine) ensureEDNS0(msg *dns.Msg) {
	if msg.IsEdns0() != nil {
		msg.IsEdns0().SetDo()
		return
	}
	opt := &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
	}
	opt.SetUDPSize(4096)
	opt.SetDo()
	msg.Extra = append(msg.Extra, opt)
}

func rcodeToStatus(rcode int) string {
	switch rcode {
	case dns.RcodeSuccess:
		return "成功"
	case dns.RcodeNameError:
		return "NXDOMAIN"
	case dns.RcodeServerFailure:
		return "SERVFAIL"
	case dns.RcodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE_%d", rcode)
	}
}

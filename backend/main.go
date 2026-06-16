package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"modern-dns/config"
	"modern-dns/internal/dnsengine"
	"modern-dns/internal/handler"
	"modern-dns/internal/model"
	"modern-dns/internal/router"
	"modern-dns/migrations"
	"modern-dns/pkg/alertengine"
	"modern-dns/pkg/cluster"
	"modern-dns/pkg/db"
	"modern-dns/pkg/notify"
	"modern-dns/pkg/rbac"
	"modern-dns/pkg/scheduler"
	"modern-dns/pkg/session"
	"modern-dns/pkg/syslog"
	"modern-dns/pkg/sysmon"

	"github.com/gin-gonic/gin"
)

func main() {
	if err := config.Init(); err != nil {
		log.Fatalf("[config] %v", err)
	}

	// Top-level cancellable context. Cancelled when the process
	// receives SIGINT / SIGTERM so every long-running goroutine
	// (session GC, cluster sampler, sync worker) can wind down
	// in lockstep with the HTTP server's graceful shutdown.
	rootCtx, stopSignals := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	gin.SetMode(config.C.Server.Mode)

	if err := db.InitMySQL(); err != nil {
		log.Fatalf("[mysql] %v", err)
	}
	if err := db.RunBootstrapSchema(migrations.SchemaSQL); err != nil {
		log.Fatalf("[db] bootstrap schema failed: %v", err)
	}
	if err := db.InitRedis(); err != nil {
		log.Fatalf("[redis] %v", err)
	}
	if err := db.DB.AutoMigrate(
		// Auth & RBAC
		&model.Role{}, &model.User{}, &model.RolePermission{}, &model.OperationLog{},
		// Dashboard & Alert
		&model.AlertRule{}, &model.AlertEvent{}, &model.AlertAuditLog{}, &model.DomainHealth{},
		// Domain
		&model.Zone{}, &model.DNSRecord{}, &model.ZoneSOA{}, &model.ZoneDNSSECKey{}, &model.ZoneOptions{},
		// Forward
		&model.ForwardGlobal{}, &model.ForwardServer{}, &model.ForwardRule{},
		// Cache
		&model.CacheGlobalStrategy{}, &model.CacheDomainRule{}, &model.CacheClearLog{},
		// Security
		&model.BWRule{}, &model.DDoSGlobal{}, &model.DDoSDomainRule{},
		&model.SecurityDNSSEC{}, &model.TLSCert{},
		&model.AclRule{}, &model.RpzRule{},
		// Monitor
		&model.QueryLog{},
		&model.MonitorQPSRule{}, &model.MonitorNXDomainRule{},
		&model.MonitorLatencyRule{}, &model.MonitorCacheHitRule{},
		&model.MonitorRuleHistory{}, &model.AlertSubscribeRule{}, &model.AlertContactGroup{},
		&model.AlertSilenceRule{}, &model.AlertInhibitRule{},
		// Tools
		&model.DigHistory{}, &model.GlobalTestHistory{},
		// Cluster
		&model.ClusterNode{}, &model.ClusterSettings{}, &model.ClusterConfigSync{}, &model.ClusterSyncHistory{},
		// Setting
		&model.SystemConfig{}, &model.Backup{}, &model.NoticeConfig{}, &model.NoticeTemplate{}, &model.AlertNotifyDeadLetter{}, &model.ApiKey{},
		// Load Balance
		&model.LbGroup{}, &model.LbServer{},
	); err != nil {
		log.Printf("[db] AutoMigrate error: %v", err)
	}

	// One-shot data fixup: an earlier fix briefly wrote zones.status =
	// '启用' to satisfy the DNS engine's strict-equal zone filter. The
	// engine has since been relaxed to "<> 禁用", so the canonical UI
	// vocabulary {正常, 异常, 同步中, 禁用} is what we want in the DB.
	// Without this, the zone-list table renders mixed badges (some green
	// "正常", some neutral grey "启用") for rows that are functionally
	// identical. Idempotent: re-running just updates zero rows.
	if res := db.DB.Model(&model.Zone{}).Where("status = ?", "启用").Update("status", "正常"); res.Error == nil && res.RowsAffected > 0 {
		log.Printf("[db] normalised %d zones.status row(s) from '启用' to '正常'", res.RowsAffected)
	}

	handler.SeedAdmin()
	rbac.Init()
	notify.PrewarmTemplates()

	// Apply DB pool sizing from system_config so operators' tuning
	// survives a restart. The function silently no-ops on zero values
	// so a fresh deploy keeps the conservative defaults set in
	// db.InitMySQL above.
	{
		var sc model.SystemConfig
		if db.DB.First(&sc, 1).Error == nil {
			db.ApplyPool(sc.DBMaxOpenConns, sc.DBMaxIdleConns, sc.DBConnMaxLifetimeMin, sc.DBConnMaxIdleMin)
		}
	}

	// Background NTP poller — observes drift only, never slews the OS
	// clock. Configurable via system_config.ntp_servers.
	sysmon.StartNTP()
	defer sysmon.StopNTP()

	// Optional syslog forwarder for operation_log entries. Spawns the
	// dispatcher goroutine unconditionally; it idles until the operator
	// fills in syslog_server (audit-log → 配置). Initial Reconfigure
	// reads the persisted row so a restart picks up the saved state
	// without waiting for the next save.
	syslog.Start()
	defer syslog.Stop()
	{
		var sysCfg model.SystemConfig
		if err := db.DB.FirstOrCreate(&sysCfg, model.SystemConfig{ID: 1}).Error; err == nil {
			syslog.Reconfigure(syslog.Config{
				Enabled: sysCfg.SyslogEnabled,
				Server:  sysCfg.SyslogServer,
			})
		}
	}

	// Background sweeper that drops stale members from the Redis
	// session table. Without it, rolling logins leave one ghost
	// member per session forever (Register's per-key EXPIRE refreshes
	// the whole key, never an individual member). 1-minute interval
	// is fine — well under the access-token TTL — and cheap.
	go session.RunGC(rootCtx, session.GCConfig{
		Interval:  time.Minute,
		AccessTTL: time.Duration(config.C.JWT.AccessExpireMin) * time.Minute,
	})

	cluster.LoadTokenFromDB()
	if n := cluster.LoadPinsFromDB(); n > 0 {
		log.Printf("[cluster] loaded %d peer cert pin(s)", n)
	}

	// ── Secondary auto-join ──
	if config.C.Cluster.Secondary.Enabled && config.C.Cluster.Secondary.PrimaryURL != "" {
		go runSecondary()
	}

	// ── DNS Engine ──
	if config.C.DNS.Enabled {
		engine := dnsengine.New(dnsengine.EngineConfig{
			ListenAddr: config.C.DNS.Listen,
			DoTPort:    config.C.DNS.DoTPort,
			DoHPort:    config.C.DNS.DoHPort,
			CertFile:   config.C.DNS.CertFile,
			KeyFile:    config.C.DNS.KeyFile,
		})
		if err := engine.Start(); err != nil {
			log.Printf("[dns-engine] failed to start: %v (continuing without DNS)", err)
		} else {
			defer engine.Stop()
		}
	}

	// ── Alert Engine ──
	alertEng := alertengine.New(30 * time.Second)
	alertengine.SetDefaultEngine(alertEng)
	alertEng.Start()
	defer alertEng.Stop()

	// ── Scheduler ── auto-backup + retention cleanup driven by SystemConfig
	scheduler.Start()
	defer scheduler.Stop()

	// ── Self-metrics sampler ── publishes the local node's mem/QPS into
	// pkg/cluster Runtime every 10s so the cluster overview shows the
	// primary's own resources, not just secondaries' heartbeat data.
	cluster.StartSelfMetricsSampler(rootCtx, 10*time.Second)

	// ── Cluster sync worker ── retries failed pushes with exponential
	// backoff and runs the auto-sync cycle driven by ConfigRefreshSec.
	handler.StartClusterSyncWorker(rootCtx)
	defer handler.StopClusterSyncWorker()

	// ── Secondary zone auto-refresh ── periodically re-AXFRs every
	// Secondary zone whose configured SOA.Refresh has elapsed since
	// its last successful sync, honouring per-zone Transport
	// (TCP / TLS / QUIC) and AXFRInsecure.
	handler.StartSecondaryRefreshWorker(rootCtx)
	defer handler.StopSecondaryRefreshWorker()

	r := gin.New()
	r.Use(gin.Recovery())

	// Constrain which upstream proxies may set X-Forwarded-For. Empty
	// config defaults to loopback only — gin's "trust all proxies"
	// fallback would otherwise let any client forge ClientIP() and
	// silently bypass the IP allowlist / login lockout / audit IP.
	trustedProxies := config.C.Server.TrustedProxies
	if len(trustedProxies) == 0 {
		trustedProxies = []string{"127.0.0.1", "::1"}
	}
	if err := r.SetTrustedProxies(trustedProxies); err != nil {
		log.Printf("[server] SetTrustedProxies(%v) failed: %v — falling back to gin default", trustedProxies, err)
	}

	router.Setup(r)

	addr := ":" + config.C.Server.Port
	log.Printf("[server] listening on %s", addr)

	// We hold the listener references so the signal handler below can
	// call Shutdown(ctx) and release the ports cleanly. Without this,
	// Ctrl-C would let main return immediately, the OS would reap the
	// process before in-flight HTTP requests finished, and the next
	// dev-loop run would race for the same port.
	httpSrv := &http.Server{Addr: addr, Handler: r}
	var httpsSrv *http.Server

	// ── Optional HTTPS for cluster peer-to-peer ──
	// Cluster API token + TLS protect inter-node traffic per the
	// cluster spec. HTTP keeps serving the operator UI; HTTPS is
	// started in parallel when enabled.
	if config.C.Cluster.HTTPSEnabled {
		certPath, keyPath, err := cluster.EnsureSelfSignedCert(config.C.Cluster.CertDir, "", nil)
		if err != nil {
			log.Printf("[cluster] tls cert init failed: %v (HTTPS disabled)", err)
		} else {
			httpsAddr := ":" + config.C.Cluster.HTTPSPort
			httpsSrv = &http.Server{Addr: httpsAddr, Handler: r}
			go func() {
				log.Printf("[cluster] HTTPS listening on %s", httpsAddr)
				if err := httpsSrv.ListenAndServeTLS(certPath, keyPath); err != nil &&
					!errors.Is(err, http.ErrServerClosed) {
					log.Printf("[cluster] HTTPS server stopped: %v", err)
				}
			}()
		}
	}

	// Run HTTP in a goroutine so the main goroutine can wait for a
	// signal and orchestrate Shutdown ordering deterministically.
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[server] failed: %v", err)
		}
	}()

	<-rootCtx.Done()
	log.Printf("[server] shutdown signal received, draining...")
	stopSignals() // restore default handlers so a second Ctrl-C kills hard

	// 10 s is generous: the longest in-flight request budget in this
	// codebase is the 5 s upstream forward, so a request started right
	// before the signal still has time to land. We don't tie this to
	// rootCtx because rootCtx is already cancelled.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[server] graceful shutdown error: %v", err)
	}
	if httpsSrv != nil {
		if err := httpsSrv.Shutdown(shutdownCtx); err != nil {
			log.Printf("[cluster] HTTPS graceful shutdown error: %v", err)
		}
	}
	// `defer`s above (engine.Stop, alertEng.Stop, scheduler.Stop,
	// syslog.Stop, sysmon.StopNTP, handler.StopClusterSyncWorker)
	// fire as main returns, in reverse declaration order.
	log.Printf("[server] shutdown complete")
}

// runSecondary boots the cluster secondary client based on config.cluster.secondary.
// Lives for the duration of the process; we don't gracefully stop it because
// the OS will kill the process before any graceful path matters.
func runSecondary() {
	sec := config.C.Cluster.Secondary
	heartbeat := time.Duration(config.C.Cluster.HeartbeatIntervalSec) * time.Second
	if heartbeat <= 0 {
		heartbeat = 5 * time.Second
	}

	ips := sec.IPAddrs
	if len(ips) == 0 {
		ips = []string{"127.0.0.1"}
	}
	scheme := "http"
	if config.C.Cluster.HTTPSEnabled {
		scheme = "https"
	}
	port := config.C.Cluster.HTTPSPort
	if scheme == "http" {
		port = config.C.Server.Port
	}
	nodeURL := scheme + "://" + ips[0] + ":" + port

	// Read our own cert (if HTTPS configured) to advertise during join — the
	// primary will record its fingerprint and pin future calls to us.
	ownCert := ""
	if config.C.Cluster.HTTPSEnabled {
		certPath := config.C.Cluster.CertDir + "/cluster-cert.pem"
		if pem, err := cluster.LoadOwnCertPEM(certPath); err == nil {
			ownCert = pem
		}
	}

	client := cluster.NewSecondary(
		sec.PrimaryURL, sec.APIToken,
		sec.NodeName, nodeURL, ips,
		func(s *cluster.SecondaryClient) {
			if sec.NodeID != "" {
				s.NodeID = sec.NodeID
			}
			s.Zone = sec.Zone
			s.Version = sec.Version
			s.HeartbeatInterval = heartbeat
			s.IgnoreCertErrors = config.C.Cluster.IgnoreCertificateErrors
			s.OwnCertPEM = ownCert
		},
	)

	log.Printf("[cluster-secondary] starting (primary=%s heartbeat=%s)", sec.PrimaryURL, heartbeat)
	client.Start()
}

package router

import (
	"time"

	"modern-dns/internal/handler"
	"modern-dns/middleware"
	"modern-dns/pkg/rbac"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func Setup(r *gin.Engine) {
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Demo-Frontend", "X-Confirm-Password", "X-Confirm-TOTP"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
	}))
	r.Use(middleware.Logger())

	api := r.Group("/api")

	// ── Auth (public, but admin-IP-restricted) ────────────────────────────
	// Login itself is gated by the SystemConfig.IPWhitelist so a forbidden
	// IP cannot brute-force the login endpoint.
	auth := api.Group("/auth")
	auth.Use(middleware.IPAllowlist())
	{
		// Aggressive per-IP rate limit on login: even when the per-username
		// lock-out kicks in, an attacker can rotate usernames; the IP
		// limit caps total brute-force throughput at 10 req/min/IP. Refresh
		// is bounded too because a token leak shouldn't translate into an
		// unbounded refresh storm.
		auth.POST("/login", middleware.RateLimit("login", 10, time.Minute), handler.Login)
		auth.POST("/refresh", middleware.RateLimit("refresh", 30, time.Minute), handler.RefreshToken)
	}

	// ── Cluster internal (peer-to-peer, token-authenticated, audited) ──────
	// Bypasses IPAllowlist + MaintenanceMode on purpose: cluster nodes have
	// their own ClusterToken and may live on IPs not present in the admin
	// allowlist; pausing peer sync during a maintenance window would also
	// rip the cluster apart.
	clusterInternal := api.Group("/cluster/internal")
	clusterInternal.Use(middleware.ClusterToken(), middleware.ClusterAudit())
	{
		clusterInternal.POST("/join", handler.PeerJoin)
		clusterInternal.POST("/heartbeat", handler.PeerHeartbeat)
		clusterInternal.POST("/leave", handler.PeerLeave)
		clusterInternal.GET("/state", handler.PeerGetClusterState)
		clusterInternal.GET("/state-snapshot", handler.PeerGetStateSnapshot)
		clusterInternal.GET("/health", handler.PeerHealth)
		clusterInternal.POST("/apply-config", handler.PeerApplyConfig)
		clusterInternal.POST("/command", handler.PeerRunCommand)
	}

	// ── TOTP setup / verify ────────────────────────────────────────────────
	// Accept access OR enrollment tokens so two distinct flows can share the
	// same endpoints: voluntary enable from a logged-in user, and the
	// MFA-required first-login enrolment wizard. IPAllowlist still applies
	// (this is admin surface). MaintenanceMode skipped: even during maint we
	// must let an admin finish enrolment to disable maintenance.
	enroll := api.Group("/auth/totp")
	enroll.Use(middleware.AuthEnrollment(), middleware.IPAllowlist())
	{
		enroll.POST("/setup", handler.TOTPSetup)
		enroll.POST("/verify", handler.TOTPVerify)
	}

	// ── Protected routes ───────────────────────────────────────────────────
	// Order: Auth → IPAllowlist → MaintenanceMode. Auth runs first so an
	// expired/missing token gets a clean 401 instead of leaking IP-policy
	// info; MaintenanceMode is last so 401/403 still beat 503 when both
	// would apply.
	protected := api.Group("/")
	protected.Use(middleware.Auth(), middleware.IPAllowlist(), middleware.MaintenanceMode())
	{
		protected.POST("/auth/logout", handler.Logout)
		protected.GET("/auth/profile", handler.GetProfile)
		protected.PUT("/auth/profile", handler.UpdateProfile)
		protected.POST("/auth/change-password", handler.ChangePassword)
		protected.POST("/auth/totp/disable", handler.TOTPDisable)

		// Returns the calling client's IP as seen by the server.
		// Powers the "fill my IP" button on the zone-options ACL
		// textareas, the forward-rule ACL editor, etc. — anywhere the
		// operator wants to seed a rule with their own address.
		protected.GET("/system/whoami", handler.Whoami)

		// Dashboard
		dash := protected.Group("/dashboard")
		{
			dash.GET("/overview", handler.DashboardOverview)
			dash.GET("/domain-status", handler.DashboardDomainStatus)
			dash.GET("/alerts", handler.DashboardAlerts)
			dash.GET("/resource", handler.DashboardResource)
			dash.GET("/security-posture", handler.GetSecurityPosture)
			dash.GET("/alert-rules", handler.ListAlertRules)
			dash.POST("/alert-rules", middleware.RequirePerm(rbac.PermMonitorWrite), handler.AddAlertRule)
			dash.PUT("/alert-rules/:id", middleware.RequirePerm(rbac.PermMonitorWrite), handler.EditAlertRule)
			dash.DELETE("/alert-rules/:id", middleware.RequirePerm(rbac.PermMonitorWrite), handler.DeleteAlertRule)
			dash.POST("/alert-rules/:id/test", middleware.RequirePerm(rbac.PermMonitorWrite), handler.TestAlertRule)

			dash.PATCH("/alerts/read-all", handler.MarkAllAlertsRead)
			dash.PATCH("/alerts/:id/handle", handler.HandleAlertEvent)
			dash.DELETE("/alerts/batch", middleware.RequirePerm(rbac.PermMonitorWrite), handler.BatchDeleteAlertEvents)
		}

		// Domain / Zones
		domain := protected.Group("/domain")
		{
			domainWrite := middleware.RequirePerm(rbac.PermDomainWrite)

			// batch routes must be registered before param routes to avoid Gin conflicts
			domain.DELETE("/zones-batch", domainWrite, handler.BatchDeleteZones)
			domain.PATCH("/zones-batch-status", domainWrite, handler.BatchUpdateZoneStatus)

			domain.GET("/zones", handler.ListZones)
			domain.POST("/zones", domainWrite, handler.CreateZone)
			domain.GET("/zones/:id", handler.GetZoneDetail)
			domain.PUT("/zones/:id", domainWrite, handler.UpdateZone)
			domain.DELETE("/zones/:id", domainWrite, handler.DeleteZone)

			domain.GET("/records/template", handler.DownloadRecordTemplate)
			domain.POST("/records/touch", handler.TouchRecordUsage)

			domain.GET("/zones/:id/records", handler.ListRecords)
			domain.GET("/zones/:id/records/export", handler.ExportRecords)
			domain.POST("/zones/:id/records/import", domainWrite, handler.ImportRecords)
			domain.POST("/zones/:id/records", domainWrite, handler.CreateRecord)
			domain.PUT("/zones/:id/records/:rid", domainWrite, handler.UpdateRecord)
			domain.DELETE("/zones/:id/records-batch", domainWrite, handler.BatchDeleteRecords)
			domain.PATCH("/zones/:id/records/:rid/status", domainWrite, handler.UpdateRecordStatus)

			domain.GET("/zones/:id/soa", handler.GetSOA)
			domain.PUT("/zones/:id/soa", domainWrite, handler.SaveSOA)

			// 区域选项 — query/transfer/notify/dyn-update policy.
			domain.GET("/zones/:id/options", handler.GetZoneOptions)
			domain.PUT("/zones/:id/options", domainWrite, handler.SaveZoneOptions)

			// AXFR pull from master — Secondary zones only.
			domain.POST("/zones/:id/sync", domainWrite, handler.SyncSecondaryZone)

			domain.GET("/zones/:id/dnssec", handler.GetZoneDNSSEC)
			domain.PUT("/zones/:id/dnssec/toggle", domainWrite, handler.ToggleZoneDNSSEC)
			domain.POST("/zones/:id/dnssec/generate", domainWrite, handler.GenerateZoneDNSSECKey)
			domain.DELETE("/zones/:id/dnssec/:kid", domainWrite, handler.DeleteZoneDNSSECKey)
		}

		// Forward
		fwd := protected.Group("/forward")
		{
			fwdWrite := middleware.RequirePerm(rbac.PermForwardWrite)

			fwd.GET("/global", handler.GetForwardGlobal)
			fwd.PUT("/global", fwdWrite, handler.SaveForwardGlobal)
			fwd.POST("/global/toggle", fwdWrite, handler.ToggleForwardGlobal)

			fwd.GET("/servers", handler.ListForwardServers)
			fwd.POST("/servers", fwdWrite, handler.CreateForwardServer)
			fwd.PUT("/servers/:id", fwdWrite, handler.UpdateForwardServer)
			fwd.DELETE("/servers/:id", fwdWrite, handler.DeleteForwardServer)

			fwd.GET("/condition/rules", handler.ListForwardRules)
			fwd.POST("/condition/rules", fwdWrite, handler.CreateForwardRule)
			fwd.PUT("/condition/rules/batch-status", fwdWrite, handler.BatchUpdateForwardRuleStatus)
			fwd.PUT("/condition/rules/reorder", fwdWrite, handler.ReorderForwardRules)
			fwd.DELETE("/condition/rules/batch", fwdWrite, handler.BatchDeleteForwardRules)
			fwd.PUT("/condition/rules/:id", fwdWrite, handler.UpdateForwardRule)
			fwd.DELETE("/condition/rules/:id", fwdWrite, handler.DeleteForwardRule)

			fwd.GET("/traffic-stats", handler.GetForwardTrafficStats)
			fwd.POST("/latency-test", handler.LatencyTest)

			fwd.GET("/lb/groups", handler.ListLbGroups)
			fwd.POST("/lb/groups", fwdWrite, handler.CreateLbGroup)
			fwd.DELETE("/lb/groups/:id", fwdWrite, handler.DeleteLbGroup)
			fwd.POST("/lb/groups/:id/servers", fwdWrite, handler.CreateLbServer)
			fwd.POST("/lb/groups/:id/health-check", fwdWrite, handler.LbHealthCheck)
			fwd.PUT("/lb/servers/:sid", fwdWrite, handler.UpdateLbServer)
			fwd.DELETE("/lb/servers/:sid", fwdWrite, handler.DeleteLbServer)
			fwd.PUT("/lb/servers/:sid/toggle", fwdWrite, handler.ToggleLbServer)
		}

		// Cache
		cache := protected.Group("/cache")
		{
			cacheWrite := middleware.RequirePerm(rbac.PermCacheWrite)
			cache.GET("/strategy", handler.GetCacheStrategy)
			cache.PUT("/strategy/global", cacheWrite, handler.SaveCacheGlobalStrategy)
			cache.POST("/strategy/domain-rules", cacheWrite, handler.CreateCacheDomainRule)
			cache.DELETE("/strategy/domain-rules/batch", cacheWrite, handler.BatchDeleteCacheDomainRules)
			cache.PUT("/strategy/domain-rules/:id", cacheWrite, handler.UpdateCacheDomainRule)
			cache.DELETE("/strategy/domain-rules/:id", cacheWrite, handler.DeleteCacheDomainRule)
			cache.GET("/entries", handler.GetCacheEntries)
			cache.POST("/clear", cacheWrite, handler.ClearCache)
			cache.GET("/clear/logs", handler.GetCacheClearLogs)
			cache.DELETE("/clear/logs", cacheWrite, handler.PurgeCacheClearLogs)
		}

		// Security
		sec := protected.Group("/security")
		{
			secWrite := middleware.RequirePerm(rbac.PermSecurityWrite)

			sec.GET("/bw-rules", handler.ListBWRules)
			sec.POST("/bw-rules", secWrite, handler.CreateBWRule)
			sec.PUT("/bw-rules/batch-status", secWrite, handler.BatchUpdateBWStatus)
			sec.DELETE("/bw-rules/batch", secWrite, handler.BatchDeleteBWRules)
			sec.POST("/bw-rules/import", secWrite, handler.ImportBWRules)
			sec.PUT("/bw-rules/:id", secWrite, handler.UpdateBWRule)
			sec.DELETE("/bw-rules/:id", secWrite, handler.DeleteBWRule)

			sec.GET("/ddos", handler.GetDDoS)
			sec.PUT("/ddos/global", secWrite, handler.SaveDDoSGlobal)
			sec.POST("/ddos/domain-rules", secWrite, handler.CreateDDoSDomainRule)
			sec.DELETE("/ddos/domain-rules/batch", secWrite, handler.BatchDeleteDDoSDomainRules)
			sec.PUT("/ddos/domain-rules/:id", secWrite, handler.UpdateDDoSDomainRule)
			sec.DELETE("/ddos/domain-rules/:id", secWrite, handler.DeleteDDoSDomainRule)

			sec.GET("/dnssec", handler.ListSecurityDNSSEC)
			sec.POST("/dnssec/check-all", secWrite, handler.CheckAllDNSSEC)
			sec.POST("/dnssec/:id/check", secWrite, handler.CheckOneDNSSEC)
			sec.PUT("/dnssec/:id/toggle", secWrite, handler.ToggleDNSSEC)
			sec.POST("/dnssec/:id/generate-key", secWrite, handler.GenerateSecurityDNSSECKey)
			sec.DELETE("/dnssec/:id/keys/:keyId", secWrite, handler.DeleteSecurityDNSSECKey)

			sec.GET("/certs", handler.ListCerts)
			sec.POST("/certs", secWrite, handler.UploadCert)
			sec.POST("/certs/:id/renew", secWrite, handler.RenewCert)
			sec.DELETE("/certs/:id", secWrite, handler.DeleteCert)

			sec.GET("/acl", handler.ListAclRules)
			sec.POST("/acl", secWrite, handler.CreateAclRule)
			sec.PUT("/acl/:id", secWrite, handler.UpdateAclRule)
			sec.DELETE("/acl/:id", secWrite, handler.DeleteAclRule)
			sec.PATCH("/acl/:id/toggle", secWrite, handler.ToggleAclRule)

			sec.GET("/rpz", handler.ListRpzRules)
			sec.POST("/rpz", secWrite, handler.CreateRpzRule)
			sec.PUT("/rpz/:id", secWrite, handler.UpdateRpzRule)
			sec.DELETE("/rpz/:id", secWrite, handler.DeleteRpzRule)
			sec.PUT("/rpz/:id/toggle", secWrite, handler.ToggleRpzRule)
		}

		// Monitor
		mon := protected.Group("/monitor")
		{
			monWrite := middleware.RequirePerm(rbac.PermMonitorWrite)
			auditExport := middleware.RequirePerm(rbac.PermAuditExport)

			mon.GET("/realtime", handler.GetRealTimeLogs)
			mon.POST("/realtime/refresh", handler.RefreshRealTime)
			mon.GET("/resolve-logs", handler.GetResolveLogs)
			mon.POST("/resolve-logs/export", auditExport, handler.ExportResolveLogs)
			mon.GET("/rules", handler.GetMonitorRules)
			mon.PUT("/rules/qps", monWrite, handler.SaveQPSRule)
			mon.POST("/rules/qps/reset", monWrite, handler.ResetQPSRule)
			mon.PUT("/rules/nxdomain", monWrite, handler.SaveNXDomainRule)
			mon.POST("/rules/nxdomain/reset", monWrite, handler.ResetNXDomainRule)
			mon.PUT("/rules/latency", monWrite, handler.SaveLatencyRule)
			mon.POST("/rules/latency/reset", monWrite, handler.ResetLatencyRule)
			mon.PUT("/rules/cache-hit", monWrite, handler.SaveCacheHitRule)
			mon.POST("/rules/cache-hit/reset", monWrite, handler.ResetCacheHitRule)
			mon.PATCH("/rule-history/:id/handle", monWrite, handler.HandleRuleHistory)
			mon.GET("/report", handler.GetMonitorReport)
			mon.GET("/report/extended", handler.GetMonitorReportExtended)
			mon.GET("/alert-metrics", handler.GetAlertMetrics)

			mon.GET("/alert-subscribe/rules", handler.ListAlertSubscribeRules)
			mon.POST("/alert-subscribe/rules", monWrite, handler.CreateAlertSubscribeRule)
			mon.PATCH("/alert-subscribe/rules/batch", monWrite, handler.BatchUpdateAlertSubscribeRules)
			mon.PUT("/alert-subscribe/rules/:id", monWrite, handler.UpdateAlertSubscribeRule)
			mon.DELETE("/alert-subscribe/rules/:id", monWrite, handler.DeleteAlertSubscribeRule)
			mon.PATCH("/alert-subscribe/rules/:id/toggle", monWrite, handler.ToggleAlertSubscribeRule)
			mon.GET("/alert-subscribe/contact-groups", handler.ListAlertContactGroups)
			mon.POST("/alert-subscribe/contact-groups", monWrite, handler.CreateAlertContactGroup)
			mon.PUT("/alert-subscribe/contact-groups/:id", monWrite, handler.UpdateAlertContactGroup)
			mon.DELETE("/alert-subscribe/contact-groups/:id", monWrite, handler.DeleteAlertContactGroup)
			mon.GET("/alert-subscribe/users", handler.ListAlertContactUsers)
			mon.GET("/alert-subscribe/silence-rules", handler.ListAlertSilenceRules)
			mon.POST("/alert-subscribe/silence-rules", monWrite, handler.CreateAlertSilenceRule)
			mon.PUT("/alert-subscribe/silence-rules/:id", monWrite, handler.UpdateAlertSilenceRule)
			mon.DELETE("/alert-subscribe/silence-rules/:id", monWrite, handler.DeleteAlertSilenceRule)
			mon.GET("/alert-subscribe/inhibit-rules", handler.ListAlertInhibitRules)
			mon.POST("/alert-subscribe/inhibit-rules", monWrite, handler.CreateAlertInhibitRule)
			mon.PUT("/alert-subscribe/inhibit-rules/:id", monWrite, handler.UpdateAlertInhibitRule)
			mon.DELETE("/alert-subscribe/inhibit-rules/:id", monWrite, handler.DeleteAlertInhibitRule)

			mon.GET("/slow-query", handler.GetSlowQueries)

			mon.GET("/client-analysis", handler.GetClientAnalysis)
		}

		// Alert Events
		alerts := protected.Group("/alert-events")
		{
			alerts.GET("", handler.ListAlertEvents)
			alerts.GET("/summary", handler.AlertEventSummary)
			alerts.PATCH("/:id/confirm", middleware.RequirePerm(rbac.PermMonitorWrite), handler.ConfirmAlertEvent)
			alerts.PATCH("/confirm-all", middleware.RequirePerm(rbac.PermMonitorWrite), handler.ConfirmAllAlertEvents)
			alerts.DELETE("/clean", middleware.RequirePerm(rbac.PermMonitorWrite), handler.CleanAlertEvents)
		}

		// Tools
		tools := protected.Group("/tools")
		{
			tools.POST("/dig", handler.RunDig)
			tools.GET("/dig/history", handler.GetDigHistory)
			tools.DELETE("/dig/history", handler.ClearDigHistory)
			tools.DELETE("/dig/history/:id", handler.DeleteDigHistory)
			tools.POST("/dnssec-debug", handler.RunDNSSECDebug)
			tools.POST("/global-test", handler.RunGlobalTest)
			tools.GET("/global-test/history", handler.GetGlobalTestHistory)
			tools.POST("/ip-location", handler.LookupIPLocation)
		}

		// Cluster
		clusterGrp := protected.Group("/cluster")
		{
			clusterAdmin := middleware.RequirePerm(rbac.PermClusterAdmin)
			clusterGrp.GET("/overview", handler.GetClusterOverview)
			clusterGrp.GET("/state", handler.GetClusterState)
			clusterGrp.GET("/nodes", handler.ListClusterNodes)
			clusterGrp.POST("/initialize", clusterAdmin, handler.InitializeCluster)
			// Destructive cluster operations require step-up auth on top of
			// the regular RBAC perm check. SensitiveConfirm reads
			// X-Confirm-Password / X-Confirm-TOTP headers and 401-with-4401
			// when missing, so a stolen access token alone can't tear the
			// cluster down. See middleware/sensitive.go for details.
			clusterGrp.DELETE("", clusterAdmin, middleware.SensitiveConfirm(), handler.DeleteCluster)
			clusterGrp.POST("/resync", clusterAdmin, handler.ResyncCluster)
			clusterGrp.POST("/command", clusterAdmin, handler.DispatchClusterCommand)
			clusterGrp.POST("/nodes", clusterAdmin, handler.AddClusterNode)
			clusterGrp.POST("/nodes/refresh", clusterAdmin, handler.RefreshClusterNodes)
			clusterGrp.POST("/nodes/batch-remove", clusterAdmin, middleware.SensitiveConfirm(), handler.BatchRemoveNodes)
			clusterGrp.PUT("/nodes/:id", clusterAdmin, handler.UpdateClusterNode)
			clusterGrp.DELETE("/nodes/:id", clusterAdmin, handler.RemoveClusterNode)
			clusterGrp.POST("/nodes/:id/failover", clusterAdmin, handler.FailoverClusterNode)
			clusterGrp.POST("/nodes/:id/drain", clusterAdmin, handler.SetDrain(true))
			clusterGrp.POST("/nodes/:id/undrain", clusterAdmin, handler.SetDrain(false))
			clusterGrp.GET("/nodes/:id/metrics", handler.GetNodeMetrics)
			clusterGrp.POST("/rotate-token", clusterAdmin, middleware.SensitiveConfirm(), handler.RotateClusterToken)
			clusterGrp.GET("/stream", handler.StreamClusterEvents)
			clusterGrp.GET("/config-sync", handler.ListConfigSync)
			clusterGrp.POST("/config-sync/sync-all", clusterAdmin, handler.SyncAllNodeConfigs)
			clusterGrp.POST("/config-sync/:id/sync", clusterAdmin, handler.SyncNodeConfig)
			clusterGrp.GET("/config-sync/:id/diff", handler.GetConfigSyncDiff)
			clusterGrp.POST("/config-sync/:id/diff/refresh", clusterAdmin, handler.RefreshConfigSyncDiff)
			clusterGrp.GET("/sync-history", handler.ListSyncHistory)
		}

		// Setting
		setting := protected.Group("/setting")
		{
			settingWrite := middleware.RequirePerm(rbac.PermSettingWrite)
			userWrite := middleware.RequirePerm(rbac.PermUserWrite)
			roleWrite := middleware.RequirePerm(rbac.PermRoleWrite)
			auditExport := middleware.RequirePerm(rbac.PermAuditExport)
			backupCreate := middleware.RequirePerm("setting:backup:create", rbac.PermBackupWrite)
			backupRestore := middleware.RequirePerm("setting:backup:restore", rbac.PermBackupWrite)
			backupDelete := middleware.RequirePerm("setting:backup:delete", rbac.PermBackupWrite)
			logPurge := middleware.RequirePerm("setting:log:purge", rbac.PermSettingWrite)

			setting.GET("/common", handler.GetCommonConfig)
			setting.PUT("/common", settingWrite, handler.SaveCommonConfig)
			setting.POST("/common/reset", settingWrite, handler.ResetCommonConfig)
			setting.POST("/common/ntp/test", settingWrite, handler.TestNTP)
			setting.PUT("/common/log", settingWrite, handler.SaveLogConfig)
			setting.GET("/users", handler.ListUsersV2)
			setting.POST("/users", userWrite, handler.SaveUser)
			setting.DELETE("/users/:id", userWrite, handler.DeleteUser)
			setting.POST("/users/:id/reset-password", userWrite, handler.ResetUserPassword)
			setting.GET("/users/:id/lock-status", handler.GetLockStatus)
			setting.POST("/users/:id/unlock", userWrite, handler.UnlockAccount)
			setting.POST("/users/:id/kick-sessions", userWrite, handler.KickUserSessions)
			setting.GET("/online-sessions", handler.ListOnlineSessions)
			setting.POST("/online-sessions/revoke", userWrite, handler.RevokeSession)
			setting.GET("/roles", handler.ListRoles)
			setting.POST("/roles", roleWrite, handler.SaveRole)
			setting.DELETE("/roles/:id", roleWrite, handler.DeleteRole)
			setting.GET("/roles/:id/permissions", handler.GetRolePermissions)
			setting.PUT("/roles/:id/permissions", roleWrite, handler.SaveRolePermissions)
			setting.GET("/backups", handler.ListBackupsV2)
			setting.POST("/backups", backupCreate, handler.CreateBackup)
			// Upload is a precursor to Restore — gate it the same way.
			setting.POST("/backups/upload", backupRestore, handler.UploadBackup)
			setting.POST("/backups/restore", backupRestore, handler.RestoreBackupByFile)
			setting.POST("/backups/:id/restore", backupRestore, handler.RestoreBackup)
			setting.GET("/backups/:id/export", handler.ExportBackupFile)
			setting.DELETE("/backups/:id", backupDelete, handler.DeleteBackup)

			setting.GET("/notice", handler.GetNoticeConfig)
			setting.PUT("/notice", settingWrite, handler.SaveNoticeConfig)
			setting.PUT("/notice/:channel", settingWrite, handler.SaveNoticeChannelConfig)
			setting.POST("/notice/test", settingWrite, handler.TestNoticeChannel)
			setting.GET("/notice/templates", handler.ListNoticeTemplates)
			setting.PUT("/notice/templates/:channel", settingWrite, handler.UpdateNoticeTemplate)
			setting.POST("/notice/templates/:channel/reset", settingWrite, handler.ResetNoticeTemplate)
			setting.POST("/notice/templates/:channel/preview", settingWrite, handler.PreviewNoticeTemplate)

			setting.GET("/api-keys", handler.ListApiKeys)
			setting.POST("/api-keys", userWrite, handler.CreateApiKey)
			setting.PUT("/api-keys/:id", userWrite, handler.UpdateApiKey)
			setting.PATCH("/api-keys/:id/toggle", userWrite, handler.ToggleApiKeyStatus)
			setting.DELETE("/api-keys/:id", userWrite, handler.RevokeApiKey)

			setting.GET("/logs", handler.GetOperationLogs)
			setting.POST("/logs/export", auditExport, handler.ExportOperationLogs)
			setting.POST("/logs/purge-expired", logPurge, handler.PurgeExpiredOperationLogs)
		}
	}
}

// security_posture.go aggregates the bits of system state that
// matter at-a-glance for an operations / security on-call: who's
// locked out, how many sessions are live, when did anything get
// kicked, how many users are overdue for a password change, and
// whether the encrypted-channel padding policy is actually firing.
//
// The numbers come from three sources we already maintain
// independently — Redis (locks + sessions), MySQL (password ages,
// recent audit log entries), and dnsengine atomics (padding
// counters) — so there's no new persistence layer required. The
// query is intentionally bounded:
//
//   - Redis SCANs cap at 200 keys per cursor pass.
//   - SQL counts use indexed columns and a single round-trip per
//     metric.
//
// All five metrics together cost O(10 ms) on a small deployment;
// it's safe to call from the dashboard refresh loop.

package handler

import (
	"context"
	"strings"
	"time"

	"modern-dns/internal/dnsengine"
	"modern-dns/internal/model"
	"modern-dns/pkg/db"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
)

// SecurityPosture is the JSON shape consumed by the dashboard
// "security posture" card. Field names map 1:1 to the i18n labels.
type SecurityPosture struct {
	// Number of accounts currently in login-lockout (failure
	// counter ≥ LoginMaxFailures). Counted by SCAN over the
	// `login:fail:*` keyspace + GET each value; cheap because the
	// keyspace is bounded by operator headcount.
	LockedAccounts int64 `json:"lockedAccounts"`

	// Active operator sessions = sum of ZCARD(user:sids:*).
	// Distinct users with ≥1 active session is also surfaced so
	// the dashboard can show "5 sessions across 3 people" without
	// double-counting concurrent tabs.
	ActiveSessions int64 `json:"activeSessions"`
	OnlineUsers    int64 `json:"onlineUsers"`

	// Number of audit-log entries in the last 24h whose action is
	// either 强制下线 or 下线会话. Spikes here often correlate with
	// incident response or new-employee onboarding cleanup;
	// surfacing it on the dashboard means the security team
	// doesn't have to dig into operation_log to find them.
	KickedLast24h int64 `json:"kickedLast24h"`

	// Users whose password hasn't been changed in PasswordExpireDays
	// (from SystemConfig). Ignored when PwdExpireDays is 0 (policy
	// disabled). Counted via a single COUNT() query on users.
	OverduePasswordUsers int64 `json:"overduePasswordUsers"`

	// Padding counters from the DNS engine. Inbound = response
	// padding to clients; Outbound = query padding to DoH/DoT
	// upstreams. Zero suggests either padding is disabled or the
	// channel mix doesn't have any encrypted upstream traffic.
	PaddingInbound  int64 `json:"paddingInbound"`
	PaddingOutbound int64 `json:"paddingOutbound"`

	// SampledAt is the server's clock when the snapshot was built.
	// The dashboard uses this to surface "data updated 12 s ago"
	// when the operator hasn't refreshed in a while.
	SampledAt time.Time `json:"sampledAt"`
}

// GET /api/dashboard/security-posture
//
// Surfaces SecurityPosture for the dashboard card. Read-only,
// permissions-checked by the same Auth middleware as the other
// /dashboard/* endpoints.
func GetSecurityPosture(c *gin.Context) {
	ctx := c.Request.Context()
	out := SecurityPosture{SampledAt: time.Now()}

	// ── 1. Locked accounts ──
	if db.RDBAuth != nil {
		var cursor uint64
		for {
			keys, next, err := db.RDBAuth.Scan(ctx, cursor, "login:fail:*", 200).Result()
			if err != nil {
				break
			}
			// Pull the failure counts in one pipeline rather than
			// N round-trips. We don't fetch SystemConfig.LoginMaxFailures
			// here on every key — instead we read it once and compare
			// in-memory below.
			if len(keys) > 0 {
				pipe := db.RDBAuth.Pipeline()
				cmds := make([]interface{ Val() string }, 0, len(keys))
				for _, k := range keys {
					cmds = append(cmds, pipe.Get(ctx, k))
				}
				_, _ = pipe.Exec(ctx)

				maxFails := lockMaxFailuresFromCfg()
				for _, cm := range cmds {
					n := atoiSafe(cm.Val())
					if n >= maxFails {
						out.LockedAccounts++
					}
				}
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}
	}

	// ── 2 + 3. Active sessions / online users ──
	if db.RDBSession != nil {
		var cursor uint64
		for {
			keys, next, err := db.RDBSession.Scan(ctx, cursor, "user:sids:*", 200).Result()
			if err != nil {
				break
			}
			for _, k := range keys {
				if n, err := db.RDBSession.ZCard(ctx, k).Result(); err == nil && n > 0 {
					out.ActiveSessions += n
					out.OnlineUsers++ // one key per userID
				}
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}
	}

	// ── 4. Kicks in the last 24h ──
	cutoff := time.Now().Add(-24 * time.Hour)
	_ = db.DB.Model(&model.OperationLog{}).
		Where("action IN ? AND created_at >= ?",
			[]string{"强制下线", "下线会话"}, cutoff).
		Count(&out.KickedLast24h).Error

	// ── 5. Password-overdue users ──
	if cfg := loadSystemConfigForPosture(); cfg.PwdExpireDays > 0 {
		expiryCutoff := time.Now().AddDate(0, 0, -cfg.PwdExpireDays)
		_ = db.DB.Model(&model.User{}).
			Where("password_changed_at IS NOT NULL AND password_changed_at < ?", expiryCutoff).
			Count(&out.OverduePasswordUsers).Error
	}

	// ── 6. Padding counters ──
	snap := dnsengine.Snapshot()
	out.PaddingInbound = snap.PaddingInbound
	out.PaddingOutbound = snap.PaddingOutbound

	resp.OK(c, out)
}

// lockMaxFailuresFromCfg reads the threshold once. Cached for 30 s
// in this file to avoid hammering MySQL on every dashboard refresh —
// the threshold is a system-config knob, not a hot field.
var (
	postureCfgCache    model.SystemConfig
	postureCfgCachedAt time.Time
)

func loadSystemConfigForPosture() model.SystemConfig {
	if time.Since(postureCfgCachedAt) < 30*time.Second && postureCfgCache.ID != 0 {
		return postureCfgCache
	}
	var cfg model.SystemConfig
	if err := db.DB.First(&cfg, 1).Error; err == nil {
		postureCfgCache = cfg
		postureCfgCachedAt = time.Now()
	}
	return postureCfgCache
}

func lockMaxFailuresFromCfg() int {
	cfg := loadSystemConfigForPosture()
	if cfg.LoginMaxFailures > 0 {
		return cfg.LoginMaxFailures
	}
	return 5 // matches defaultLoginFailMax in auth.go
}

// atoiSafe parses a string into int, returning 0 on any error.
// Used for Redis-stored counters where we trust our own writers
// not to insert garbage but still don't want a panic on edge cases.
func atoiSafe(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

// avoid "imported and not used" if the dev-loop order swaps. The
// real call site is GetSecurityPosture above.
var _ = context.Background

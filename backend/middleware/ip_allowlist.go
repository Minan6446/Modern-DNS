package middleware

import (
	"net"
	"strings"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
)

// IPAllowlist gates the admin surface (login + protected routes) against the
// CIDR list configured in SystemConfig.IPWhitelist. Behaviour:
//
//   - Empty list → allow everyone (default).
//   - Loopback (127.0.0.1 / ::1) is always allowed so an operator who
//     mis-configures the list can recover via local shell + DB edit.
//   - Cluster peer endpoints (/api/cluster/internal/*) bypass this entirely
//     because they are gated by ClusterToken, not by an admin IP rule.
//
// The CIDR list is read fresh on every request: a single SELECT on a PK is
// sub-millisecond and avoids stale-cache hazards when the operator updates
// the whitelist via /api/setting/common.
func IPAllowlist() gin.HandlerFunc {
	return func(c *gin.Context) {
		var cfg model.SystemConfig
		if err := db.DB.First(&cfg, 1).Error; err != nil {
			// Bootstrapping (no row yet) — fail open so the operator can
			// finish first-run setup.
			c.Next()
			return
		}
		entries := SplitAllowlist(cfg.IPWhitelist)
		if len(entries) == 0 {
			c.Next()
			return
		}

		clientIP := c.ClientIP()
		ip := net.ParseIP(clientIP)
		if ip != nil && ip.IsLoopback() {
			c.Next()
			return
		}
		if ip == nil {
			resp.Forbidden(c, "客户端 IP 无效")
			return
		}

		for _, entry := range entries {
			if strings.Contains(entry, "/") {
				if _, cidr, err := net.ParseCIDR(entry); err == nil && cidr.Contains(ip) {
					c.Next()
					return
				}
				continue
			}
			if parsed := net.ParseIP(entry); parsed != nil && parsed.Equal(ip) {
				c.Next()
				return
			}
		}
		resp.Forbidden(c, "您的 IP 不在管理后台白名单内")
	}
}

// IPMatchesAllowlist reports whether `ip` is permitted by `raw`. Used by
// settings save flow to detect "operator about to lock themselves out"
// before persisting the new whitelist. Same semantics as the middleware:
//
//   - Empty allowlist → allow (caller must check raw == "" if it cares).
//   - Loopback always allowed.
//   - Plain IPs are equality-matched; CIDR entries are tested via
//     net.ParseCIDR.Contains.
func IPMatchesAllowlist(raw, ip string) bool {
	entries := SplitAllowlist(raw)
	if len(entries) == 0 {
		return true
	}
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() {
		return true
	}
	for _, entry := range entries {
		if strings.Contains(entry, "/") {
			if _, cidr, err := net.ParseCIDR(entry); err == nil && cidr.Contains(parsed) {
				return true
			}
			continue
		}
		if p := net.ParseIP(entry); p != nil && p.Equal(parsed) {
			return true
		}
	}
	return false
}

// SplitAllowlist normalises operator input. The textarea on the General
// Settings page lets users separate entries by newlines, commas, semicolons
// or spaces; we accept all of them so a paste from spreadsheets / configs
// just works.
func SplitAllowlist(raw string) []string {
	s := raw
	for _, sep := range []string{"\r\n", "\n", ";", " ", "\t"} {
		s = strings.ReplaceAll(s, sep, ",")
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

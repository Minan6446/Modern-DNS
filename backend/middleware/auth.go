package middleware

import (
	"strings"
	"sync/atomic"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"
	"modern-dns/pkg/jwt"
	"modern-dns/pkg/resp"
	"modern-dns/pkg/session"

	"github.com/gin-gonic/gin"
)

const CtxUserKey = "claims"

// legacyGraceCache holds the operator-configured cutoff (in days) for
// accepting JWTs minted before the MaxConcurrentLogin upgrade — i.e.
// tokens with no Sid claim. The auth middleware hits the DB at most
// once every 30 seconds (a save handler could call invalidate, but
// the value rarely changes after initial deploy and a 30 s lag is
// acceptable for a soft-deadline knob).
var (
	legacyGraceDays  atomic.Int32
	legacyGraceTS    atomic.Int64
	legacyGraceTTLNs = int64(30 * time.Second)
)

func legacyGraceCutoff() time.Time {
	now := time.Now()
	last := legacyGraceTS.Load()
	if last == 0 || now.UnixNano()-last > legacyGraceTTLNs {
		days := int32(7) // safe default if DB read fails
		if db.DB != nil {
			var cfg model.SystemConfig
			if err := db.DB.Select("session_legacy_grace_days").First(&cfg, 1).Error; err == nil {
				days = int32(cfg.SessionLegacyGraceDays)
			}
		}
		legacyGraceDays.Store(days)
		legacyGraceTS.Store(now.UnixNano())
	}
	d := legacyGraceDays.Load()
	if d <= 0 {
		// 0 = disabled; sentinel zero-time means "never reject for age".
		return time.Time{}
	}
	return now.Add(-time.Duration(d) * 24 * time.Hour)
}

func Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Pull the bearer token from the Authorization header in the
		// normal case; fall back to a `?token=` query parameter so the
		// SSE endpoint (EventSource cannot set custom headers) and
		// download links can authenticate the same way.
		var tokenStr string
		if header := c.GetHeader("Authorization"); strings.HasPrefix(header, "Bearer ") {
			tokenStr = strings.TrimPrefix(header, "Bearer ")
		} else if q := c.Query("token"); q != "" {
			tokenStr = q
		} else {
			resp.Unauthorized(c, "缺少认证令牌")
			return
		}
		claims, err := jwt.Parse(tokenStr)
		if err != nil {
			resp.Unauthorized(c, "令牌无效或已过期")
			return
		}
		if claims.Type != "access" {
			resp.Unauthorized(c, "令牌类型错误")
			return
		}
		// Legacy-token soft-deadline: a token with no Sid was minted
		// before the MaxConcurrentLogin upgrade. We accepted them
		// indefinitely during the initial roll-out, but past
		// SessionLegacyGraceDays from IssuedAt we 401 so an attacker
		// who stashed a pre-upgrade token can't keep using it forever.
		// Active users will have rotated through refresh-token at
		// least once well before the deadline lands.
		if claims.Sid == "" && claims.IssuedAt != nil {
			cutoff := legacyGraceCutoff()
			if !cutoff.IsZero() && claims.IssuedAt.Time.Before(cutoff) {
				resp.Unauthorized(c, "令牌版本过旧，请重新登录")
				return
			}
		}
		// MaxConcurrentLogin enforcement: when the token carries a sid
		// (i.e. was minted post-2026-Q3) we re-check against the
		// Redis-backed session table. Tokens without a sid that pass
		// the soft-deadline above degrade to trust-the-signature.
		if !session.IsLive(c.Request.Context(), claims.UserID, claims.Sid) {
			resp.Unauthorized(c, "会话已被踢出，请重新登录")
			return
		}
		c.Set(CtxUserKey, claims)
		c.Next()
	}
}

// AuthEnrollment accepts access OR enrollment tokens. Mounted only on the
// TOTP setup/verify endpoints so a user trapped in the MFA-required-but-
// not-yet-enrolled state can finish enrolment with their short-lived
// enrollment token, while regular voluntary-enable flows from logged-in
// users keep working with their normal access token.
func AuthEnrollment() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			resp.Unauthorized(c, "缺少认证令牌")
			return
		}
		tokenStr := strings.TrimPrefix(header, "Bearer ")
		claims, err := jwt.Parse(tokenStr)
		if err != nil {
			resp.Unauthorized(c, "令牌无效或已过期")
			return
		}
		if claims.Type != "access" && claims.Type != "enrollment" {
			resp.Unauthorized(c, "令牌类型错误")
			return
		}
		c.Set(CtxUserKey, claims)
		c.Next()
	}
}

func GetClaims(c *gin.Context) *jwt.Claims {
	val, _ := c.Get(CtxUserKey)
	claims, _ := val.(*jwt.Claims)
	return claims
}

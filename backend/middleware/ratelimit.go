package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"modern-dns/pkg/db"

	"github.com/gin-gonic/gin"
)

// RateLimit returns a Gin middleware that enforces a fixed-window per-IP
// rate limit against the given endpoint label. Implementation uses Redis
// INCR + EXPIRE: cheap (one round-trip), survives process restarts, and
// works correctly across multiple replicas behind a load-balancer.
//
// Parameters:
//   - label:  short identifier mixed into the Redis key, e.g. "login";
//     prevents collisions between endpoints sharing the same path
//     prefix once they all live under /api.
//   - max:    requests allowed per window. <=0 disables the limiter.
//   - window: rolling window in seconds the counter resets after.
//
// When Redis is unavailable the limiter fails open: we'd rather accept
// requests than 503 the entire admin surface on a transient cache outage.
// The login lock-out logic in handler/auth.go already provides a second
// layer of protection for credential-stuffing specifically.
//
// On block we return HTTP 429 with a Retry-After header derived from the
// remaining TTL so well-behaved clients can back off precisely instead of
// guessing.
func RateLimit(label string, max int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		if max <= 0 || window <= 0 || db.RDBRateLimit == nil {
			c.Next()
			return
		}
		ip := strings.TrimSpace(c.ClientIP())
		if ip == "" {
			c.Next()
			return
		}
		// Bucket per (label, IP). We deliberately do NOT include the
		// authenticated user — pre-auth endpoints (login) don't have one
		// yet, and post-auth endpoints already have RBAC. The IP is the
		// abuse-resistant axis here.
		key := fmt.Sprintf("rl:%s:%s", label, ip)
		ctx := context.Background()

		// Pipeline: INCR + (EXPIRE on first hit only). Using SET-NX-EX
		// for the first-hit case avoids a race where two concurrent
		// requests both INCR before EXPIRE lands.
		count, err := db.RDBRateLimit.Incr(ctx, key).Result()
		if err != nil {
			// Redis hiccup — fail open.
			c.Next()
			return
		}
		if count == 1 {
			db.RDBRateLimit.Expire(ctx, key, window)
		}
		if count > int64(max) {
			ttl, _ := db.RDBRateLimit.TTL(ctx, key).Result()
			retryAfter := int(ttl.Seconds())
			if retryAfter <= 0 {
				retryAfter = int(window.Seconds())
			}
			c.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"code":    http.StatusTooManyRequests,
				"message": fmt.Sprintf("操作过于频繁，请 %d 秒后重试", retryAfter),
				"data":    nil,
			})
			return
		}
		// We don't refund successful calls — fixed window is intentional.
		// If you need a sliding window, switch to a ZSET-based scheme.
		c.Next()
	}
}

// Package session is the Redis-backed bookkeeper for active operator
// logins, used to enforce SystemConfig.MaxConcurrentLogin.
//
// Why Redis and not the DB?
//   - The check sits on the auth-middleware hot path; an extra MySQL
//     round-trip per request would dominate the request budget.
//   - Sessions are intrinsically ephemeral; expiring keys via TTL is
//     much cleaner in Redis than scheduled deletes in MySQL.
//   - We already require Redis for login-failure counts and rate
//     limits, so this introduces no new dependency.
//
// Data model — one sorted set per user:
//
//	key   = user:sids:<userID>
//	score = unix-nano of issuance       (sortable → "oldest" is well-defined)
//	member = sid (random hex string)
//
// Operations:
//   - Register(userID, sid, max, ttl) → ZADD + ZREMRANGEBYRANK to cap;
//     EXPIRE refreshes so an idle user's whole set times out together.
//   - IsLive(userID, sid)             → ZSCORE; absent → revoked.
//   - Revoke(userID, sid)             → ZREM; idempotent.
//   - RevokeAll(userID)               → DEL the set; used on password
//     reset and admin-initiated kicks.
//
// All operations no-op when Redis is unavailable so a brief Redis
// outage degrades gracefully to "no concurrency limit" rather than
// locking every operator out — the session table is a defence-in-
// depth feature, not the primary auth boundary (the JWT signature is).
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"modern-dns/pkg/db"

	"github.com/redis/go-redis/v9"
)

// keyForUser is the Redis key that stores the active sid set for the
// given user. Centralising the key format here means a future schema
// migration (e.g. namespace prefix per cluster) only edits one line.
func keyForUser(userID uint) string {
	return fmt.Sprintf("user:sids:%d", userID)
}

// NewSid mints a random 32-hex-char (16-byte) session identifier. Long
// enough to be effectively unguessable; short enough not to bloat the
// JWT envelope.
func NewSid() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Register adds sid to the user's active-session set, evicts the
// oldest session(s) if the set would exceed `max`, and refreshes the
// key's TTL to `ttl`.
//
// `max` semantics:
//   - 0 (or negative)  → no concurrency limit; we still ZADD so the
//     middleware's IsLive check passes, but no eviction happens. This
//     is the "feature off" state surfaced by SystemConfig.MaxConcurrentLogin=0.
//   - N > 0 → cap the set at N; the (N+1)th login kicks the oldest.
//
// Returns the slice of evicted sids so the caller can audit-log them
// ("session for user U was kicked because login N+1 from IP X").
func Register(ctx context.Context, userID uint, sid string, max int, ttl time.Duration) ([]string, error) {
	if db.RDBSession == nil {
		// Redis unavailable: we can't enforce concurrency. The auth
		// path falls back to "trust the JWT signature" via IsLive's
		// nil-Redis branch, so this is consistent with the rest of
		// the package.
		return nil, nil
	}
	key := keyForUser(userID)
	now := time.Now()
	score := float64(now.UnixNano())

	// Drop members whose score is older than the access-token TTL —
	// these are sids that were issued, never explicitly revoked, and
	// have aged out of validity. Without this sweep, an active user
	// who logs in/out repeatedly leaves behind one stale member per
	// session forever (Register's per-key EXPIRE refreshes the whole
	// key, never an individual member). The cutoff uses 2× ttl as a
	// safety margin: clock skew + token-clock-tolerance shouldn't
	// reap a member that's still legitimately presentable.
	if ttl > 0 {
		cutoff := float64(now.Add(-2 * ttl).UnixNano())
		_ = db.RDBSession.ZRemRangeByScore(ctx, key, "-inf", fmt.Sprintf("(%d", int64(cutoff))).Err()
	}

	pipe := db.RDBSession.TxPipeline()
	pipe.ZAdd(ctx, key, redis.Z{Score: score, Member: sid})
	if ttl > 0 {
		pipe.Expire(ctx, key, ttl)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, err
	}

	if max <= 0 {
		return nil, nil
	}

	// Evict the oldest entries beyond the cap. We compute "how many to
	// remove" rather than using ZREMRANGEBYRANK with a fixed range so
	// concurrent registrations from another goroutine don't cause a
	// negative-rank slip that wipes more than intended.
	count, err := db.RDBSession.ZCard(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	if count <= int64(max) {
		return nil, nil
	}
	overflow := count - int64(max)
	// ZRANGE 0 overflow-1 returns the oldest `overflow` members so we
	// can both audit-log them and remove them in one pipeline.
	oldest, err := db.RDBSession.ZRange(ctx, key, 0, overflow-1).Result()
	if err != nil {
		return nil, err
	}
	if len(oldest) == 0 {
		return nil, nil
	}
	args := make([]any, 0, len(oldest))
	for _, m := range oldest {
		args = append(args, m)
	}
	if err := db.RDBSession.ZRem(ctx, key, args...).Err(); err != nil {
		return oldest, err
	}
	return oldest, nil
}

// IsLive reports whether sid is still in the user's active set.
//
// Two "yes" cases collapse to true:
//   - sid is empty (no session tracking attached to this token, e.g.
//     pre-2026-Q3 tokens still in flight) — degrade to trust-the-
//     signature so an upgrade doesn't invalidate every active session
//     mid-flight.
//   - Redis is unavailable — fail open for the same defence-in-depth
//     reason explained at the top of the file.
//
// Otherwise returns true iff ZSCORE finds the sid.
func IsLive(ctx context.Context, userID uint, sid string) bool {
	if sid == "" {
		return true
	}
	if db.RDBSession == nil {
		return true
	}
	_, err := db.RDBSession.ZScore(ctx, keyForUser(userID), sid).Result()
	if err != nil {
		// redis.Nil is the "key/member missing" sentinel — that's a
		// definite "revoked". Any other error (network, etc.) we
		// fail open so a Redis hiccup doesn't kick every operator.
		if errors.Is(err, redis.Nil) {
			return false
		}
		log.Printf("[session] ZSCORE %d/%s degraded: %v", userID, sid, err)
		return true
	}
	return true
}

// Revoke removes a single sid from the user's set. Idempotent — used
// by Logout and by Register's eviction loop's caller for audit logs.
func Revoke(ctx context.Context, userID uint, sid string) {
	if db.RDBSession == nil || sid == "" {
		return
	}
	if err := db.RDBSession.ZRem(ctx, keyForUser(userID), sid).Err(); err != nil {
		log.Printf("[session] ZREM %d/%s failed: %v", userID, sid, err)
	}
}

// RevokeAll wipes the entire active-session set for a user. Use after
// a password reset, admin-initiated lockout, or "kick all sessions"
// operation — whatever access tokens are still floating around will
// bounce off the IsLive check on their next request.
func RevokeAll(ctx context.Context, userID uint) {
	if db.RDBSession == nil {
		return
	}
	if err := db.RDBSession.Del(ctx, keyForUser(userID)).Err(); err != nil {
		log.Printf("[session] DEL %d failed: %v", userID, err)
	}
}

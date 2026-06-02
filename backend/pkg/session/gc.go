// gc.go runs a periodic background sweep that removes session-table
// members whose score (issuance time) has aged past the access-token
// TTL. The complementary in-Register sweep (see session.go) handles
// the busy-user case; this loop catches the abandoned-account case
// where a user logged in once weeks ago and never came back — their
// per-key EXPIRE has long fired, but until that fire moment the
// online-users tab would have surfaced a ghost row.
//
// Trade-offs vs alternatives we considered:
//
//   - "ZREM on IsLive miss" was the original sketch. Doesn't help:
//     when the sid is missing, ZREM is a no-op (member already
//     absent). The ghost case we actually need to clean is members
//     that are *present* but past their TTL.
//   - "Per-member key with EXPIRE" was rejected because the user-
//     management page wants O(1) ZCARD-style lookups; one key per
//     sid would force a SCAN to count active sessions.
//
// SCAN is intentional rather than KEYS — non-blocking, plays nice
// with Redis Cluster shards. The default 1-minute interval is well
// under the typical access-TTL (15 min) so a stale member is removed
// before any operator notices it on the online-users tab.
package session

import (
	"context"
	"fmt"
	"log"
	"time"

	"modern-dns/pkg/db"
)

// GCConfig parametrises the background sweep. Caller should keep
// the same values that govern Register's access-token TTL so the
// "older than TTL × 2" cutoff stays consistent across both paths.
type GCConfig struct {
	// Interval between sweeps. Zero or negative defaults to 1 min.
	Interval time.Duration
	// AccessTTL is the same TTL Register receives. Members older
	// than 2× this are reaped. Zero disables score-based reap (only
	// orphan-keyspace scanning remains useful).
	AccessTTL time.Duration
}

// RunGC blocks until ctx is done, sweeping the session table on
// every tick. Designed to be launched from main as
//
//	go session.RunGC(ctx, session.GCConfig{Interval: time.Minute, AccessTTL: 15*time.Minute})
//
// Cheap when the system is idle (one SCAN cursor pass + zero
// ZREMRANGEBYSCORE removals). The first tick fires after one
// interval; we don't kick on entry because the in-Register sweep
// already covers fresh-startup load.
func RunGC(ctx context.Context, cfg GCConfig) {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	t := time.NewTicker(cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweepOnce(ctx, cfg.AccessTTL)
		}
	}
}

// sweepOnce performs one pass over user:sids:* keys, removing
// members with score below `now - 2*accessTTL`. Public so a future
// admin "force GC" button can call it without waiting for the next
// tick.
func sweepOnce(ctx context.Context, accessTTL time.Duration) {
	if db.RDBSession == nil {
		return
	}
	cutoff := time.Now().Add(-2 * accessTTL).UnixNano()
	if accessTTL <= 0 {
		// No cutoff to apply — nothing to do until the operator
		// gives us an access-TTL hint.
		return
	}

	var (
		cursor  uint64
		scanned int
		removed int64
		passes  int
	)
	const safetyCap = 64 // bound iterations so a runaway keyspace can't pin a goroutine
	for {
		batch, next, err := db.RDBSession.Scan(ctx, cursor, "user:sids:*", 200).Result()
		if err != nil {
			log.Printf("[session/gc] SCAN cursor=%d failed: %v", cursor, err)
			return
		}
		scanned += len(batch)
		for _, k := range batch {
			n, err := db.RDBSession.ZRemRangeByScore(ctx, k,
				"-inf", fmt.Sprintf("(%d", cutoff)).Result()
			if err != nil {
				// A single key failing shouldn't abort the whole
				// sweep — log and keep going.
				log.Printf("[session/gc] ZREMRANGEBYSCORE %s: %v", k, err)
				continue
			}
			removed += n
		}
		cursor = next
		passes++
		if cursor == 0 || passes >= safetyCap {
			break
		}
	}
	if removed > 0 {
		log.Printf("[session/gc] reaped %d stale sids across %d keys", removed, scanned)
	}
}

package db

import (
	"context"
	"log"

	"modern-dns/config"

	"github.com/redis/go-redis/v9"
)

var RDB *redis.Client
var RDBCache *redis.Client
var RDBSession *redis.Client
var RDBRateLimit *redis.Client
var RDBAuth *redis.Client

func pickDB(preferred, fallback int) int {
	if preferred >= 0 {
		return preferred
	}
	return fallback
}

func newClient(dbIndex int) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     config.C.Redis.Addr,
		Password: config.C.Redis.Password,
		DB:       dbIndex,
	})
}

func initClient(name string, dbIndex int) *redis.Client {
	client := newClient(dbIndex)
	if err := client.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("[redis] connect failed (%s, db=%d): %v", name, dbIndex, err)
	}
	log.Printf("[redis] connected (%s, db=%d)", name, dbIndex)
	return client
}

func InitRedis() {
	fallbackDB := config.C.Redis.DB
	cacheDB := pickDB(config.C.Redis.CacheDB, fallbackDB)
	sessionDB := pickDB(config.C.Redis.SessionDB, fallbackDB)
	rateLimitDB := pickDB(config.C.Redis.RateLimitDB, fallbackDB)
	authDB := pickDB(config.C.Redis.AuthDB, fallbackDB)

	RDBCache = initClient("cache", cacheDB)
	RDBSession = initClient("session", sessionDB)
	RDBRateLimit = initClient("ratelimit", rateLimitDB)
	RDBAuth = initClient("auth", authDB)

	// Legacy alias kept for backward compatibility with yet-to-be-migrated
	// call sites. New code should use the per-concern clients above.
	RDB = RDBCache
}

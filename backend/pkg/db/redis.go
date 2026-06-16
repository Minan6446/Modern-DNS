package db

import (
	"context"
	"fmt"
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

func initClient(name string, dbIndex int) (*redis.Client, error) {
	client := newClient(dbIndex)
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("redis connect (%s, db=%d): %w", name, dbIndex, err)
	}
	log.Printf("[redis] connected (%s, db=%d)", name, dbIndex)
	return client, nil
}

func InitRedis() error {
	fallbackDB := config.C.Redis.DB
	cacheDB := pickDB(config.C.Redis.CacheDB, fallbackDB)
	sessionDB := pickDB(config.C.Redis.SessionDB, fallbackDB)
	rateLimitDB := pickDB(config.C.Redis.RateLimitDB, fallbackDB)
	authDB := pickDB(config.C.Redis.AuthDB, fallbackDB)

	var err error
	RDBCache, err = initClient("cache", cacheDB)
	if err != nil {
		return err
	}
	RDBSession, err = initClient("session", sessionDB)
	if err != nil {
		return err
	}
	RDBRateLimit, err = initClient("ratelimit", rateLimitDB)
	if err != nil {
		return err
	}
	RDBAuth, err = initClient("auth", authDB)
	if err != nil {
		return err
	}

	// Legacy alias kept for backward compatibility with yet-to-be-migrated
	// call sites. New code should use the per-concern clients above.
	RDB = RDBCache
	return nil
}

package config

import (
	"fmt"
	"log"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server  ServerConfig
	MySQL   MySQLConfig
	Redis   RedisConfig
	JWT     JWTConfig
	DNS     DNSConfig
	Cluster ClusterConfig
}

type ClusterConfig struct {
	HTTPSEnabled            bool            `mapstructure:"https_enabled"`
	HTTPSPort               string          `mapstructure:"https_port"`
	CertDir                 string          `mapstructure:"cert_dir"`
	HeartbeatIntervalSec    int             `mapstructure:"heartbeat_interval_sec"`
	ConfigRefreshSec        int             `mapstructure:"config_refresh_sec"`
	IgnoreCertificateErrors bool            `mapstructure:"ignore_certificate_errors"`
	Secondary               SecondaryConfig `mapstructure:"secondary"`
}

// SecondaryConfig describes how a non-primary node bootstraps itself: where
// the primary lives, which token to present, and what label to advertise.
type SecondaryConfig struct {
	Enabled    bool     `mapstructure:"enabled"`
	PrimaryURL string   `mapstructure:"primary_url"`
	APIToken   string   `mapstructure:"api_token"`
	NodeName   string   `mapstructure:"node_name"`
	NodeID     string   `mapstructure:"node_id"`
	IPAddrs    []string `mapstructure:"ip_addresses"`
	Zone       string   `mapstructure:"zone"`
	Version    string   `mapstructure:"version"`
}

type ServerConfig struct {
	Port string
	Mode string
	// TrustedProxies tells gin which CIDR/IP ranges may legitimately
	// terminate X-Forwarded-For / X-Real-IP. When empty we lock down
	// to loopback only — gin's default behaviour of trusting *all*
	// proxies (and the noisy startup warning that goes with it) lets
	// any caller forge ClientIP() by setting their own XFF, which
	// breaks the IP whitelist, login-failure counter, and audit logs.
	TrustedProxies []string `mapstructure:"trusted_proxies"`
}

type MySQLConfig struct {
	DSN string
}

type RedisConfig struct {
	Addr        string
	Password    string
	DB          int
	CacheDB     int `mapstructure:"cache_db"`
	SessionDB   int `mapstructure:"session_db"`
	RateLimitDB int `mapstructure:"ratelimit_db"`
	AuthDB      int `mapstructure:"auth_db"`
}

type DNSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Listen   string `mapstructure:"listen"`
	DoTPort  string `mapstructure:"dot_port"`  // DNS-over-TLS, default "853"
	DoHPort  string `mapstructure:"doh_port"`  // DNS-over-HTTPS, default "443"
	CertFile string `mapstructure:"cert_file"` // TLS cert PEM (shared DoT+DoH)
	KeyFile  string `mapstructure:"key_file"`  // TLS key  PEM
}

type JWTConfig struct {
	Secret          string `mapstructure:"secret"`
	AccessExpireMin int    `mapstructure:"access_expire_min"`
	RefreshExpireH  int    `mapstructure:"refresh_expire_h"`
}

var C Config

func Init() error {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	viper.SetDefault("server.port", "8080")
	viper.SetDefault("server.mode", "debug")
	viper.SetDefault("mysql.dsn", "root:password@tcp(127.0.0.1:3306)/modern_dns?charset=utf8mb4&parseTime=True&loc=Local")
	viper.SetDefault("redis.addr", "127.0.0.1:6379")
	viper.SetDefault("redis.password", "")
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.cache_db", -1)
	viper.SetDefault("redis.session_db", -1)
	viper.SetDefault("redis.ratelimit_db", -1)
	viper.SetDefault("redis.auth_db", -1)
	viper.SetDefault("dns.enabled", true)
	viper.SetDefault("dns.listen", ":53")
	viper.SetDefault("dns.dot_port", "853")
	viper.SetDefault("dns.doh_port", "443")
	viper.SetDefault("dns.cert_file", "")
	viper.SetDefault("dns.key_file", "")

	viper.SetDefault("jwt.secret", "modern-dns-secret-change-in-production")
	viper.SetDefault("jwt.access_expire_min", 60)
	viper.SetDefault("jwt.refresh_expire_h", 168)

	viper.SetDefault("cluster.https_enabled", false)
	viper.SetDefault("cluster.https_port", "8443")
	viper.SetDefault("cluster.cert_dir", "./certs")
	viper.SetDefault("cluster.heartbeat_interval_sec", 5)
	viper.SetDefault("cluster.config_refresh_sec", 30)
	viper.SetDefault("cluster.ignore_certificate_errors", false)

	if err := viper.ReadInConfig(); err != nil {
		log.Printf("[config] no config file found, using defaults: %v", err)
	}

	if err := viper.Unmarshal(&C); err != nil {
		return fmt.Errorf("unmarshal config: %w", err)
	}
	return nil
}

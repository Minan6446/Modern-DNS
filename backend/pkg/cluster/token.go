package cluster

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"
)

// HeaderClusterToken is the HTTP header carrying the cluster API token on
// inter-node calls. Each request from a peer must include this header with the
// shared cluster token; otherwise the cluster middleware returns 401.
const HeaderClusterToken = "X-Cluster-Token"

var (
	tokenMu sync.RWMutex
	token   string
	// prevToken / prevExpiresAt support seamless rotation: when an operator
	// rotates the cluster token, the old one keeps verifying for a brief
	// grace window so already-running secondaries can refresh credentials
	// on their next heartbeat without dropping the cluster.
	prevToken     string
	prevExpiresAt time.Time
)

// GenerateToken returns a 32-byte hex token suitable for use as the cluster
// API token. The caller is responsible for persisting it on the singleton
// ClusterSettings row.
func GenerateToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// SetToken caches the active cluster token in memory; cleared on DeleteCluster.
func SetToken(t string) {
	tokenMu.Lock()
	token = strings.TrimSpace(t)
	tokenMu.Unlock()
}

// CurrentToken returns the in-memory token (may be empty when uninitialized).
func CurrentToken() string {
	tokenMu.RLock()
	defer tokenMu.RUnlock()
	return token
}

// LoadTokenFromDB hydrates the in-memory token from cluster_settings on boot.
// Returns true when a non-empty token is found.
func LoadTokenFromDB() bool {
	var s model.ClusterSettings
	if err := db.DB.First(&s, 1).Error; err != nil {
		return false
	}
	if s.APIToken == "" {
		return false
	}
	SetToken(s.APIToken)
	return true
}

// VerifyToken does a constant-time-ish comparison between the supplied token
// and the active cluster token. During a rotation grace window the previous
// token also verifies — that lets running secondaries finish their next
// heartbeat with the old credential and pick up the new one from the
// /state response. Empty active token rejects everything.
func VerifyToken(supplied string) bool {
	s := strings.TrimSpace(supplied)
	if s == "" {
		return false
	}
	tokenMu.RLock()
	current := token
	prev := prevToken
	prevExp := prevExpiresAt
	tokenMu.RUnlock()
	if current == "" {
		return false
	}
	if strings.EqualFold(s, current) {
		return true
	}
	if prev != "" && time.Now().Before(prevExp) && strings.EqualFold(s, prev) {
		return true
	}
	return false
}

// RotateToken installs a freshly-generated token as current and demotes the
// previous one to a grace-window slot so in-flight secondary calls keep
// authenticating until they refresh. Returns the new token string. Caller
// is responsible for persisting it onto cluster_settings.api_token.
func RotateToken(grace time.Duration) string {
	if grace <= 0 {
		grace = 60 * time.Second
	}
	newToken := GenerateToken()
	tokenMu.Lock()
	prevToken = token
	prevExpiresAt = time.Now().Add(grace)
	token = newToken
	tokenMu.Unlock()
	return newToken
}

// PreviousToken returns the still-valid prev token + remaining grace duration,
// or ("", 0) when no rotation is currently within the grace window.
func PreviousToken() (string, time.Duration) {
	tokenMu.RLock()
	defer tokenMu.RUnlock()
	if prevToken == "" {
		return "", 0
	}
	remaining := time.Until(prevExpiresAt)
	if remaining <= 0 {
		return "", 0
	}
	return prevToken, remaining
}

// LoadPinsFromDB rebuilds the in-memory pin store from cluster_nodes rows,
// using each node's stored PEM certificate. Called once during boot after
// the database is up; no-op when the table is empty.
func LoadPinsFromDB() int {
	var rows []struct {
		URL         string
		Certificate string
	}
	if err := db.DB.Table("cluster_nodes").Select("url, certificate").
		Where("certificate <> '' AND url <> ''").Scan(&rows).Error; err != nil {
		return 0
	}
	loaded := 0
	for _, r := range rows {
		fp := FingerprintPEM(r.Certificate)
		if fp == "" {
			continue
		}
		host := extractHost(r.URL)
		if host == "" {
			continue
		}
		SetPin(host, fp)
		loaded++
	}
	return loaded
}

// extractHost is duplicated here to keep this package self-contained.
func extractHost(rawURL string) string {
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(strings.ToLower(rawURL), prefix) {
			rest := rawURL[len(prefix):]
			if end := strings.IndexAny(rest, "/?#"); end >= 0 {
				rest = rest[:end]
			}
			return rest
		}
	}
	return ""
}

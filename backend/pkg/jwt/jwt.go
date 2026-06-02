package jwt

import (
	"errors"
	"time"

	"modern-dns/config"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID   uint   `json:"uid"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Type     string `json:"type"` // "access" | "refresh" | "enrollment"
	// Sid is a per-login session identifier embedded in access /
	// refresh tokens (omitted from enrollment-stage tokens). It is
	// the lookup key in the Redis-backed session table that powers
	// SystemConfig.MaxConcurrentLogin enforcement: the auth
	// middleware re-checks the sid is still live, and the operator
	// can kick a session by simply removing the sid from the set.
	//
	// Empty Sid means "no session tracking applied" — used for
	// pre-2026-Q3 tokens still in flight after an upgrade, and for
	// tokens minted by paths that don't go through Login (e.g.
	// internal cluster service tokens). The middleware degrades to
	// trust-the-signature when Sid is blank, so old tokens keep
	// working until they naturally expire.
	Sid string `json:"sid,omitempty"`
	jwtlib.RegisteredClaims
}

// SignAccess uses the default TTL configured in config.yaml.
func SignAccess(userID uint, username, role string) (string, error) {
	return SignAccessWithTTL(userID, username, role, 0)
}

// SignAccessWithTTL mints an access token with the given lifetime. A ttl of
// zero falls back to config.C.JWT.AccessExpireMin so callers that don't need
// dynamic session length keep working unchanged. The caller is expected to
// resolve the dynamic value (e.g. SystemConfig.LoginTimeoutMinutes) before
// invoking this entry point.
//
// Returns a token with no Sid claim. New code on the Login path should
// prefer SignAccessWithSid so MaxConcurrentLogin enforcement works; this
// signature is preserved for callers (refresh-token rotation, MFA
// enrollment swap) that don't need session tracking.
func SignAccessWithTTL(userID uint, username, role string, ttl time.Duration) (string, error) {
	return SignAccessWithSid(userID, username, role, "", ttl)
}

// SignAccessWithSid is SignAccessWithTTL plus the per-login session
// identifier required for MaxConcurrentLogin enforcement. Callers
// generate the sid (random 16-byte hex is a reasonable default) and
// register it in the session table before issuing the token; the auth
// middleware re-checks the sid is still live on every request.
func SignAccessWithSid(userID uint, username, role, sid string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = time.Duration(config.C.JWT.AccessExpireMin) * time.Minute
	}
	claims := Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
		Type:     "access",
		Sid:      sid,
		RegisteredClaims: jwtlib.RegisteredClaims{
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwtlib.NewNumericDate(time.Now()),
		},
	}
	return jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims).SignedString([]byte(config.C.JWT.Secret))
}

// SignEnrollment mints a short-lived (5 min) token used solely by the
// "MFA enrollment in progress" flow. The bearer is a user who has just
// authenticated with username + password but cannot yet receive a full
// access token because SystemConfig.MFARequired = true and they have no
// TOTP secret bound. The middleware that accepts this token type only
// allows /api/auth/totp/setup and /api/auth/totp/verify; on a successful
// verify, the handler swaps it for a real access + refresh pair.
func SignEnrollment(userID uint, username, role string) (string, error) {
	claims := Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
		Type:     "enrollment",
		RegisteredClaims: jwtlib.RegisteredClaims{
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwtlib.NewNumericDate(time.Now()),
		},
	}
	return jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims).SignedString([]byte(config.C.JWT.Secret))
}

func SignRefresh(userID uint, username, role string) (string, error) {
	return SignRefreshWithSid(userID, username, role, "")
}

// SignRefreshWithSid pairs the refresh token with the same sid the
// access token carries, so refresh-token rotation can keep the
// session alive (re-Register's the existing sid) and Logout can
// revoke the whole session by sid alone.
func SignRefreshWithSid(userID uint, username, role, sid string) (string, error) {
	exp := time.Duration(config.C.JWT.RefreshExpireH) * time.Hour
	claims := Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
		Type:     "refresh",
		Sid:      sid,
		RegisteredClaims: jwtlib.RegisteredClaims{
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(exp)),
			IssuedAt:  jwtlib.NewNumericDate(time.Now()),
		},
	}
	return jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims).SignedString([]byte(config.C.JWT.Secret))
}

func Parse(tokenStr string) (*Claims, error) {
	token, err := jwtlib.ParseWithClaims(tokenStr, &Claims{}, func(t *jwtlib.Token) (any, error) {
		if _, ok := t.Method.(*jwtlib.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(config.C.JWT.Secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"
	"modern-dns/pkg/jwt"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// ─── test bootstrap ──────────────────────────────────────────────────────────

// setupSensitiveTest spins up an in-memory SQLite database, migrates the
// User model, seeds two fixture users (one with MFA, one without), and
// installs them as the global db.DB so the middleware's user lookup
// succeeds without touching MySQL. Each test case calls this in a
// t.Cleanup'd helper to keep the suite isolated and parallel-safe.
func setupSensitiveTest(t *testing.T) (mfaUser, plainUser *model.User) {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := gdb.AutoMigrate(&model.User{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	pwHash, err := bcrypt.GenerateFromPassword([]byte("correct-horse"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}

	plainUser = &model.User{Username: "alice", Password: string(pwHash), TOTPEnabled: false}
	mfaUser = &model.User{Username: "bob", Password: string(pwHash), TOTPEnabled: true, TOTPSecret: "JBSWY3DPEHPK3PXP"}
	if err := gdb.Create(plainUser).Error; err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	if err := gdb.Create(mfaUser).Error; err != nil {
		t.Fatalf("seed bob: %v", err)
	}

	prevDB := db.DB
	db.DB = gdb
	t.Cleanup(func() { db.DB = prevDB })

	// Reset the TOTP validator hook to a stub so each test case controls
	// it explicitly. Default = always-fail to surface accidental misuse.
	prevValidator := validateTOTPCodeForUser
	validateTOTPCodeForUser = func(*model.User, string) bool { return false }
	t.Cleanup(func() { validateTOTPCodeForUser = prevValidator })
	return mfaUser, plainUser
}

// buildSensitiveRouter creates a gin router with a fake-auth middleware
// (bypasses JWT signing entirely) followed by SensitiveConfirm and a
// terminal handler that just writes 200. The fake-auth shortcut keeps
// the test laser-focused on the middleware under test instead of the
// JWT plumbing, which has its own test coverage upstream.
func buildSensitiveRouter(uid uint, username string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(CtxUserKey, &jwt.Claims{UserID: uid, Username: username})
		c.Next()
	})
	r.POST("/sensitive", SensitiveConfirm(), func(c *gin.Context) {
		stepUp, _ := c.Get("step_up")
		c.JSON(http.StatusOK, gin.H{"ok": true, "stepUp": stepUp})
	})
	return r
}

// decodeBody is a tiny helper to keep the test bodies readable. Using
// json.Decoder directly clutters the assertions.
func decodeBody(t *testing.T, body []byte) map[string]any {
	t.Helper()
	out := map[string]any{}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return out
}

// ─── tests ───────────────────────────────────────────────────────────────────

// MissingHeaders asserts the unauthenticated path: when neither header
// is supplied, the middleware must short-circuit with 401 + sentinel
// 4401 and the requireConfirm flag in `data` so the frontend knows to
// pop the SensitiveConfirmModal.
func TestSensitiveConfirm_MissingHeaders(t *testing.T) {
	_, alice := setupSensitiveTest(t)
	r := buildSensitiveRouter(alice.ID, alice.Username)

	req := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	body := decodeBody(t, w.Body.Bytes())
	if int(body["code"].(float64)) != 4401 {
		t.Fatalf("code = %v, want 4401", body["code"])
	}
	data, _ := body["data"].(map[string]any)
	if data == nil || data["requireConfirm"] != true {
		t.Fatalf("data.requireConfirm = %v, want true", body["data"])
	}
	if data["mfaEnabled"] != false {
		t.Fatalf("data.mfaEnabled = %v, want false (alice has MFA off)", data["mfaEnabled"])
	}
}

// MissingHeaders_MFA covers the same shape as above but for an MFA user;
// the middleware must report mfaEnabled=true so the frontend defaults
// the modal to the TOTP method instead of the password input.
func TestSensitiveConfirm_MissingHeaders_MFA(t *testing.T) {
	bob, _ := setupSensitiveTest(t)
	r := buildSensitiveRouter(bob.ID, bob.Username)

	req := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	body := decodeBody(t, w.Body.Bytes())
	data, _ := body["data"].(map[string]any)
	if data["mfaEnabled"] != true {
		t.Fatalf("data.mfaEnabled = %v, want true", data["mfaEnabled"])
	}
}

// CorrectPassword exercises the happy-path password branch: the middleware
// must let the request through AND tag the gin context with step_up=password
// so writeOpLog can persist the proof type for audit.
func TestSensitiveConfirm_CorrectPassword(t *testing.T) {
	_, alice := setupSensitiveTest(t)
	r := buildSensitiveRouter(alice.ID, alice.Username)

	req := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
	req.Header.Set("X-Confirm-Password", "correct-horse")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w.Body.Bytes())
	if body["stepUp"] != "password" {
		t.Fatalf("stepUp = %v, want password", body["stepUp"])
	}
}

// WrongPassword: the middleware must reject without falling through to a
// password→OK path. We assert specifically on 4401 (not just any non-200)
// so a regression that swallows the bcrypt error wouldn't pass.
func TestSensitiveConfirm_WrongPassword(t *testing.T) {
	_, alice := setupSensitiveTest(t)
	r := buildSensitiveRouter(alice.ID, alice.Username)

	req := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
	req.Header.Set("X-Confirm-Password", "incorrect")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	body := decodeBody(t, w.Body.Bytes())
	if int(body["code"].(float64)) != 4401 {
		t.Fatalf("code = %v, want 4401", body["code"])
	}
}

// CorrectTOTP exercises the MFA branch with the validator hook stubbed to
// accept. We deliberately don't import the real otp library here — the
// validator is injected via SetTOTPValidator in production, so the
// middleware's own contract is just "delegate to the hook and trust it".
func TestSensitiveConfirm_CorrectTOTP(t *testing.T) {
	bob, _ := setupSensitiveTest(t)
	validateTOTPCodeForUser = func(u *model.User, code string) bool {
		return u.ID == bob.ID && code == "123456"
	}
	r := buildSensitiveRouter(bob.ID, bob.Username)

	req := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
	req.Header.Set("X-Confirm-TOTP", "123456")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w.Body.Bytes())
	if body["stepUp"] != "totp" {
		t.Fatalf("stepUp = %v, want totp", body["stepUp"])
	}
}

// WrongTOTP: validator returns false → 401. Critically, the middleware
// must NOT silently fall through to checking the password header (which
// is empty here anyway) — a TOTP failure is a hard fail, not a hint to
// try the other factor on the same request.
func TestSensitiveConfirm_WrongTOTP(t *testing.T) {
	bob, _ := setupSensitiveTest(t)
	validateTOTPCodeForUser = func(*model.User, string) bool { return false }
	r := buildSensitiveRouter(bob.ID, bob.Username)

	req := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
	req.Header.Set("X-Confirm-TOTP", "000000")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

// TOTPHeader_OnNonMfaUser: a user without MFA bound supplies a TOTP code.
// The middleware should ignore the TOTP header (since the user has no
// secret) and fall through to the "missing headers" branch — meaning a
// 4401 + requireConfirm response, NOT a silent pass.
func TestSensitiveConfirm_TOTPHeader_OnNonMfaUser(t *testing.T) {
	_, alice := setupSensitiveTest(t)
	r := buildSensitiveRouter(alice.ID, alice.Username)

	req := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
	req.Header.Set("X-Confirm-TOTP", "123456")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (alice has no TOTP bound)", w.Code)
	}
}

// PasswordOnMfaUser: even when MFA is bound, the middleware accepts a
// correct password as defence-in-depth. This lets operators recover when
// their authenticator app is unavailable but they still know the
// account password.
func TestSensitiveConfirm_PasswordOnMfaUser(t *testing.T) {
	bob, _ := setupSensitiveTest(t)
	r := buildSensitiveRouter(bob.ID, bob.Username)

	req := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
	req.Header.Set("X-Confirm-Password", "correct-horse")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (password fallback should work for MFA users)", w.Code)
	}
	body := decodeBody(t, w.Body.Bytes())
	if body["stepUp"] != "password" {
		t.Fatalf("stepUp = %v, want password", body["stepUp"])
	}
}

// NoClaims: a request with no auth context (e.g. middleware misconfig)
// should hit the early-return guard and respond 401 instead of NPE'ing.
func TestSensitiveConfirm_NoClaims(t *testing.T) {
	setupSensitiveTest(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/sensitive", SensitiveConfirm(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

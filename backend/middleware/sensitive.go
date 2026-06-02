package middleware

import (
	"strings"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// SensitiveConfirm gates destructive endpoints behind a step-up auth
// challenge: the operator must present either their current password or
// a fresh TOTP code (when MFA is bound) in addition to the standard
// session cookie / bearer token. Without this, a stolen access token or
// hijacked session would be enough to delete the cluster, rotate the API
// token, or bulk-remove nodes.
//
// Wire format: client sends one of
//
//	X-Confirm-Password: <plain text current password>
//	X-Confirm-TOTP:     <6-digit code>
//
// Both are POST-only headers — they never appear in URLs / referrers /
// browser history. The middleware:
//
//  1. Resolves the authenticated user from the JWT claims placed by Auth().
//  2. Tries the TOTP header first when MFA is bound — that's the more
//     phishing-resistant proof.
//  3. Falls back to bcrypt-comparing the password header otherwise.
//  4. Returns 401 + a sentinel code so the frontend can pop a re-auth
//     dialog instead of silently logging the user out.
//
// The function name is plural-safe: import once, reuse on every sensitive
// route. Because the middleware reads claims, it MUST run AFTER Auth().
func SensitiveConfirm() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := GetClaims(c)
		if claims == nil {
			resp.Unauthorized(c, "未登录")
			return
		}
		var user model.User
		if err := db.DB.First(&user, claims.UserID).Error; err != nil {
			resp.Unauthorized(c, "用户不存在")
			return
		}

		totpHeader := strings.TrimSpace(c.GetHeader("X-Confirm-TOTP"))
		pwdHeader := strings.TrimSpace(c.GetHeader("X-Confirm-Password"))

		// TOTP path: only meaningful when the user actually bound a secret.
		if user.TOTPEnabled && totpHeader != "" {
			if !validateTOTPCodeForUser(&user, totpHeader) {
				abortWithReauth(c, "TOTP 验证码错误")
				return
			}
			// Tag the request so writeOpLogAuth can record which factor
			// the operator used. See model.OperationLog.StepUp.
			c.Set("step_up", "totp")
			c.Next()
			return
		}

		// Password path: works regardless of MFA state. We accept this
		// even when MFA is bound because some operators prefer typing
		// their password — defence-in-depth, not gate-keeping which
		// factor is "good enough".
		if pwdHeader != "" {
			if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(pwdHeader)); err != nil {
				abortWithReauth(c, "密码错误")
				return
			}
			c.Set("step_up", "password")
			c.Next()
			return
		}

		// Neither header present — surface the requirement to the client.
		c.AbortWithStatusJSON(401, gin.H{
			"code":    4401, // sentinel: "step-up required"
			"message": "敏感操作需要二次确认",
			"data": gin.H{
				"requireConfirm": true,
				"mfaEnabled":     user.TOTPEnabled,
			},
		})
	}
}

// validateTOTPCodeForUser is a thin wrapper kept here to avoid an import
// cycle with internal/handler. The handler package owns the TOTP logic;
// this function calls into it via a registered hook so middleware stays
// dependency-light.
var validateTOTPCodeForUser = func(user *model.User, code string) bool {
	// Default: deny when no validator was registered (means the handler
	// package didn't initialise — refuse rather than silently pass).
	return false
}

// SetTOTPValidator lets internal/handler plug its real ValidateTOTPCode
// implementation in at startup. Called from handler/totp.go init.
func SetTOTPValidator(fn func(*model.User, string) bool) {
	if fn != nil {
		validateTOTPCodeForUser = fn
	}
}

func abortWithReauth(c *gin.Context, msg string) {
	c.AbortWithStatusJSON(401, gin.H{
		"code":    4401,
		"message": msg,
		"data":    gin.H{"requireConfirm": true},
	})
}

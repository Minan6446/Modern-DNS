package handler

import (
	"strings"
	"time"

	"modern-dns/config"
	"modern-dns/internal/model"
	"modern-dns/middleware"
	"modern-dns/pkg/db"
	"modern-dns/pkg/jwt"
	"modern-dns/pkg/resp"
	"modern-dns/pkg/session"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
)

// init wires this package's TOTP validator into the middleware package so
// SensitiveConfirm can verify step-up codes without creating an import
// cycle (middleware → handler would be a cycle).
func init() {
	middleware.SetTOTPValidator(ValidateTOTPCode)
}

// ─── TOTP MFA endpoints ──────────────────────────────────────────────────────

// POST /api/auth/totp/setup
// Generates a fresh TOTP secret for the current user (not yet enabled).
// Returns the otpauth:// URL the client renders as a QR code.
func TOTPSetup(c *gin.Context) {
	claims := middleware.GetClaims(c)
	if claims == nil {
		resp.Unauthorized(c, "未登录")
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Modern-DNS",
		AccountName: claims.Username,
	})
	if err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	// Store secret but do NOT enable yet — caller must verify a code first.
	db.DB.Model(&model.User{}).Where("id = ?", claims.UserID).Updates(map[string]interface{}{
		"totp_secret":  key.Secret(),
		"totp_enabled": false,
	})
	resp.OK(c, gin.H{
		"secret":  key.Secret(),
		"otpauth": key.URL(),
	})
}

// POST /api/auth/totp/verify
// Validates a 6-digit code against the pending secret; on success enables MFA.
func TOTPVerify(c *gin.Context) {
	claims := middleware.GetClaims(c)
	if claims == nil {
		resp.Unauthorized(c, "未登录")
		return
	}
	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}

	var user model.User
	if err := db.DB.First(&user, claims.UserID).Error; err != nil {
		resp.NotFound(c, "用户不存在")
		return
	}
	if user.TOTPSecret == "" {
		resp.BadRequest(c, "请先调用 setup 生成密钥")
		return
	}
	if !totp.Validate(strings.TrimSpace(req.Code), user.TOTPSecret) {
		resp.BadRequest(c, "验证码不匹配")
		return
	}
	db.DB.Model(&model.User{}).Where("id = ?", claims.UserID).Update("totp_enabled", true)

	// Enrollment-token path: this verify call is the final step of the
	// MFA-required-but-not-yet-enrolled login flow. Hand back full tokens
	// so the client transitions seamlessly into a normal session.
	if claims.Type == "enrollment" {
		_, _, sessionTTL := loginLimits()
		// MFA-enrollment swap goes through the same session-tracking
		// path as Login so MaxConcurrentLogin enforcement applies
		// equally whether the user authenticated via password-only or
		// password+MFA-enrollment.
		sid, sErr := session.NewSid()
		if sErr != nil {
			resp.ServerError(c, "生成会话标识失败")
			return
		}
		sidTTL := sessionTTL
		if sidTTL <= 0 {
			sidTTL = time.Duration(config.C.JWT.AccessExpireMin) * time.Minute
		}
		_, _ = session.Register(c.Request.Context(), user.ID, sid, maxConcurrentLogin(), sidTTL)

		accessToken, err := jwt.SignAccessWithSid(user.ID, user.Username, user.RoleName, sid, sessionTTL)
		if err != nil {
			resp.ServerError(c, "生成令牌失败")
			return
		}
		refreshToken, err := jwt.SignRefreshWithSid(user.ID, user.Username, user.RoleName, sid)
		if err != nil {
			resp.ServerError(c, "生成令牌失败")
			return
		}
		writeOpLog(c, user.Username, "登录", "认证中心", "完成 MFA 强制绑定并登录", "")
		resp.OK(c, gin.H{
			"enabled":      true,
			"token":        accessToken,
			"refreshToken": refreshToken,
			"user": gin.H{
				"name":   user.RealName,
				"role":   user.RoleName,
				"avatar": "",
			},
		})
		return
	}

	resp.OK(c, gin.H{"enabled": true})
}

// POST /api/auth/totp/disable
// Removes MFA after the operator confirms a final valid code.
func TOTPDisable(c *gin.Context) {
	claims := middleware.GetClaims(c)
	if claims == nil {
		resp.Unauthorized(c, "未登录")
		return
	}
	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	var user model.User
	if err := db.DB.First(&user, claims.UserID).Error; err != nil {
		resp.NotFound(c, "用户不存在")
		return
	}
	if user.TOTPEnabled && !totp.Validate(strings.TrimSpace(req.Code), user.TOTPSecret) {
		resp.BadRequest(c, "验证码不匹配")
		return
	}
	db.DB.Model(&model.User{}).Where("id = ?", claims.UserID).Updates(map[string]interface{}{
		"totp_secret":  "",
		"totp_enabled": false,
	})
	resp.OK(c, gin.H{"enabled": false})
}

// ValidateTOTPCode is exposed so login flow can require a code when the user
// has MFA enabled.
func ValidateTOTPCode(user *model.User, code string) bool {
	if !user.TOTPEnabled || user.TOTPSecret == "" {
		return true
	}
	return totp.Validate(strings.TrimSpace(code), user.TOTPSecret)
}

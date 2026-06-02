package handler

import (
	crand "crypto/rand"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"modern-dns/internal/dnsengine"
	"modern-dns/internal/model"
	"modern-dns/middleware"
	"modern-dns/pkg/backup"
	"modern-dns/pkg/db"
	"modern-dns/pkg/notify"
	"modern-dns/pkg/rbac"
	"modern-dns/pkg/resp"
	"modern-dns/pkg/syslog"
	"modern-dns/pkg/sysmon"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var userPhonePattern = regexp.MustCompile(`^\+?[0-9][0-9\- ]{5,31}$`)

// GET /api/setting/common
func GetCommonConfig(c *gin.Context) {
	var cfg model.SystemConfig
	db.DB.FirstOrCreate(&cfg, model.SystemConfig{ID: 1})
	resp.OK(c, cfg)
}

// PUT /api/setting/common
//
// Self-lockout guard: if the new IPWhitelist would NOT match the operator's
// current client IP, we refuse with sentinel code 4422 and a hint payload
// so the frontend can pop a "your IP isn't in the new list — really save?"
// dialog. The operator can opt out of this guard by re-issuing the request
// with `?confirmLockout=1`, which is what the dialog's "Yes, lock me out"
// button does. Loopback always matches (matches the middleware's behaviour)
// so a local shell session can fix things if anyone really does lock
// themselves out anyway.
func SaveCommonConfig(c *gin.Context) {
	var req model.SystemConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if err := validateCommonConfig(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if c.Query("confirmLockout") != "1" && strings.TrimSpace(req.IPWhitelist) != "" {
		if !middleware.IPMatchesAllowlist(req.IPWhitelist, c.ClientIP()) {
			c.JSON(http.StatusOK, gin.H{
				"code":    4422, // sentinel: client must confirm self-lockout
				"message": "新的 IP 白名单不包含您当前的来源 IP，保存后您将无法再访问后台。",
				"data": gin.H{
					"confirmLockout": true,
					"clientIP":       c.ClientIP(),
				},
			})
			return
		}
	}
	req.ID = 1
	// Use Save() but Omit poller-owned status columns. Without Omit,
	// gorm.Save() round-trips every gin-bound field including the NTP
	// status fields the frontend sent back from its last GET. The
	// background poller writes those columns concurrently — letting
	// Save clobber them caused the UI to flip between "stale failure"
	// (saved row) and "fresh success" (poller row) on every save.
	if err := db.DB.Omit("ntp_last_sync", "ntp_last_drift_ms", "ntp_last_error").
		Save(&req).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}

	// Live-apply the DB pool tuning from the new config. We deliberately
	// run this *after* the Save so a typo (e.g. setting MaxOpenConns to
	// 0) doesn't strand the goroutine that's currently writing the row.
	db.ApplyPool(req.DBMaxOpenConns, req.DBMaxIdleConns, req.DBConnMaxLifetimeMin, req.DBConnMaxIdleMin)

	// Wake the NTP poller so the operator's new server list is tested
	// within seconds rather than waiting up to NTPCheckInterval.
	sysmon.Kick()

	// Apply syslog forwarder config live. Empty server / Enabled=false
	// puts the forwarder in idle mode without tearing down the goroutine.
	syslog.Reconfigure(syslog.Config{
		Enabled: req.SyslogEnabled,
		Server:  req.SyslogServer,
	})

	// Bust the dnsengine policy caches so TTL-clamp / ECS / padding /
	// upstream-protocol-order changes are visible on the very next
	// query. The 1-second TTL would otherwise let the old value
	// linger right after the operator clicks Save, which is the
	// most-common "did my change actually apply?" complaint.
	dnsengine.InvalidatePolicies()

	writeOpLogAuth(c, "配置", "系统设置", "保存常规配置", "")
	resp.OK(c, gin.H{"savedAt": time.Now().Format("2006-01-02 15:04:05")})
}

// validateCommonConfig clamps the operator-supplied SystemConfig into
// the documented valid ranges. Frontend already does this in the form
// `clampInt` helpers, but never trust the client — a direct API call
// could otherwise wedge the server (e.g. dbMaxOpenConns=0 collapses
// the pool, ntpCheckIntervalSec=1 hammers the upstream NTP).
//
// Approach: we coerce out-of-range values back to the documented
// minimum / maximum rather than reject the whole request. That gives
// API users a forgiving experience while still preventing self-DoS.
// Truly malformed payloads (negative durations on positive-only
// fields) get clamped to the floor the same way.
func validateCommonConfig(c *model.SystemConfig) error {
	clampMin := func(v *int, lo int) {
		if *v < lo {
			*v = lo
		}
	}
	clampRange := func(v *int, lo, hi int) {
		if *v < lo {
			*v = lo
		} else if *v > hi {
			*v = hi
		}
	}

	// DNS policy
	clampMin(&c.DefaultTTL, 0)
	clampMin(&c.NegativeCacheTTL, 0)
	clampRange(&c.MinTTL, 0, 86400)
	clampRange(&c.MaxTTL, 0, 604800)
	clampRange(&c.UpstreamTimeoutMs, 200, 30000)
	clampRange(&c.ECSPrefixV4, 0, 32)
	clampRange(&c.ECSPrefixV6, 0, 128)
	clampRange(&c.DNSPaddingBlock, 32, 1024)

	// Login / session policy
	clampRange(&c.LoginTimeoutMinutes, 1, 1440)
	clampRange(&c.LoginMaxFailures, 1, 100)
	clampRange(&c.LoginLockMinutes, 1, 1440)
	clampRange(&c.MaxConcurrentLogin, 0, 20)

	// Password policy. Floor at 8 — we never let an operator set the
	// minimum below the Modern-DNS baseline, even by direct API call.
	clampRange(&c.PwdMinLength, 8, 64)
	clampRange(&c.PwdExpireDays, 0, 365)

	// DB connection pool. 0 would unmount the pool entirely; refuse.
	clampRange(&c.DBMaxOpenConns, 1, 500)
	clampRange(&c.DBMaxIdleConns, 0, 500)
	clampRange(&c.DBConnMaxLifetimeMin, 1, 240)
	clampRange(&c.DBConnMaxIdleMin, 1, 120)

	// NTP — 60 s is the documented floor (lower is rude to upstream
	// pools); 3600 s the ceiling beyond which drift drift becomes
	// useless to alert on.
	clampRange(&c.NTPCheckInterval, 60, 3600)

	// Logs
	clampRange(&c.LogRetentionDays, 0, 730) // 0 = never purge

	return nil
}

// POST /api/setting/common/ntp/test
//
// Runs a synchronous NTP probe against the request body's `servers`
// list (or the persisted system_config list when omitted). Used by
// the General Settings page's "立即测试" button so operators can
// validate the server list *before* committing it to the DB.
//
// We deliberately keep the call synchronous: the entire helper budget
// is bounded by sysmon.perServerTimeout × len(servers), and the
// frontend already shows a spinner while it waits. Returning the
// chosen server + drift lets the UI display "由 ntp.aliyun.com 同步成功，偏移 -3ms"
// without a follow-up GET.
func TestNTP(c *gin.Context) {
	var req struct {
		Servers []string `json:"servers"`
	}
	_ = c.ShouldBindJSON(&req)

	server, drift, err := sysmon.TestNow(req.Servers)
	if err != nil {
		// 200 with success=false so the UI can render the error inline
		// without triggering its global error toast.
		resp.OK(c, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	resp.OK(c, gin.H{
		"success": true,
		"server":  server,
		"driftMs": drift.Milliseconds(),
		"checkAt": time.Now().Format("2006-01-02 15:04:05"),
	})
}

// PUT /api/setting/common/log
//
// Scoped writer that updates *only* the log-related columns of
// system_config. Exists because AuditLogPage's config dialog is the
// secondary editor for these fields (the primary being the General
// Settings panel, which still uses the full SaveCommonConfig route).
//
// Without this sub-endpoint the audit page had to round-trip the
// entire SystemConfig payload, which created a last-writer-wins race:
// open the dialog → some other tab edits a *different* field → audit
// page saves → other tab's edit is silently reverted.
//
// The endpoint enforces the same range clamps as SaveCommonConfig but
// limited to the relevant columns (LogRetentionDays + the three
// presentation/syslog knobs). Other fields in the payload are ignored.
type logConfigReq struct {
	LogLevel         string `json:"logLevel"`
	LogRetentionDays int    `json:"logRetentionDays"`
	LogExportFormat  string `json:"logExportFormat"`
	SyslogEnabled    bool   `json:"syslogEnabled"`
	SyslogServer     string `json:"syslogServer"`
}

func SaveLogConfig(c *gin.Context) {
	var req logConfigReq
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}

	// Clamp retention into the documented range; mirror
	// validateCommonConfig so behaviour is identical no matter which
	// endpoint the operator goes through.
	if req.LogRetentionDays < 0 {
		req.LogRetentionDays = 0
	} else if req.LogRetentionDays > 730 {
		req.LogRetentionDays = 730
	}
	// Defensive normalisation for the dropdowns. Empty / unknown
	// values fall back to the documented defaults instead of writing
	// garbage strings the audit-export handler would later reject.
	switch strings.ToUpper(strings.TrimSpace(req.LogLevel)) {
	case "DEBUG", "INFO", "WARN", "ERROR":
		req.LogLevel = strings.ToUpper(strings.TrimSpace(req.LogLevel))
	default:
		req.LogLevel = "INFO"
	}
	switch strings.ToLower(strings.TrimSpace(req.LogExportFormat)) {
	case "csv", "json", "syslog":
		req.LogExportFormat = strings.ToLower(strings.TrimSpace(req.LogExportFormat))
	default:
		req.LogExportFormat = "csv"
	}

	updates := map[string]any{
		"log_level":          req.LogLevel,
		"log_retention_days": req.LogRetentionDays,
		"log_export_format":  req.LogExportFormat,
		"syslog_enabled":     req.SyslogEnabled,
		"syslog_server":      strings.TrimSpace(req.SyslogServer),
	}
	if err := db.DB.Model(&model.SystemConfig{}).Where("id = 1").Updates(updates).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}

	// Apply syslog forwarder config live. Mirrors the SaveCommonConfig
	// path so the audit-log dialog "save" button takes effect without
	// requiring an app restart or a separate "apply" action.
	syslog.Reconfigure(syslog.Config{
		Enabled: req.SyslogEnabled,
		Server:  strings.TrimSpace(req.SyslogServer),
	})

	writeOpLogAuth(c, "配置", "审计日志", "更新日志配置", "")
	resp.OK(c, gin.H{"savedAt": time.Now().Format("2006-01-02 15:04:05")})
}

// POST /api/setting/common/reset
//
// Re-seeds the system_config row with the engineering-recommended
// defaults. Anything not listed below stays at the zero-value, which
// for the GORM-mapped columns is also the documented "no override"
// behavior (see SystemConfig comments). New fields added in 2026-05
// (DB pool, NTP, password policy, TTL clamp, ECS prefix, padding) are
// included here so a "reset to default" gives the operator a clean,
// documented baseline rather than half-zero-half-default state.
func ResetCommonConfig(c *gin.Context) {
	defaults := model.SystemConfig{
		ID:                  1,
		Timezone:            "UTC+8",
		Language:            "zh-CN",
		AutoBackup:          true,
		BackupCycle:         "每日",
		BackupRetentionDays: 30,
		DNSSECGlobal:        true,
		DefaultTTL:          3600,
		NegativeCacheTTL:    300,

		// TTL clamp off by default — operators opt in.
		MinTTL: 0,
		MaxTTL: 0,

		UpstreamProtocolOrder: "udp,tcp",
		UpstreamTimeoutMs:     2000,
		ECSPrefixV4:           24,
		ECSPrefixV6:           56,
		DNSPaddingEnabled:     false,
		DNSPaddingBlock:       128,

		LoginTimeoutMinutes: 30,
		LoginMaxFailures:    5,
		LoginLockMinutes:    15,

		PwdMinLength:       8,
		PwdRequireUpper:    true,
		PwdRequireLower:    true,
		PwdRequireDigit:    true,
		PwdRequireSymbol:   false,
		PwdExpireDays:      0,
		MaxConcurrentLogin: 0,

		DBMaxOpenConns:       50,
		DBMaxIdleConns:       25,
		DBConnMaxLifetimeMin: 10,
		DBConnMaxIdleMin:     5,

		NTPEnabled:       true,
		NTPServers:       "pool.ntp.org\ntime.cloudflare.com",
		NTPCheckInterval: 300,

		LogRetentionDays: 90,
		LogLevel:         "INFO",
		LogExportFormat:  "csv",
		// GlobalQPSThreshold removed in 2026-05 cleanup; column is
		// retained in DB but no longer mapped on the model. See
		// model.SystemConfig comments for full rationale.
	}
	// Same Omit() guard as SaveCommonConfig: the NTP status columns
	// are owned by the background poller; resetting other fields must
	// not blank out the live drift / last-sync row, otherwise the UI
	// flickers "等待首次同步" until the next tick.
	db.DB.Omit("ntp_last_sync", "ntp_last_drift_ms", "ntp_last_error").Save(&defaults)
	sysmon.Kick() // re-poll with the freshly-reset server list immediately
	// Apply the freshly-reset pool values too, so a click-reset
	// immediately reflects in the live *sql.DB.
	db.ApplyPool(defaults.DBMaxOpenConns, defaults.DBMaxIdleConns,
		defaults.DBConnMaxLifetimeMin, defaults.DBConnMaxIdleMin)
	// Same cache-bust as SaveCommonConfig — defaults wipe ECS /
	// padding / upstream-protocol-order, the operator should see
	// the change immediately.
	dnsengine.InvalidatePolicies()
	resp.OK(c, defaults)
}

// ─── Users ────────────────────────────────────────────────────────────────────

// GET /api/setting/users
func ListUsers(c *gin.Context) {
	var users []model.User
	db.DB.Order("created_at DESC").Find(&users)
	resp.OK(c, users)
}

// POST /api/setting/users
//
// Uses an explicit DTO instead of binding directly into model.User because
// User.Password carries the json:"-" tag (so the bcrypt hash never leaks
// outbound), which also blocks Gin's inbound JSON decoder from reading the
// "password" field on creation. Without this DTO, every new-user POST would
// fail with "新建用户必须设置密码".
func SaveUser(c *gin.Context) {
	var req struct {
		ID         uint   `json:"id"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		RealName   string `json:"realName"`
		Email      string `json:"email"`
		Phone      string `json:"phone"`
		Department string `json:"department"`
		RoleID     uint   `json:"roleId"`
		RoleName   string `json:"roleName"`
		Status     string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.RealName = strings.TrimSpace(req.RealName)
	req.Email = strings.TrimSpace(req.Email)
	req.Phone = strings.TrimSpace(req.Phone)
	req.Department = strings.TrimSpace(req.Department)

	if req.ID == 0 {
		if req.Password == "" {
			resp.BadRequest(c, "新建用户必须设置密码")
			return
		}
		if req.Email == "" {
			resp.BadRequest(c, "新建用户必须填写邮箱")
			return
		}
		if req.Phone == "" {
			resp.BadRequest(c, "新建用户必须填写手机号")
			return
		}
		if _, err := mail.ParseAddress(req.Email); err != nil {
			resp.BadRequest(c, "邮箱格式不正确")
			return
		}
		if !userPhonePattern.MatchString(req.Phone) {
			resp.BadRequest(c, "手机号格式不正确")
			return
		}
		if err := validatePasswordPolicy(req.Password); err != nil {
			resp.BadRequest(c, err.Error())
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			resp.ServerError(c, "密码加密失败")
			return
		}
		user := model.User{
			Username:   req.Username,
			Password:   string(hash),
			RealName:   req.RealName,
			Email:      req.Email,
			Phone:      req.Phone,
			Department: req.Department,
			RoleID:     req.RoleID,
			RoleName:   req.RoleName,
			Status:     req.Status,
			// Stamp the rotation baseline so PwdExpireDays starts the
			// clock from "now" rather than from time.Time{} (which the
			// login path treats as never-expired and would let the new
			// account skip the very first rotation cycle).
			PasswordChangedAt: time.Now(),
		}
		if err := db.DB.Create(&user).Error; err != nil {
			resp.ServerError(c, err.Error())
			return
		}
		writeOpLogAuth(c, "新增", "用户管理", fmt.Sprintf("创建用户 %s", user.Username), "")
		resp.OK(c, user)
		return
	}

	updates := map[string]any{
		"real_name":  req.RealName,
		"email":      req.Email,
		"phone":      req.Phone,
		"department": req.Department,
		"role_id":    req.RoleID,
		"role_name":  req.RoleName,
		"status":     req.Status,
	}
	// Allow optional in-place password change on edit; ignored when blank.
	if req.Password != "" {
		if err := validatePasswordPolicy(req.Password); err != nil {
			resp.BadRequest(c, err.Error())
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			resp.ServerError(c, "密码加密失败")
			return
		}
		updates["password"] = string(hash)
		updates["password_changed_at"] = time.Now()
	}
	if err := db.DB.Model(&model.User{}).Where("id = ?", req.ID).Updates(updates).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	var user model.User
	db.DB.First(&user, req.ID)
	writeOpLogAuth(c, "编辑", "用户管理", fmt.Sprintf("保存用户 %s", user.Username), "")
	resp.OK(c, user)
}

// DELETE /api/setting/users/:id
func DeleteUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	claims := middleware.GetClaims(c)
	if claims != nil && claims.UserID == uint(id) {
		resp.BadRequest(c, "不能删除当前登录用户")
		return
	}
	// Capture the username *before* the delete so the audit log can read
	// "删除用户 alice" — after the row is gone we'd only have the ID.
	var u model.User
	target := fmt.Sprintf("删除用户 #%d", id)
	if db.DB.Select("username").First(&u, id).Error == nil && u.Username != "" {
		target = fmt.Sprintf("删除用户 %s", u.Username)
	}
	db.DB.Delete(&model.User{}, id)
	writeOpLogAuth(c, "删除", "用户管理", target, "")
	resp.OK(c, gin.H{"id": id})
}

// POST /api/setting/users/:id/reset-password
//
// Resets the target user's password. The operator workflow is:
//
//  1. Admin clicks "重置密码" on the user-management table.
//  2. Frontend POSTs here with optional {password}. When password is empty
//     (the common case — there's no password input in the dialog) we
//     generate a strong random temp password on the server.
//  3. Response carries the new plaintext password so the admin can copy
//     and hand it to the user out-of-band.
//
// Previously the handler hard-required `password` via gin's binding tag,
// which caused the call to 400 with "Field validation for 'Password'
// failed on the 'required' tag" because the frontend never collected
// one. Auto-generating server-side is both safer (no weak operator
// choices) and matches the existing UX — the dialog only confirms intent.
func ResetUserPassword(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req struct {
		Password string `json:"password"`
	}
	// Body is optional; tolerate empty / no JSON.
	_ = c.ShouldBindJSON(&req)

	password := strings.TrimSpace(req.Password)
	if password == "" {
		generated, err := generateTempPassword()
		if err != nil {
			resp.ServerError(c, "生成临时密码失败")
			return
		}
		password = generated
	} else if err := validatePasswordPolicy(password); err != nil {
		// Operator typed an explicit password — enforce policy. The
		// auto-generated branch always satisfies the default rules so
		// it deliberately skips the check.
		resp.BadRequest(c, err.Error())
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		resp.ServerError(c, "密码加密失败")
		return
	}
	// Updates() with a map writes both columns in a single statement.
	// Bumping password_changed_at on an admin-driven reset is correct:
	// the user effectively has a fresh credential and the rotation
	// clock should restart, not carry over the old age.
	db.DB.Model(&model.User{}).Where("id = ?", id).Updates(map[string]any{
		"password":            string(hash),
		"password_changed_at": time.Now(),
	})
	// Look up the username so the audit-table 操作对象 column reads
	// "重置用户 admin 的密码" instead of an opaque numeric ID. Falls back
	// to the ID form if the row was already gone (race with concurrent
	// delete).
	var u model.User
	target := fmt.Sprintf("重置用户密码 #%d", id)
	if db.DB.Select("username").First(&u, id).Error == nil && u.Username != "" {
		target = fmt.Sprintf("重置用户 %s 的密码", u.Username)
	}
	writeOpLogAuth(c, "编辑", "用户管理", target, "")
	resp.OK(c, gin.H{"success": true, "id": id, "password": password})
}

// validatePasswordPolicy enforces the operator-configured complexity
// rules from system_config. Returns nil when the password is acceptable
// or an error whose Error() string is suitable for direct user display.
//
// Resolution order:
//  1. Read system_config row (id=1).
//  2. Apply baseline floors so a brand-new deployment with all-zero
//     pwd_* columns still gets the Modern-DNS default (8 chars,
//     upper+lower+digit). Operators can *raise* the bar but a config
//     error must not silently *lower* it.
//  3. Walk the supplied string once tallying class membership.
func validatePasswordPolicy(pw string) error {
	var cfg model.SystemConfig
	db.DB.First(&cfg, 1)

	minLen := cfg.PwdMinLength
	if minLen < 8 {
		minLen = 8 // baseline floor; never weaker than this
	}
	if len(pw) < minLen {
		return fmt.Errorf("密码至少 %d 个字符", minLen)
	}

	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range pw {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()-_=+[]{};:,.<>?/|`~'\"\\", r):
			hasSymbol = true
		}
	}
	// Default-on classes (upper/lower/digit) match what
	// generateTempPassword produces, so admin-reset passwords always
	// satisfy the policy without bouncing back through validation.
	if cfg.PwdRequireUpper && !hasUpper {
		return fmt.Errorf("密码必须包含至少一个大写字母")
	}
	if cfg.PwdRequireLower && !hasLower {
		return fmt.Errorf("密码必须包含至少一个小写字母")
	}
	if cfg.PwdRequireDigit && !hasDigit {
		return fmt.Errorf("密码必须包含至少一个数字")
	}
	if cfg.PwdRequireSymbol && !hasSymbol {
		return fmt.Errorf("密码必须包含至少一个特殊符号")
	}
	return nil
}

// generateTempPassword returns a 12-char password drawn from a 4-class
// alphabet (upper / lower / digit / symbol) so it satisfies typical
// "8+ chars with letters and digits" UI rules without further massaging.
// Uses crypto/rand to avoid predictable output.
func generateTempPassword() (string, error) {
	const (
		upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		lower   = "abcdefghjkmnpqrstuvwxyz"
		digits  = "23456789"
		symbols = "@$!%*#?&"
	)
	classes := []string{upper, lower, digits, symbols}
	out := make([]byte, 12)
	// First 4 chars: one from each class so we always satisfy the
	// "letters + digits" front-end rule.
	for i, alphabet := range classes {
		idx, err := cryptoRandIntn(len(alphabet))
		if err != nil {
			return "", err
		}
		out[i] = alphabet[idx]
	}
	pool := upper + lower + digits + symbols
	for i := len(classes); i < len(out); i++ {
		idx, err := cryptoRandIntn(len(pool))
		if err != nil {
			return "", err
		}
		out[i] = pool[idx]
	}
	// Fisher-Yates shuffle so the class-prefix ordering isn't predictable.
	for i := len(out) - 1; i > 0; i-- {
		j, err := cryptoRandIntn(i + 1)
		if err != nil {
			return "", err
		}
		out[i], out[j] = out[j], out[i]
	}
	return string(out), nil
}

func cryptoRandIntn(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("invalid n=%d", n)
	}
	bi, err := crand.Int(crand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(bi.Int64()), nil
}

// ─── Roles ────────────────────────────────────────────────────────────────────
//
// The role/permission surface is small (4 endpoints) but easy to get
// subtly wrong. The version below addresses the issues the original
// minimal implementation glossed over:
//
//   - Validation: name is trimmed, required, length-capped, and checked
//     for uniqueness (case-insensitive) before INSERT/UPDATE rather than
//     leaning on the DB unique index (which surfaces opaque "Duplicate
//     entry for key 'name'" messages to the operator).
//   - Built-in role protection: renaming or deleting the SuperAdminRole
//     would silently brick the cluster because pkg/rbac short-circuits
//     on that exact role name. Both ops are now refused 4xx.
//   - Cascading rename: User.RoleName is denormalised. When a role is
//     renamed we propagate the new name to every user row holding that
//     role_id so RBAC checks based on the user's stored role keep
//     working without a re-login.
//   - Cascading delete: previously a role could be deleted while users
//     still pointed at it, leaving orphaned role_id values. We now
//     refuse delete when users still reference the role.
//   - Atomicity: the "delete then re-insert" permission save is wrapped
//     in a transaction so a mid-batch failure doesn't leave the role
//     with zero permissions.
//   - rbac.Reload() is called *immediately* after every mutation so the
//     in-memory cache reflects the change in the same request rather
//     than waiting for the next 30s ticker.
//   - Audit log entries quote the role name (not just numeric id) so
//     the audit table reads naturally in Chinese.

// roleResponse decorates the bare model.Role row with userCount so the
// listing UI doesn't have to fan-out a second query per row to display
// "N 人" on the role card. The extra field is computed in a single
// GROUP BY so the cost is one SELECT instead of one-per-role.
type roleResponse struct {
	model.Role
	UserCount int `json:"userCount"`
}

// GET /api/setting/roles
func ListRoles(c *gin.Context) {
	var roles []model.Role
	if err := db.DB.Order("id").Find(&roles).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}

	// userCount per role in one round-trip.
	type countRow struct {
		RoleID uint
		N      int
	}
	var counts []countRow
	db.DB.Table("users").Select("role_id, COUNT(*) AS n").Group("role_id").Scan(&counts)
	countByRole := make(map[uint]int, len(counts))
	for _, r := range counts {
		countByRole[r.RoleID] = r.N
	}

	out := make([]roleResponse, 0, len(roles))
	for _, r := range roles {
		out = append(out, roleResponse{Role: r, UserCount: countByRole[r.ID]})
	}
	resp.OK(c, out)
}

// validateRoleName centralises the name rules so create / update share
// identical behaviour. Returns the cleaned name on success.
func validateRoleName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", fmt.Errorf("角色名称不能为空")
	}
	if utf8RuneLen(name) > 64 {
		return "", fmt.Errorf("角色名称长度不能超过 64 个字符")
	}
	return name, nil
}

func utf8RuneLen(s string) int {
	n := 0
	for range s {
		n++
	}
	return n
}

// POST /api/setting/roles
func SaveRole(c *gin.Context) {
	var role model.Role
	if err := c.ShouldBindJSON(&role); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	name, err := validateRoleName(role.Name)
	if err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	role.Name = name
	role.Remark = strings.TrimSpace(role.Remark)
	if utf8RuneLen(role.Remark) > 255 {
		resp.BadRequest(c, "备注长度不能超过 255 个字符")
		return
	}

	// Uniqueness check (case-insensitive). The DB unique index would
	// also catch this but with a less helpful error message.
	var collision model.Role
	if err := db.DB.Where("LOWER(name) = LOWER(?)", role.Name).
		First(&collision).Error; err == nil && collision.ID != role.ID {
		resp.BadRequest(c, "角色名称已存在: "+role.Name)
		return
	}

	if role.ID == 0 {
		// Forbid create with the SuperAdmin name to keep that role
		// singular and tied to id=1 (where the seed data places it).
		if role.Name == rbac.SuperAdminRole {
			resp.BadRequest(c, "不能创建与超级管理员同名的角色")
			return
		}
		if err := db.DB.Create(&role).Error; err != nil {
			resp.ServerError(c, err.Error())
			return
		}
		writeOpLogAuth(c, "新增", "用户管理", fmt.Sprintf("创建角色 %s", role.Name), "")
	} else {
		// Update: load existing, refuse to rename a built-in role away
		// from its known name, propagate rename to denormalised
		// users.role_name so HasPermission checks (which key on the
		// user's stored role) keep working.
		var existing model.Role
		if err := db.DB.First(&existing, role.ID).Error; err != nil {
			resp.NotFound(c, "角色不存在")
			return
		}
		if existing.Name == rbac.SuperAdminRole && role.Name != rbac.SuperAdminRole {
			resp.BadRequest(c, "超级管理员角色不可被重命名")
			return
		}

		err := db.DB.Transaction(func(tx *gorm.DB) error {
			if err := tx.Model(&model.Role{}).
				Where("id = ?", role.ID).
				Updates(map[string]any{
					"name":   role.Name,
					"remark": role.Remark,
				}).Error; err != nil {
				return err
			}
			if existing.Name != role.Name {
				if err := tx.Model(&model.User{}).
					Where("role_id = ?", role.ID).
					Update("role_name", role.Name).Error; err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			resp.ServerError(c, err.Error())
			return
		}
		target := fmt.Sprintf("编辑角色 %s", role.Name)
		if existing.Name != role.Name {
			target = fmt.Sprintf("重命名角色 %s → %s", existing.Name, role.Name)
		}
		writeOpLogAuth(c, "编辑", "用户管理", target, "")
	}
	rbac.Reload()
	resp.OK(c, role)
}

// DELETE /api/setting/roles/:id
func DeleteRole(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var role model.Role
	if err := db.DB.First(&role, id).Error; err != nil {
		resp.NotFound(c, "角色不存在")
		return
	}
	// Use role-name based detection rather than the magic id<=3 check
	// the original code used. The role table's seed positions
	// SuperAdmin at id=1 today, but switching to a name check makes the
	// guard robust to seed-row reordering / migration.
	if role.Name == rbac.SuperAdminRole {
		resp.BadRequest(c, "超级管理员角色不可删除")
		return
	}

	// Refuse delete while any user still references this role —
	// otherwise we'd leave orphaned users.role_id rows that point at a
	// non-existent role.
	var userCount int64
	db.DB.Model(&model.User{}).Where("role_id = ?", id).Count(&userCount)
	if userCount > 0 {
		resp.BadRequest(c, fmt.Sprintf(
			"角色仍有 %d 位用户在使用，请先转移或删除这些用户后再尝试", userCount))
		return
	}

	err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&model.Role{}, id).Error; err != nil {
			return err
		}
		return tx.Where("role_id = ?", id).Delete(&model.RolePermission{}).Error
	})
	if err != nil {
		resp.ServerError(c, err.Error())
		return
	}

	rbac.Reload()
	writeOpLogAuth(c, "删除", "用户管理", fmt.Sprintf("删除角色 %s", role.Name), "")
	resp.OK(c, gin.H{"id": id})
}

// GET /api/setting/roles/:id/permissions
func GetRolePermissions(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var role model.Role
	if err := db.DB.First(&role, id).Error; err != nil {
		resp.NotFound(c, "角色不存在")
		return
	}
	var perms []model.RolePermission
	db.DB.Where("role_id = ?", id).Find(&perms)

	// Dedupe + sort so the response is deterministic regardless of how
	// the rows were inserted historically.
	seen := make(map[string]struct{}, len(perms))
	keys := make([]string, 0, len(perms))
	for _, p := range perms {
		k := strings.TrimSpace(p.Permission)
		if k == "" {
			continue
		}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	resp.OK(c, keys)
}

// PUT /api/setting/roles/:id/permissions
func SaveRolePermissions(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var role model.Role
	if err := db.DB.First(&role, id).Error; err != nil {
		resp.NotFound(c, "角色不存在")
		return
	}

	var req struct {
		Permissions []string `json:"permissions"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}

	// Trim + dedupe so the operator can paste lists with cosmetic
	// duplicates without tripping the unique index. Rejecting the entry
	// with whitespace-only "permissions" silently rather than 400-ing
	// keeps drag-select behaviours forgiving.
	seen := make(map[string]struct{}, len(req.Permissions))
	clean := make([]string, 0, len(req.Permissions))
	for _, raw := range req.Permissions {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		if utf8RuneLen(p) > 64 {
			resp.BadRequest(c, "权限标识长度不能超过 64 个字符: "+p)
			return
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		clean = append(clean, p)
	}
	sort.Strings(clean)

	// Atomic delete-then-insert. Without the transaction a mid-batch
	// failure would leave the role with a partial permission set —
	// often worse than the previous state because the operator still
	// sees a "saved" toast.
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("role_id = ?", id).Delete(&model.RolePermission{}).Error; err != nil {
			return err
		}
		if len(clean) == 0 {
			return nil
		}
		rows := make([]model.RolePermission, 0, len(clean))
		for _, p := range clean {
			rows = append(rows, model.RolePermission{RoleID: uint(id), Permission: p})
		}
		// CreateInBatches keeps the round-trip count constant for
		// large permission sets; 100 is conservative for any DB.
		return tx.CreateInBatches(rows, 100).Error
	})
	if err != nil {
		resp.ServerError(c, err.Error())
		return
	}

	rbac.Reload()

	detail, _ := json.Marshal(map[string]interface{}{
		"roleId":      role.ID,
		"roleName":    role.Name,
		"permissions": clean,
	})
	writeOpLogAuth(c, "配置", "用户管理",
		fmt.Sprintf("配置角色 %s 权限（共 %d 项）", role.Name, len(clean)),
		string(detail))

	resp.OK(c, gin.H{
		"roleId":      role.ID,
		"permissions": clean,
	})
}

// ─── Backup ───────────────────────────────────────────────────────────────────

// GET /api/setting/backups
func ListBackups(c *gin.Context) {
	var backups []model.Backup
	db.DB.Order("backup_time DESC").Find(&backups)
	resp.OK(c, backups)
}

// POST /api/setting/backups
//
// Creates a new system backup. Validates the requested scope list against
// the supported set and surfaces per-table warnings (an empty / corrupt
// sub-table no longer takes down the whole export thanks to the
// per-table error capture in pkg/backup). The Backup row is only written
// if the on-disk file was successfully produced; if the export aborts
// after the file write but before DB insert (rare, e.g. SQLite locked),
// we delete the orphan file so a retry can re-use the same name.
//
// Response shape extends the legacy Backup row with stats + warnings so
// the UI can show "已备份 1234 行 / 14 张表" and a per-table warning list
// without an extra round-trip.
func CreateBackup(c *gin.Context) {
	supported := []string{"系统配置", "域名解析", "黑白名单", "安全规则"}

	var req struct {
		BackupScope  []string `json:"backupScope"`
		BackupFormat string   `json:"backupFormat"`
		Note         string   `json:"note"`
	}
	_ = c.ShouldBindJSON(&req)

	// Default to "系统配置" only — matches the historical UI default and
	// keeps audit semantics stable. Operators who want everything must
	// explicitly tick the boxes.
	if len(req.BackupScope) == 0 {
		req.BackupScope = []string{"系统配置"}
	}
	if req.BackupFormat == "" {
		req.BackupFormat = "JSON"
	} else if strings.ToUpper(req.BackupFormat) != "JSON" {
		resp.BadRequest(c, "目前仅支持 JSON 格式备份")
		return
	}

	// Reject typo'd scopes early — without this the export would silently
	// produce an empty file. The supported set lives next to scopeTables
	// in pkg/backup; mirror it here so the error surfaces on the API
	// boundary instead of inside pkg/backup.
	supportedSet := make(map[string]struct{}, len(supported))
	for _, s := range supported {
		supportedSet[s] = struct{}{}
	}
	scopeOrder := make([]string, 0, len(req.BackupScope))
	scopeSeen := make(map[string]struct{}, len(req.BackupScope))
	for _, s := range req.BackupScope {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := supportedSet[s]; !ok {
			resp.BadRequest(c, "不支持的备份范围: "+s+"。可选: "+strings.Join(supported, " / "))
			return
		}
		if _, dup := scopeSeen[s]; dup {
			continue
		}
		scopeSeen[s] = struct{}{}
		scopeOrder = append(scopeOrder, s)
	}
	if len(scopeOrder) == 0 {
		resp.BadRequest(c, "备份范围不能为空")
		return
	}

	backupID := fmt.Sprintf("BK-%d", time.Now().UnixMilli())

	filePath, fileSize, stats, err := backup.Export(backupID, scopeOrder)
	if err != nil {
		resp.ServerError(c, "备份失败: "+err.Error())
		return
	}

	scopeJSON, _ := json.Marshal(scopeOrder)
	rec := model.Backup{
		BackupID:    backupID,
		BackupScope: model.JSON(scopeJSON),
		BackupTime:  time.Now(),
		FileSize:    fileSize,
		Format:      req.BackupFormat,
		FileName:    filepath.Base(filePath),
	}
	if err := db.DB.Create(&rec).Error; err != nil {
		// Roll back the file so a retry isn't blocked by a duplicate
		// name. We deliberately swallow the os.Remove error — if even
		// the cleanup fails, surfacing the original DB error is more
		// actionable than nesting both.
		_ = os.Remove(filePath)
		resp.ServerError(c, "备份记录写入失败: "+err.Error())
		return
	}

	auditTarget := fmt.Sprintf("创建备份 %s（%s · 共 %d 行）",
		rec.BackupID, strings.Join(scopeOrder, "+"), stats.TotalRows)
	if len(stats.WarnedTables) > 0 {
		auditTarget += fmt.Sprintf("，%d 张表跳过", len(stats.WarnedTables))
	}
	detail, _ := json.Marshal(map[string]interface{}{
		"scope":    scopeOrder,
		"format":   req.BackupFormat,
		"fileSize": fileSize,
		"stats":    stats,
		"note":     req.Note,
	})
	writeOpLogAuth(c, "备份", "备份还原", auditTarget, string(detail))

	resp.OK(c, gin.H{
		"id":           rec.ID,
		"backupId":     rec.BackupID,
		"backupTime":   rec.BackupTime.Format("2006-01-02 15:04:05"),
		"backupScope":  scopeOrder,
		"format":       rec.Format,
		"fileName":     rec.FileName,
		"fileSize":     rec.FileSize,
		"totalRows":    stats.TotalRows,
		"tables":       stats.Tables,
		"warnedTables": stats.WarnedTables,
	})
}

// POST /api/setting/backups/:id/restore
func RestoreBackup(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	var rec model.Backup
	if err := db.DB.First(&rec, id).Error; err != nil {
		resp.NotFound(c, "备份记录不存在")
		return
	}

	// Accept optional restoreScope from body; default to backup's full scope
	var body struct {
		RestoreScope []string `json:"restoreScope"`
	}
	c.ShouldBindJSON(&body)
	scopes := body.RestoreScope
	if len(scopes) == 0 {
		var saved []string
		json.Unmarshal(rec.BackupScope, &saved)
		scopes = saved
	}

	filePath := backup.FilePath(rec.FileName)
	if err := backup.Restore(filePath, scopes); err != nil {
		resp.ServerError(c, "还原失败: "+err.Error())
		return
	}

	writeOpLogAuth(c, "还原", "备份还原", fmt.Sprintf("还原备份 %s", rec.BackupID), "")
	resp.OK(c, gin.H{"success": true, "id": id, "restoredScope": scopes})
}

// POST /api/setting/backups/restore  (restore from uploaded file)
func RestoreBackupByFile(c *gin.Context) {
	var req struct {
		FileName     string   `json:"fileName"`
		RestoreScope []string `json:"restoreScope"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}

	filePath := backup.FilePath(req.FileName)
	scopes := req.RestoreScope
	if len(scopes) == 0 {
		bf, err := backup.ParseFile(filePath)
		if err != nil {
			resp.ServerError(c, "解析备份失败: "+err.Error())
			return
		}
		scopes = bf.BackupScope
	}

	if err := backup.Restore(filePath, scopes); err != nil {
		resp.ServerError(c, "还原失败: "+err.Error())
		return
	}

	writeOpLogAuth(c, "还原", "备份还原", fmt.Sprintf("从文件还原 %s", req.FileName), "")
	resp.OK(c, gin.H{"success": true, "fileName": req.FileName, "restoredScope": scopes})
}

// DELETE /api/setting/backups/:id
//
// Removes a backup file from disk and the corresponding row from the
// backups table. The audit entry is captured *before* the row is wiped
// so the operation_log row can quote the backup ID — once the row is
// gone we'd only have a numeric primary key, which is useless when the
// operator is reviewing the audit page later.
func DeleteBackup(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	var rec model.Backup
	rowFound := db.DB.First(&rec, id).Error == nil

	// Build the audit target before we touch the DB so the message is
	// readable even when the row didn't exist (replay / double-click
	// scenarios still log a meaningful "尝试删除不存在的备份 #N" line).
	target := fmt.Sprintf("删除备份 #%d", id)
	detail := ""
	if rowFound {
		var scope []string
		_ = json.Unmarshal(rec.BackupScope, &scope)
		target = fmt.Sprintf("删除备份 %s（%s）", rec.BackupID, rec.FileName)
		detailBytes, _ := json.Marshal(map[string]interface{}{
			"backupId":   rec.BackupID,
			"fileName":   rec.FileName,
			"fileSize":   rec.FileSize,
			"format":     rec.Format,
			"scope":      scope,
			"backupTime": rec.BackupTime.Format("2006-01-02 15:04:05"),
		})
		detail = string(detailBytes)
		os.Remove(backup.FilePath(rec.FileName))
	} else {
		target = fmt.Sprintf("删除备份 #%d（记录不存在）", id)
	}

	db.DB.Delete(&model.Backup{}, id)
	writeOpLogAuth(c, "删除", "备份还原", target, detail)
	resp.OK(c, gin.H{"id": id})
}

// POST /api/setting/backups/upload
func UploadBackup(c *gin.Context) {
	// Support both multipart file upload and JSON body {fileName}
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		// Fallback: frontend may send a JSON body with just fileName
		var body struct {
			FileName string `json:"fileName"`
		}
		if e := c.ShouldBindJSON(&body); e != nil || body.FileName == "" {
			resp.BadRequest(c, "请上传文件")
			return
		}
		// Check if the file already exists in backup dir (e.g. drag-and-drop name match)
		filePath := backup.FilePath(body.FileName)
		bf, e := backup.ParseFile(filePath)
		if e != nil {
			// File doesn't exist yet — return generic scopes
			resp.OK(c, gin.H{
				"fileName":     body.FileName,
				"restoreScope": []string{"系统配置", "域名解析", "黑白名单", "安全规则"},
				"format":       "JSON",
			})
			return
		}
		resp.OK(c, gin.H{
			"fileName":     body.FileName,
			"restoreScope": backup.AllScopes(bf),
			"format":       "JSON",
		})
		return
	}
	defer file.Close()

	// Save file to backup dir
	os.MkdirAll(backup.Dir, 0755)
	name := header.Filename
	dstPath := backup.FilePath(name)
	dst, err := os.Create(dstPath)
	if err != nil {
		resp.ServerError(c, "保存文件失败: "+err.Error())
		return
	}
	defer dst.Close()
	io.Copy(dst, file)

	// Parse to detect available scopes
	format := "JSON"
	restoreScope := []string{"系统配置", "域名解析", "黑白名单", "安全规则"}
	if bf, e := backup.ParseFile(dstPath); e == nil {
		restoreScope = backup.AllScopes(bf)
	}

	// Audit only the upload branch — the JSON-body fallback above is a
	// metadata probe that doesn't write any file, so logging it would
	// just spam the audit table on every drag-and-drop preview.
	detailBytes, _ := json.Marshal(map[string]interface{}{
		"fileName":     name,
		"size":         header.Size,
		"format":       format,
		"restoreScope": restoreScope,
	})
	writeOpLogAuth(c, "上传", "备份还原",
		fmt.Sprintf("上传备份文件 %s（%s）", name, humanFileSize(header.Size)),
		string(detailBytes))

	resp.OK(c, gin.H{
		"fileName":     name,
		"restoreScope": restoreScope,
		"format":       format,
	})
}

// humanFileSize formats a byte count for the audit log target column.
// Matches pkg/backup.humanSize formatting so the audit row reads the
// same as the listing.
func humanFileSize(b int64) string {
	const KB, MB, GB int64 = 1024, 1024 * 1024, 1024 * 1024 * 1024
	switch {
	case b >= GB:
		return fmt.Sprintf("%.1fGB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1fMB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1fKB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

// GET /api/setting/backups/:id/export
func ExportBackupFile(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var rec model.Backup
	if err := db.DB.First(&rec, id).Error; err != nil {
		resp.NotFound(c, "备份不存在")
		return
	}

	filePath := backup.FilePath(rec.FileName)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// File missing on disk — return the DB record metadata so frontend can
		// still generate a download from the record itself.
		resp.OK(c, rec)
		return
	}

	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", rec.FileName))
	c.Header("Content-Type", "application/octet-stream")
	c.File(filePath)
}

// ─── Notice ───────────────────────────────────────────────────────────────────

// GET /api/setting/notice
func GetNoticeConfig(c *gin.Context) {
	var configs []model.NoticeConfig
	db.DB.Find(&configs)
	result := gin.H{}
	for _, cfg := range configs {
		var m map[string]any
		json.Unmarshal(cfg.ConfigJSON, &m)
		if m == nil {
			m = map[string]any{}
		}
		m["enabled"] = cfg.Enabled
		result[cfg.Channel] = m
	}
	resp.OK(c, result)
}

// PUT /api/setting/notice
func SaveNoticeConfig(c *gin.Context) {
	var req map[string]json.RawMessage
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	for channel, raw := range req {
		var m map[string]any
		json.Unmarshal(raw, &m)
		enabled, _ := m["enabled"].(bool)
		b, _ := json.Marshal(m)
		var cfg model.NoticeConfig
		if db.DB.Where("channel = ?", channel).First(&cfg).Error != nil {
			db.DB.Create(&model.NoticeConfig{
				Channel:    channel,
				Enabled:    enabled,
				ConfigJSON: model.JSON(b),
			})
		} else {
			db.DB.Model(&model.NoticeConfig{}).Where("channel = ?", channel).
				Updates(map[string]any{"enabled": enabled, "config_json": string(b)})
		}
	}
	notify.Invalidate()
	writeOpLogAuth(c, "配置", "通知设置", "保存通知配置", "")
	resp.OK(c, gin.H{"savedAt": time.Now().Format("2006-01-02 15:04:05")})
}

// PUT /api/setting/notice/:channel
//
// Saves a single notification channel's config. When the channel is
// being *enabled*, we validate the required fields server-side so an
// operator can't accidentally turn on a half-configured webhook / SMS
// integration that would silently drop every alert. Disabling a channel
// skips validation — operators may legitimately want to keep partial
// drafts saved.
func SaveNoticeChannelConfig(c *gin.Context) {
	channel := c.Param("channel")
	if channel == "" {
		resp.BadRequest(c, "channel 不能为空")
		return
	}
	var m map[string]any
	if err := c.ShouldBindJSON(&m); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	enabled, _ := m["enabled"].(bool)
	if enabled {
		if err := validateNoticeChannel(channel, m); err != nil {
			resp.BadRequest(c, err.Error())
			return
		}
	}
	b, _ := json.Marshal(m)
	var cfg model.NoticeConfig
	if db.DB.Where("channel = ?", channel).First(&cfg).Error != nil {
		db.DB.Create(&model.NoticeConfig{
			Channel:    channel,
			Enabled:    enabled,
			ConfigJSON: model.JSON(b),
		})
	} else {
		db.DB.Model(&model.NoticeConfig{}).Where("channel = ?", channel).
			Updates(map[string]any{"enabled": enabled, "config_json": string(b)})
	}
	notify.Invalidate()
	writeOpLogAuth(c, "配置", "通知设置",
		fmt.Sprintf("保存 %s 通道配置", channelDisplayName(channel)), "")

	// Re-fetch and return full merged notice config
	var configs []model.NoticeConfig
	db.DB.Find(&configs)
	result := gin.H{}
	for _, nc := range configs {
		var cm map[string]any
		json.Unmarshal(nc.ConfigJSON, &cm)
		if cm == nil {
			cm = map[string]any{}
		}
		cm["enabled"] = nc.Enabled
		result[nc.Channel] = cm
	}
	resp.OK(c, result)
}

// validateNoticeChannel performs server-side sanity checks on a notice
// channel config when it's being *saved as enabled*. Front-end already
// validates these but a malicious or buggy client could still POST a
// half-filled payload; rejecting at the API boundary keeps the
// notice_config table from accumulating "enabled but inert" rows.
func validateNoticeChannel(channel string, m map[string]any) error {
	str := func(k string) string { v, _ := m[k].(string); return strings.TrimSpace(v) }

	switch channel {
	case "email":
		if str("smtpHost") == "" {
			return fmt.Errorf("SMTP 主机不能为空")
		}
		// smtpPort accepts both number and numeric-string variants.
		port := 0
		switch v := m["smtpPort"].(type) {
		case float64:
			port = int(v)
		case int:
			port = v
		case string:
			fmt.Sscanf(v, "%d", &port)
		}
		if port <= 0 || port > 65535 {
			return fmt.Errorf("SMTP 端口必须在 1 - 65535 之间")
		}
		if str("sender") == "" && str("smtpUser") == "" {
			return fmt.Errorf("发件邮箱不能为空")
		}
		// `receivers` is intentionally NOT required at save time. The
		// field exists so operators can target the "send test email"
		// button without polluting alert routing — actual alert
		// recipients come from the subscription/route rules, not from
		// this column. Empty here means "no test recipients yet",
		// which is a perfectly valid intermediate state.
		return nil

	case "webhook":
		u := str("url")
		if u == "" {
			return fmt.Errorf("Webhook 地址不能为空")
		}
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return fmt.Errorf("Webhook 地址必须以 http:// 或 https:// 开头")
		}
		if method := strings.ToUpper(str("method")); method != "" && method != "GET" && method != "POST" {
			return fmt.Errorf("Webhook 仅支持 GET / POST 方法，收到: %s", method)
		}
		if mode := strings.ToLower(str("templateMode")); mode != "" &&
			mode != "raw" && mode != "dingtalk" && mode != "feishu" && mode != "wecom" {
			return fmt.Errorf("Webhook 模板模式仅支持 raw / dingtalk / feishu / wecom，收到: %s", mode)
		}
		if lvl := strings.ToLower(str("minLevel")); lvl != "" &&
			lvl != "info" && lvl != "warning" && lvl != "critical" {
			return fmt.Errorf("Webhook minLevel 仅支持 info / warning / critical，收到: %s", lvl)
		}
		return nil

	case "sms":
		if str("accessKeyId") == "" || str("accessKeySecret") == "" {
			return fmt.Errorf("阿里云 AccessKey ID / Secret 不能为空")
		}
		if str("signName") == "" {
			return fmt.Errorf("短信签名（signName）不能为空")
		}
		if str("templateCode") == "" {
			return fmt.Errorf("短信模板号（templateCode）不能为空")
		}
		phones := str("phones")
		if phones == "" {
			return fmt.Errorf("收件号码（phones）不能为空")
		}
		// Light client-side check; the channel sender does the strict
		// validation, but catching obvious blanks here gives a faster
		// feedback loop than waiting for the next alert to fail.
		if tp := str("templateParams"); tp != "" {
			var probe map[string]any
			if err := json.Unmarshal([]byte(tp), &probe); err != nil {
				return fmt.Errorf("templateParams 不是合法 JSON: %w", err)
			}
		}
		if lvl := strings.ToLower(str("minLevel")); lvl != "" &&
			lvl != "info" && lvl != "warning" && lvl != "critical" {
			return fmt.Errorf("SMS minLevel 仅支持 info / warning / critical，收到: %s", lvl)
		}
		return nil

	case "dingtalk", "feishu", "wecom", "slack":
		// All four chat-platform channels share the same shape: bot URL
		// is mandatory, optional sign secret, no other hard-required
		// fields. The platform-specific senders enforce richer rules
		// (e.g. DingTalk keyword presence) at send time so a malformed
		// bot URL surfaces the precise error rather than a generic
		// "missing field".
		u := str("url")
		if u == "" {
			return fmt.Errorf("%s 机器人 URL 不能为空", chatPlatformLabel(channel))
		}
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return fmt.Errorf("%s URL 必须以 http:// 或 https:// 开头", chatPlatformLabel(channel))
		}
		if lvl := strings.ToLower(str("minLevel")); lvl != "" &&
			lvl != "info" && lvl != "warning" && lvl != "critical" {
			return fmt.Errorf("%s minLevel 仅支持 info / warning / critical，收到: %s", chatPlatformLabel(channel), lvl)
		}
		return nil

	case "voice":
		if str("accessKeyId") == "" || str("accessKeySecret") == "" {
			return fmt.Errorf("阿里云 AccessKey ID / Secret 不能为空")
		}
		if str("ttsCode") == "" {
			return fmt.Errorf("语音模板号（ttsCode）不能为空")
		}
		if str("phones") == "" {
			return fmt.Errorf("被叫号码（phones）不能为空")
		}
		if tp := str("ttsParam"); tp != "" {
			var probe map[string]any
			if err := json.Unmarshal([]byte(tp), &probe); err != nil {
				return fmt.Errorf("ttsParam 不是合法 JSON: %w", err)
			}
		}
		if lvl := strings.ToLower(str("minLevel")); lvl != "" &&
			lvl != "info" && lvl != "warning" && lvl != "critical" {
			return fmt.Errorf("Voice minLevel 仅支持 info / warning / critical，收到: %s", lvl)
		}
		return nil
	}
	// Unknown channel — skip strict checks; existing flow accepts custom
	// channel names for forward compatibility.
	return nil
}

// chatPlatformLabel returns the operator-facing display name for a chat
// platform channel code. Used in validation error messages so the
// rejection text matches what the operator clicked in the tab strip.
func chatPlatformLabel(channel string) string {
	switch channel {
	case "dingtalk":
		return "钉钉"
	case "feishu":
		return "飞书"
	case "wecom":
		return "企业微信"
	case "slack":
		return "Slack"
	}
	return channel
}

// channelDisplayName covers every supported notification channel,
// extending chatPlatformLabel to also cover email / webhook / sms /
// voice. Used to render audit-log target strings in Chinese while
// keeping the wire-level channel codes English.
func channelDisplayName(channel string) string {
	switch channel {
	case "email":
		return "邮件"
	case "webhook":
		return "Webhook"
	case "sms":
		return "短信"
	case "voice":
		return "电话"
	}
	return chatPlatformLabel(channel)
}

// POST /api/setting/notice/test
//
// Real test send: takes the (possibly unsaved) channel config from the
// request body and dispatches a synthetic event through the corresponding
// channel implementation in pkg/notify. The frontend uses this so an
// operator can validate SMTP credentials / webhook reachability / SMS
// signing before persisting changes.
func TestNoticeChannel(c *gin.Context) {
	// Frontend sends the flat shape `{channel, ...configFields}` — i.e. the
	// channel discriminator alongside the inline config keys. Bind into a
	// single map so we don't care whether the caller nests under `config`
	// or not, then peel off `channel` and feed the remainder to notify.Test.
	// This used to use ShouldBindJSON twice which silently dropped the body
	// on the second call; keep a single read to avoid that class of bug.
	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		resp.BadRequest(c, "请求体无效")
		return
	}
	channel, _ := body["channel"].(string)
	if channel == "" {
		resp.BadRequest(c, "channel 不能为空")
		return
	}
	// Support both `{channel, config:{...}}` (explicit) and
	// `{channel, ...inline}` (current EmailTab shape).
	cfg, _ := body["config"].(map[string]any)
	if len(cfg) == 0 {
		cfg = make(map[string]any, len(body))
		for k, v := range body {
			if k == "channel" {
				continue
			}
			cfg[k] = v
		}
	}
	// Channel codes are English; the audit page is rendered in Chinese,
	// so translate here for human readers and keep the raw code in
	// Detail for filtering.
	channelLabel := channelDisplayName(channel)
	msg, err := notify.Test(notify.Channel(channel), cfg)
	if err != nil {
		writeOpLogAuth(c, "测试", "通知设置",
			fmt.Sprintf("%s 通道测试失败：%s", channelLabel, err.Error()),
			fmt.Sprintf(`{"channel":"%s","error":%q}`, channel, err.Error()))
		resp.BadRequest(c, err.Error())
		return
	}
	writeOpLogAuth(c, "测试", "通知设置",
		fmt.Sprintf("%s 通道测试成功", channelLabel),
		fmt.Sprintf(`{"channel":"%s"}`, channel))
	resp.OK(c, gin.H{"success": true, "channel": channel, "message": msg})
}

// ─── Logs ─────────────────────────────────────────────────────────────────────

// GET /api/setting/logs
func GetOperationLogs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	if page < 1 {
		page = 1
	}
	keyword := c.Query("keyword")
	module := c.Query("module")
	action := c.Query("action")
	result := c.Query("result")
	startTime := c.Query("startTime")
	endTime := c.Query("endTime")

	query := db.DB.Model(&model.OperationLog{})
	if keyword != "" {
		query = query.Where("operator LIKE ? OR content LIKE ? OR target LIKE ? OR ip LIKE ?",
			"%"+keyword+"%", "%"+keyword+"%", "%"+keyword+"%", "%"+keyword+"%")
	}
	if module != "" {
		query = query.Where("module = ?", module)
	}
	if action != "" {
		query = query.Where("`action` = ?", action)
	}
	if result != "" {
		query = query.Where("result = ?", result)
	}
	if startTime != "" {
		query = query.Where("created_at >= ?", startTime)
	}
	if endTime != "" {
		query = query.Where("created_at <= ?", endTime)
	}

	var total int64
	query.Count(&total)

	var logs []model.OperationLog
	query.Order("created_at DESC").
		Offset((page - 1) * size).
		Limit(size).
		Find(&logs)
	if logs == nil {
		logs = []model.OperationLog{}
	}
	resp.OK(c, gin.H{"total": total, "rows": logs})
}

// POST /api/setting/logs/purge-expired
//
// Manually triggers the same retention policy the scheduler runs every
// minute, so the operator doesn't have to wait up to a tick to reclaim
// space after lowering LogRetentionDays. Returns the number of deleted
// rows for the audit trail and so the UI can show a meaningful toast.
//
// LogRetentionDays = 0 means "keep forever" — we refuse to purge in that
// case rather than wiping every log row, which would be the literal
// interpretation of `created_at < now - 0`.
func PurgeExpiredOperationLogs(c *gin.Context) {
	var cfg model.SystemConfig
	if err := db.DB.First(&cfg, 1).Error; err != nil {
		resp.ServerError(c, "读取系统配置失败")
		return
	}
	if cfg.LogRetentionDays <= 0 {
		resp.BadRequest(c, "日志保留天数为 0（表示永不清理），请先设置一个正整数后再执行清理。")
		return
	}
	cutoff := time.Now().Add(-time.Duration(cfg.LogRetentionDays) * 24 * time.Hour)
	res := db.DB.Where("created_at < ?", cutoff).Delete(&model.OperationLog{})
	if res.Error != nil {
		resp.ServerError(c, res.Error.Error())
		return
	}
	writeOpLogAuth(c, "配置", "审计日志", "手动清理过期日志", "")
	resp.OK(c, gin.H{
		"deleted":       res.RowsAffected,
		"retentionDays": cfg.LogRetentionDays,
		"cutoff":        cutoff.Format("2006-01-02 15:04:05"),
	})
}

// POST /api/setting/logs/export
//
// Streams the operation_log table to the response as a real downloadable
// file. Supports two formats:
//
//   - "csv"  (default) — UTF-8 with BOM so Excel renders Chinese columns
//     without garbling. Columns mirror the audit page.
//   - "json"           — array of OperationLog objects, identical schema
//     to GET /setting/logs.
//
// All filter knobs (keyword/module/action/result/timeRange) match the
// list endpoint exactly so an export is "what you see in the table"
// rather than "everything ever logged". A defensive cap of MaxExport
// rows prevents pathological queries from saturating the server; the
// response header `X-Export-Truncated: 1` flags when the cap kicked in
// so the UI can warn the operator.
func ExportOperationLogs(c *gin.Context) {
	const MaxExport = 100000

	var req struct {
		Format    string   `json:"format"`
		Keyword   string   `json:"keyword"`
		Module    string   `json:"module"`
		Action    string   `json:"action"`
		Result    string   `json:"result"`
		StartTime string   `json:"startTime"`
		EndTime   string   `json:"endTime"`
		TimeRange []string `json:"timeRange"`
	}
	_ = c.ShouldBindJSON(&req)

	// Resolution order for the export format:
	//   1. explicit `req.Format` from the request body (overrides on
	//      a per-export basis — operator clicks "Export as JSON" once)
	//   2. persisted system_config.log_export_format — the operator's
	//      durable default set in the audit-log config dialog
	//   3. "csv" hardwired fallback
	// Without #2 the persisted preference was a UI-only knob: clicking
	// it changed the dropdown but the actual exports kept defaulting
	// to CSV because the frontend always sent format='csv'.
	format := strings.ToLower(strings.TrimSpace(req.Format))
	if format == "" {
		var cfg model.SystemConfig
		if err := db.DB.First(&cfg, 1).Error; err == nil {
			format = strings.ToLower(strings.TrimSpace(cfg.LogExportFormat))
		}
	}
	if format == "" {
		format = "csv"
	}
	// `syslog` is a transport, not a downloadable format — the audit
	// page's dropdown lists it for completeness but we coerce to CSV
	// for the synchronous export path. (Future syslog forwarder will
	// drain operation_log over the wire continuously instead.)
	if format == "syslog" {
		format = "csv"
	}
	if format != "csv" && format != "json" {
		resp.BadRequest(c, "不支持的导出格式: "+format)
		return
	}

	// `timeRange` is the legacy two-element form ([start, end]); the
	// dedicated startTime/endTime fields are the newer way. Either
	// works; explicit fields take precedence.
	startTime := req.StartTime
	endTime := req.EndTime
	if startTime == "" && len(req.TimeRange) >= 1 {
		startTime = req.TimeRange[0]
	}
	if endTime == "" && len(req.TimeRange) >= 2 {
		endTime = req.TimeRange[1]
	}

	query := db.DB.Model(&model.OperationLog{})
	if req.Keyword != "" {
		kw := "%" + req.Keyword + "%"
		query = query.Where(
			"operator LIKE ? OR content LIKE ? OR target LIKE ? OR ip LIKE ? OR log_id LIKE ?",
			kw, kw, kw, kw, kw,
		)
	}
	if req.Module != "" {
		query = query.Where("module = ?", req.Module)
	}
	if req.Action != "" {
		// Match either the canonical category (action_type) or the legacy
		// free-form `action` column. The audit page uses action_type for
		// its dropdown, but older rows (and external integrations) may
		// only have populated `action`.
		query = query.Where("action_type = ? OR `action` = ?", req.Action, req.Action)
	}
	if req.Result != "" {
		query = query.Where("result = ?", req.Result)
	}
	if startTime != "" {
		query = query.Where("created_at >= ?", startTime)
	}
	if endTime != "" {
		query = query.Where("created_at <= ?", endTime)
	}

	var rows []model.OperationLog
	if err := query.Order("created_at DESC").Limit(MaxExport + 1).Find(&rows).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}

	truncated := false
	if len(rows) > MaxExport {
		rows = rows[:MaxExport]
		truncated = true
	}

	// Audit *before* writing the body so the operation log row reflects
	// what was attempted even if the client disconnects mid-stream.
	// Target string is rendered in the audit table 操作对象 column, so we
	// keep it human-readable in Chinese (the rest of the audit copy is
	// Chinese too) and stash the machine-readable detail in the Detail
	// column for the diff drawer.
	formatLabel := strings.ToUpper(format)
	target := fmt.Sprintf("导出 %s 格式 · 共 %d 条", formatLabel, len(rows))
	if truncated {
		target += "（已截断）"
	}
	writeOpLogAuth(c, "导出", "审计日志", target,
		fmt.Sprintf(`{"format":"%s","count":%d,"truncated":%t}`, format, len(rows), truncated),
	)

	stamp := time.Now().Format("20060102-150405")
	if truncated {
		c.Writer.Header().Set("X-Export-Truncated", "1")
	}
	c.Writer.Header().Set("X-Export-Count", strconv.Itoa(len(rows)))
	// Expose our custom headers to the browser-side fetch — without this
	// the JS code can't read them through CORS or the axios shim.
	c.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Disposition, X-Export-Count, X-Export-Truncated")

	switch format {
	case "json":
		filename := fmt.Sprintf("audit-logs-%s.json", stamp)
		c.Writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		c.Writer.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		enc := json.NewEncoder(c.Writer)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			// Headers already flushed — best effort log; client sees a
			// truncated file which is the same failure mode as a network
			// drop, and JS layer treats both alike.
			fmt.Printf("[audit-export] json encode failed: %v\n", err)
		}
	default: // csv
		filename := fmt.Sprintf("audit-logs-%s.csv", stamp)
		c.Writer.Header().Set("Content-Type", "text/csv; charset=utf-8")
		c.Writer.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		// UTF-8 BOM so Excel auto-detects the encoding instead of
		// rendering Chinese columns as mojibake.
		_, _ = c.Writer.Write([]byte("\xEF\xBB\xBF"))

		w := csv.NewWriter(c.Writer)
		_ = w.Write([]string{
			"日志ID", "时间", "操作人", "角色", "来源IP",
			"模块", "类型", "操作", "目标", "操作内容",
			"结果", "耗时(ms)",
		})
		for _, r := range rows {
			actionType := r.ActionType
			if actionType == "" {
				actionType = r.Action
			}
			_ = w.Write([]string{
				r.LogID,
				r.CreatedAt.Format("2006-01-02 15:04:05"),
				r.Operator,
				r.OperatorRole,
				r.IP,
				r.Module,
				actionType,
				r.Action,
				r.Target,
				r.Content,
				r.Result,
				strconv.Itoa(r.Duration),
			})
		}
		w.Flush()
		if err := w.Error(); err != nil {
			fmt.Printf("[audit-export] csv flush failed: %v\n", err)
		}
	}
}

// ─── Users (paginated) ────────────────────────────────────────────────────────

// GET /api/setting/users  (enhanced with pagination + filters)
func ListUsersV2(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	if page < 1 {
		page = 1
	}
	username := c.Query("username")
	status := c.Query("status")
	roleID := c.Query("roleId")

	query := db.DB.Model(&model.User{})
	if username != "" {
		query = query.Where("username LIKE ? OR real_name LIKE ?", "%"+username+"%", "%"+username+"%")
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if roleID != "" {
		query = query.Where("role_id = ?", roleID)
	}

	var total int64
	query.Count(&total)
	var users []model.User
	query.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&users)
	if users == nil {
		users = []model.User{}
	}
	resp.OK(c, gin.H{"total": total, "list": users})
}

// ─── Backup (paginated) ───────────────────────────────────────────────────────

// GET /api/setting/backups  (enhanced with pagination + filters)
func ListBackupsV2(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "10"))
	if page < 1 {
		page = 1
	}
	keyword := c.Query("keyword")
	format := c.Query("format")

	query := db.DB.Model(&model.Backup{})
	if keyword != "" {
		query = query.Where("backup_id LIKE ? OR file_name LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}
	if format != "" {
		query = query.Where("format = ?", format)
	}

	var total int64
	query.Count(&total)
	var backups []model.Backup
	query.Order("backup_time DESC").Offset((page - 1) * size).Limit(size).Find(&backups)
	if backups == nil {
		backups = []model.Backup{}
	}
	resp.OK(c, gin.H{"total": total, "list": backups})
}

// ─── API Keys ─────────────────────────────────────────────────────────────────

// GET /api/setting/api-keys
func ListApiKeys(c *gin.Context) {
	keyword := c.Query("keyword")
	status := c.Query("status")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	if page < 1 {
		page = 1
	}
	query := db.DB.Model(&model.ApiKey{})
	if keyword != "" {
		query = query.Where("name LIKE ? OR prefix LIKE ? OR created_by LIKE ?", "%"+keyword+"%", "%"+keyword+"%", "%"+keyword+"%")
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	var total int64
	query.Count(&total)
	var keys []model.ApiKey
	query.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&keys)
	if keys == nil {
		keys = []model.ApiKey{}
	}
	resp.OK(c, gin.H{"total": total, "list": keys})
}

// POST /api/setting/api-keys
func CreateApiKey(c *gin.Context) {
	var req struct {
		Name      string   `json:"name"      binding:"required"`
		Scope     []string `json:"scope"`
		ExpiresAt string   `json:"expiresAt"`
		NoExpiry  bool     `json:"noExpiry"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if len(req.Scope) == 0 {
		resp.BadRequest(c, "scope 不能为空")
		return
	}

	// Generate secret
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	randStr := func(n int) string {
		b := make([]byte, n)
		crand.Read(b)
		for i := range b {
			b[i] = chars[int(b[i])%len(chars)]
		}
		return string(b)
	}
	secret := "dns_" + randStr(8) + "_" + randStr(16) + "_" + randStr(8)
	prefix := secret[:12] + "****"

	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		resp.ServerError(c, "密钥加密失败")
		return
	}

	operator := "admin"
	if claims := middleware.GetClaims(c); claims != nil {
		operator = claims.Username
	}

	expiresAt := "never"
	if !req.NoExpiry && req.ExpiresAt != "" {
		expiresAt = req.ExpiresAt
	}

	scopeJSON, _ := json.Marshal(req.Scope)
	key := model.ApiKey{
		Name:      req.Name,
		Prefix:    prefix,
		KeyHash:   string(hash),
		Scope:     model.JSON(scopeJSON),
		CreatedBy: operator,
		ExpiresAt: expiresAt,
		Status:    "正常",
		CreatedAt: time.Now(),
	}
	db.DB.Create(&key)
	writeOpLogAuth(c, "新增", "API密钥", key.Name, "")
	// Return the secret only once
	resp.OK(c, gin.H{
		"id":        key.ID,
		"name":      key.Name,
		"prefix":    prefix,
		"scope":     req.Scope,
		"createdBy": operator,
		"expiresAt": expiresAt,
		"status":    "正常",
		"createdAt": key.CreatedAt.Format("2006-01-02"),
		"secret":    secret, // only returned once
	})
}

// PUT /api/setting/api-keys/:id
func UpdateApiKey(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req struct {
		Name      string   `json:"name"`
		Scope     []string `json:"scope"`
		ExpiresAt string   `json:"expiresAt"`
		NoExpiry  bool     `json:"noExpiry"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	expiresAt := "never"
	if !req.NoExpiry && req.ExpiresAt != "" {
		expiresAt = req.ExpiresAt
	}
	scopeJSON, _ := json.Marshal(req.Scope)
	db.DB.Model(&model.ApiKey{}).Where("id = ?", id).Updates(map[string]any{
		"name":       req.Name,
		"scope":      string(scopeJSON),
		"expires_at": expiresAt,
	})
	var key model.ApiKey
	db.DB.First(&key, id)
	resp.OK(c, key)
}

// PATCH /api/setting/api-keys/:id/toggle
func ToggleApiKeyStatus(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var key model.ApiKey
	if err := db.DB.First(&key, id).Error; err != nil {
		resp.NotFound(c, "密钥不存在")
		return
	}
	nextStatus := "已禁用"
	if key.Status == "已禁用" {
		nextStatus = "正常"
	}
	db.DB.Model(&key).Update("status", nextStatus)
	writeOpLogAuth(c, "配置", "API密钥", fmt.Sprintf("%s → %s", key.Name, nextStatus), "")
	resp.OK(c, gin.H{"id": id, "status": nextStatus})
}

// DELETE /api/setting/api-keys/:id
func RevokeApiKey(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var key model.ApiKey
	if err := db.DB.First(&key, id).Error; err != nil {
		resp.NotFound(c, "密钥不存在")
		return
	}
	db.DB.Delete(&key)
	writeOpLogAuth(c, "吊销", "API密钥", key.Name, "")
	resp.OK(c, gin.H{"id": id})
}

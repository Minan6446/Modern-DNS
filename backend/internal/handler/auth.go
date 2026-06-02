package handler

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"modern-dns/config"
	"modern-dns/internal/model"
	"modern-dns/middleware"
	"modern-dns/pkg/db"
	"modern-dns/pkg/jwt"
	"modern-dns/pkg/resp"
	"modern-dns/pkg/session"
	"modern-dns/pkg/syslog"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

// Sane fallbacks used only when SystemConfig has not been initialised yet
// (e.g. very early bootstrap before the migrate step seeds row id=1).
const (
	defaultLoginFailMax   = 5
	defaultLoginLockMin   = 15
	defaultSessionTimeout = 0 // 0 → fall back to config.yaml AccessExpireMin
)

func loginLockKey(username string) string {
	return fmt.Sprintf("login:fail:%s", username)
}

// pwdExpireDays returns SystemConfig.PwdExpireDays (0 = never expire,
// the documented disabled-state). Errors short-circuit to 0 so a DB
// hiccup doesn't accidentally lock every operator out at login time.
func pwdExpireDays() int {
	var cfg model.SystemConfig
	if err := db.DB.First(&cfg, 1).Error; err != nil {
		return 0
	}
	if cfg.PwdExpireDays < 0 {
		return 0
	}
	return cfg.PwdExpireDays
}

// maxConcurrentLogin reads SystemConfig.MaxConcurrentLogin (0 = no
// limit). Same fail-open behaviour as pwdExpireDays — a DB error
// must not turn into a session-eviction storm.
func maxConcurrentLogin() int {
	var cfg model.SystemConfig
	if err := db.DB.First(&cfg, 1).Error; err != nil {
		return 0
	}
	if cfg.MaxConcurrentLogin < 0 {
		return 0
	}
	return cfg.MaxConcurrentLogin
}

// loginLimits resolves max-failures, lock-duration, and session TTL from
// the system_config row so the General Settings UI takes effect without a
// restart. DB errors / missing row degrade to constants above; a zero
// sessionTTL means "use the JWT package default".
func loginLimits() (int, time.Duration, time.Duration) {
	var cfg model.SystemConfig
	if err := db.DB.First(&cfg, 1).Error; err != nil {
		return defaultLoginFailMax, time.Duration(defaultLoginLockMin) * time.Minute, time.Duration(defaultSessionTimeout)
	}
	failMax := cfg.LoginMaxFailures
	if failMax <= 0 {
		failMax = defaultLoginFailMax
	}
	lockMin := cfg.LoginLockMinutes
	if lockMin <= 0 {
		lockMin = defaultLoginLockMin
	}
	var sessionTTL time.Duration
	if cfg.LoginTimeoutMinutes > 0 {
		sessionTTL = time.Duration(cfg.LoginTimeoutMinutes) * time.Minute
	}
	return failMax, time.Duration(lockMin) * time.Minute, sessionTTL
}

// mustEnrollMFA reports whether the given user must complete TOTP
// enrolment before being granted a real access token. It returns true when
// the global SystemConfig.MFARequired switch is on AND the user has not
// yet bound a TOTP secret. DB read failures fail open so a broken DB row
// can't lock everyone out of the console.
func mustEnrollMFA(user *model.User) bool {
	if user.TOTPEnabled {
		return false
	}
	var cfg model.SystemConfig
	if err := db.DB.First(&cfg, 1).Error; err != nil {
		return false
	}
	return cfg.MFARequired
}

// SeedAdmin 在首次启动时创建默认管理员账号（admin / Admin@2026!）
func SeedAdmin() {
	var count int64
	db.DB.Model(&model.User{}).Count(&count)
	if count > 0 {
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("Admin@2026!"), bcrypt.DefaultCost)
	admin := model.User{
		Username: "admin",
		Password: string(hash),
		RealName: "超级管理员",
		RoleID:   1,
		RoleName: "超级管理员",
		Status:   "启用",
	}
	db.DB.Create(&admin)
}

// ─── Login ────────────────────────────────────────────────────────────────────

type loginReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	TOTPCode string `json:"totpCode"`
}

func Login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, "用户名和密码不能为空")
		return
	}
	username := strings.TrimSpace(req.Username)
	failMax, lockExpiry, sessionTTL := loginLimits()

	// ── 检查锁定状态 ──
	lockKey := loginLockKey(username)
	if db.RDBAuth != nil {
		if cur, err := db.RDBAuth.Get(context.Background(), lockKey).Int(); err == nil && cur >= failMax {
			resp.Fail(c, http.StatusTooManyRequests, fmt.Sprintf("账号已因多次失败被锁定，请 %d 分钟后重试", int(lockExpiry.Minutes())))
			return
		}
	}

	var user model.User
	if err := db.DB.Where("username = ?", username).First(&user).Error; err != nil {
		incrementLoginFail(lockKey, lockExpiry)
		resp.Unauthorized(c, "用户名或密码错误")
		return
	}
	if user.Status != "启用" {
		resp.Forbidden(c, "账号已禁用，请联系管理员")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		incrementLoginFail(lockKey, lockExpiry)
		remaining := failMax - getLoginFailCount(lockKey) - 1
		if remaining <= 0 {
			resp.Fail(c, http.StatusTooManyRequests, fmt.Sprintf("密码错误次数过多，账号已锁定 %d 分钟", int(lockExpiry.Minutes())))
		} else {
			resp.Unauthorized(c, fmt.Sprintf("用户名或密码错误，还可尝试 %d 次", remaining))
		}
		return
	}

	// ── TOTP 二次校验 (仅在开启时强制) ──
	if user.TOTPEnabled {
		if strings.TrimSpace(req.TOTPCode) == "" {
			resp.Fail(c, http.StatusUnauthorized, "需要 TOTP 验证码")
			return
		}
		if !ValidateTOTPCode(&user, req.TOTPCode) {
			incrementLoginFail(lockKey, lockExpiry)
			resp.Unauthorized(c, "TOTP 验证码错误")
			return
		}
	}

	// ── 登录成功，清除失败计数 ──
	if db.RDBAuth != nil {
		db.RDBAuth.Del(context.Background(), lockKey)
	}

	// ── 密码过期检查 (SystemConfig.PwdExpireDays) ──
	// Refuse to issue an access token when the user's password is past
	// its rotation window. We respond with HTTP 200 + a sentinel
	// `action: "PASSWORD_EXPIRED"` payload (no JWT) so the frontend
	// can route the operator into the change-password flow without us
	// having to invent a 4xx code that confuses generic 401 handlers.
	//
	// Pre-2026-05 rows have PasswordChangedAt = zero time; we treat
	// zero as "set on first login" rather than "expired" — otherwise
	// every existing operator would be locked out at upgrade time.
	if expDays := pwdExpireDays(); expDays > 0 && !user.PasswordChangedAt.IsZero() {
		if time.Since(user.PasswordChangedAt) > time.Duration(expDays)*24*time.Hour {
			writeOpLog(c, user.Username, "登录", "认证中心",
				fmt.Sprintf("密码已过期 (%d 天未更新)，要求重置", expDays), "")
			resp.OK(c, gin.H{
				"action":  "PASSWORD_EXPIRED",
				"message": fmt.Sprintf("您的密码已超过 %d 天未更新，请先修改密码", expDays),
			})
			return
		}
	}

	// ── 全局强制 MFA：未绑定 → 进入绑定向导 ──
	if mustEnrollMFA(&user) {
		enrollToken, err := jwt.SignEnrollment(user.ID, user.Username, user.RoleName)
		if err != nil {
			resp.ServerError(c, "生成绑定令牌失败")
			return
		}
		writeOpLog(c, user.Username, "登录", "认证中心", "进入 MFA 强制绑定流程", "")
		resp.OK(c, gin.H{
			"action":      "ENROLL_MFA",
			"enrollToken": enrollToken,
			"message":     "管理员已开启全局双因素认证，请先绑定 TOTP",
		})
		return
	}

	// Mint a fresh session id and register it before issuing the JWT.
	// SystemConfig.MaxConcurrentLogin caps the user's active set; the
	// (N+1)th login here evicts the oldest sid, and the middleware's
	// IsLive check on the next request from that evicted session will
	// 401 it. We surface evictions via the audit log so operators can
	// see "alice logged in from 1.2.3.4 — kicked her old session".
	sid, err := session.NewSid()
	if err != nil {
		resp.ServerError(c, "生成会话标识失败")
		return
	}
	maxConc := maxConcurrentLogin()
	sidTTL := sessionTTL
	if sidTTL <= 0 {
		sidTTL = time.Duration(config.C.JWT.AccessExpireMin) * time.Minute
	}
	evicted, regErr := session.Register(c.Request.Context(), user.ID, sid, maxConc, sidTTL)
	if regErr != nil {
		log.Printf("[auth] session.Register %d failed: %v (continuing without enforcement)", user.ID, regErr)
	}
	if len(evicted) > 0 {
		writeOpLog(c, user.Username, "会话踢出", "认证中心",
			fmt.Sprintf("超过并发会话上限 %d，踢出旧会话 %d 个", maxConc, len(evicted)), "")
	}

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

	writeOpLog(c, user.Username, "登录", "认证中心", "控制台登录成功", "")

	resp.OK(c, gin.H{
		"token":        accessToken,
		"refreshToken": refreshToken,
		"user": gin.H{
			"name":   user.RealName,
			"role":   user.RoleName,
			"avatar": "",
		},
	})
}

// ─── Refresh Token ────────────────────────────────────────────────────────────

func RefreshToken(c *gin.Context) {
	header := c.GetHeader("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		resp.Unauthorized(c, "缺少令牌")
		return
	}
	tokenStr := strings.TrimPrefix(header, "Bearer ")
	claims, err := jwt.Parse(tokenStr)
	if err != nil {
		resp.Unauthorized(c, "令牌无效或已过期")
		return
	}
	if claims.Type != "refresh" {
		resp.Unauthorized(c, "令牌类型错误")
		return
	}

	_, _, sessionTTL := loginLimits()
	// Refresh keeps the same sid so the session stays continuous.
	// Re-register to bump the TTL on the active-session set; an idle
	// user who's been silently refreshing tokens for an hour shouldn't
	// have their session vanish from Redis.
	if claims.Sid != "" {
		sidTTL := sessionTTL
		if sidTTL <= 0 {
			sidTTL = time.Duration(config.C.JWT.AccessExpireMin) * time.Minute
		}
		_, _ = session.Register(c.Request.Context(), claims.UserID, claims.Sid, maxConcurrentLogin(), sidTTL)
	}
	accessToken, err := jwt.SignAccessWithSid(claims.UserID, claims.Username, claims.Role, claims.Sid, sessionTTL)
	if err != nil {
		resp.ServerError(c, "刷新令牌失败")
		return
	}
	resp.OK(c, gin.H{"token": accessToken})
}

// ─── Profile ──────────────────────────────────────────────────────────────────

func GetProfile(c *gin.Context) {
	claims := middleware.GetClaims(c)
	var user model.User
	if err := db.DB.First(&user, claims.UserID).Error; err != nil {
		resp.NotFound(c, "用户不存在")
		return
	}
	resp.OK(c, gin.H{
		"id":         user.ID,
		"username":   user.Username,
		"realName":   user.RealName,
		"email":      user.Email,
		"phone":      user.Phone,
		"department": user.Department,
		"role":       user.RoleName,
		"roleId":     user.RoleID,
		"status":     user.Status,
	})
}

// PUT /api/auth/profile
func UpdateProfile(c *gin.Context) {
	claims := middleware.GetClaims(c)
	var req struct {
		RealName   string `json:"realName"`
		Email      string `json:"email"`
		Phone      string `json:"phone"`
		Department string `json:"department"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}

	req.RealName = strings.TrimSpace(req.RealName)
	req.Email = strings.TrimSpace(req.Email)
	req.Phone = strings.TrimSpace(req.Phone)
	req.Department = strings.TrimSpace(req.Department)

	if req.Email == "" {
		resp.BadRequest(c, "邮箱不能为空")
		return
	}
	if _, err := mail.ParseAddress(req.Email); err != nil {
		resp.BadRequest(c, "邮箱格式不正确")
		return
	}
	if req.Phone == "" {
		resp.BadRequest(c, "手机号不能为空")
		return
	}
	if !userPhonePattern.MatchString(req.Phone) {
		resp.BadRequest(c, "手机号格式不正确")
		return
	}

	updates := map[string]any{
		"real_name":  req.RealName,
		"email":      req.Email,
		"phone":      req.Phone,
		"department": req.Department,
		"updated_at": time.Now(),
	}
	if err := db.DB.Model(&model.User{}).Where("id = ?", claims.UserID).Updates(updates).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}

	var user model.User
	if err := db.DB.First(&user, claims.UserID).Error; err != nil {
		resp.NotFound(c, "用户不存在")
		return
	}

	writeOpLogAuth(c, "编辑", "个人资料", fmt.Sprintf("更新个人资料 %s", user.Username), "")
	resp.OK(c, gin.H{
		"id":         user.ID,
		"username":   user.Username,
		"realName":   user.RealName,
		"email":      user.Email,
		"phone":      user.Phone,
		"department": user.Department,
		"role":       user.RoleName,
		"roleId":     user.RoleID,
		"status":     user.Status,
	})
}

// ─── Change Password ──────────────────────────────────────────────────────────

// POST /api/auth/change-password
func ChangePassword(c *gin.Context) {
	claims := middleware.GetClaims(c)
	var req struct {
		OldPassword string `json:"oldPassword" binding:"required"`
		NewPassword string `json:"newPassword" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, "参数错误：新密码至少8位")
		return
	}
	var user model.User
	if err := db.DB.First(&user, claims.UserID).Error; err != nil {
		resp.NotFound(c, "用户不存在")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.OldPassword)); err != nil {
		resp.BadRequest(c, "旧密码不正确")
		return
	}
	if err := validatePasswordPolicy(req.NewPassword); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		resp.ServerError(c, "密码加密失败")
		return
	}
	// Update password + reset rotation timestamp atomically. The
	// timestamp gates the PwdExpireDays check on subsequent logins;
	// not bumping it here would let users "rotate" by re-saving the
	// same password and indefinitely bypass expiry.
	db.DB.Model(&user).Updates(map[string]any{
		"password":            string(hash),
		"password_changed_at": time.Now(),
	})
	writeOpLog(c, claims.Username, "修改密码", "认证中心", "用户修改了登录密码", "")
	resp.OK(c, gin.H{"success": true})
}

// ─── Logout ───────────────────────────────────────────────────────────────────

func Logout(c *gin.Context) {
	// Best-effort revoke the session id so the now-orphaned access
	// token (still in the operator's browser localStorage until the
	// frontend clears it) can no longer pass the IsLive check.
	if claims := middleware.GetClaims(c); claims != nil && claims.Sid != "" {
		session.Revoke(c.Request.Context(), claims.UserID, claims.Sid)
	}
	writeOpLogAuth(c, "登出", "认证中心", "退出登录", "")
	c.JSON(http.StatusOK, gin.H{"code": 0, "data": nil, "message": "ok"})
}

// POST /api/setting/users/:id/unlock
//
// Clears the Redis-backed login-failure counter for a user. Useful when an
// operator gets locked out after a typo storm and the security team
// doesn't want to wait for the natural lock-expiry window. Audited.
//
// We resolve the lock key by looking up the username from the user ID so
// the API still works when the operator only knows the user row id (e.g.
// from the user-management table); otherwise we'd be exposing username as
// a path parameter purely for cache addressing reasons.
func UnlockAccount(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var u model.User
	if err := db.DB.First(&u, id).Error; err != nil {
		resp.NotFound(c, "用户不存在")
		return
	}
	if db.RDBAuth != nil {
		db.RDBAuth.Del(context.Background(), loginLockKey(u.Username))
	}
	writeOpLogAuth(c, "解锁账号", "用户管理", u.Username, "")
	resp.OK(c, gin.H{"username": u.Username, "unlocked": true})
}

// GET /api/setting/online-sessions
//
// Lists every operator currently holding at least one live access-token
// sid. Powers the user-management page's "在线用户" tab. The query
// shape is intentionally batch-y rather than per-user so opening the
// tab is one round-trip instead of N (one for every user row).
//
// Implementation notes:
//   - We SCAN the `user:sids:*` keyspace rather than hold a separate
//     index of online users. SCAN is non-blocking and the cardinality
//     here is bounded by the operator headcount (typically O(10s),
//     not O(millions of DNS queries) — Redis is not stressed).
//   - For each key we ZRANGE all members + ZSCORE to get issuance
//     timestamps; the score is the unix-nano set in session.Register
//     so we can show "最早登录于 …" without an extra column.
//   - Username/realName/role are joined from MySQL in a single batch
//     query, not per-sid, so a user with N concurrent sessions costs
//     1 row read total.
//
// Response shape: a flat slice where each row is one (user, sid)
// pair. Keeping it flat lets the frontend render one table row per
// session and "kick" individual sessions independently — the user-
// level "kick all" button is a separate POST that already exists.
func ListOnlineSessions(c *gin.Context) {
	if db.RDBSession == nil {
		// Redis unavailable: there's no session table to read from.
		// Return an empty list rather than 500 so the UI shows
		// "no online users" instead of an error toast.
		resp.OK(c, []any{})
		return
	}
	ctx := c.Request.Context()

	// SCAN all session-table keys. Cursor-based iteration so we don't
	// block Redis with KEYS on a busy server.
	var keys []string
	var cursor uint64
	for {
		batch, next, err := db.RDBSession.Scan(ctx, cursor, "user:sids:*", 200).Result()
		if err != nil {
			resp.ServerError(c, "扫描会话表失败: "+err.Error())
			return
		}
		keys = append(keys, batch...)
		cursor = next
		if cursor == 0 {
			break
		}
	}

	type row struct {
		UserID    uint   `json:"userId"`
		Username  string `json:"username"`
		RealName  string `json:"realName"`
		RoleName  string `json:"roleName"`
		Sid       string `json:"sid"`
		IssuedAt  int64  `json:"issuedAt"`  // unix-millis for the frontend
		IsCurrent bool   `json:"isCurrent"` // matches caller's own sid
	}
	out := make([]row, 0, len(keys))

	// Pull every (sid, score) pair across all users in a pipeline.
	// One round-trip total regardless of how many users are online.
	type pending struct {
		userID uint
		key    string
	}
	pendings := make([]pending, 0, len(keys))
	pipe := db.RDBSession.Pipeline()
	cmds := make([]*redis.ZSliceCmd, 0, len(keys))
	for _, k := range keys {
		var uid uint
		_, err := fmt.Sscanf(k, "user:sids:%d", &uid)
		if err != nil || uid == 0 {
			continue
		}
		pendings = append(pendings, pending{userID: uid, key: k})
		cmds = append(cmds, pipe.ZRangeWithScores(ctx, k, 0, -1))
	}
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		log.Printf("[auth] online-sessions pipeline: %v", err)
	}

	// Batch-fetch usernames so we render "alice (王某)" rather than
	// raw user IDs. Missing rows (deleted user with stale Redis key)
	// fall back to "#<id>" — the orphaned entry is also a hint that
	// a cleanup pass is overdue.
	userMap := map[uint]model.User{}
	if len(pendings) > 0 {
		ids := make([]uint, 0, len(pendings))
		for _, p := range pendings {
			ids = append(ids, p.userID)
		}
		var users []model.User
		if err := db.DB.Where("id IN ?", ids).Find(&users).Error; err == nil {
			for _, u := range users {
				userMap[u.ID] = u
			}
		}
	}

	callerSid := ""
	if cl := middleware.GetClaims(c); cl != nil {
		callerSid = cl.Sid
	}

	for i, p := range pendings {
		u := userMap[p.userID]
		uname := u.Username
		if uname == "" {
			uname = fmt.Sprintf("#%d", p.userID)
		}
		members, err := cmds[i].Result()
		if err != nil {
			continue
		}
		for _, m := range members {
			sid, _ := m.Member.(string)
			out = append(out, row{
				UserID:    p.userID,
				Username:  uname,
				RealName:  u.RealName,
				RoleName:  u.RoleName,
				Sid:       sid,
				IssuedAt:  int64(m.Score) / int64(time.Millisecond),
				IsCurrent: sid != "" && sid == callerSid,
			})
		}
	}

	resp.OK(c, out)
}

// POST /api/setting/online-sessions/revoke
//
// Revokes a single (userID, sid) pair surfaced by ListOnlineSessions.
// The frontend's per-row "下线" button hits this; the user-level
// "全部下线" button reuses the existing /users/:id/kick-sessions.
//
// Self-protection: refuses to revoke the caller's own current sid so
// an operator can't accidentally end their own session by clicking
// the wrong row in the online-users table. Other sessions of the
// caller (e.g. another browser tab they want to clean up) are fine
// to revoke individually.
func RevokeSession(c *gin.Context) {
	var req struct {
		UserID uint   `json:"userId"`
		Sid    string `json:"sid"`
		// Reason is the operator-selected motive (e.g. "凭据泄露",
		// "离职", "异常活动", "其他"). Free-form on the wire — the
		// frontend keeps it as an enum, but the audit log is more
		// useful when an operator can also paste a ticket reference.
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.UserID == 0 || req.Sid == "" {
		resp.BadRequest(c, "参数缺失")
		return
	}
	if cl := middleware.GetClaims(c); cl != nil && cl.UserID == req.UserID && cl.Sid == req.Sid {
		resp.BadRequest(c, "不能下线当前会话，请使用「退出登录」")
		return
	}
	var u model.User
	if err := db.DB.First(&u, req.UserID).Error; err != nil {
		resp.NotFound(c, "用户不存在")
		return
	}
	session.Revoke(c.Request.Context(), req.UserID, req.Sid)
	target := fmt.Sprintf("用户 %s 的会话 %s 已被下线", u.Username, req.Sid[:min(8, len(req.Sid))])
	if r := strings.TrimSpace(req.Reason); r != "" {
		target = target + "（原因：" + r + "）"
	}
	writeOpLogAuth(c, "下线会话", "在线用户", target, req.Reason)
	resp.OK(c, gin.H{"success": true})
}

// POST /api/setting/users/:id/kick-sessions
//
// Wipes every active sid for the user from the Redis session table,
// effectively logging them out everywhere. Their browser keeps the
// (now-orphaned) JWT in localStorage until the page makes its next
// request, at which point the auth middleware's IsLive check fails
// and the response is 401 → frontend redirects to login.
//
// Use cases this is meant for:
//   - employee leaves the team and access must be revoked promptly
//   - shared / leaked credentials suspected
//   - post-password-reset cleanup (the reset itself doesn't kick
//     existing sessions; we keep that as a deliberate operator
//     decision because a self-service password change shouldn't
//     necessarily nuke the user's other tabs)
//
// Self-protection: the handler refuses when the target is the caller
// themselves. The operator can still use logout for that, but a click
// on their own row in the user table should not silently sign them
// out — confusing UX, easy to do by accident.
func KickUserSessions(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if id <= 0 {
		resp.BadRequest(c, "无效的用户 ID")
		return
	}
	claims := middleware.GetClaims(c)
	if claims != nil && claims.UserID == uint(id) {
		resp.BadRequest(c, "不能强制下线当前登录用户，请使用「退出登录」")
		return
	}
	var u model.User
	if err := db.DB.First(&u, id).Error; err != nil {
		resp.NotFound(c, "用户不存在")
		return
	}
	// Reason is optional on the wire (operator can dismiss the prompt
	// for a quick kick) but strongly preferred — the frontend's
	// confirmation dialog forces a selection. We tolerate empty here
	// so the API stays usable from scripts / curl.
	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body)

	// Best-effort sample of the active session count *before* wiping
	// so the audit log records the impact ("strong-revoked 3 active
	// sessions for alice"). Failure to read that count must not block
	// the kick — the actual revoke uses DEL, which is unconditional.
	var before int64
	if db.RDBSession != nil {
		before, _ = db.RDBSession.ZCard(c.Request.Context(),
			fmt.Sprintf("user:sids:%d", id)).Result()
	}
	session.RevokeAll(c.Request.Context(), uint(id))

	target := fmt.Sprintf("用户 %s 的 %d 个活跃会话已全部踢出", u.Username, before)
	if r := strings.TrimSpace(body.Reason); r != "" {
		target = target + "（原因：" + r + "）"
	}
	writeOpLogAuth(c, "强制下线", "用户管理", target, body.Reason)
	resp.OK(c, gin.H{
		"username": u.Username,
		"kicked":   before,
	})
}

// GET /api/setting/users/:id/lock-status
//
// Returns current failure count + remaining lock seconds for a user, so
// the user-management UI can flag locked accounts without waiting for an
// operator to try logging in. Cheap (single Redis GET + TTL).
func GetLockStatus(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var u model.User
	if err := db.DB.First(&u, id).Error; err != nil {
		resp.NotFound(c, "用户不存在")
		return
	}
	failMax, _, _ := loginLimits()
	failCount := 0
	lockTTL := 0
	if db.RDBAuth != nil {
		failCount = getLoginFailCount(loginLockKey(u.Username))
		if ttl, err := db.RDBAuth.TTL(context.Background(), loginLockKey(u.Username)).Result(); err == nil && ttl > 0 {
			lockTTL = int(ttl.Seconds())
		}
	}
	resp.OK(c, gin.H{
		"username":   u.Username,
		"failCount":  failCount,
		"failMax":    failMax,
		"locked":     failCount >= failMax,
		"lockTTLSec": lockTTL,
	})
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func incrementLoginFail(lockKey string, lockExpiry time.Duration) {
	if db.RDBAuth == nil {
		return
	}
	ctx := context.Background()
	pipe := db.RDBAuth.Pipeline()
	pipe.Incr(ctx, lockKey)
	pipe.Expire(ctx, lockKey, lockExpiry)
	pipe.Exec(ctx)
}

func getLoginFailCount(lockKey string) int {
	if db.RDBAuth == nil {
		return 0
	}
	val, err := db.RDBAuth.Get(context.Background(), lockKey).Int()
	if err != nil {
		return 0
	}
	return val
}

func writeOpLog(c *gin.Context, operator, actionType, module, content, detail string) {
	ip := ""
	stepUp := ""
	if c != nil {
		ip = c.ClientIP()
		// `step_up` is set by middleware.SensitiveConfirm when the route
		// passed step-up verification. Empty for routes without it.
		if v, ok := c.Get("step_up"); ok {
			if s, isStr := v.(string); isStr {
				stepUp = s
			}
		}
	}
	// Action and ActionType were historically separate columns (ActionType
	// = category like "编辑", Action = free-form description). The audit
	// log UI only renders Action, so we mirror the category into both
	// fields here. Without this every row surfaces as "吊销" (the
	// frontend's fallback for unknown action strings) because Action stays
	// empty for every writeOpLog call site.
	//
	// Result defaults to "成功" — call sites that hit a failure branch
	// already encode the failure text into Content (e.g. "测试失败: ..."),
	// and the audit list filters off the Result column. Empty Result was
	// rendering as "拒绝" via the same unknown-fallback path on the
	// frontend, so we set a sensible default here.
	entry := model.OperationLog{
		LogID:      "LOG-" + time.Now().Format("20060102150405"),
		Operator:   operator,
		Action:     actionType,
		ActionType: actionType,
		Module:     module,
		Content:    content,
		Target:     content,
		IP:         ip,
		Result:     "成功",
		Detail:     detail,
		StepUp:     stepUp,
	}
	db.DB.Create(&entry)
	// Fan out to the syslog forwarder. No-op when the operator hasn't
	// configured a server (the forwarder checks Enabled itself); we
	// always call so toggling syslog on doesn't require an app restart.
	syslog.Send(syslog.Entry{
		LogID:      entry.LogID,
		Operator:   entry.Operator,
		ActionType: entry.ActionType,
		Module:     entry.Module,
		Content:    entry.Content,
		IP:         entry.IP,
		Result:     entry.Result,
		Time:       entry.CreatedAt,
	})
}

func writeOpLogAuth(c *gin.Context, actionType, module, content, detail string) {
	claims := middleware.GetClaims(c)
	if claims != nil {
		writeOpLog(c, claims.Username, actionType, module, content, detail)
	}
}

// actorUsername returns the current request's authenticated username, or
// "system" when invoked from a non-HTTP path (passed nil context).
func actorUsername(c *gin.Context) string {
	if c == nil {
		return "system"
	}
	if claims := middleware.GetClaims(c); claims != nil {
		return claims.Username
	}
	return "system"
}

package resp

// Friendly DB-error translation.
//
// Why this exists
// ───────────────
// Most write handlers shell out to GORM with `db.DB.Create(&x).Error`
// or `Updates(...).Error` and pass the raw `err.Error()` straight to
// the operator. That works fine when something genuinely unexpected
// happens (e.g. connection drop), but for the *predictable* failure
// modes — UNIQUE-key conflicts, out-of-range values, FK violations —
// it leaks a English-only MySQL error like
//
//   Error 1062 (23000): Duplicate entry 'wdx.com' for key 'zones.idx_zones_domain'
//
// onto a Chinese-locale UI. The operator usually has no way to
// translate "idx_zones_domain" into "you tried to create a duplicate
// domain"; surfacing that as a friendly Chinese message is much
// more useful than a faithful copy of the wire error.
//
// Design
// ──────
// FriendlyDBError takes the raw error and returns a (status, message)
// pair the handlers can pass to Fail / BadRequest / ServerError.
// We deliberately match on substrings of err.Error() rather than
// importing the MySQL driver's typed errors here — the resp package
// must stay driver-agnostic so the SQLite-backed test build keeps
// compiling, and the message string is stable across the drivers we
// care about (MySQL 5.7+, MariaDB 10.x, SQLite via glebarez).
//
// Callers
// ───────
// The dominant entry point is `DBError(c, err)`; new handlers should
// prefer it over `ServerError(c, err.Error())`. Existing callers can
// migrate opportunistically.

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

// duplicateEntryRE pulls out the offending value and index name from
// the canonical MySQL 1062 message:
//
//	Duplicate entry 'wdx.com' for key 'zones.idx_zones_domain'
//
// Group 1: the value the user just tried to write
// Group 2: the (qualified) index name — we don't show this to the
//
//	operator but we use it to pick a column-specific label.
var duplicateEntryRE = regexp.MustCompile(`Duplicate entry '([^']*)' for key '([^']+)'`)

// FriendlyDBError returns (httpStatus, message) for a DB error,
// translating known MySQL error patterns into Chinese operator-
// friendly text. Falls back to the raw error string when nothing
// matches so we never *hide* an error — we only ever make it nicer.
func FriendlyDBError(err error) (int, string) {
	if err == nil {
		return http.StatusOK, ""
	}
	raw := err.Error()

	// ─── 1062 / Duplicate entry ───
	if m := duplicateEntryRE.FindStringSubmatch(raw); m != nil {
		value, key := m[1], m[2]
		// The index name conventions across the codebase:
		//
		//   zones.idx_zones_domain        → 域名
		//   zones.zone_id  (unique)       → ZONE 编号
		//   forward_servers.uk_address    → 上游服务器地址
		//   users.username                → 用户名
		//   ...
		//
		// We fall back to a generic "已存在" message when we don't
		// recognise the key — still better than the English original.
		label := dupKeyLabel(key)
		if label == "" {
			return http.StatusConflict, "记录已存在：'" + value + "' 与现有数据重复"
		}
		return http.StatusConflict, label + " '" + value + "' 已存在，请使用其他取值"
	}

	// ─── 1366 / Incorrect string value (usually a utf8mb3 column
	// being fed an emoji or other 4-byte UTF-8 character) ───
	if strings.Contains(raw, "Incorrect string value") {
		return http.StatusBadRequest, "字段包含数据库不支持的字符（通常是 4 字节表情符号），请改用普通文本"
	}

	// ─── 1264 / Out of range value ───
	if strings.Contains(raw, "Out of range value") {
		return http.StatusBadRequest, "字段数值超出数据库允许范围"
	}

	// ─── 1406 / Data too long for column ───
	if strings.Contains(raw, "Data too long for column") {
		return http.StatusBadRequest, "字段长度超过数据库限制，请缩短内容后重试"
	}

	// ─── 1452 / FK constraint fails on INSERT/UPDATE
	//      1451 / FK constraint fails on DELETE ───
	if strings.Contains(raw, "a foreign key constraint fails") {
		if strings.Contains(raw, "DELETE") || strings.Contains(raw, "Cannot delete") {
			return http.StatusConflict, "该记录被其他数据引用，无法删除；请先解除引用后重试"
		}
		return http.StatusBadRequest, "外键约束未满足：所引用的关联数据不存在"
	}

	// Unknown error → preserve original. Operator + log keep the
	// full English message; UI also sees it (matches old behaviour).
	return http.StatusInternalServerError, raw
}

// dupKeyLabel maps an offending index name to a user-facing field
// label. Tries the qualified form first ("table.index") then the bare
// trailing segment so we tolerate drivers that emit either style.
func dupKeyLabel(key string) string {
	// Strip the optional `table.` prefix so the table can be matched
	// alongside the bare key form below.
	bare := key
	if idx := strings.LastIndex(key, "."); idx >= 0 {
		bare = key[idx+1:]
	}
	switch bare {
	case "idx_zones_domain", "domain", "uk_domain":
		return "域名"
	case "zone_id", "uk_zone_id":
		return "ZONE 编号"
	case "username", "uk_username":
		return "用户名"
	case "uk_address", "address":
		return "上游服务器地址"
	case "uk_name", "name":
		return "名称"
	}
	return ""
}

// DBError responds to the client with the friendly form of err. It
// is the recommended replacement for `ServerError(c, err.Error())`
// at the boundary of GORM calls — everything else (input validation
// failures, business-rule violations) should continue to use the
// existing BadRequest / Forbidden / etc. helpers directly.
func DBError(c *gin.Context, err error) {
	status, msg := FriendlyDBError(err)
	if status == http.StatusOK {
		// Defensive: caller asked us to respond but the err was nil.
		// Fall through to a generic 500 so the client still gets a
		// usable error instead of an empty body.
		Fail(c, http.StatusInternalServerError, "未知错误")
		return
	}
	Fail(c, status, msg)
}

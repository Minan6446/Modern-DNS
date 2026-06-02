// Package rbac implements role-based access control on top of the existing
// roles / role_permissions tables. Permissions are simple dotted strings like
// "security.write" and are enforced by the middleware.RequirePerm decorator.
//
// The cache is rebuilt periodically (30s) and on demand via Reload(), which
// the role-management handler invokes after writing new permissions so that
// changes take effect immediately rather than after the next refresh tick.
package rbac

import (
	"strings"
	"sync"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"
)

// Permission constants used throughout the codebase. New strings should be
// declared here so the spec is centralized and greppable.
//
// Two parallel naming conventions live in this package:
//
//   - "Coarse" keys like `setting.write` are what existing route
//     decorators reference (RequirePerm(rbac.PermSettingWrite)). They
//     map roughly 1:1 to a write-shaped resource group.
//
//   - "Fine-grained" keys like `setting:backup:delete` mirror the UI
//     permission tree the operator ticks per role. The frontend stores
//     them verbatim in role_permissions.
//
// Both shapes are honored by HasPermission. The bridging happens at
// Reload() time: granting a fine-grained key implicitly grants the
// coarse alias listed in fineToCoarse below, so older routes that test
// `setting.write` keep working when the operator only ticked
// `setting:backup:delete`. New routes can also decorate with a
// fine-grained key directly via RequirePerm("setting:backup:delete")
// for finer enforcement; the same set-membership lookup serves both.
const (
	PermClusterAdmin  = "cluster.admin"
	PermUserWrite     = "user.write"
	PermRoleWrite     = "role.write"
	PermSettingWrite  = "setting.write"
	PermSecurityWrite = "security.write"
	PermDomainWrite   = "domain.write"
	PermForwardWrite  = "forward.write"
	PermCacheWrite    = "cache.write"
	PermMonitorWrite  = "monitor.write"
	PermBackupWrite   = "backup.write"
	PermAuditExport   = "audit.export"
)

// fineToCoarse maps a fine-grained UI permission key to the coarse
// capability constant it implies. Only **mutating** fine-grained keys
// have entries — `setting:user:view` is a read-only marker that doesn't
// need to imply anything because list endpoints don't gate themselves.
//
// The expansion happens in Reload(): when a role's row in
// role_permissions holds a fine-grained key, both the original key and
// its coarse alias are inserted into the in-memory set. This keeps the
// route decorators (which still use coarse constants) working without
// requiring every route to be re-decorated.
//
// When adding new fine-grained keys to the UI tree, add the matching
// alias here — otherwise the operator will tick the box, see the
// permission persist in DB, and still get 403'd by the middleware.
var fineToCoarse = map[string]string{
	// Settings module ───────────────────────────────────────────────
	"setting:general:edit":   PermSettingWrite,
	"setting:user:edit":      PermUserWrite,
	"setting:role:edit":      PermRoleWrite,
	"setting:api-key:edit":   PermUserWrite, // API keys live alongside users
	"setting:notice:edit":    PermSettingWrite,
	"setting:log:export":     PermAuditExport,
	"setting:log:purge":      PermSettingWrite,
	"setting:backup:create":  PermBackupWrite,
	"setting:backup:restore": PermBackupWrite,
	"setting:backup:delete":  PermBackupWrite,
	// Domain module ─────────────────────────────────────────────────
	"domain:record:edit":   PermDomainWrite,
	"domain:record:delete": PermDomainWrite,
	// Forward module ────────────────────────────────────────────────
	"forward:rules:edit":        PermForwardWrite,
	"forward:load-balance:edit": PermForwardWrite,
	"forward:cache:edit":        PermCacheWrite,
	// Security module ───────────────────────────────────────────────
	"security:domain-access:edit": PermSecurityWrite,
	"security:ddos:edit":          PermSecurityWrite,
	"security:dnssec:edit":        PermSecurityWrite,
	// Monitor module ────────────────────────────────────────────────
	"monitor:alert-center:edit": PermMonitorWrite,
	"monitor:rule:edit":         PermMonitorWrite,
	"monitor:report:export":     PermAuditExport,
	// Cluster module ────────────────────────────────────────────────
	"cluster:nodes:edit":       PermClusterAdmin,
	"cluster:config-sync:edit": PermClusterAdmin,
	// Tools module — operate verbs imply no coarse perm because the
	// tools endpoints are read-shaped diagnostic helpers; gate them
	// directly with RequirePerm("tools:dig:edit") if needed.
}

// FineGrainedPermissions returns the set of fine-grained UI keys that
// have a coarse alias registered. Used by the seed step in Reload to
// decide which keys to expand without leaking the table contents.
func FineGrainedPermissions() map[string]string {
	out := make(map[string]string, len(fineToCoarse))
	for k, v := range fineToCoarse {
		out[k] = v
	}
	return out
}

// SuperAdminRole names the role that bypasses all permission checks. Existing
// data uses the Chinese label "超级管理员"; we keep that for compatibility.
const SuperAdminRole = "超级管理员"

var (
	mu        sync.RWMutex
	rolePerms map[string]map[string]struct{} // role name → set of perms
	loadedAt  time.Time
)

// Init loads the cache from DB and starts a periodic refresher. Safe to call
// once during application startup.
func Init() {
	Reload()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			Reload()
		}
	}()
}

// Reload rebuilds the in-memory role→permission cache from the database.
func Reload() {
	var roles []model.Role
	if err := db.DB.Find(&roles).Error; err != nil {
		return
	}
	roleByID := make(map[uint]string, len(roles))
	for _, r := range roles {
		roleByID[r.ID] = strings.TrimSpace(r.Name)
	}

	var rps []model.RolePermission
	if err := db.DB.Find(&rps).Error; err != nil {
		return
	}

	next := make(map[string]map[string]struct{}, len(roles))
	for _, r := range roles {
		next[strings.TrimSpace(r.Name)] = make(map[string]struct{})
	}
	for _, rp := range rps {
		name := roleByID[rp.RoleID]
		if name == "" {
			continue
		}
		set, ok := next[name]
		if !ok {
			set = make(map[string]struct{})
			next[name] = set
		}
		key := strings.TrimSpace(rp.Permission)
		if key == "" {
			continue
		}
		set[key] = struct{}{}
		// If this is a fine-grained UI key, also insert the coarse
		// alias so middleware decorators using PermXxx constants
		// continue to grant access. The alias is purely additive —
		// granting a fine-grained edit key strictly *adds* the
		// matching coarse capability; granting only the coarse key
		// remains unchanged.
		if alias, ok := fineToCoarse[key]; ok && alias != "" {
			set[alias] = struct{}{}
		}
	}

	mu.Lock()
	rolePerms = next
	loadedAt = time.Now()
	mu.Unlock()
}

// HasPermission reports whether the named role grants the given permission.
// SuperAdminRole always returns true. Roles unknown to the cache fail closed.
func HasPermission(role, perm string) bool {
	if role == SuperAdminRole {
		return true
	}
	mu.RLock()
	defer mu.RUnlock()
	set, ok := rolePerms[role]
	if !ok {
		return false
	}
	if _, ok := set["*"]; ok {
		return true
	}
	if _, ok := set[perm]; ok {
		return true
	}
	// Wildcard prefix (e.g. "security.*" grants security.write)
	dot := strings.IndexByte(perm, '.')
	if dot > 0 {
		prefix := perm[:dot] + ".*"
		if _, ok := set[prefix]; ok {
			return true
		}
	}
	return false
}

// LoadedAt returns the timestamp of the most recent successful Reload(),
// useful for diagnostics endpoints.
func LoadedAt() time.Time {
	mu.RLock()
	defer mu.RUnlock()
	return loadedAt
}

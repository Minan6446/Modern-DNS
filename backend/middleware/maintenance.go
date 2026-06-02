package middleware

import (
	"net/http"
	"strings"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"

	"github.com/gin-gonic/gin"
)

// MaintenanceMode short-circuits write requests with HTTP 503 when
// SystemConfig.MaintenanceEnabled is on. The following pass through
// unconditionally so the operator never gets locked out:
//
//   - All GET requests (read-only paths stay browseable during maint).
//   - /api/auth/* (login / refresh / logout / profile / change-password /
//     totp-* — auth flows must keep working so the admin can log in to
//     disable maintenance).
//   - /api/setting/common (so saving "maintenanceEnabled = false" is
//     always reachable, including the PUT verb).
//
// Like IPAllowlist this re-reads SystemConfig per request: cheap (PK lookup,
// prepared-statement cache) and avoids any cache-invalidation hazard when
// the operator flips the toggle from the UI.
func MaintenanceMode() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet {
			c.Next()
			return
		}
		path := c.Request.URL.Path
		if strings.HasPrefix(path, "/api/auth/") {
			c.Next()
			return
		}
		if path == "/api/setting/common" || path == "/api/setting/common/reset" {
			c.Next()
			return
		}

		var cfg model.SystemConfig
		if err := db.DB.First(&cfg, 1).Error; err != nil {
			c.Next()
			return
		}
		if !cfg.MaintenanceEnabled {
			c.Next()
			return
		}
		if w := strings.TrimSpace(cfg.MaintenanceWindow); w != "" {
			c.Header("Retry-After-Window", w)
		}
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
			"code":    503,
			"message": "系统正在维护中，写操作暂不可用",
			"data":    nil,
		})
	}
}

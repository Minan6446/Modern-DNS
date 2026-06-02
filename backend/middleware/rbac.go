package middleware

import (
	"modern-dns/pkg/rbac"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
)

// RequirePerm returns a Gin middleware that aborts with 403 unless the caller's
// JWT role grants the given permission (or any of the alternatives, if more
// than one is supplied — useful for routes that any of several capabilities
// can satisfy).
//
// Must be used after Auth(). The super-admin role bypasses all checks.
func RequirePerm(perms ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := GetClaims(c)
		if claims == nil {
			resp.Unauthorized(c, "缺少认证令牌")
			return
		}
		for _, p := range perms {
			if rbac.HasPermission(claims.Role, p) {
				c.Next()
				return
			}
		}
		resp.Forbidden(c, "权限不足")
	}
}

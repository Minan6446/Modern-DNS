package middleware

import (
	"modern-dns/pkg/cluster"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
)

// ClusterToken authenticates inter-node /api/cluster/internal calls using the
// shared cluster API token. Returns 401 when the header is missing or invalid.
func ClusterToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		supplied := c.GetHeader(cluster.HeaderClusterToken)
		if !cluster.VerifyToken(supplied) {
			resp.Unauthorized(c, "无效的集群令牌")
			return
		}
		c.Next()
	}
}

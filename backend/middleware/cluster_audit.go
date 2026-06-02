package middleware

import (
	"bytes"
	"io"
	"strings"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"

	"github.com/gin-gonic/gin"
)

// ClusterAudit logs every inter-node call into operation_logs so the cluster
// admin can audit which peer hit which endpoint, when, and what payload they
// sent. Runs after ClusterToken so unauthenticated calls are excluded.
//
// Body is captured up to 2 KiB; longer payloads are truncated with a "…"
// marker to keep the log table manageable.
func ClusterAudit() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Capture body for the audit record (limited).
		var bodySnippet string
		if c.Request.Body != nil {
			buf, _ := io.ReadAll(io.LimitReader(c.Request.Body, 2048))
			bodySnippet = string(buf)
			// Restore body for downstream handlers.
			c.Request.Body = io.NopCloser(bytes.NewReader(buf))
		}

		c.Next()

		result := "成功"
		if c.Writer.Status() >= 400 {
			result = "失败"
		}

		entry := model.OperationLog{
			Operator:     "cluster-peer",
			OperatorRole: "cluster",
			ActionType:   "集群通信",
			Action:       c.Request.Method + " " + c.FullPath(),
			Module:       "集群",
			Target:       extractNodeID(bodySnippet),
			Content:      truncate(bodySnippet, 1024),
			IP:           c.ClientIP(),
			Result:       result,
			Duration:     int(time.Since(start).Milliseconds()),
			CreatedAt:    time.Now(),
		}
		// Best-effort write; failures shouldn't block the response.
		_ = db.DB.Create(&entry)
	}
}

// extractNodeID looks for `"nodeId":"…"` or `"secondaryNodeId":"…"` in the
// payload snippet and returns the value, otherwise empty. This avoids fully
// JSON-decoding every body just for the audit field.
func extractNodeID(s string) string {
	for _, key := range []string{`"nodeId":"`, `"secondaryNodeId":"`} {
		if idx := strings.Index(s, key); idx >= 0 {
			rest := s[idx+len(key):]
			if end := strings.Index(rest, `"`); end > 0 {
				return rest[:end]
			}
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

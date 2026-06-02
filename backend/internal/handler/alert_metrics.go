package handler

import (
	"modern-dns/pkg/alertmetrics"

	"github.com/gin-gonic/gin"
)

// GET /api/monitor/alert-metrics
func GetAlertMetrics(c *gin.Context) {
	c.Header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	c.String(200, alertmetrics.RenderPrometheus())
}

package handler

import (
	"strconv"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/alertmetrics"
	"modern-dns/pkg/db"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
)

// GET /api/alert-events
func ListAlertEvents(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 100 {
		size = 20
	}

	level := c.Query("level")
	alertType := c.Query("type")
	status := c.Query("status")
	keyword := c.Query("keyword")

	query := db.DB.Model(&model.AlertEvent{})
	if level != "" {
		query = query.Where("level = ?", level)
	}
	if alertType != "" {
		query = query.Where("type = ?", alertType)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if keyword != "" {
		like := "%" + keyword + "%"
		query = query.Where("content LIKE ? OR domain LIKE ? OR type LIKE ?", like, like, like)
	}

	var total int64
	query.Count(&total)

	var events []model.AlertEvent
	query.Order("triggered_at DESC").
		Offset((page - 1) * size).
		Limit(size).
		Find(&events)
	if events == nil {
		events = []model.AlertEvent{}
	}

	// Unread count for badge display
	var unread int64
	db.DB.Model(&model.AlertEvent{}).Where("is_read = ?", false).Count(&unread)

	resp.OK(c, gin.H{"list": events, "total": total, "unread": unread})
}

// PATCH /api/alert-events/:id/confirm
func ConfirmAlertEvent(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var event model.AlertEvent
	if err := db.DB.First(&event, id).Error; err != nil {
		resp.NotFound(c, "告警事件不存在")
		return
	}
	result := db.DB.Model(&model.AlertEvent{}).Where("id = ? AND status <> ?", id, "已处理").Updates(map[string]interface{}{
		"status":  "已处理",
		"is_read": true,
	})
	if result.Error != nil {
		resp.ServerError(c, result.Error.Error())
		return
	}
	if result.RowsAffected > 0 {
		alertmetrics.IncEventResolved(result.RowsAffected)
	}
	markMonitorRuleHistoryHandledByEvent(event)
	appendAlertAudit(c, "确认告警", event.Content)
	resp.OK(c, event)
}

// PATCH /api/alert-events/confirm-all
func ConfirmAllAlertEvents(c *gin.Context) {
	result := db.DB.Model(&model.AlertEvent{}).
		Where("status = ?", "未处理").
		Updates(map[string]interface{}{"status": "已处理", "is_read": true})
	if result.Error == nil && result.RowsAffected > 0 {
		alertmetrics.IncEventResolved(result.RowsAffected)
	}
	appendAlertAudit(c, "批量确认所有告警", "全部")
	resp.OK(c, gin.H{"success": true})
}

// DELETE /api/alert-events/clean
func CleanAlertEvents(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "30"))
	if days < 1 {
		days = 30
	}
	cutoff := time.Now().AddDate(0, 0, -days)

	result := db.DB.Where("triggered_at < ?", cutoff).Delete(&model.AlertEvent{})
	appendAlertAudit(c, "清理历史告警", "")
	resp.OK(c, gin.H{"deleted": result.RowsAffected, "beforeDate": cutoff.Format("2006-01-02")})
}

// GET /api/alert-events/summary
func AlertEventSummary(c *gin.Context) {
	type levelCount struct {
		Level string `json:"level"`
		Count int64  `json:"count"`
	}
	var byLevel []levelCount
	db.DB.Model(&model.AlertEvent{}).
		Select("level, COUNT(*) as count").
		Where("status = ?", "未处理").
		Group("level").
		Scan(&byLevel)
	if byLevel == nil {
		byLevel = []levelCount{}
	}

	var totalUnread int64
	db.DB.Model(&model.AlertEvent{}).Where("is_read = ?", false).Count(&totalUnread)

	var totalPending int64
	db.DB.Model(&model.AlertEvent{}).Where("status = ?", "未处理").Count(&totalPending)

	resp.OK(c, gin.H{
		"byLevel":      byLevel,
		"totalUnread":  totalUnread,
		"totalPending": totalPending,
	})
}

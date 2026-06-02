package handler

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"
)

// markMonitorRuleHistoryHandledByEvent keeps monitor_rule_history aligned with
// alert_event handled status for both new and legacy AUTO-* rows.
func markMonitorRuleHistoryHandledByEvent(event model.AlertEvent) {
	if event.ID <= 0 {
		return
	}
	windowStart := event.TriggeredAt.Add(-5 * time.Second)
	windowEnd := event.TriggeredAt.Add(5 * time.Second)

	db.DB.Model(&model.MonitorRuleHistory{}).
		Where(
			"rule_id = ? OR (rule_type = ? AND content = ? AND trigger_at >= ? AND trigger_at <= ?)",
			fmt.Sprintf("AUTO-%d", event.ID),
			event.Type,
			event.Content,
			windowStart,
			windowEnd,
		).
		Update("handle_status", "已处理")
}

// reconcileMonitorRuleHistoryHandled backfills stale AUTO history rows whose
// corresponding alert_event has already been handled.
func reconcileMonitorRuleHistoryHandled(maxRows int) {
	if maxRows <= 0 {
		maxRows = 120
	}

	var pending []model.MonitorRuleHistory
	db.DB.Where("handle_status <> ? AND rule_id LIKE ?", "已处理", "AUTO-%").
		Order("trigger_at DESC").
		Limit(maxRows).
		Find(&pending)

	for _, row := range pending {
		if historyMatchesHandledEvent(row) {
			db.DB.Model(&model.MonitorRuleHistory{}).
				Where("id = ?", row.ID).
				Update("handle_status", "已处理")
		}
	}
}

func historyMatchesHandledEvent(row model.MonitorRuleHistory) bool {
	if strings.HasPrefix(row.RuleID, "AUTO-") {
		idStr := strings.TrimSpace(strings.TrimPrefix(row.RuleID, "AUTO-"))
		if id, err := strconv.Atoi(idStr); err == nil && id > 0 {
			var exact int64
			db.DB.Model(&model.AlertEvent{}).
				Where("id = ? AND status = ?", id, "已处理").
				Count(&exact)
			if exact > 0 {
				return true
			}
		}
	}

	windowStart := row.TriggerAt.Add(-5 * time.Second)
	windowEnd := row.TriggerAt.Add(5 * time.Second)
	var legacy int64
	db.DB.Model(&model.AlertEvent{}).
		Where("type = ? AND content = ? AND status = ? AND triggered_at >= ? AND triggered_at <= ?",
			row.RuleType,
			row.Content,
			"已处理",
			windowStart,
			windowEnd,
		).
		Count(&legacy)
	return legacy > 0
}

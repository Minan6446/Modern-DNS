package handler

import (
	"net"
	"strconv"
	"strings"
	"time"

	"modern-dns/internal/dnsengine"
	"modern-dns/internal/model"
	"modern-dns/pkg/db"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// ─── Validation helpers ─────────────────────────────────────────────────────

// validProtocols mirrors what dnsengine.resolveProbeProto accepts.
// Values are stored as-typed (UDP/TCP/DoT/DoH) and matched
// case-insensitively at probe time.
var lbValidProtocols = map[string]struct{}{
	"udp": {}, "tcp": {}, "dot": {}, "doh": {}, "tls": {}, "tcp-tls": {}, "https": {},
}

// normalizeServerInput trims fields, defaults, and validates them. Returns
// a human-readable error suitable for surfacing to the operator.
func normalizeServerInput(s *model.LbServer) string {
	s.Address = strings.TrimSpace(s.Address)
	s.Name = strings.TrimSpace(s.Name)
	s.Protocol = strings.TrimSpace(s.Protocol)
	if s.Address == "" {
		return "address required"
	}
	// Accept IP literal or hostname; only reject obviously bad chars.
	// We don't gate on "must be IP" because operators legitimately
	// configure DoH/DoT endpoints by hostname for SNI.
	if strings.ContainsAny(s.Address, " \t\r\n,;") {
		return "address contains whitespace or comma"
	}
	if ip := net.ParseIP(s.Address); ip == nil {
		// Try as hostname — must contain at least one dot or be a
		// valid bare label; we only reject characters that would
		// break URL/host parsing downstream.
		if strings.ContainsAny(s.Address, "/?#@") {
			return "address contains illegal characters"
		}
	}
	if s.Port <= 0 || s.Port > 65535 {
		return "port must be 1-65535"
	}
	if s.Protocol == "" {
		s.Protocol = "UDP"
	}
	if _, ok := lbValidProtocols[strings.ToLower(s.Protocol)]; !ok {
		return "protocol must be one of UDP/TCP/DoT/DoH"
	}
	if s.Weight <= 0 {
		s.Weight = 1
	}
	if s.Weight > 1000 {
		return "weight must be ≤ 1000"
	}
	if s.MaxConns < 0 {
		s.MaxConns = 0
	}
	return ""
}

// ─── Groups ──────────────────────────────────────────────────────────────────

// GET /api/forward/lb/groups
//
// Returns all LB groups with their servers embedded. Servers are loaded
// in a single batched IN(group_ids) query — earlier per-group SELECTs
// were a textbook N+1 that hammered the DB on dashboards with many groups.
//
// QPS estimate: total query_logs in the last minute, divided by total
// healthy enabled servers, divided by 60 (s/min). Operators see a
// per-server-equivalent QPS the same group attracts. This intentionally
// over-counts when traffic is uneven across groups, but the dashboard
// only uses it as an order-of-magnitude indicator. Earlier code ran
// the integer divisions in the wrong order (logCount / total / 60),
// which truncated to zero whenever logCount < total*60.
func ListLbGroups(c *gin.Context) {
	var groups []model.LbGroup
	db.DB.Order("created_at DESC").Find(&groups)

	type groupResp struct {
		model.LbGroup
		Servers []model.LbServer `json:"servers"`
		QPS     int              `json:"qps"`
	}

	// 1) Batch-load all servers belonging to any returned group.
	groupIDs := make([]uint, 0, len(groups))
	for _, g := range groups {
		groupIDs = append(groupIDs, g.ID)
	}
	serversByGroup := make(map[uint][]model.LbServer, len(groupIDs))
	if len(groupIDs) > 0 {
		var allServers []model.LbServer
		db.DB.Where("group_id IN ?", groupIDs).Order("group_id, created_at").Find(&allServers)
		for _, s := range allServers {
			serversByGroup[s.GroupID] = append(serversByGroup[s.GroupID], s)
		}
	}

	// 2) QPS: compute per-server-per-second from the minute window.
	since := time.Now().Add(-1 * time.Minute)
	var logCount int64
	db.DB.Model(&model.QueryLog{}).Where("created_at >= ?", since).Count(&logCount)

	var totalHealthy int64
	db.DB.Model(&model.LbServer{}).
		Where("enabled = ? AND status = ?", true, "健康").
		Count(&totalHealthy)

	perServerQPS := 0
	if totalHealthy > 0 {
		// float div to avoid integer-truncation-to-zero on small
		// volumes; round half-away-from-zero for the dashboard.
		raw := float64(logCount) / float64(totalHealthy) / 60.0
		if raw < 0 {
			raw = 0
		}
		perServerQPS = int(raw + 0.5)
	}

	result := make([]groupResp, 0, len(groups))
	for _, g := range groups {
		servers := serversByGroup[g.ID]
		qps := 0
		for _, s := range servers {
			if s.Enabled && s.Status == "健康" {
				qps += perServerQPS
			}
		}
		result = append(result, groupResp{LbGroup: g, Servers: servers, QPS: qps})
	}
	resp.OK(c, result)
}

// POST /api/forward/lb/groups
func CreateLbGroup(c *gin.Context) {
	var group model.LbGroup
	if err := c.ShouldBindJSON(&group); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	group.ID = 0
	group.Name = strings.TrimSpace(group.Name)
	if group.Name == "" {
		resp.BadRequest(c, "name required")
		return
	}
	if group.Status == "" {
		group.Status = "启用"
	}
	if group.HealthCheckInterval <= 0 {
		group.HealthCheckInterval = 30
	}
	if group.HealthCheckInterval < 5 {
		// Hard floor: probes are at least 5s apart so a bank of
		// upstreams behind a slow VPN can't be put into a hot loop
		// by an over-eager operator.
		group.HealthCheckInterval = 5
	}
	if err := db.DB.Create(&group).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	dnsengine.Trigger()
	resp.OK(c, group)
}

// DELETE /api/forward/lb/groups/:id
//
// Group + member servers are deleted atomically inside a single
// transaction. The earlier two-step delete could leave orphan rows in
// lb_servers if the second statement crashed (rare but real on a
// dying replica), and the engine then kept probing zombies forever.
func DeleteLbGroup(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if id <= 0 {
		resp.BadRequest(c, "invalid id")
		return
	}
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("group_id = ?", id).Delete(&model.LbServer{}).Error; err != nil {
			return err
		}
		return tx.Delete(&model.LbGroup{}, id).Error
	})
	if err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	dnsengine.Trigger()
	resp.OK(c, gin.H{"success": true})
}

// ─── Servers ─────────────────────────────────────────────────────────────────

// POST /api/forward/lb/groups/:id/servers
func CreateLbServer(c *gin.Context) {
	groupID, _ := strconv.Atoi(c.Param("id"))
	if groupID <= 0 {
		resp.BadRequest(c, "invalid group id")
		return
	}
	// Ensure the group actually exists; earlier code happily inserted
	// orphan servers under a non-existent group_id, which then never
	// got cleaned up because the cascading delete keys off the parent.
	var grp model.LbGroup
	if err := db.DB.First(&grp, groupID).Error; err != nil {
		resp.NotFound(c, "group not found")
		return
	}

	var server model.LbServer
	if err := c.ShouldBindJSON(&server); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if msg := normalizeServerInput(&server); msg != "" {
		resp.BadRequest(c, msg)
		return
	}
	server.ID = 0
	server.GroupID = uint(groupID)
	server.Status = "检测中"
	// Honor caller's Enabled if explicitly false; default true for backwards compat.
	// Gin's ShouldBindJSON already populated server.Enabled from the body.
	server.Latency = 0
	server.SuccessRate = 0
	server.LastError = ""
	if err := db.DB.Create(&server).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	dnsengine.Trigger()
	resp.OK(c, server)
}

// PUT /api/forward/lb/servers/:sid
//
// Edits the mutable fields of a server (name, address, port, protocol,
// weight, max_conns) without disturbing the probe state (latency /
// success_rate / status / last_error) — those will refresh on the
// next health-check cycle naturally. enabled is intentionally NOT
// updated here; use the dedicated /toggle endpoint so the audit log
// distinguishes "operator changed config" from "operator paused
// traffic".
func UpdateLbServer(c *gin.Context) {
	sid, _ := strconv.Atoi(c.Param("sid"))
	if sid <= 0 {
		resp.BadRequest(c, "invalid id")
		return
	}
	var existing model.LbServer
	if err := db.DB.First(&existing, sid).Error; err != nil {
		resp.NotFound(c, "server not found")
		return
	}
	var patch model.LbServer
	if err := c.ShouldBindJSON(&patch); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	// Apply only mutable config fields onto the existing row.
	existing.Name = patch.Name
	existing.Address = patch.Address
	existing.Port = patch.Port
	existing.Protocol = patch.Protocol
	existing.Weight = patch.Weight
	existing.MaxConns = patch.MaxConns
	if msg := normalizeServerInput(&existing); msg != "" {
		resp.BadRequest(c, msg)
		return
	}
	// Reset probe state — address/protocol may have changed, so the
	// previous status is stale by definition.
	updates := map[string]interface{}{
		"name":         existing.Name,
		"address":      existing.Address,
		"port":         existing.Port,
		"protocol":     existing.Protocol,
		"weight":       existing.Weight,
		"max_conns":    existing.MaxConns,
		"status":       "检测中",
		"latency":      0,
		"success_rate": 0,
		"last_error":   "",
	}
	if err := db.DB.Model(&model.LbServer{}).Where("id = ?", sid).Updates(updates).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	dnsengine.Trigger()
	resp.OK(c, existing)
}

// DELETE /api/forward/lb/servers/:sid
func DeleteLbServer(c *gin.Context) {
	sid, _ := strconv.Atoi(c.Param("sid"))
	if sid <= 0 {
		resp.BadRequest(c, "invalid id")
		return
	}
	res := db.DB.Delete(&model.LbServer{}, sid)
	if res.Error != nil {
		resp.ServerError(c, res.Error.Error())
		return
	}
	if res.RowsAffected == 0 {
		resp.NotFound(c, "server not found")
		return
	}
	dnsengine.Trigger()
	resp.OK(c, gin.H{"success": true})
}

// PUT /api/forward/lb/servers/:sid/toggle
//
// Flips enabled. When disabling we also reset status to "禁用" so the
// dashboard doesn't keep showing the last-known 异常/健康 state for a
// row that's no longer being probed; the probe loop wouldn't touch a
// disabled row anyway, so the indicator would otherwise freeze.
func ToggleLbServer(c *gin.Context) {
	sid, _ := strconv.Atoi(c.Param("sid"))
	if sid <= 0 {
		resp.BadRequest(c, "invalid id")
		return
	}
	var existing model.LbServer
	if err := db.DB.First(&existing, sid).Error; err != nil {
		resp.NotFound(c, "server not found")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}

	updates := map[string]interface{}{"enabled": req.Enabled}
	if !req.Enabled {
		updates["status"] = "禁用"
		updates["last_error"] = ""
	} else if existing.Status == "禁用" {
		// Coming out of paused state — give the probe loop a clean
		// slate so the dashboard immediately shows "检测中" until
		// the next probe cycle confirms health.
		updates["status"] = "检测中"
	}
	if err := db.DB.Model(&model.LbServer{}).Where("id = ?", sid).Updates(updates).Error; err != nil {
		resp.ServerError(c, err.Error())
		return
	}
	dnsengine.Trigger()
	resp.OK(c, gin.H{"success": true})
}

// POST /api/forward/lb/groups/:id/health-check
//
// Triggers an immediate engine probe pass for the given group's enabled
// servers (disabled rows are skipped — probing them would just rewrite
// "禁用" status back to 异常/健康 and confuse the dashboard) and returns
// the freshly-updated rows from the DB. The engine's background loop
// continues to refresh status on its own schedule.
func LbHealthCheck(c *gin.Context) {
	groupID, _ := strconv.Atoi(c.Param("id"))
	if groupID <= 0 {
		resp.BadRequest(c, "invalid group id")
		return
	}
	var servers []model.LbServer
	db.DB.Where("group_id = ? AND enabled = ?", groupID, true).Find(&servers)

	if len(servers) > 0 {
		dnsengine.ProbeServers(servers)
	}

	// Re-read all rows in the group (including disabled ones) so the
	// dashboard sees the same set it just rendered.
	var all []model.LbServer
	db.DB.Where("group_id = ?", groupID).Order("created_at").Find(&all)
	resp.OK(c, all)
}

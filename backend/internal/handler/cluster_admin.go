package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"modern-dns/config"
	"modern-dns/internal/dnsengine"
	"modern-dns/internal/model"
	"modern-dns/pkg/cluster"
	"modern-dns/pkg/db"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
)

// ─── Cluster control-plane (admin) ────────────────────────────────────────────
//
// These endpoints implement the ClusterManager spec:
//   POST   /api/cluster/initialize  – create the cluster (Primary)
//   DELETE /api/cluster              – tear down the cluster
//   POST   /api/cluster/resync       – force config sync to all nodes
//   POST   /api/cluster/internal/join       – peer→primary registration
//   POST   /api/cluster/internal/heartbeat  – peer→primary keep-alive
//   POST   /api/cluster/internal/leave      – peer→primary graceful exit
//   GET    /api/cluster/internal/state      – peer←primary cluster snapshot
//
// /internal/* are token-authenticated (X-Cluster-Token); /initialize, /resync,
// and DELETE require the cluster.admin RBAC permission.

// ─── Public admin endpoints ──────────────────────────────────────────────────

// POST /api/cluster/initialize
func InitializeCluster(c *gin.Context) {
	var payload struct {
		ClusterDomain        string   `json:"clusterDomain" binding:"required"`
		PrimaryNodeIPAddrs   []string `json:"primaryNodeIpAddresses" binding:"required"`
		HeartbeatIntervalSec int      `json:"heartbeatIntervalSec"`
		ConfigRefreshSec     int      `json:"configRefreshSec"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if len(payload.PrimaryNodeIPAddrs) == 0 || len(payload.PrimaryNodeIPAddrs) > 10 {
		resp.BadRequest(c, "primaryNodeIpAddresses 长度必须在 1-10 之间")
		return
	}

	var settings model.ClusterSettings
	db.DB.First(&settings, 1)
	if settings.Initialized {
		resp.BadRequest(c, "集群已初始化，请先 DELETE 后再重建")
		return
	}

	// Generate token + ensure HTTPS cert
	token := cluster.GenerateToken()
	if _, _, err := cluster.EnsureSelfSignedCert(config.C.Cluster.CertDir, payload.ClusterDomain, payload.PrimaryNodeIPAddrs); err != nil {
		resp.ServerError(c, "证书生成失败: "+err.Error())
		return
	}

	heartbeat := payload.HeartbeatIntervalSec
	if heartbeat <= 0 {
		heartbeat = config.C.Cluster.HeartbeatIntervalSec
	}
	refresh := payload.ConfigRefreshSec
	if refresh <= 0 {
		refresh = config.C.Cluster.ConfigRefreshSec
	}

	settings = model.ClusterSettings{
		ID:                   1,
		Initialized:          true,
		ClusterDomain:        payload.ClusterDomain,
		PrimaryIPs:           strings.Join(payload.PrimaryNodeIPAddrs, ","),
		APIToken:             token,
		HeartbeatIntervalSec: heartbeat,
		ConfigRefreshSec:     refresh,
		ConfigVersion:        newConfigVersion(),
		UpdatedAt:            time.Now(),
	}
	db.DB.Save(&settings)
	cluster.SetToken(token)

	// Register self as Primary node (static identity only; live state lives
	// in pkg/cluster runtime).
	now := time.Now()
	self := model.ClusterNode{
		NodeID:      newNodeID(),
		Name:        "primary-" + payload.ClusterDomain,
		IP:          payload.PrimaryNodeIPAddrs[0],
		IPAddresses: strings.Join(payload.PrimaryNodeIPAddrs, ","),
		URL:         fmt.Sprintf("https://%s:%s", payload.PrimaryNodeIPAddrs[0], config.C.Cluster.HTTPSPort),
		Port:        parsePortDefault(config.C.Cluster.HTTPSPort, 8443),
		Role:        "主节点",
		Version:     appNodeVersion,
		JoinedAt:    now,
	}
	db.DB.Create(&self)
	cluster.RegisterSelf(self.NodeID)

	writeOpLogAuth(c, "初始化", "集群", payload.ClusterDomain, "")
	// Return the token exactly once so the operator can hand it to peers.
	resp.OK(c, gin.H{
		"clusterDomain":        settings.ClusterDomain,
		"apiToken":             token,
		"heartbeatIntervalSec": settings.HeartbeatIntervalSec,
		"configRefreshSec":     settings.ConfigRefreshSec,
		"configVersion":        settings.ConfigVersion,
	})
}

// DELETE /api/cluster
func DeleteCluster(c *gin.Context) {
	force := c.Query("force") == "1" || c.Query("forceDelete") == "true"
	var settings model.ClusterSettings
	db.DB.First(&settings, 1)
	if !settings.Initialized {
		resp.OK(c, gin.H{"deleted": false})
		return
	}

	// Forget every non-self runtime entry; peers gracefully detach on next
	// heartbeat failure.
	cluster.ForgetAllExceptSelf()
	if force {
		selfID := cluster.SelfID()
		if selfID != "" {
			db.DB.Where("node_id <> ?", selfID).Delete(&model.ClusterNode{})
		} else {
			db.DB.Where("role <> ?", "主节点").Delete(&model.ClusterNode{})
		}
	}

	db.DB.Model(&settings).Updates(map[string]interface{}{
		"initialized":    false,
		"api_token":      "",
		"primary_ips":    "",
		"cluster_domain": "",
		"updated_at":     time.Now(),
	})
	cluster.SetToken("")

	forceLabel := "仅本节点"
	if force {
		forceLabel = "强制解散全集群"
	}
	writeOpLogAuth(c, "解散", "集群", forceLabel, fmt.Sprintf(`{"force":%v}`, force))
	resp.OK(c, gin.H{"deleted": true, "force": force})
}

// POST /api/cluster/resync — actually push the snapshot to every secondary.
func ResyncCluster(c *gin.Context) {
	snap := buildAndStampSnapshot()
	pushResults := pushSnapshotToAllSecondaries(&snap, "manual-all", actorUsername(c))

	writeOpLogAuth(c, "强制同步", "集群",
		fmt.Sprintf("版本 %s・成功 %d・失败 %d", snap.Version, pushResults.Success, pushResults.Failed),
		fmt.Sprintf(`{"version":"%s","success":%d,"failed":%d}`, snap.Version, pushResults.Success, pushResults.Failed))
	resp.OK(c, gin.H{
		"configVersion": snap.Version,
		"syncedAt":      time.Now().Format("2006-01-02 15:04:05"),
		"results":       pushResults.Detail,
	})
}

// POST /api/cluster/rotate-token
//
// Rotates the cluster API token. The previous token continues to verify
// for `graceSec` seconds (default 60) so secondaries can pick up the new
// value on their next heartbeat without dropping the cluster. The new
// token is returned ONCE in the response — operators must record it
// before navigating away (the GET /state endpoint never reveals tokens).
func RotateClusterToken(c *gin.Context) {
	var payload struct {
		GraceSec int `json:"graceSec"`
	}
	_ = c.ShouldBindJSON(&payload)
	if payload.GraceSec <= 0 {
		payload.GraceSec = 60
	}
	if payload.GraceSec > 600 {
		payload.GraceSec = 600
	}
	var settings model.ClusterSettings
	if err := db.DB.First(&settings, 1).Error; err != nil || !settings.Initialized {
		resp.BadRequest(c, "集群未初始化，无法轮换 token")
		return
	}
	newToken := cluster.RotateToken(time.Duration(payload.GraceSec) * time.Second)
	db.DB.Model(&settings).Update("api_token", newToken)

	writeOpLogAuth(c, "密钥轮换", "集群",
		fmt.Sprintf("老密钥宽限期 %d 秒", payload.GraceSec),
		fmt.Sprintf(`{"graceSec":%d}`, payload.GraceSec))
	resp.OK(c, gin.H{
		"apiToken":  newToken,
		"graceSec":  payload.GraceSec,
		"rotatedAt": time.Now().Format("2006-01-02 15:04:05"),
		"reminder":  "请立即将新 token 同步给所有从节点；旧 token 会在缓冲期后失效。",
	})
}

// pushResult summarizes a fan-out of config pushes to secondary nodes.
type pushResult struct {
	Success int        `json:"success"`
	Failed  int        `json:"failed"`
	Detail  []pushItem `json:"detail"`
}

type pushItem struct {
	NodeID  string `json:"nodeId"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

// retry backoff schedule. After 3 failed pushes the row is left at "异常"
// and the scheduler stops retrying — operator must intervene.
var retryBackoff = []time.Duration{
	30 * time.Second,
	2 * time.Minute,
	10 * time.Minute,
}

// pushSnapshotToNodes fans the given snapshot out to the supplied secondary
// nodes (skipping any with an empty URL or that aren't 从节点 roles). Failures
// per node are collected; one bad node never aborts the others. Each node's
// cluster_config_sync row is updated to reflect the push outcome — including
// retry_count / next_retry_at bookkeeping consumed by the scheduler.
//
// `trigger` is one of "manual" / "manual-all" / "auto" / "retry"; it is
// stamped into the ClusterSyncHistory audit row that gets written when this
// function returns.
//
// Used by Resync / SyncNodeConfig / SyncAllNodeConfigs / scheduler so they
// share the same real wire path; before the B1+B2 work the per-node
// Sync* handlers only flipped DB state without contacting the secondary.
func pushSnapshotToNodes(snap *cluster.ConfigSnapshot, nodes []model.ClusterNode, trigger, operator string) pushResult {
	cli := cluster.NewClient(0, config.C.Cluster.IgnoreCertificateErrors)
	token := cluster.CurrentToken()

	startedAt := time.Now()
	out := pushResult{Detail: make([]pushItem, 0, len(nodes))}
	for _, n := range nodes {
		if n.Role != "从节点" || strings.TrimSpace(n.URL) == "" {
			continue
		}
		if n.Drained {
			// Drained nodes are intentionally excluded from sync rotation;
			// the operator must un-drain before pushes resume.
			continue
		}
		item := pushItem{NodeID: n.NodeID, Name: n.Name, URL: n.URL}
		now := time.Now()
		if token == "" {
			item.Message = "集群未初始化或 token 为空"
			out.Detail = append(out.Detail, item)
			out.Failed++
			recordPushFailure(n.ID, now, item.Message)
			continue
		}
		err := cli.Post(cluster.JoinURL(n.URL, "/api/cluster/internal/apply-config"), token, snap, nil)
		if err != nil {
			item.Message = err.Error()
			out.Detail = append(out.Detail, item)
			out.Failed++
			recordPushFailure(n.ID, now, err.Error())
			continue
		}
		item.OK = true
		out.Detail = append(out.Detail, item)
		out.Success++
		db.DB.Model(&model.ClusterConfigSync{}).Where("node_id = ?", n.ID).Updates(map[string]interface{}{
			"sync_status":    "已同步",
			"config_version": snap.Version,
			"diff_count":     0,
			"diff_detail":    "[]",
			"last_sync_at":   now,
			"retry_count":    0,
			"next_retry_at":  time.Time{},
		})
	}

	// Audit row — only when at least one target was actually attempted.
	if len(out.Detail) > 0 {
		notes, _ := json.Marshal(out.Detail)
		db.DB.Create(&model.ClusterSyncHistory{
			Version:      snap.Version,
			StartedAt:    startedAt,
			FinishedAt:   time.Now(),
			TotalNodes:   len(out.Detail),
			SuccessCount: out.Success,
			FailedCount:  out.Failed,
			Trigger:      trigger,
			TriggeredBy:  operator,
			Notes:        string(notes),
		})
		// Notify SSE subscribers so the sync-management page can refresh
		// its rows + history modal without waiting on a poll tick.
		cluster.Publish("sync-finished", "", map[string]any{
			"version": snap.Version,
			"trigger": trigger,
			"success": out.Success,
			"failed":  out.Failed,
		})
	}
	return out
}

// recordPushFailure stamps the failure message + advances the retry budget.
// When retry_count reaches len(retryBackoff) we leave next_retry_at at zero
// so the scheduler doesn't pick it up again — operator action required.
func recordPushFailure(nodeID uint, now time.Time, errMsg string) {
	var rec model.ClusterConfigSync
	if err := db.DB.Where("node_id = ?", nodeID).First(&rec).Error; err != nil {
		return
	}
	next := rec.RetryCount + 1
	updates := map[string]any{
		"sync_status":  "异常",
		"last_sync_at": now,
		"diff_detail":  errMsg,
		"retry_count":  next,
	}
	if next <= len(retryBackoff) {
		updates["next_retry_at"] = now.Add(retryBackoff[next-1])
	} else {
		// Out of retry budget — clear the schedule so the auto-retry loop
		// stops touching it.
		updates["next_retry_at"] = time.Time{}
	}
	db.DB.Model(&rec).Updates(updates)
}

// pushSnapshotToAllSecondaries is a convenience wrapper around
// pushSnapshotToNodes that selects every active 从节点 from the database.
func pushSnapshotToAllSecondaries(snap *cluster.ConfigSnapshot, trigger, operator string) pushResult {
	var nodes []model.ClusterNode
	db.DB.Where("role = ? AND url <> ''", "从节点").Find(&nodes)
	return pushSnapshotToNodes(snap, nodes, trigger, operator)
}

// buildAndStampSnapshot generates a fresh ConfigSnapshot, advances
// cluster_settings.config_version, and returns both. Centralised so all sync
// paths produce versions that increase monotonically and the value the UI
// shows always matches what was actually pushed.
func buildAndStampSnapshot() cluster.ConfigSnapshot {
	version := newConfigVersion()
	db.DB.Model(&model.ClusterSettings{}).Where("id = 1").Updates(map[string]interface{}{
		"config_version": version,
		"updated_at":     time.Now(),
	})
	return cluster.BuildSnapshot(version)
}

// GET /api/cluster/state — admin-friendly snapshot
func GetClusterState(c *gin.Context) {
	state := buildClusterInfo()
	resp.OK(c, state)
}

// ─── Internal peer endpoints (token-protected) ───────────────────────────────

// POST /api/cluster/internal/join
func PeerJoin(c *gin.Context) {
	var payload struct {
		SecondaryNodeID  string   `json:"secondaryNodeId"`
		SecondaryName    string   `json:"secondaryName"`
		SecondaryURL     string   `json:"secondaryNodeUrl" binding:"required"`
		SecondaryIPAddrs []string `json:"secondaryNodeIpAddresses"`
		SecondaryCert    string   `json:"secondaryNodeCertificate"`
		Zone             string   `json:"zone"`
		Version          string   `json:"version"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if !strings.HasPrefix(strings.ToLower(payload.SecondaryURL), "https://") {
		resp.BadRequest(c, "secondaryNodeUrl 必须为 HTTPS")
		return
	}
	if len(payload.SecondaryURL) > 255 {
		resp.BadRequest(c, "secondaryNodeUrl 长度超出限制")
		return
	}
	if len(payload.SecondaryIPAddrs) > 10 {
		resp.BadRequest(c, "secondaryNodeIpAddresses 最多 10 项")
		return
	}

	nodeID := strings.TrimSpace(payload.SecondaryNodeID)
	if nodeID == "" {
		nodeID = newNodeID()
	}

	// Auto-pin: record the secondary's certificate fingerprint so future
	// outbound calls from this primary (apply-config / command) can verify it.
	if fp := cluster.FingerprintPEM(payload.SecondaryCert); fp != "" {
		if host := urlHost(payload.SecondaryURL); host != "" {
			cluster.SetPin(host, fp)
		}
	}

	now := time.Now()
	primaryIP := firstNonEmpty(payload.SecondaryIPAddrs)

	var node model.ClusterNode
	q := db.DB.Where("node_id = ?", nodeID)
	if err := q.First(&node).Error; err != nil {
		// new join — persist static identity only
		node = model.ClusterNode{
			NodeID:      nodeID,
			Name:        firstNonEmpty([]string{payload.SecondaryName, "secondary-" + shortID(nodeID)}),
			IP:          primaryIP,
			IPAddresses: strings.Join(payload.SecondaryIPAddrs, ","),
			URL:         payload.SecondaryURL,
			Port:        extractPort(payload.SecondaryURL),
			Role:        "从节点",
			Zone:        payload.Zone,
			Version:     payload.Version,
			Certificate: payload.SecondaryCert,
			JoinedAt:    now,
		}
		db.DB.Create(&node)
		db.DB.Create(&model.ClusterConfigSync{
			NodeID:        node.ID,
			ConfigVersion: "",
			MasterVersion: currentMasterVersion(),
			SyncStatus:    "待同步",
			LastSyncAt:    now,
		})
	} else {
		// re-join: refresh static identity only (URL / cert / version)
		db.DB.Model(&node).Updates(map[string]interface{}{
			"name":         firstNonEmpty([]string{payload.SecondaryName, node.Name}),
			"ip":           firstNonEmpty([]string{primaryIP, node.IP}),
			"ip_addresses": strings.Join(payload.SecondaryIPAddrs, ","),
			"url":          payload.SecondaryURL,
			"certificate":  payload.SecondaryCert,
			"version":      payload.Version,
		})
	}
	// Always (re)mark this peer as connected in runtime state.
	cluster.TouchJoin(nodeID, payload.Version)
	cluster.Publish("node-joined", nodeID, map[string]any{
		"name": payload.SecondaryName,
		"url":  payload.SecondaryURL,
	})

	resp.OK(c, gin.H{"nodeId": nodeID, "clusterInfo": buildClusterInfo()})
}

// POST /api/cluster/internal/heartbeat
func PeerHeartbeat(c *gin.Context) {
	var payload struct {
		NodeID   string `json:"nodeId" binding:"required"`
		CPUUsage int    `json:"cpuUsage"`
		MemUsage int    `json:"memUsage"`
		QPS      int    `json:"qps"`
		SyncLag  int    `json:"syncLag"`
		Version  string `json:"version"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	// Heartbeats no longer touch MySQL: live metrics live in pkg/cluster
	// runtime so we don't churn the DB once per heartbeat × node.
	var count int64
	db.DB.Model(&model.ClusterNode{}).Where("node_id = ?", payload.NodeID).Count(&count)
	if count == 0 {
		resp.NotFound(c, "未找到节点")
		return
	}
	cluster.UpdateHeartbeat(payload.NodeID, payload.CPUUsage, payload.MemUsage, payload.QPS, payload.SyncLag, payload.Version)
	if payload.Version != "" {
		db.DB.Model(&model.ClusterNode{}).Where("node_id = ? AND version <> ?", payload.NodeID, payload.Version).Update("version", payload.Version)
	}
	resp.OK(c, gin.H{"clusterInfo": buildClusterInfo()})
}

// POST /api/cluster/internal/leave
func PeerLeave(c *gin.Context) {
	var payload struct {
		NodeID string `json:"nodeId" binding:"required"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	selfID := cluster.SelfID()
	if payload.NodeID == selfID {
		resp.BadRequest(c, "不能让主节点退出集群")
		return
	}
	cluster.Forget(payload.NodeID)
	db.DB.Where("node_id = ?", payload.NodeID).Delete(&model.ClusterNode{})
	cluster.Publish("node-left", payload.NodeID, nil)
	resp.OK(c, gin.H{"left": payload.NodeID})
}

// GET /api/cluster/internal/state — secondaries pull cluster info on demand.
func PeerGetClusterState(c *gin.Context) {
	resp.OK(c, buildClusterInfo())
}

// GET /api/cluster/internal/state-snapshot
//
// Returns the receiver's current ConfigSnapshot so the primary can compare
// it row-by-row against its own snapshot and produce a real diff for the
// "差异预览" modal. Cheap on small databases; for very large authoritative
// zones the primary should consider hashing only.
func PeerGetStateSnapshot(c *gin.Context) {
	snap := cluster.BuildSnapshot(currentMasterVersion())
	resp.OK(c, snap)
}

// GET /api/cluster/internal/health — lightweight liveness summary.
//
// Exposed to the primary so the overview page can show what's actually
// running on each secondary (snapshot version applied, DB reachable, DNS
// engine running) — distinct from the network-level reachability that the
// node "在线" badge already reflects.
func PeerHealth(c *gin.Context) {
	dbOK := true
	if db.DB == nil {
		dbOK = false
	} else {
		var probe int64
		if err := db.DB.Raw("SELECT 1").Scan(&probe).Error; err != nil {
			dbOK = false
		}
	}
	resp.OK(c, gin.H{
		"ok":            dbOK,
		"configVersion": currentMasterVersion(),
		"time":          time.Now().Format(time.RFC3339),
	})
}

// POST /api/cluster/internal/apply-config — secondary applies a snapshot.
func PeerApplyConfig(c *gin.Context) {
	var snap cluster.ConfigSnapshot
	if err := c.ShouldBindJSON(&snap); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if err := cluster.ApplySnapshot(&snap); err != nil {
		resp.ServerError(c, "应用配置失败: "+err.Error())
		return
	}
	// Persist the new version locally so subsequent /state shows it.
	db.DB.Model(&model.ClusterSettings{}).Where("id = 1").Updates(map[string]interface{}{
		"config_version": snap.Version,
		"updated_at":     time.Now(),
	})
	dnsengine.Trigger()
	resp.OK(c, gin.H{"applied": true, "version": snap.Version})
}

// POST /api/cluster/internal/command — primary→secondary one-shot directives.
//
// Supported actions:
//   - forceUpdateBlockLists: trigger dnsengine.Reload() on the receiver
//   - temporaryDisableBlocking: { minutes:int } — pause BW/RPZ enforcement
//   - notify: free-form notify; receiver just reloads config
func PeerRunCommand(c *gin.Context) {
	var payload struct {
		Action string                 `json:"action" binding:"required"`
		Args   map[string]interface{} `json:"args"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	switch payload.Action {
	case "forceUpdateBlockLists", "notify":
		dnsengine.Trigger()
	case "temporaryDisableBlocking":
		minutes, _ := payload.Args["minutes"].(float64)
		if minutes <= 0 {
			minutes = 5
		}
		dnsengine.SetPolicyBypassFor(time.Duration(minutes) * time.Minute)
	default:
		resp.BadRequest(c, "未知指令: "+payload.Action)
		return
	}
	resp.OK(c, gin.H{"executed": payload.Action})
}

// POST /api/cluster/command — primary fan-out command to secondaries.
func DispatchClusterCommand(c *gin.Context) {
	var payload struct {
		Action string                 `json:"action" binding:"required"`
		Args   map[string]interface{} `json:"args"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}

	// Apply locally first (the primary is also a node).
	switch payload.Action {
	case "forceUpdateBlockLists":
		dnsengine.Trigger()
	case "temporaryDisableBlocking":
		minutes, _ := payload.Args["minutes"].(float64)
		if minutes <= 0 {
			minutes = 5
		}
		dnsengine.SetPolicyBypassFor(time.Duration(minutes) * time.Minute)
	}

	var nodes []model.ClusterNode
	db.DB.Where("role = ? AND url <> ''", "从节点").Find(&nodes)
	cli := cluster.NewClient(0, config.C.Cluster.IgnoreCertificateErrors)
	token := cluster.CurrentToken()

	results := make([]pushItem, 0, len(nodes))
	success, failed := 0, 0
	for _, n := range nodes {
		item := pushItem{NodeID: n.NodeID, Name: n.Name, URL: n.URL}
		err := cli.Post(cluster.JoinURL(n.URL, "/api/cluster/internal/command"), token, payload, nil)
		if err != nil {
			item.Message = err.Error()
			failed++
		} else {
			item.OK = true
			success++
		}
		results = append(results, item)
	}
	writeOpLogAuth(c, "集群指令", "集群",
		fmt.Sprintf("指令 %s・成功 %d・失败 %d", payload.Action, success, failed),
		fmt.Sprintf(`{"action":"%s","success":%d,"failed":%d}`, payload.Action, success, failed))
	resp.OK(c, gin.H{"action": payload.Action, "success": success, "failed": failed, "results": results})
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func buildClusterInfo() gin.H {
	var settings model.ClusterSettings
	db.DB.First(&settings, 1)

	var nodes []model.ClusterNode
	db.DB.Order("role DESC, id ASC").Find(&nodes)

	hb := settings.HeartbeatIntervalSec
	if hb <= 0 {
		hb = 5
	}

	type nodeInfo struct {
		ID          string    `json:"id"`
		Name        string    `json:"name"`
		URL         string    `json:"url"`
		IPAddresses []string  `json:"ipAddresses"`
		Type        string    `json:"type"`
		State       string    `json:"state"`
		Version     string    `json:"version"`
		UpSince     time.Time `json:"upSince"`
		LastSeen    time.Time `json:"lastSeen"`
	}
	out := make([]nodeInfo, 0, len(nodes))
	for _, n := range nodes {
		ips := []string{}
		for _, ip := range strings.Split(n.IPAddresses, ",") {
			if s := strings.TrimSpace(ip); s != "" {
				ips = append(ips, s)
			}
		}
		nodeType := "Secondary"
		if n.Role == "主节点" {
			nodeType = "Primary"
		}
		state := string(cluster.DeriveState(n.NodeID, hb))
		rt, _ := cluster.Get(n.NodeID)
		out = append(out, nodeInfo{
			ID:          n.NodeID,
			Name:        n.Name,
			URL:         n.URL,
			IPAddresses: ips,
			Type:        nodeType,
			State:       state,
			Version:     n.Version,
			UpSince:     rt.UpSince,
			LastSeen:    rt.LastSeen,
		})
	}

	return gin.H{
		"initialized":          settings.Initialized,
		"clusterDomain":        settings.ClusterDomain,
		"heartbeatIntervalSec": settings.HeartbeatIntervalSec,
		"configRefreshSec":     settings.ConfigRefreshSec,
		"configVersion":        settings.ConfigVersion,
		"nodes":                out,
	}
}

func defaultStateLabel(s string) string {
	if s == "" {
		return "Unknown"
	}
	return s
}

func newNodeID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newConfigVersion() string {
	return "cfg-" + time.Now().UTC().Format("20060102.150405")
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func firstNonEmpty(values []string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// urlHost extracts the "host:port" component from a URL string. Returns empty
// when the URL is malformed.
func urlHost(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(strings.ToLower(rawURL), prefix) {
			rest := rawURL[len(prefix):]
			if end := strings.IndexAny(rest, "/?#"); end >= 0 {
				rest = rest[:end]
			}
			return rest
		}
	}
	return ""
}

func extractPort(url string) int {
	parts := strings.SplitN(url, ":", 3)
	if len(parts) < 3 {
		return 8443
	}
	rest := parts[2]
	end := strings.IndexAny(rest, "/?#")
	if end >= 0 {
		rest = rest[:end]
	}
	if rest == "" {
		return 8443
	}
	return parsePortDefault(rest, 8443)
}

func parsePortDefault(s string, fallback int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	v := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return fallback
		}
		v = v*10 + int(ch-'0')
	}
	if v <= 0 || v > 65535 {
		return fallback
	}
	return v
}

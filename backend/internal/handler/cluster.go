package handler

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"modern-dns/config"
	"modern-dns/internal/model"
	"modern-dns/pkg/cluster"
	"modern-dns/pkg/db"
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
)

// currentMasterVersion returns the live cluster_settings.config_version, which
// is the value stamped onto every snapshot push. We previously hard-coded a
// constant here, which made the UI show a different version than the one
// secondaries actually applied. Empty string when the cluster has not been
// initialised yet — callers should treat that as "no version yet".
func currentMasterVersion() string {
	var s model.ClusterSettings
	if err := db.DB.First(&s, 1).Error; err != nil {
		return ""
	}
	return s.ConfigVersion
}

// nodeView is the cluster_nodes row enriched with the live runtime metrics
// resolved from pkg/cluster.Runtime. The shape is kept identical to the old
// persisted struct so the frontend contract does not change.
type nodeView struct {
	ID            uint      `json:"id"`
	NodeID        string    `json:"nodeId"`
	Name          string    `json:"name"`
	IP            string    `json:"ip"`
	IPAddresses   string    `json:"ipAddresses"`
	URL           string    `json:"url"`
	Port          int       `json:"port"`
	Role          string    `json:"role"`
	Zone          string    `json:"zone"`
	Version       string    `json:"version"`
	Status        string    `json:"status"`
	State         string    `json:"state"`
	CPUUsage      int       `json:"cpuUsage"`
	MemUsage      int       `json:"memUsage"`
	QPS           int       `json:"qps"`
	SyncLag       int       `json:"syncLag"`
	UpSince       time.Time `json:"upSince"`
	LastHeartbeat time.Time `json:"lastHeartbeat"`
	LastSeen      time.Time `json:"lastSeen"`
	JoinedAt      time.Time `json:"joinedAt"`
	Drained       bool      `json:"drained"`
}

// heartbeatInterval reads the configured cluster heartbeat interval, falling
// back to a 5-second default when uninitialized.
func heartbeatInterval() int {
	var s model.ClusterSettings
	db.DB.First(&s, 1)
	if s.HeartbeatIntervalSec > 0 {
		return s.HeartbeatIntervalSec
	}
	return 5
}

// hydrateNode merges a static cluster_nodes row with its runtime entry.
func hydrateNode(n *model.ClusterNode, hbSec int) nodeView {
	rt, ok := cluster.Get(n.NodeID)
	state := cluster.DeriveState(n.NodeID, hbSec)
	v := nodeView{
		ID:          n.ID,
		NodeID:      n.NodeID,
		Name:        n.Name,
		IP:          n.IP,
		IPAddresses: n.IPAddresses,
		URL:         n.URL,
		Port:        n.Port,
		Role:        n.Role,
		Zone:        n.Zone,
		Version:     n.Version,
		Status:      cluster.StateLabel(state),
		State:       string(state),
		JoinedAt:    n.JoinedAt,
		Drained:     n.Drained,
	}
	if ok {
		v.CPUUsage = rt.CPUUsage
		v.MemUsage = rt.MemUsage
		v.QPS = rt.QPS
		v.SyncLag = rt.SyncLag
		v.UpSince = rt.UpSince
		v.LastHeartbeat = rt.LastHeartbeat
		v.LastSeen = rt.LastSeen
		if rt.Version != "" {
			v.Version = rt.Version
		}
	}
	return v
}

// ─── Overview ─────────────────────────────────────────────────────────────────

// GET /api/cluster/overview
func GetClusterOverview(c *gin.Context) {
	var nodes []model.ClusterNode
	db.DB.Find(&nodes)
	hb := heartbeatInterval()

	online, offline, syncIssues := 0, 0, 0
	totalQPS, cpuSum, memSum, activeCount := 0, 0, 0, 0

	views := make([]nodeView, 0, len(nodes))
	for i := range nodes {
		v := hydrateNode(&nodes[i], hb)
		views = append(views, v)
		totalQPS += v.QPS
		switch v.Status {
		case "在线":
			online++
			cpuSum += v.CPUUsage
			memSum += v.MemUsage
			activeCount++
		case "离线":
			offline++
		}
		if v.SyncLag > 100 {
			syncIssues++
		}
	}

	avgCPU, avgMem := 0, 0
	if activeCount > 0 {
		avgCPU = cpuSum / activeCount
		avgMem = memSum / activeCount
	}

	// Build time-series trend from query_logs in a single SQL pass.
	type trendPoint struct {
		Time    string `json:"time"`
		QPS     int    `json:"qps"`
		Latency int    `json:"latency"`
	}
	now := time.Now()
	// Range parameter resolves to a (window, buckets, label format) triple.
	// Pre-fix the chart always showed a 26h window even when the UI said
	// "1h", so we honour ?range= so the backend matches the operator's
	// selection. Buckets always == 13 to keep the renderer simple.
	bucketCount := 13
	rangeKey := strings.ToLower(strings.TrimSpace(c.Query("range")))
	var window time.Duration
	var labelFmt string
	switch rangeKey {
	case "1h":
		window = time.Hour
		labelFmt = "15:04"
	case "6h":
		window = 6 * time.Hour
		labelFmt = "15:04"
	case "7d":
		window = 7 * 24 * time.Hour
		labelFmt = "01-02"
	case "1d", "":
		fallthrough
	default:
		window = 24 * time.Hour
		labelFmt = "15:04"
	}
	slotDur := window / time.Duration(bucketCount)
	if slotDur <= 0 {
		slotDur = 5 * time.Minute
	}
	slots := make([]struct {
		label string
		start time.Time
		end   time.Time
	}, bucketCount)
	for i := bucketCount - 1; i >= 0; i-- {
		slotEnd := now.Add(time.Duration(-i) * slotDur)
		slotStart := slotEnd.Add(-slotDur)
		slots[bucketCount-1-i].label = slotEnd.Format(labelFmt)
		slots[bucketCount-1-i].start = slotStart
		slots[bucketCount-1-i].end = slotEnd
	}

	var caseSB strings.Builder
	caseArgs := make([]interface{}, 0, len(slots)*2)
	caseSB.WriteString("(CASE ")
	for i, s := range slots {
		caseSB.WriteString("WHEN created_at >= ? AND created_at < ? THEN ")
		caseSB.WriteString(strconv.Itoa(i))
		caseSB.WriteString(" ")
		caseArgs = append(caseArgs, s.start, s.end)
	}
	caseSB.WriteString("ELSE -1 END)")

	var slotRows []struct {
		Idx   int     `gorm:"column:bucket_idx"`
		Cnt   int64   `gorm:"column:cnt"`
		AvgRT float64 `gorm:"column:avg_rt"`
	}
	db.DB.Model(&model.QueryLog{}).
		Select(caseSB.String()+" AS bucket_idx, COUNT(*) AS cnt, COALESCE(AVG(response_time),0) AS avg_rt", caseArgs...).
		Where("created_at >= ?", slots[0].start).
		Group("bucket_idx").
		Scan(&slotRows)

	trend := make([]trendPoint, len(slots))
	for i, s := range slots {
		trend[i] = trendPoint{Time: s.label}
	}
	slotSeconds := int64(slotDur / time.Second)
	if slotSeconds <= 0 {
		slotSeconds = 1
	}
	for _, r := range slotRows {
		if r.Idx < 0 || r.Idx >= len(trend) {
			continue
		}
		// QPS = rows in the bucket / bucket duration in seconds. Pre-fix
		// the response shipped raw row counts, which made the chart Y
		// axis swing wildly when the operator switched ranges.
		trend[r.Idx].QPS = int(r.Cnt / slotSeconds)
		trend[r.Idx].Latency = int(r.AvgRT)
	}

	resp.OK(c, gin.H{
		"nodes": views,
		"stats": gin.H{
			"online":     online,
			"offline":    offline,
			"syncIssues": syncIssues,
			"totalQps":   totalQPS,
			"avgCpu":     avgCPU,
			"avgMem":     avgMem,
			"total":      len(nodes),
		},
		"trend": trend,
	})
}

// ─── Node Management ──────────────────────────────────────────────────────────

// GET /api/cluster/nodes
//
// Pagination caveat: status now lives in runtime state (pkg/cluster), not
// in cluster_nodes, so a status filter cannot run in SQL. We hydrate the
// SQL-side hits, drop ones that don't match the status, then page the
// resulting slice in memory. This keeps the response's `total` exactly
// equal to `list.length` after filtering — pre-fix the SQL COUNT could be
// larger than the post-hydration list, which broke the paginator.
func ListClusterNodes(c *gin.Context) {
	keyword := c.Query("keyword")
	role := c.Query("role")
	statusFilter := c.Query("status")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	if page < 1 {
		page = 1
	}
	if size <= 0 {
		size = 20
	}

	query := db.DB.Model(&model.ClusterNode{})
	if keyword != "" {
		query = query.Where("name LIKE ? OR ip LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}
	if role != "" {
		query = query.Where("role = ?", role)
	}

	var nodes []model.ClusterNode
	query.Order("id ASC").Find(&nodes)

	hb := heartbeatInterval()
	views := make([]nodeView, 0, len(nodes))
	for i := range nodes {
		v := hydrateNode(&nodes[i], hb)
		if statusFilter != "" && v.Status != statusFilter {
			continue
		}
		views = append(views, v)
	}

	total := len(views)
	start := (page - 1) * size
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	resp.OK(c, gin.H{"total": total, "list": views[start:end]})
}

// POST /api/cluster/nodes
func AddClusterNode(c *gin.Context) {
	var req struct {
		Name string `json:"name" binding:"required"`
		IP   string `json:"ip"   binding:"required"`
		Port int    `json:"port"`
		Role string `json:"role"`
		Zone string `json:"zone"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if req.Port == 0 {
		req.Port = 53
	}
	if req.Role == "" {
		req.Role = "从节点"
	}

	node := model.ClusterNode{
		NodeID:   newNodeID(),
		Name:     req.Name,
		IP:       req.IP,
		Port:     req.Port,
		Role:     req.Role,
		Zone:     req.Zone,
		Version:  appNodeVersion,
		JoinedAt: time.Now(),
	}
	db.DB.Create(&node)

	// Create a corresponding config-sync record (FK by primary-key id only).
	db.DB.Create(&model.ClusterConfigSync{
		NodeID:        node.ID,
		ConfigVersion: "",
		MasterVersion: currentMasterVersion(),
		SyncStatus:    "待同步",
		LastSyncAt:    time.Now(),
		DiffCount:     0,
	})

	writeOpLogAuth(c, "添加", "集群节点", node.Name, "")

	// Adding a row only declares intent — the node only turns "在线" once a
	// secondary process running on req.IP successfully POSTs to
	// /api/cluster/internal/join with the cluster token. Surface that to
	// the operator so the persistent "未知" status doesn't look like a bug.
	view := hydrateNode(&node, heartbeatInterval())
	resp.OK(c, gin.H{
		"node":     view,
		"joinHint": "节点已登记，等待对端 secondary 进程握手。请在该主机上启动 modern-dns-backend 并配置 cluster.secondary.primaryUrl 与 apiToken 指向当前主节点。",
	})
}

// PUT /api/cluster/nodes/:id
func UpdateClusterNode(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var payload struct {
		Name string `json:"name"`
		IP   string `json:"ip"`
		Port int    `json:"port"`
		Role string `json:"role"`
		Zone string `json:"zone"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	db.DB.Model(&model.ClusterNode{}).Where("id = ?", id).Updates(map[string]interface{}{
		"name": payload.Name,
		"ip":   payload.IP,
		"port": payload.Port,
		"role": payload.Role,
		"zone": payload.Zone,
	})
	var node model.ClusterNode
	db.DB.First(&node, id)
	resp.OK(c, hydrateNode(&node, heartbeatInterval()))
}

// DELETE /api/cluster/nodes/:id
func RemoveClusterNode(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var node model.ClusterNode
	if err := db.DB.First(&node, id).Error; err != nil {
		resp.NotFound(c, "节点不存在")
		return
	}
	cluster.Forget(node.NodeID)
	db.DB.Delete(&node)
	db.DB.Where("node_id = ?", node.ID).Delete(&model.ClusterConfigSync{})
	writeOpLogAuth(c, "移除", "集群节点", node.Name, "")
	resp.OK(c, gin.H{"id": id})
}

// POST /api/cluster/nodes/:id/drain — flip Drained=true.
// POST /api/cluster/nodes/:id/undrain — flip Drained=false.
//
// drain takes a secondary out of sync rotation without deleting it. The
// secondary's DNS engine continues serving cached data; the primary stops
// pushing snapshots and the auto-sync loop ignores it. Use this before
// taking a node offline for maintenance so configs don't slip out of sync
// and resync attempts don't keep failing in the audit log.
func SetDrain(drained bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		var node model.ClusterNode
		if err := db.DB.First(&node, id).Error; err != nil {
			resp.NotFound(c, "节点不存在")
			return
		}
		if node.Role == "主节点" {
			resp.BadRequest(c, "不能将主节点置为 drained")
			return
		}
		db.DB.Model(&node).Update("drained", drained)
		action := "退出轮换"
		if !drained {
			action = "恢复轮换"
		}
		writeOpLogAuth(c, action, "集群节点", node.Name, "")
		resp.OK(c, gin.H{"id": id, "drained": drained})
	}
}

// POST /api/cluster/nodes/batch-remove
// Body: { "ids": [int...] }
//
// Bulk variant of DELETE /nodes/:id used by the multi-select UI. Skips the
// primary even if it sneaks into the request — operators occasionally tick
// "select all" without thinking.
func BatchRemoveNodes(c *gin.Context) {
	var payload struct {
		IDs []uint `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if len(payload.IDs) == 0 {
		resp.BadRequest(c, "ids 不能为空")
		return
	}

	var targets []model.ClusterNode
	db.DB.Where("id IN ? AND role <> ?", payload.IDs, "主节点").Find(&targets)
	removedNames := make([]string, 0, len(targets))
	for _, n := range targets {
		cluster.Forget(n.NodeID)
		db.DB.Delete(&n)
		db.DB.Where("node_id = ?", n.ID).Delete(&model.ClusterConfigSync{})
		removedNames = append(removedNames, n.Name)
	}
	writeOpLogAuth(c, "批量移除", "集群节点",
		fmt.Sprintf("共 %d 个节点", len(removedNames)), strings.Join(removedNames, ", "))
	resp.OK(c, gin.H{"removed": len(removedNames), "names": removedNames})
}

// GET /api/cluster/nodes/:id/metrics
//
// Returns the in-memory metrics ring buffer for the given node — up to 60
// recent samples (≈5 minutes at 5s heartbeat). Used by the node detail
// chart. Cheap by design: no DB round-trip, no aggregation. For longer
// horizons the operator should look at the overview trend chart which
// uses query_logs.
func GetNodeMetrics(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var node model.ClusterNode
	if err := db.DB.First(&node, id).Error; err != nil {
		resp.NotFound(c, "节点不存在")
		return
	}
	samples := cluster.History(node.NodeID)
	resp.OK(c, gin.H{
		"nodeId":  node.NodeID,
		"name":    node.Name,
		"samples": samples,
	})
}

// POST /api/cluster/nodes/refresh
//
// Active probe: for every secondary with a callback URL, GET its
// /api/cluster/internal/state. Reachable peers have their LastSeen bumped
// (cluster.TouchJoin) so their `state` flips to Connected before the next
// natural heartbeat. Unreachable peers are reported in the response so
// the operator can see exactly which nodes failed and why.
//
// Pre-fix this handler only touched runtime entries that already existed
// in memory, which meant freshly-rebooted primaries reported "refreshed"
// without contacting any peer at all.
func RefreshClusterNodes(c *gin.Context) {
	var nodes []model.ClusterNode
	db.DB.Find(&nodes)

	cli := cluster.NewClient(0, config.C.Cluster.IgnoreCertificateErrors)
	token := cluster.CurrentToken()
	selfID := cluster.SelfID()

	type probeItem struct {
		NodeID  string `json:"nodeId"`
		Name    string `json:"name"`
		URL     string `json:"url"`
		OK      bool   `json:"ok"`
		Message string `json:"message,omitempty"`
	}
	results := make([]probeItem, 0, len(nodes))
	reachable, unreachable := 0, 0
	for _, n := range nodes {
		// Skip self — primary doesn't probe itself; metrics come from the
		// in-process self-sampler.
		if n.NodeID == selfID {
			cluster.TouchJoin(n.NodeID, n.Version)
			continue
		}
		if strings.TrimSpace(n.URL) == "" {
			results = append(results, probeItem{NodeID: n.NodeID, Name: n.Name, URL: n.URL, Message: "无回调 URL"})
			unreachable++
			continue
		}
		item := probeItem{NodeID: n.NodeID, Name: n.Name, URL: n.URL}
		if token == "" {
			item.Message = "集群未初始化或 token 为空"
			results = append(results, item)
			unreachable++
			continue
		}
		var into map[string]any
		if err := cli.Get(cluster.JoinURL(n.URL, "/api/cluster/internal/state"), token, &into); err != nil {
			item.Message = err.Error()
			results = append(results, item)
			unreachable++
			continue
		}
		cluster.TouchJoin(n.NodeID, n.Version)
		item.OK = true
		results = append(results, item)
		reachable++
	}

	resp.OK(c, gin.H{
		"success":     unreachable == 0,
		"refreshedAt": time.Now().Format("2006-01-02 15:04:05"),
		"reachable":   reachable,
		"unreachable": unreachable,
		"results":     results,
	})
}

// POST /api/cluster/nodes/:id/failover
func FailoverClusterNode(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var target model.ClusterNode
	if err := db.DB.First(&target, id).Error; err != nil {
		resp.NotFound(c, "节点不存在")
		return
	}
	if target.Role == "主节点" {
		resp.BadRequest(c, "该节点已是主节点")
		return
	}
	// Demote current master
	db.DB.Model(&model.ClusterNode{}).Where("role = ?", "主节点").
		Update("role", "从节点")
	// Promote target
	db.DB.Model(&target).Update("role", "主节点")
	target.Role = "主节点"
	writeOpLogAuth(c, "故障切主", "集群节点", fmt.Sprintf("切换到 %s", target.Name), "")

	// IMPORTANT: this is a metadata-only failover — the role column flips
	// in the DB, but we do NOT re-issue the cluster token, do NOT migrate
	// the pkg/scheduler ownership, and do NOT update any external VIP or
	// upstream DNS records. Running this on a live cluster is unsafe; it
	// is intended for lab / planned-maintenance scenarios only. The UI
	// surfaces this warning so the operator can't trip over the gap.
	resp.OK(c, gin.H{
		"node":    hydrateNode(&target, heartbeatInterval()),
		"warning": "切主仅更新 role 标签，并不会重新签发集群 token、迁移定时任务所有权、或刷新外部 VIP / DNS 记录。生产环境请配合上游网络层的切换与 secondary 进程重启使用。",
	})
}

// ─── Config Sync ──────────────────────────────────────────────────────────────

// configSyncRow is the JOIN result returned to the frontend. Node identity
// columns come from cluster_nodes; sync facts come from cluster_config_sync.
type configSyncRow struct {
	ID            uint      `json:"id"`
	NodeID        uint      `json:"nodeId"`
	Name          string    `json:"name"`
	IP            string    `json:"ip"`
	Role          string    `json:"role"`
	Zone          string    `json:"zone"`
	ConfigVersion string    `json:"configVersion"`
	MasterVersion string    `json:"masterVersion"`
	SyncStatus    string    `json:"syncStatus"`
	LastSyncAt    time.Time `json:"lastSyncAt"`
	DiffCount     int       `json:"diffCount"`
}

// GET /api/cluster/config-sync
func ListConfigSync(c *gin.Context) {
	keyword := c.Query("keyword")
	syncStatus := c.Query("syncStatus")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	if page < 1 {
		page = 1
	}

	q := db.DB.Table("cluster_config_sync AS s").
		Select(`s.id, s.node_id, n.name AS name, n.ip AS ip, n.role AS role, n.zone AS zone,
		        s.config_version, s.master_version, s.sync_status, s.last_sync_at, s.diff_count`).
		Joins("LEFT JOIN cluster_nodes n ON n.id = s.node_id")
	if keyword != "" {
		q = q.Where("n.name LIKE ? OR n.ip LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}
	if syncStatus != "" {
		q = q.Where("s.sync_status = ?", syncStatus)
	}

	var total int64
	q.Count(&total)
	var rows []configSyncRow
	q.Order("s.id ASC").Offset((page - 1) * size).Limit(size).Scan(&rows)
	if rows == nil {
		rows = []configSyncRow{}
	}
	resp.OK(c, gin.H{"total": total, "list": rows, "masterVersion": currentMasterVersion()})
}

// POST /api/cluster/config-sync/:id/sync
//
// Real per-node sync: builds a fresh snapshot, advances the master version,
// and POSTs it to the target secondary's /apply-config. The cluster_config_sync
// row is updated by pushSnapshotToNodes based on the actual HTTP outcome.
//
// Pre-fix this handler only flipped sync_status='已同步' in the DB and never
// contacted the secondary, which is why the per-node "同步" UI button was
// effectively a no-op.
func SyncNodeConfig(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var record model.ClusterConfigSync
	if err := db.DB.First(&record, id).Error; err != nil {
		resp.NotFound(c, "同步记录不存在")
		return
	}
	var node model.ClusterNode
	if err := db.DB.First(&node, record.NodeID).Error; err != nil {
		resp.NotFound(c, "目标节点不存在")
		return
	}
	if node.Role != "从节点" {
		resp.BadRequest(c, "只能向从节点同步")
		return
	}
	if strings.TrimSpace(node.URL) == "" {
		resp.BadRequest(c, "目标节点未提供回调 URL，secondary 尚未握手")
		return
	}

	snap := buildAndStampSnapshot()
	res := pushSnapshotToNodes(&snap, []model.ClusterNode{node}, "manual", actorUsername(c))

	// Re-read the row so the response reflects the columns the helper just
	// wrote (sync_status / last_sync_at / config_version).
	db.DB.First(&record, id)

	writeOpLogAuth(c, "配置同步", "集群节点",
		fmt.Sprintf("%s・版本 %s・成功 %d・失败 %d", node.Name, snap.Version, res.Success, res.Failed),
		fmt.Sprintf(`{"node":"%s","version":"%s","success":%d,"failed":%d}`, node.Name, snap.Version, res.Success, res.Failed))

	if res.Failed > 0 {
		// Surface the wire error to the operator without losing the row state.
		msg := "未知错误"
		if len(res.Detail) > 0 && res.Detail[0].Message != "" {
			msg = res.Detail[0].Message
		}
		resp.BadRequest(c, "同步失败: "+msg)
		return
	}
	resp.OK(c, gin.H{"record": record, "result": res.Detail})
}

// POST /api/cluster/config-sync/sync-all
//
// Mirrors the SyncNodeConfig fix: actually pushes to every pending secondary
// over HTTP rather than blindly stamping sync_status='已同步'.
func SyncAllNodeConfigs(c *gin.Context) {
	// Find every secondary whose latest sync state is not "已同步".
	var pending []model.ClusterNode
	db.DB.Table("cluster_nodes AS n").
		Joins("JOIN cluster_config_sync AS s ON s.node_id = n.id").
		Where("n.role = ? AND n.url <> '' AND s.sync_status <> ?", "从节点", "已同步").
		Find(&pending)

	if len(pending) == 0 {
		resp.OK(c, gin.H{
			"success":  true,
			"syncedAt": time.Now().Format("2006-01-02 15:04:05"),
			"results":  []pushItem{},
			"message":  "无待同步节点",
		})
		return
	}

	snap := buildAndStampSnapshot()
	res := pushSnapshotToNodes(&snap, pending, "manual-all", actorUsername(c))

	writeOpLogAuth(c, "批量配置同步", "集群",
		fmt.Sprintf("version=%s pending=%d success=%d failed=%d",
			snap.Version, len(pending), res.Success, res.Failed), "")

	resp.OK(c, gin.H{
		"success":       res.Failed == 0,
		"configVersion": snap.Version,
		"syncedAt":      time.Now().Format("2006-01-02 15:04:05"),
		"successCount":  res.Success,
		"failedCount":   res.Failed,
		"results":       res.Detail,
	})
}

// GET /api/cluster/config-sync/:id/diff
//
// Returns the cached diff stored by the most recent push or refresh. If the
// cached blob is empty the operator should call POST /diff/refresh to
// trigger a live pull.
func GetConfigSyncDiff(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var record model.ClusterConfigSync
	if err := db.DB.First(&record, id).Error; err != nil {
		resp.NotFound(c, "同步记录不存在")
		return
	}

	if record.DiffDetail != "" && record.DiffDetail != "[]" {
		var items []cluster.DiffItem
		if err := json.Unmarshal([]byte(record.DiffDetail), &items); err == nil {
			resp.OK(c, items)
			return
		}
	}
	resp.OK(c, []cluster.DiffItem{})
}

// POST /api/cluster/config-sync/:id/diff/refresh
//
// Live diff: pulls the secondary's current snapshot, computes the diff
// against the primary's snapshot, and stores the JSON in
// cluster_config_sync.diff_detail / diff_count for the next GET. Returns
// the freshly-computed items so the modal can render immediately.
func RefreshConfigSyncDiff(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var record model.ClusterConfigSync
	if err := db.DB.First(&record, id).Error; err != nil {
		resp.NotFound(c, "同步记录不存在")
		return
	}
	var node model.ClusterNode
	if err := db.DB.First(&node, record.NodeID).Error; err != nil {
		resp.NotFound(c, "目标节点不存在")
		return
	}
	if strings.TrimSpace(node.URL) == "" {
		resp.BadRequest(c, "目标节点未握手，无法拉取快照")
		return
	}

	cli := cluster.NewClient(0, config.C.Cluster.IgnoreCertificateErrors)
	token := cluster.CurrentToken()
	if token == "" {
		resp.BadRequest(c, "集群未初始化或 token 为空")
		return
	}
	var nodeSnap cluster.ConfigSnapshot
	if err := cli.Get(cluster.JoinURL(node.URL, "/api/cluster/internal/state-snapshot"), token, &nodeSnap); err != nil {
		resp.BadRequest(c, "拉取节点快照失败: "+err.Error())
		return
	}

	masterSnap := cluster.BuildSnapshot(currentMasterVersion())
	diff := cluster.DiffSnapshots(&masterSnap, &nodeSnap)

	blob, _ := json.Marshal(diff.Items)
	db.DB.Model(&model.ClusterConfigSync{}).Where("id = ?", id).Updates(map[string]any{
		"diff_count":  diff.Changed,
		"diff_detail": string(blob),
	})
	resp.OK(c, diff.Items)
}

// GET /api/cluster/sync-history
//
// Audit feed for the "同步历史" tab. Returns rows newest-first; supports
// keyword (matches version / triggered_by) and trigger filters. The Notes
// column is parsed back into the per-node detail array so the modal can
// drill into individual node outcomes.
func ListSyncHistory(c *gin.Context) {
	keyword := strings.TrimSpace(c.Query("keyword"))
	trigger := strings.TrimSpace(c.Query("trigger"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	if page < 1 {
		page = 1
	}
	if size <= 0 {
		size = 20
	}

	q := db.DB.Model(&model.ClusterSyncHistory{})
	if keyword != "" {
		q = q.Where("version LIKE ? OR triggered_by LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}
	if trigger != "" {
		q = q.Where("trigger = ?", trigger)
	}

	var total int64
	q.Count(&total)
	var rows []model.ClusterSyncHistory
	q.Order("id DESC").Offset((page - 1) * size).Limit(size).Find(&rows)

	type historyItem struct {
		model.ClusterSyncHistory
		Detail []pushItem `json:"detail"`
	}
	out := make([]historyItem, 0, len(rows))
	for _, r := range rows {
		var detail []pushItem
		if r.Notes != "" {
			_ = json.Unmarshal([]byte(r.Notes), &detail)
		}
		out = append(out, historyItem{ClusterSyncHistory: r, Detail: detail})
	}
	resp.OK(c, gin.H{"total": total, "list": out})
}

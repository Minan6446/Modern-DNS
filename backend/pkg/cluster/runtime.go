package cluster

import (
	"sync"
	"time"
)

// Runtime tracks per-node live state that should NOT be persisted in the
// database (heartbeat timestamps, CPU/memory/QPS samples, derived state).
// All timestamps and counters live here and are computed on demand.
//
// Keyed by ClusterNode.NodeID (the stable UUID, not the SQL primary key).

// NodeState mirrors the spec's ClusterNodeState enum.
type NodeState string

const (
	StateSelf        NodeState = "Self"
	StateConnected   NodeState = "Connected"
	StateUnreachable NodeState = "Unreachable"
	StateUnknown     NodeState = "Unknown"
)

// NodeRuntime is the in-memory live snapshot for a single node.
type NodeRuntime struct {
	NodeID        string
	IsSelf        bool
	CPUUsage      int
	MemUsage      int
	QPS           int
	SyncLag       int
	Version       string
	UpSince       time.Time
	LastHeartbeat time.Time
	LastSeen      time.Time

	// History is a ring buffer of recent metric samples used by the node
	// detail chart. Capacity is small on purpose: this is for "what's
	// happening right now", not long-term storage.
	History []MetricSample
}

// MetricSample is one point in NodeRuntime.History.
type MetricSample struct {
	At       time.Time `json:"at"`
	CPUUsage int       `json:"cpuUsage"`
	MemUsage int       `json:"memUsage"`
	QPS      int       `json:"qps"`
	SyncLag  int       `json:"syncLag"`
}

// historyCap caps the per-node ring buffer size. With 5s heartbeats this
// covers a 5-minute window which is plenty for a "live" detail chart.
const historyCap = 60

var (
	rtMu     sync.RWMutex
	rtNodes  = make(map[string]*NodeRuntime)
	rtSelfID string
)

// RegisterSelf marks the given nodeID as the local primary node so its
// derived state always returns StateSelf and its lifecycle never expires.
func RegisterSelf(nodeID string) {
	if nodeID == "" {
		return
	}
	now := time.Now()
	rtMu.Lock()
	defer rtMu.Unlock()
	rtSelfID = nodeID
	r, ok := rtNodes[nodeID]
	if !ok {
		r = &NodeRuntime{NodeID: nodeID, UpSince: now}
		rtNodes[nodeID] = r
	}
	r.IsSelf = true
	r.LastHeartbeat = now
	r.LastSeen = now
	if r.UpSince.IsZero() {
		r.UpSince = now
	}
}

// SelfID returns the registered self node id (empty string when not set).
func SelfID() string {
	rtMu.RLock()
	defer rtMu.RUnlock()
	return rtSelfID
}

// TouchJoin records a fresh join/heartbeat for nodeID, allocating a runtime
// entry if one does not yet exist.
func TouchJoin(nodeID, version string) {
	if nodeID == "" {
		return
	}
	now := time.Now()
	rtMu.Lock()
	defer rtMu.Unlock()
	r, ok := rtNodes[nodeID]
	if !ok {
		r = &NodeRuntime{NodeID: nodeID, UpSince: now}
		rtNodes[nodeID] = r
	}
	r.LastHeartbeat = now
	r.LastSeen = now
	if version != "" {
		r.Version = version
	}
}

// UpdateHeartbeat applies metrics from a /heartbeat call. Returns true on
// the first heartbeat that brings a previously-Unreachable node back to
// Connected so the caller can emit a transition event.
func UpdateHeartbeat(nodeID string, cpu, mem, qps, syncLag int, version string) bool {
	if nodeID == "" {
		return false
	}
	now := time.Now()
	rtMu.Lock()
	r, ok := rtNodes[nodeID]
	wasUnreachable := false
	if !ok {
		r = &NodeRuntime{NodeID: nodeID, UpSince: now}
		rtNodes[nodeID] = r
		wasUnreachable = true // first ever heartbeat counts as "back online"
	} else if !r.LastSeen.IsZero() {
		// Naive check: if the gap since LastSeen is bigger than 30s the
		// node was effectively Unreachable. We don't read heartbeat
		// interval here to avoid plumbing it through; 30s catches the
		// common case (default 5s × 3 = 15s + slack).
		wasUnreachable = now.Sub(r.LastSeen) > 30*time.Second
	}
	r.CPUUsage = cpu
	r.MemUsage = mem
	r.QPS = qps
	r.SyncLag = syncLag
	if version != "" {
		r.Version = version
	}
	r.LastHeartbeat = now
	r.LastSeen = now
	r.History = appendSample(r.History, MetricSample{
		At: now, CPUUsage: cpu, MemUsage: mem, QPS: qps, SyncLag: syncLag,
	})
	rtMu.Unlock()

	if wasUnreachable {
		Publish("node-state", nodeID, map[string]any{"state": "Connected"})
	}
	return true
}

// appendSample is a fixed-capacity ring buffer push. When the slice would
// grow past historyCap we drop the oldest entry, keeping the chart's
// rendering cost bounded regardless of uptime.
func appendSample(buf []MetricSample, s MetricSample) []MetricSample {
	if len(buf) >= historyCap {
		// Reuse the underlying array: shift left by one and overwrite tail.
		copy(buf, buf[1:])
		buf[len(buf)-1] = s
		return buf
	}
	return append(buf, s)
}

// History returns a copy of the per-node metrics ring buffer (oldest →
// newest). Used by the node-detail chart.
func History(nodeID string) []MetricSample {
	rtMu.RLock()
	defer rtMu.RUnlock()
	r, ok := rtNodes[nodeID]
	if !ok || len(r.History) == 0 {
		return nil
	}
	out := make([]MetricSample, len(r.History))
	copy(out, r.History)
	return out
}

// UpdateSelfMetrics lets the local process publish its own resource usage
// without going through the heartbeat HTTP path.
func UpdateSelfMetrics(cpu, mem, qps int) {
	rtMu.Lock()
	defer rtMu.Unlock()
	if rtSelfID == "" {
		return
	}
	r, ok := rtNodes[rtSelfID]
	if !ok {
		return
	}
	now := time.Now()
	r.CPUUsage = cpu
	r.MemUsage = mem
	r.QPS = qps
	r.LastHeartbeat = now
	r.LastSeen = now
	r.History = appendSample(r.History, MetricSample{
		At: now, CPUUsage: cpu, MemUsage: mem, QPS: qps, SyncLag: r.SyncLag,
	})
}

// Forget drops the runtime entry for nodeID (e.g. after PeerLeave / removal).
func Forget(nodeID string) {
	rtMu.Lock()
	defer rtMu.Unlock()
	delete(rtNodes, nodeID)
	if rtSelfID == nodeID {
		rtSelfID = ""
	}
}

// ForgetAllExceptSelf clears every runtime entry except the local primary's.
// Used by DELETE /api/cluster.
func ForgetAllExceptSelf() {
	rtMu.Lock()
	defer rtMu.Unlock()
	for id := range rtNodes {
		if id != rtSelfID {
			delete(rtNodes, id)
		}
	}
}

// Get returns a copy of the runtime entry for nodeID.
func Get(nodeID string) (NodeRuntime, bool) {
	rtMu.RLock()
	defer rtMu.RUnlock()
	r, ok := rtNodes[nodeID]
	if !ok {
		return NodeRuntime{}, false
	}
	return *r, true
}

// DeriveState resolves the spec's NodeState given the heartbeat interval.
// A node is Connected while LastSeen is within 3× heartbeatInterval, and
// Unreachable beyond that. The local Self entry is always StateSelf, and
// nodes with no runtime data yet are StateUnknown.
func DeriveState(nodeID string, heartbeatIntervalSec int) NodeState {
	rtMu.RLock()
	defer rtMu.RUnlock()
	if nodeID != "" && nodeID == rtSelfID {
		return StateSelf
	}
	r, ok := rtNodes[nodeID]
	if !ok {
		return StateUnknown
	}
	if r.LastSeen.IsZero() {
		return StateUnknown
	}
	if heartbeatIntervalSec <= 0 {
		heartbeatIntervalSec = 5
	}
	limit := time.Duration(heartbeatIntervalSec*3) * time.Second
	if time.Since(r.LastSeen) <= limit {
		return StateConnected
	}
	return StateUnreachable
}

// StateLabel maps the NodeState to the legacy 在线/离线 status string used
// across the existing UI and persisted operation logs.
func StateLabel(s NodeState) string {
	switch s {
	case StateSelf, StateConnected:
		return "在线"
	case StateUnreachable:
		return "离线"
	default:
		return "未知"
	}
}

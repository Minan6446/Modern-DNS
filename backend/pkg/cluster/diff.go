package cluster

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// DiffItem is the per-table outcome of comparing two ConfigSnapshots. It is
// shaped to match the existing frontend `ConfigDiffItem` so the diff modal
// renders without UI changes.
type DiffItem struct {
	Key         string `json:"key"`         // table key, e.g. "zones"
	Label       string `json:"label"`       // human label, e.g. "权威 Zone"
	MasterValue string `json:"masterValue"` // "<rows>条 / sha=<short>"
	NodeValue   string `json:"nodeValue"`
	Changed     bool   `json:"changed"`
}

// DiffResult bundles per-table comparisons plus aggregate counts.
type DiffResult struct {
	Items   []DiffItem `json:"items"`
	Changed int        `json:"changed"`
}

// DiffSnapshots compares master and node ConfigSnapshots table-by-table and
// returns a stable, sorted list of DiffItems. Comparison strategy: row count
// + sha256 of canonically-serialised rows. We do NOT attempt a row-by-row
// "added/updated/deleted" breakdown — that requires PK-aware diffing per
// table and grows the snapshot endpoint cost; the per-table count + hash
// is enough for the operator to know which planes will change.
func DiffSnapshots(master, node *ConfigSnapshot) DiffResult {
	pairs := []struct {
		key   string
		label string
		mv    any
		nv    any
	}{
		{"zones", "权威 Zone", master.Zones, node.Zones},
		{"dnsRecords", "DNS 记录", master.DNSRecords, node.DNSRecords},
		{"forwardGlobal", "全局转发策略", master.ForwardGlobal, node.ForwardGlobal},
		{"forwardServers", "转发服务器", master.ForwardServers, node.ForwardServers},
		{"forwardRules", "转发规则", master.ForwardRules, node.ForwardRules},
		{"lbGroups", "负载均衡组", master.LbGroups, node.LbGroups},
		{"lbServers", "负载均衡后端", master.LbServers, node.LbServers},
		{"cacheGlobal", "全局缓存策略", master.CacheGlobal, node.CacheGlobal},
		{"cacheDomainRules", "缓存域名规则", master.CacheDomainRules, node.CacheDomainRules},
		{"bwRules", "黑白名单", master.BWRules, node.BWRules},
		{"rpzRules", "RPZ 规则", master.RpzRules, node.RpzRules},
		{"aclRules", "ACL 规则", master.AclRules, node.AclRules},
		{"ddosGlobal", "全局 DDoS 防护", master.DDoSGlobal, node.DDoSGlobal},
		{"ddosDomainRules", "DDoS 域名规则", master.DDoSDomainRules, node.DDoSDomainRules},
	}

	out := DiffResult{Items: make([]DiffItem, 0, len(pairs))}
	for _, p := range pairs {
		mn, mh := summarise(p.mv)
		nn, nh := summarise(p.nv)
		changed := mh != nh
		out.Items = append(out.Items, DiffItem{
			Key:         p.key,
			Label:       p.label,
			MasterValue: fmt.Sprintf("%d 条 / sha=%s", mn, shortHash(mh)),
			NodeValue:   fmt.Sprintf("%d 条 / sha=%s", nn, shortHash(nh)),
			Changed:     changed,
		})
		if changed {
			out.Changed++
		}
	}
	return out
}

// summarise returns (rowCount, sha256Hex) for any snapshot field. Single
// objects (e.g. CacheGlobal) count as 1 row. JSON marshal failures yield a
// zero hash so the caller can still distinguish "empty" from "data".
func summarise(v any) (int, string) {
	count := 1
	// Use reflection-light approach via json marshalling: arrays serialise
	// as [...] starting with '[', singletons as objects.
	b, err := json.Marshal(v)
	if err != nil {
		return 0, ""
	}
	// Detect array → count via re-decode.
	if len(b) > 0 && b[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(b, &arr); err == nil {
			count = len(arr)
		}
	}
	sum := sha256.Sum256(b)
	return count, hex.EncodeToString(sum[:])
}

func shortHash(h string) string {
	if len(h) >= 8 {
		return h[:8]
	}
	return h
}

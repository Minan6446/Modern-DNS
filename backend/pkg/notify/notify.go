// Package notify dispatches operator-facing notifications across the email
// (SMTP), webhook, and Aliyun SMS channels. Channel configuration lives in
// the `notice_config` table and is cached with short TTL plus explicit
// invalidation so UI edits take effect quickly.
package notify

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"
)

// Channel identifies one of the supported delivery channels.
type Channel string

const (
	ChannelEmail    Channel = "email"
	ChannelWebhook  Channel = "webhook"
	ChannelSMS      Channel = "sms"
	ChannelDingTalk Channel = "dingtalk"
	ChannelFeishu   Channel = "feishu"
	ChannelWecom    Channel = "wecom"
	ChannelSlack    Channel = "slack"
	ChannelVoice    Channel = "voice"
)

// allChannels lists every wire-recognized channel. Used by Dispatch to fan
// out and by the operator UI/handler to build the list of known channels.
var allChannels = []Channel{
	ChannelEmail,
	ChannelWebhook,
	ChannelSMS,
	ChannelDingTalk,
	ChannelFeishu,
	ChannelWecom,
	ChannelSlack,
	ChannelVoice,
}

// AllChannels returns a copy of the registered channel list.
func AllChannels() []Channel {
	out := make([]Channel, len(allChannels))
	copy(out, allChannels)
	return out
}

// Event is the canonical payload passed to every channel sender.
type Event struct {
	Level       string    // info / warning / critical
	Type        string    // alert type/category, e.g. "DDoS防护"
	Title       string    // short headline
	Message     string    // full body
	Domain      string    // optional domain context
	TriggeredAt time.Time // event time
}

type configSnapshot struct {
	version uint64
	at      time.Time
	configs map[string]map[string]any
}

var (
	refreshMu     sync.Mutex
	configVersion atomic.Uint64
	cfgSnapshot   atomic.Value // stores configSnapshot
)

const cacheTTL = 30 * time.Second

func init() {
	cfgSnapshot.Store(configSnapshot{})
}

func loadConfigs() map[string]map[string]any {
	targetVersion := configVersion.Load()
	if snap, ok := cfgSnapshot.Load().(configSnapshot); ok {
		if snap.configs != nil && snap.version == targetVersion && time.Since(snap.at) < cacheTTL {
			return snap.configs
		}
	}

	refreshMu.Lock()
	defer refreshMu.Unlock()
	if snap, ok := cfgSnapshot.Load().(configSnapshot); ok {
		if snap.configs != nil && snap.version == targetVersion && time.Since(snap.at) < cacheTTL {
			return snap.configs
		}
	}

	var rows []model.NoticeConfig
	if err := db.DB.Find(&rows).Error; err != nil {
		log.Printf("[notify] load notice_config failed: %v", err)
		return nil
	}
	out := make(map[string]map[string]any, len(rows))
	for _, r := range rows {
		var m map[string]any
		_ = json.Unmarshal(r.ConfigJSON, &m)
		if m == nil {
			m = map[string]any{}
		}
		m["enabled"] = r.Enabled
		out[r.Channel] = m
	}
	cfgSnapshot.Store(configSnapshot{version: targetVersion, at: time.Now(), configs: out})
	return out
}

// Invalidate forces the next Send call to re-read notice_config from DB.
func Invalidate() {
	configVersion.Add(1)
}

// Dispatch fans an event out to every enabled channel.
func Dispatch(ev Event) {
	dispatchThroughWorkers(ev)
}

// Test sends a synthetic event through the given channel using supplied config.
func Test(ch Channel, raw map[string]any) (string, error) {
	if raw == nil {
		raw = map[string]any{}
	}
	ev := testNotificationEvent()
	if err := dispatchTestThroughWorkers(ch, raw, ev); err != nil {
		return "", err
	}
	switch ch {
	case ChannelEmail:
		recv := strings.TrimSpace(stringField(raw, "receivers"))
		return fmt.Sprintf("测试邮件已发送至：%s", recv), nil
	case ChannelWebhook:
		return fmt.Sprintf("测试请求已发送至：%s", stringField(raw, "url")), nil
	case ChannelSMS:
		return fmt.Sprintf("测试短信已下发至：%s", stringField(raw, "phones")), nil
	case ChannelDingTalk:
		return "测试卡片已发送至 DingTalk 机器人", nil
	case ChannelFeishu:
		return "测试卡片已发送至 Feishu 机器人", nil
	case ChannelWecom:
		return "测试卡片已发送至 企业微信 机器人", nil
	case ChannelSlack:
		return "测试卡片已发送至 Slack 频道", nil
	case ChannelVoice:
		return fmt.Sprintf("测试语音呼叫已发起至：%s", stringField(raw, "phones")), nil
	}
	return "测试已完成", nil
}

// testNotificationEvent is the shared synthetic payload used by both
// the template-preview API and channel "send test" operations. Keeping
// one source avoids confusion where preview output and received test
// message diverge for the same template.
func testNotificationEvent() Event {
	return Event{
		Level:       "info",
		Type:        "测试通知",
		Title:       "Modern DNS 测试通知",
		Message:     "这是一条来自 Modern DNS 通知中心的测试消息，用于验证渠道配置。",
		Domain:      "",
		TriggeredAt: time.Now(),
	}
}

func sendOne(ch Channel, raw map[string]any, ev Event) error {
	switch ch {
	case ChannelEmail:
		return sendEmail(raw, ev)
	case ChannelWebhook:
		return sendWebhook(raw, ev)
	case ChannelSMS:
		return sendAliyunSMS(raw, ev)
	case ChannelDingTalk:
		return sendDingTalk(raw, ev)
	case ChannelFeishu:
		return sendFeishu(raw, ev)
	case ChannelWecom:
		return sendWecom(raw, ev)
	case ChannelSlack:
		return sendSlack(raw, ev)
	case ChannelVoice:
		return sendAliyunVoice(raw, ev)
	}
	return fmt.Errorf("unknown channel: %s", ch)
}

func stringField(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func intField(m map[string]any, key string, fallback int) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case string:
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return fallback
}

func splitMulti(raw string) []string {
	s := raw
	for _, sep := range []string{"\r\n", "\n", ";", " ", "\t"} {
		s = strings.ReplaceAll(s, sep, ",")
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

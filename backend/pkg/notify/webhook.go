package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ─── Webhook ─────────────────────────────────────────────────────────────────
//
// sendWebhook delivers an Event over HTTP to an arbitrary URL. Hardened
// for the operator-alert use case:
//
//   - Templates: dingtalk / feishu / wecom / raw (default). The first
//     three pre-shape the JSON body to match the chat platform's expected
//     "interactive card" schema so an operator can paste the bot URL
//     straight from those products and start receiving alerts.
//   - Replay protection: the optional HMAC signature now covers
//     `timestamp.nonce.body` (separated by ".") and the timestamp is sent
//     as `X-MDNS-Timestamp`. Receivers should reject requests older than
//     ~5 minutes after verifying the signature.
//   - SSRF guard: by default we reject loopback / link-local / RFC1918
//     hosts to block outbound abuse from a compromised admin token. Set
//     `allowPrivateNetwork: true` only for self-hosted IM where the bot
//     URL legitimately lives on an internal LAN.
//   - Severity filter: `minLevel` ∈ info / warning / critical limits
//     deliveries to the matching tier and above. Defaults to "info" so
//     existing configs keep working.
//   - Single retry on transient failure (5xx or network error) with a 1s
//     backoff. A 4xx response is *not* retried — it's almost always a
//     misconfigured URL or signature.
//
// Config keys:
//
//	url                  — required, http(s)://...
//	method               — "GET" or "POST" (default POST)
//	templateMode         — "raw" | "dingtalk" | "feishu" | "wecom"
//	secret               — optional HMAC secret
//	headers              — optional map[string]string of extra headers
//	timeoutSec           — request timeout in seconds (default 10, max 60)
//	allowPrivateNetwork  — bool, allow loopback/RFC1918 (default false)
//	minLevel             — "info" | "warning" | "critical"
//	alertTypes           — []string filter (existing behaviour)
func sendWebhook(cfg map[string]any, ev Event) error {
	target := strings.TrimSpace(stringField(cfg, "url"))
	if target == "" {
		return fmt.Errorf("webhook URL 未配置")
	}
	parsedURL, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("webhook URL 无效: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("webhook URL 仅支持 http/https，收到: %s", parsedURL.Scheme)
	}
	if parsedURL.Host == "" {
		return fmt.Errorf("webhook URL 缺少主机名")
	}

	if !boolField(cfg, "allowPrivateNetwork", false) {
		if err := guardSSRF(parsedURL.Hostname()); err != nil {
			return err
		}
	}

	method := strings.ToUpper(strings.TrimSpace(stringField(cfg, "method")))
	if method == "" {
		method = http.MethodPost
	}
	if method != http.MethodPost && method != http.MethodGet {
		return fmt.Errorf("webhook method 只支持 GET 或 POST，收到: %s", method)
	}

	if !typeAllowed(cfg, ev.Type) {
		return nil // filtered out, not an error
	}
	if !levelAllowed(cfg, ev.Level) {
		return nil
	}

	body, err := buildWebhookBody(cfg, ev)
	if err != nil {
		return err
	}

	timeout := time.Duration(intField(cfg, "timeoutSec", 10)) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if timeout > 60*time.Second {
		timeout = 60 * time.Second
	}
	client := &http.Client{Timeout: timeout}

	// Build the request once; retries reuse the same body bytes via
	// bytes.NewReader so we don't have to rebuild headers each loop.
	mkReq := func() (*http.Request, error) {
		var r *http.Request
		var err error
		switch method {
		case http.MethodGet:
			u := *parsedURL
			q := u.Query()
			q.Set("payload", string(body))
			u.RawQuery = q.Encode()
			r, err = http.NewRequest(http.MethodGet, u.String(), nil)
		default:
			r, err = http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
			if err == nil {
				r.Header.Set("Content-Type", "application/json; charset=utf-8")
			}
		}
		if err != nil {
			return nil, err
		}
		r.Header.Set("User-Agent", "Modern-DNS-Webhook/1.0")
		// Apply caller-supplied extra headers (e.g. Authorization for
		// bearer-token webhooks). Skip Content-Type so the chosen
		// rendering wins.
		if extra, ok := cfg["headers"].(map[string]any); ok {
			for k, v := range extra {
				if strings.EqualFold(k, "Content-Type") {
					continue
				}
				if s, _ := v.(string); s != "" {
					r.Header.Set(k, s)
				}
			}
		}
		// Replay-protection signature. The wire format is
		// "sha256=<hex>" with the digest computed over
		// "<timestamp>.<nonce>.<body>" so receivers can verify both
		// authenticity and freshness without storing extra state.
		if secret := strings.TrimSpace(stringField(cfg, "secret")); secret != "" {
			ts := fmt.Sprintf("%d", time.Now().Unix())
			nonce := randHex(8)
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte(ts + "." + nonce + "."))
			mac.Write(body)
			r.Header.Set("X-MDNS-Timestamp", ts)
			r.Header.Set("X-MDNS-Nonce", nonce)
			r.Header.Set("X-MDNS-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}
		return r, nil
	}

	// Two-attempt loop: at most one retry on transient failures.
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		req, err := mkReq()
		if err != nil {
			cancel()
			return err
		}
		resp, err := client.Do(req.WithContext(ctx))
		if err != nil {
			cancel()
			lastErr = fmt.Errorf("webhook 请求失败: %w", err)
			if attempt == 0 {
				time.Sleep(time.Second)
				continue
			}
			return lastErr
		}
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		cancel()
		if resp.StatusCode >= 500 && attempt == 0 {
			// Transient — retry once after a 1s backoff.
			lastErr = fmt.Errorf("webhook 返回 %d: %s", resp.StatusCode, strings.TrimSpace(string(buf)))
			time.Sleep(time.Second)
			continue
		}
		if resp.StatusCode >= 400 {
			return fmt.Errorf("webhook 返回 %d: %s", resp.StatusCode, strings.TrimSpace(string(buf)))
		}
		// Some chat platforms (DingTalk, Feishu) always respond 200 but
		// signal failure inside the JSON body. Surface that so the
		// operator's "测试" button doesn't lie.
		if err := inspectChatPlatformAck(cfg, buf); err != nil {
			return err
		}
		return nil
	}
	return lastErr
}

// buildWebhookBody renders the body bytes per the configured template
// mode. "raw" is the historical Modern-DNS shape; the chat-platform modes
// build the message payload those products expect for their incoming-bot
// URLs so an operator can paste a DingTalk / Feishu / WeCom bot URL and
// receive readable alerts without writing a transformation layer.
func buildWebhookBody(cfg map[string]any, ev Event) ([]byte, error) {
	mode := strings.ToLower(strings.TrimSpace(stringField(cfg, "templateMode")))
	if mode == "json_custom" {
		raw, err := renderAnyJSONTemplate(ChannelWebhook, ev)
		if err != nil {
			return nil, err
		}
		if raw == nil {
			return nil, errors.New("Webhook JSON 自定义模式下，模板正文不能为空")
		}
		return json.Marshal(raw)
	}
	// Operator-edited body template wins over both `templateMode`
	// preset and the historical raw JSON envelope. We treat any
	// non-empty rendered body as the literal HTTP payload — it can
	// be JSON, XML, plain text, anything the receiving service wants.
	if rendered := renderForChannel(ChannelWebhook, ev); strings.TrimSpace(rendered.Body) != "" {
		return []byte(rendered.Body), nil
	}
	if mode == "" {
		mode = "raw"
	}
	plain := fmt.Sprintf("【%s】%s\n等级：%s\n类型：%s\n域名：%s\n时间：%s\n%s",
		levelLabel(ev.Level), nonEmpty(ev.Title, ev.Type),
		levelLabel(ev.Level), nonEmpty(ev.Type, "告警"), nonEmpty(ev.Domain, "-"),
		ev.TriggeredAt.Format("2006-01-02 15:04:05"),
		ev.Message)

	switch mode {
	case "dingtalk":
		// DingTalk markdown bot — title appears in the message list,
		// body is rendered as markdown in the chat itself.
		return json.Marshal(map[string]any{
			"msgtype": "markdown",
			"markdown": map[string]any{
				"title": fmt.Sprintf("[%s] %s", levelLabel(ev.Level), nonEmpty(ev.Title, ev.Type)),
				"text":  plain,
			},
		})
	case "feishu":
		// Feishu ("Lark") bot text post.
		return json.Marshal(map[string]any{
			"msg_type": "text",
			"content":  map[string]any{"text": plain},
		})
	case "wecom":
		// WeCom (企业微信) markdown bot.
		return json.Marshal(map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]any{"content": plain},
		})
	default:
		return json.Marshal(map[string]any{
			"level":       ev.Level,
			"type":        ev.Type,
			"title":       ev.Title,
			"message":     ev.Message,
			"domain":      ev.Domain,
			"triggeredAt": ev.TriggeredAt.Format(time.RFC3339),
			"source":      "modern-dns",
		})
	}
}

// inspectChatPlatformAck decodes the 200-OK response body for chat-
// platform templates and checks the in-body status field. Without this,
// "测试" would report success even when the bot URL is wrong because
// DingTalk / Feishu / WeCom never use HTTP error codes.
func inspectChatPlatformAck(cfg map[string]any, body []byte) error {
	mode := strings.ToLower(strings.TrimSpace(stringField(cfg, "templateMode")))
	if mode == "raw" || mode == "" || len(body) == 0 {
		return nil
	}
	var ack struct {
		Errcode int    `json:"errcode"` // dingtalk / wecom
		Errmsg  string `json:"errmsg"`
		Code    int    `json:"code"` // feishu
		Msg     string `json:"msg"`
	}
	if err := json.Unmarshal(body, &ack); err != nil {
		// Body wasn't JSON — most likely a custom 200-OK consumer. Treat
		// as success rather than guessing wrong.
		return nil
	}
	if ack.Errcode != 0 {
		return fmt.Errorf("webhook 平台返回错误 %d: %s", ack.Errcode, ack.Errmsg)
	}
	if ack.Code != 0 {
		return fmt.Errorf("webhook 平台返回错误 %d: %s", ack.Code, ack.Msg)
	}
	return nil
}

// guardSSRF blocks delivery to private / loopback / link-local addresses
// unless the operator explicitly opted in. Resolves the host so a CNAME
// pointing at an internal IP can't sneak past the check.
func guardSSRF(host string) error {
	if host == "" {
		return errors.New("webhook URL 缺少主机名")
	}
	// Strip IPv6 brackets if present.
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")

	resolveCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
	if err != nil {
		// DNS failure isn't an SSRF — let the actual HTTP call surface
		// the timeout / unreachable error in language the operator
		// already understands.
		return nil
	}
	for _, a := range addrs {
		ip := a.IP
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
			ip.IsPrivate() || ip.IsUnspecified() ||
			ip.Equal(net.IPv4(169, 254, 169, 254)) /* AWS IMDS */ {
			return fmt.Errorf("出于安全策略，已阻止访问内网/回环地址 %s（如确需，请勾选 allowPrivateNetwork）", ip.String())
		}
	}
	return nil
}

// typeAllowed evaluates the optional alertTypes filter. An empty/missing
// list means "all types allowed". Test events (Type == "测试通知") always
// bypass the filter so the operator's test button isn't silently dropped.
func typeAllowed(cfg map[string]any, eventType string) bool {
	if eventType == "测试通知" {
		return true
	}
	raw, ok := cfg["alertTypes"]
	if !ok {
		return true
	}
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return true
	}
	for _, v := range list {
		if s, _ := v.(string); s == eventType {
			return true
		}
	}
	return false
}

// levelAllowed checks the minLevel filter. The order is info < warning <
// critical; events at or above the configured threshold pass. Empty /
// unrecognised value means "no floor".
func levelAllowed(cfg map[string]any, level string) bool {
	min := strings.ToLower(strings.TrimSpace(stringField(cfg, "minLevel")))
	if min == "" {
		return true
	}
	rank := func(l string) int {
		switch strings.ToLower(strings.TrimSpace(l)) {
		case "critical", "crit":
			return 3
		case "warning", "warn":
			return 2
		case "info":
			return 1
		}
		return 0
	}
	return rank(level) >= rank(min)
}

func boolField(m map[string]any, key string, fallback bool) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		return s == "true" || s == "1" || s == "yes" || s == "on"
	}
	return fallback
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func levelLabel(l string) string {
	switch strings.ToLower(strings.TrimSpace(l)) {
	case "critical", "crit":
		return "严重"
	case "warning", "warn":
		return "警告"
	default:
		return "提示"
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// sendDingTalk delivers an Event to a DingTalk custom-bot incoming
// webhook. Two operator-supplied options control authentication:
//
//   - secret (optional)  — DingTalk "加签" mode: the bot endpoint expects
//     two extra query params, `timestamp` (epoch ms) and `sign`, where
//     sign = base64(HMAC-SHA256(timestamp + "\n" + secret, secret)).
//     Operators paste the bot URL + secret separately so we can sign on
//     their behalf without forcing them to script it manually.
//
//   - keywords (optional) — DingTalk "自定义关键词" mode requires every
//     message body to contain at least one keyword. We only validate
//     that the rendered text contains one; the bot itself enforces this
//     and would 410 a message that doesn't.
//
// Config keys:
//
//	url                 — required, https://oapi.dingtalk.com/robot/send?access_token=...
//	secret              — optional sign secret
//	atMobiles           — optional []string of @-mentioned mobile numbers
//	atUserIds           — optional []string of @-mentioned userIds
//	atAll               — bool, mention everyone in the channel
//	allowPrivateNetwork — bool, opt-in for self-hosted relays
//	minLevel            — info | warning | critical (default: pass-through)
//	alertTypes          — optional category filter (existing semantics)
func sendDingTalk(cfg map[string]any, ev Event) error {
	if !typeAllowed(cfg, ev.Type) {
		return nil
	}
	if !levelAllowed(cfg, ev.Level) {
		return nil
	}
	target := strings.TrimSpace(stringField(cfg, "url"))
	if target == "" {
		return fmt.Errorf("DingTalk URL 未配置")
	}
	// Apply DingTalk's signing scheme by appending timestamp/sign as
	// query params. Done before SSRF/transport handling so postChatBot
	// receives the final URL it should hit.
	if secret := strings.TrimSpace(stringField(cfg, "secret")); secret != "" {
		signed, err := dingTalkSignURL(target, secret)
		if err != nil {
			return err
		}
		target = signed
	}

	plain := renderPlainAlert(ChannelDingTalk, ev)
	at := buildDingTalkAt(cfg)
	mode := strings.ToLower(strings.TrimSpace(stringField(cfg, "templateMode")))

	// Card title comes from the operator-edited subject template so
	// the conversation-list preview snippet stays in sync with the
	// body. nonEmpty() guards against an operator who blanked both
	// templates: we still render *something* recognisable.
	title := renderPlainAlertSubject(ChannelDingTalk, ev)
	if title == "" {
		title = fmt.Sprintf("[%s] %s", levelLabel(ev.Level), nonEmpty(ev.Title, ev.Type))
	}

	body := map[string]any{}
	if mode == "card_json" || mode == "card" {
		if raw, err := renderAnyJSONTemplate(ChannelDingTalk, ev); err != nil {
			return err
		} else if raw != nil {
			obj, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("DingTalk 卡片 JSON 模式要求模板渲染为 JSON 对象")
			}
			body = obj
		} else {
			body = map[string]any{
				"msgtype": "actionCard",
				"actionCard": map[string]any{
					"title":       title,
					"text":        appendDingTalkMentions(plain, at),
					"singleTitle": "查看告警",
					"singleURL":   "https://example.com",
				},
			}
		}
	} else {
		body = map[string]any{
			"msgtype": "markdown",
			"markdown": map[string]any{
				"title": title,
				// DingTalk @-mentions in markdown require explicit @<mobile>
				// tokens at the body end. Mirror the at[] list into the text
				// so the visual mention renders consistently with the
				// `at.atMobiles` payload.
				"text": appendDingTalkMentions(plain, at),
			},
		}
	}
	if at != nil {
		body["at"] = at
	}
	payload, _ := json.Marshal(body)

	return postChatBot(chatbotRequest{
		platform:     "DingTalk",
		url:          target,
		body:         payload,
		timeoutSec:   intField(cfg, "timeoutSec", 10),
		allowPrivate: boolField(cfg, "allowPrivateNetwork", false),
		ackInspect:   inspectDingTalkAck,
	})
}

func dingTalkSignURL(target, secret string) (string, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("DingTalk URL 无效: %w", err)
	}
	ts := fmt.Sprintf("%d", time.Now().UnixMilli())
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "\n" + secret))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	q := parsed.Query()
	q.Set("timestamp", ts)
	q.Set("sign", sig)
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

func buildDingTalkAt(cfg map[string]any) map[string]any {
	mobiles := coerceStringList(cfg["atMobiles"])
	users := coerceStringList(cfg["atUserIds"])
	atAll := boolField(cfg, "atAll", false)
	if len(mobiles) == 0 && len(users) == 0 && !atAll {
		return nil
	}
	out := map[string]any{"isAtAll": atAll}
	if len(mobiles) > 0 {
		out["atMobiles"] = mobiles
	}
	if len(users) > 0 {
		out["atUserIds"] = users
	}
	return out
}

func appendDingTalkMentions(text string, at map[string]any) string {
	if at == nil {
		return text
	}
	var tokens []string
	if mobiles, _ := at["atMobiles"].([]string); len(mobiles) > 0 {
		for _, m := range mobiles {
			tokens = append(tokens, "@"+m)
		}
	}
	if isAll, _ := at["isAtAll"].(bool); isAll {
		tokens = append(tokens, "@所有人")
	}
	if len(tokens) == 0 {
		return text
	}
	return text + "\n\n" + strings.Join(tokens, " ")
}

// inspectDingTalkAck decodes DingTalk's 200-OK envelope. The bot returns
// HTTP 200 even for misconfiguration (wrong access_token, sign mismatch,
// missing keyword); the real status sits in the JSON `errcode` field.
func inspectDingTalkAck(_ int, body []byte) error {
	if len(body) == 0 {
		return nil
	}
	var ack struct {
		Errcode int    `json:"errcode"`
		Errmsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(body, &ack); err != nil {
		return nil // unknown body shape — don't second-guess
	}
	if ack.Errcode != 0 {
		return fmt.Errorf("DingTalk 平台返回错误 %d: %s", ack.Errcode, ack.Errmsg)
	}
	return nil
}

// coerceStringList accepts the JSON variants the operator UI may send —
// raw arrays from a chip-input ([]any with string elements) or a CRLF /
// comma-delimited textarea. Normalised to a clean []string.
func coerceStringList(raw any) []string {
	switch v := raw.(type) {
	case []string:
		return trimNonEmpty(v)
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, _ := e.(string); strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	case string:
		return splitMulti(v)
	}
	return nil
}

func trimNonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}

package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// sendFeishu delivers an Event to a Feishu (Lark) custom-bot incoming
// webhook. Feishu's signing scheme differs from DingTalk in two ways:
//
//  1. The signed input is `<timestamp>\n<secret>` (note: no body bytes).
//  2. timestamp + sign go into the JSON *body*, not the URL query
//     string. So the body shape changes when signing is enabled.
//
// Unlike DingTalk, Feishu accepts richer "interactive card" payloads,
// which we use whenever the operator opts in via `useCard: true`. The
// card schema yields a colored header and structured fields rather than
// a plain markdown blob, which matches operator expectations for paged
// alerts. Falls back to a plain text post if `useCard` is false.
//
// Config keys:
//
//	url                 — required, https://open.feishu.cn/open-apis/bot/v2/hook/<id>
//	secret              — optional sign secret
//	useCard             — bool, render as interactive card (default false → text post)
//	atUsers             — optional []string of @-mentioned user open_ids
//	atAll               — bool, mention everyone
//	allowPrivateNetwork — bool, opt-in for self-hosted Lark
//	minLevel / alertTypes — same semantics as other channels
func sendFeishu(cfg map[string]any, ev Event) error {
	if !typeAllowed(cfg, ev.Type) {
		return nil
	}
	if !levelAllowed(cfg, ev.Level) {
		return nil
	}
	target := strings.TrimSpace(stringField(cfg, "url"))
	if target == "" {
		return fmt.Errorf("Feishu URL 未配置")
	}

	mode := strings.ToLower(strings.TrimSpace(stringField(cfg, "templateMode")))
	if mode == "" {
		if boolField(cfg, "useCard", false) {
			mode = "card_json"
		} else {
			mode = "markdown"
		}
	}
	plain := renderPlainAlert(ChannelFeishu, ev) + buildFeishuMentions(cfg)
	title := renderPlainAlertSubject(ChannelFeishu, ev)
	if title == "" {
		title = fmt.Sprintf("[%s] %s", levelLabel(ev.Level), nonEmpty(ev.Title, ev.Type))
	}

	var body map[string]any
	if mode == "card_json" || mode == "card" {
		if raw, err := renderAnyJSONTemplate(ChannelFeishu, ev); err != nil {
			return err
		} else if raw != nil {
			obj, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("Feishu 卡片 JSON 模式要求模板渲染为 JSON 对象")
			}
			body = map[string]any{"msg_type": "interactive", "card": obj}
		} else {
			body = map[string]any{
				"msg_type": "interactive",
				"card":     buildFeishuCard(ev, plain, title),
			}
		}
	} else {
		body = map[string]any{
			"msg_type": "interactive",
			"card":     buildFeishuCard(ev, plain, title),
		}
	}

	// Feishu's signing scheme injects timestamp + sign at the top level
	// of the body. We compute it last so any later body mutation (e.g.
	// from caller-supplied extras) doesn't invalidate the signature.
	if secret := strings.TrimSpace(stringField(cfg, "secret")); secret != "" {
		ts := fmt.Sprintf("%d", time.Now().Unix())
		body["timestamp"] = ts
		body["sign"] = feishuSign(ts, secret)
	}

	payload, _ := json.Marshal(body)

	return postChatBot(chatbotRequest{
		platform:     "Feishu",
		url:          target,
		body:         payload,
		timeoutSec:   intField(cfg, "timeoutSec", 10),
		allowPrivate: boolField(cfg, "allowPrivateNetwork", false),
		ackInspect:   inspectFeishuAck,
	})
}

func feishuSign(ts, secret string) string {
	mac := hmac.New(sha256.New, []byte(ts+"\n"+secret))
	mac.Write(nil) // canonical: empty body, key encodes the input
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func buildFeishuMentions(cfg map[string]any) string {
	users := coerceStringList(cfg["atUsers"])
	atAll := boolField(cfg, "atAll", false)
	if len(users) == 0 && !atAll {
		return ""
	}
	var tokens []string
	for _, u := range users {
		// Feishu mention syntax: <at user_id="<openId>"></at>
		tokens = append(tokens, fmt.Sprintf(`<at user_id="%s"></at>`, u))
	}
	if atAll {
		tokens = append(tokens, `<at user_id="all">所有人</at>`)
	}
	return "\n" + strings.Join(tokens, " ")
}

// buildFeishuCard renders an interactive card whose header colour
// reflects the event severity. Operators get a glanceable badge per
// alert without configuring anything.
func buildFeishuCard(ev Event, plain, title string) map[string]any {
	headerColor := "blue"
	switch strings.ToLower(strings.TrimSpace(ev.Level)) {
	case "critical", "crit":
		headerColor = "red"
	case "warning", "warn":
		headerColor = "orange"
	}
	return map[string]any{
		"config": map[string]any{"wide_screen_mode": true},
		"header": map[string]any{
			"template": headerColor,
			"title": map[string]any{
				"tag":     "plain_text",
				"content": title,
			},
		},
		"elements": []any{
			map[string]any{
				"tag": "div",
				"text": map[string]any{
					"tag":     "lark_md",
					"content": plain,
				},
			},
		},
	}
}

func inspectFeishuAck(_ int, body []byte) error {
	if len(body) == 0 {
		return nil
	}
	// Feishu uses StatusCode in v2, and `code` in some legacy envelopes;
	// accept either so older tenant URLs still surface failures.
	var ack struct {
		Code       int    `json:"code"`
		StatusCode int    `json:"StatusCode"`
		Msg        string `json:"msg"`
		StatusMsg  string `json:"StatusMessage"`
	}
	if err := json.Unmarshal(body, &ack); err != nil {
		return nil
	}
	if ack.Code != 0 {
		return fmt.Errorf("Feishu 平台返回错误 %d: %s", ack.Code, ack.Msg)
	}
	if ack.StatusCode != 0 {
		return fmt.Errorf("Feishu 平台返回错误 %d: %s", ack.StatusCode, ack.StatusMsg)
	}
	return nil
}

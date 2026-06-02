package notify

import (
	"encoding/json"
	"fmt"
	"strings"
)

// sendWecom delivers an Event to a WeCom (企业微信) custom-bot incoming
// webhook. WeCom webhooks don't sign individual messages — the URL key
// in the bot URL is the only credential. We focus on:
//
//   - Rendering markdown so colors and links survive (WeCom strips
//     unstructured text formatting).
//   - Mentioning users via `mentioned_list` (open_ids) or
//     `mentioned_mobile_list` (phone numbers).
//   - Surfacing the platform's 200-OK error envelope so an operator's
//     "测试" doesn't lie when the URL key is wrong.
//
// Config keys:
//
//	url                 — required, https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...
//	atMobiles           — optional []string of @-mentioned mobiles
//	atUsers             — optional []string of @-mentioned userIds; "@all" = everyone
//	allowPrivateNetwork — bool, opt-in for self-hosted relays
//	minLevel / alertTypes — same semantics as other channels
func sendWecom(cfg map[string]any, ev Event) error {
	if !typeAllowed(cfg, ev.Type) {
		return nil
	}
	if !levelAllowed(cfg, ev.Level) {
		return nil
	}
	target := strings.TrimSpace(stringField(cfg, "url"))
	if target == "" {
		return fmt.Errorf("WeCom URL 未配置")
	}

	plain := renderPlainAlert(ChannelWecom, ev)
	mode := strings.ToLower(strings.TrimSpace(stringField(cfg, "templateMode")))
	// WeCom's markdown bot supports `<font color="warning">` etc; render
	// the level token in colour so the header pops in a busy chat.
	colored := strings.Replace(plain,
		fmt.Sprintf("【%s】", levelLabel(ev.Level)),
		fmt.Sprintf(`<font color="%s">【%s】</font>`, wecomLevelColor(ev.Level), levelLabel(ev.Level)),
		1,
	)

	body := map[string]any{}
	if mode == "textcard" {
		if raw, err := renderAnyJSONTemplate(ChannelWecom, ev); err != nil {
			return err
		} else if raw != nil {
			obj, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("WeCom textcard 模式要求模板渲染为 JSON 对象")
			}
			body = map[string]any{"msgtype": "textcard", "textcard": obj}
		} else {
			body = map[string]any{
				"msgtype": "textcard",
				"textcard": map[string]any{
					"title":       renderPlainAlertSubject(ChannelWecom, ev),
					"description": colored,
					"url":         "https://example.com",
					"btntxt":      "查看详情",
				},
			}
		}
	} else {
		body = map[string]any{
			"msgtype": "markdown",
			"markdown": map[string]any{
				"content": colored + buildWecomMentions(cfg),
			},
		}
	}
	payload, _ := json.Marshal(body)

	return postChatBot(chatbotRequest{
		platform:     "WeCom",
		url:          target,
		body:         payload,
		timeoutSec:   intField(cfg, "timeoutSec", 10),
		allowPrivate: boolField(cfg, "allowPrivateNetwork", false),
		ackInspect:   inspectWecomAck,
	})
}

func wecomLevelColor(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical", "crit":
		return "warning" // WeCom: warning = red
	case "warning", "warn":
		return "comment" // grey-orange
	}
	return "info" // green
}

func buildWecomMentions(cfg map[string]any) string {
	mobiles := coerceStringList(cfg["atMobiles"])
	users := coerceStringList(cfg["atUsers"])
	if len(mobiles) == 0 && len(users) == 0 {
		return ""
	}
	// WeCom markdown doesn't support inline mention syntax; instead the
	// `mentioned_list` field on the outer payload would handle it for
	// text msgtype. For markdown we surface the mentions as plain
	// tokens at the body tail so they're at least visible.
	var tokens []string
	for _, u := range users {
		if u == "@all" {
			tokens = append(tokens, "@所有人")
		} else {
			tokens = append(tokens, "@"+u)
		}
	}
	for _, m := range mobiles {
		tokens = append(tokens, "@"+m)
	}
	return "\n\n" + strings.Join(tokens, " ")
}

func inspectWecomAck(_ int, body []byte) error {
	if len(body) == 0 {
		return nil
	}
	var ack struct {
		Errcode int    `json:"errcode"`
		Errmsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(body, &ack); err != nil {
		return nil
	}
	if ack.Errcode != 0 {
		return fmt.Errorf("WeCom 平台返回错误 %d: %s", ack.Errcode, ack.Errmsg)
	}
	return nil
}

package notify

import (
	"encoding/json"
	"fmt"
	"strings"
)

// sendSlack delivers an Event to a Slack incoming webhook. Slack's
// incoming-webhook envelope is the simplest of the supported chat
// platforms — a JSON document with `text` and optional `blocks` /
// `attachments`. We render two layouts:
//
//   - The legacy `attachments` colour-coded block, because most older
//     Slack workspaces still trigger their alert filters off it.
//   - A modern `blocks` array with a header, fields, and divider so
//     newer workspaces get a richer card.
//
// Slack returns plain "ok" / "invalid_payload" plain-text bodies — not
// JSON — so the ack inspector treats anything other than "ok" (after
// trimming) as failure. This matches operator expectations from the
// Slack docs.
//
// Config keys:
//
//	url                 — required, https://hooks.slack.com/services/...
//	channel             — optional override, e.g. "#alerts" (only if the
//	                      operator's webhook permits override)
//	username            — optional bot display name override
//	iconEmoji           — optional :emoji: shorthand
//	mentions            — optional []string of @users / channel groups
//	allowPrivateNetwork — bool, opt-in for self-hosted relays
//	minLevel / alertTypes — same semantics as other channels
func sendSlack(cfg map[string]any, ev Event) error {
	if !typeAllowed(cfg, ev.Type) {
		return nil
	}
	if !levelAllowed(cfg, ev.Level) {
		return nil
	}
	target := strings.TrimSpace(stringField(cfg, "url"))
	if target == "" {
		return fmt.Errorf("Slack URL 未配置")
	}

	header := renderPlainAlertSubject(ChannelSlack, ev)
	if header == "" {
		header = fmt.Sprintf("[%s] %s", levelLabel(ev.Level), nonEmpty(ev.Title, ev.Type))
	}
	plain := renderPlainAlert(ChannelSlack, ev)
	mode := strings.ToLower(strings.TrimSpace(stringField(cfg, "templateMode")))
	mentions := coerceStringList(cfg["mentions"])
	mentionPrefix := ""
	if len(mentions) > 0 {
		// Slack mention shorthands are just whitespace-separated tokens
		// at the body start (e.g. "<!channel> <@U123>"). Operators
		// typically supply them already-prefixed with @ or <!...> so we
		// pass them through.
		mentionPrefix = strings.Join(mentions, " ") + "\n"
	}

	body := map[string]any{
		// Plain `text` is the fallback for clients that don't render
		// blocks (notifications, mobile lock screen).
		"text": mentionPrefix + header,
	}
	if mode == "block_json" || mode == "block" {
		if raw, err := renderAnyJSONTemplate(ChannelSlack, ev); err != nil {
			return err
		} else if raw != nil {
			switch v := raw.(type) {
			case []any:
				body["blocks"] = v
			case map[string]any:
				if blocks, ok := v["blocks"]; ok {
					body["blocks"] = blocks
				} else {
					return fmt.Errorf("Slack Block Kit JSON 需为数组或包含 blocks 字段的对象")
				}
			default:
				return fmt.Errorf("Slack Block Kit JSON 需为数组或对象")
			}
		} else {
			body["blocks"] = []any{
				map[string]any{
					"type": "header",
					"text": map[string]any{"type": "plain_text", "text": header, "emoji": true},
				},
				map[string]any{
					"type": "section",
					"text": map[string]any{"type": "mrkdwn", "text": plain},
				},
				map[string]any{"type": "divider"},
			}
		}
	} else {
		body["attachments"] = []any{
			map[string]any{
				"color": slackLevelColor(ev.Level),
				"text":  plain,
				"ts":    ev.TriggeredAt.Unix(),
			},
		}
		body["blocks"] = []any{
			map[string]any{
				"type": "header",
				"text": map[string]any{"type": "plain_text", "text": header, "emoji": true},
			},
			map[string]any{
				"type": "section",
				"text": map[string]any{"type": "mrkdwn", "text": plain},
			},
			map[string]any{"type": "divider"},
		}
	}
	if v := strings.TrimSpace(stringField(cfg, "channel")); v != "" {
		body["channel"] = v
	}
	if v := strings.TrimSpace(stringField(cfg, "username")); v != "" {
		body["username"] = v
	}
	if v := strings.TrimSpace(stringField(cfg, "iconEmoji")); v != "" {
		body["icon_emoji"] = v
	}
	payload, _ := json.Marshal(body)

	return postChatBot(chatbotRequest{
		platform:     "Slack",
		url:          target,
		body:         payload,
		timeoutSec:   intField(cfg, "timeoutSec", 10),
		allowPrivate: boolField(cfg, "allowPrivateNetwork", false),
		ackInspect:   inspectSlackAck,
	})
}

func slackLevelColor(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical", "crit":
		return "#E54545" // red
	case "warning", "warn":
		return "#F0A020" // orange
	}
	return "#3B82F6" // info blue
}

func inspectSlackAck(_ int, body []byte) error {
	trimmed := strings.TrimSpace(string(body))
	// Slack returns the literal string "ok" on success. Any other
	// non-empty body indicates an error — bubble it up so the
	// operator's test result is honest.
	if trimmed == "" || strings.EqualFold(trimmed, "ok") {
		return nil
	}
	return fmt.Errorf("Slack 平台返回错误: %s", trimmed)
}

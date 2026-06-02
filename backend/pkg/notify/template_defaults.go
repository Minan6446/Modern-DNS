package notify

// templateSpec is a (subject, body) pair used as the package's
// hard-coded default for a channel. These strings are *Go text/template*
// source — they are parsed by template.go on first use.
//
// Editing rules of thumb:
//   - Mention every variable an operator might want via the documented
//     names: .Title .Level .LevelLabel .Type .Domain .Message .Time
//   - Keep newlines explicit (`\n`) so the wire format is predictable.
//   - For chat-bot bodies, mirror what renderPlainAlert used to emit so
//     existing operators see no behavioural change after this template
//     system lands.
//   - For webhook/voice the default is an empty body — those channels
//     have well-defined JSON envelopes built by their senders, and we
//     only want to *override* them when the operator opts in. An empty
//     default body is the signal "use sender's built-in payload".
type templateSpec struct {
	subject string
	body    string
}

// defaultTemplates is keyed by Channel. Centralising the strings here
// means a single audit point for "what does Modern DNS send by default"
// and lets the preview/reset features show identical output to the live
// dispatcher.
var defaultTemplates = map[Channel]templateSpec{
	ChannelEmail: {
		subject: `[Modern DNS][{{.Type}}] {{.Title}}`,
		body: `{{.Message}}

──────────────────
级别  : {{.LevelLabel}}
类型  : {{.Type}}
域名  : {{if .Domain}}{{.Domain}}{{else}}-{{end}}
时间  : {{.Time}}

— Modern DNS 通知中心
`,
	},

	// Chat-bot platforms share a common plain layout. Each platform
	// wraps this in its own card schema; subject becomes the card
	// title where the platform supports one.
	ChannelDingTalk: {
		subject: `[{{.LevelLabel}}] {{.Title}}`,
		body: `【{{.LevelLabel}}】{{.Title}}
等级：{{.LevelLabel}}
类型：{{.Type}}
域名：{{if .Domain}}{{.Domain}}{{else}}-{{end}}
时间：{{.Time}}
{{.Message}}`,
	},
	ChannelFeishu: {
		subject: `[{{.LevelLabel}}] {{.Title}}`,
		body: `【{{.LevelLabel}}】{{.Title}}
等级：{{.LevelLabel}}
类型：{{.Type}}
域名：{{if .Domain}}{{.Domain}}{{else}}-{{end}}
时间：{{.Time}}
{{.Message}}`,
	},
	ChannelWecom: {
		subject: `[{{.LevelLabel}}] {{.Title}}`,
		body: `【{{.LevelLabel}}】{{.Title}}
等级：{{.LevelLabel}}
类型：{{.Type}}
域名：{{if .Domain}}{{.Domain}}{{else}}-{{end}}
时间：{{.Time}}
{{.Message}}`,
	},
	ChannelSlack: {
		subject: `[{{.LevelLabel}}] {{.Title}}`,
		body: `【{{.LevelLabel}}】{{.Title}}
等级：{{.LevelLabel}}
类型：{{.Type}}
域名：{{if .Domain}}{{.Domain}}{{else}}-{{end}}
时间：{{.Time}}
{{.Message}}`,
	},

	// Aliyun SMS templates have *parameter slots*, not free text — the
	// vendor enforces a per-template length budget on each `${var}`.
	// The default ships an empty body so the existing structured
	// templateParams in cfg remain authoritative; a non-empty body
	// must render to a JSON object (parsed by renderJSONTemplate) to
	// override that map. Subject is unused on the wire because
	// Aliyun's API has no equivalent of an SMS subject.
	ChannelSMS: {
		subject: ``,
		body:    ``,
	},

	// Webhook & Voice intentionally ship an *empty* default body so the
	// existing JSON payload composer in webhook.go / voice.go remains
	// the source of truth. A non-empty operator override switches the
	// channel to template-driven mode (see renderJSONTemplate).
	ChannelWebhook: {
		subject: ``,
		body:    ``,
	},
	ChannelVoice: {
		subject: ``,
		body:    ``,
	},
}

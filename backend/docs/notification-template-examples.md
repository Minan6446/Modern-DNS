# 通知渠道模板示例库

本文给出可直接粘贴到通知模板编辑器的示例，覆盖以下模式：

- 邮件：HTML + 内联 CSS
- Webhook：JSON 自定义结构
- 短信：纯文本（极简）
- 钉钉：Markdown / 消息卡片 JSON
- 飞书：消息卡片 JSON / Markdown
- 企业微信：Markdown / textcard
- Slack：Block Kit(JSON) / mrkdwn
- 电话：纯文本（超短）

## 使用说明

1. 在通知设置中先选择对应通道的 `templateMode`。
2. 打开“通知模板”抽屉，切到对应通道。
3. 将下方示例粘贴到 `Body`（部分模式也可配 `Subject`）。
4. 点“预览”确认，再“保存”。

可用变量：

- `{{.Title}}`
- `{{.Level}}`
- `{{.LevelLabel}}`
- `{{.Type}}`
- `{{.Domain}}`
- `{{.Message}}`
- `{{.Time}}`
- `{{.Timestamp}}`

---

## 1) 邮件：HTML + 内联 CSS

前提：Email 通道 `templateMode = html`

### Subject

```text
[Modern DNS][{{.Type}}][{{.LevelLabel}}] {{.Title}}
```

### Body

```html
<!doctype html>
<html>
	<body style="margin:0;padding:0;background:#f5f7fb;font-family:Arial,'PingFang SC','Microsoft YaHei',sans-serif;">
		<div style="max-width:680px;margin:24px auto;background:#ffffff;border:1px solid #e6eaf2;border-radius:12px;overflow:hidden;">
			<div style="padding:16px 20px;background:#0f172a;color:#ffffff;font-size:18px;font-weight:700;">
				Modern DNS 告警通知
			</div>
			<div style="padding:20px;line-height:1.6;color:#1f2937;font-size:14px;">
				<p style="margin:0 0 12px;"><strong>{{.Title}}</strong></p>
				<p style="margin:0 0 8px;">等级：<span style="display:inline-block;padding:2px 8px;border-radius:10px;background:#fde68a;color:#92400e;">{{.LevelLabel}}</span></p>
				<p style="margin:0 0 8px;">类型：{{.Type}}</p>
				<p style="margin:0 0 8px;">域名：{{if .Domain}}{{.Domain}}{{else}}-{{end}}</p>
				<p style="margin:0 0 12px;">时间：{{.Time}}</p>
				<div style="padding:12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;white-space:pre-wrap;">{{.Message}}</div>
			</div>
		</div>
	</body>
</html>
```

---

## 2) Webhook：JSON 自定义结构

前提：Webhook 通道 `templateMode = json_custom`

### Body

```json
{
	"source": "modern-dns",
	"title": "{{.Title}}",
	"level": "{{.Level}}",
	"levelLabel": "{{.LevelLabel}}",
	"type": "{{.Type}}",
	"domain": "{{.Domain}}",
	"message": "{{.Message}}",
	"time": "{{.Time}}",
	"timestamp": {{.Timestamp}}
}
```

---

## 3) 短信：纯文本（极简）

前提：SMS 通道 `templateMode = text`

### Body

```text
{{.LevelLabel}} {{.Type}} {{if .Domain}}{{.Domain}}{{else}}-{{end}} {{.Time}}
```

说明：该模式会映射到短信参数中的 `content` 字段，建议保持超短。

---

## 4) 钉钉

### A. Markdown

前提：DingTalk 通道 `templateMode = markdown`

```markdown
### {{.Title}}

- **等级**: {{.LevelLabel}}
- **类型**: {{.Type}}
- **域名**: {{if .Domain}}{{.Domain}}{{else}}-{{end}}
- **时间**: {{.Time}}

> {{.Message}}
```

### B. 消息卡片 JSON

前提：DingTalk 通道 `templateMode = card_json`

```json
{
	"msgtype": "actionCard",
	"actionCard": {
		"title": "[{{.LevelLabel}}] {{.Title}}",
		"text": "#### {{.Title}}\\n\\n> 等级：{{.LevelLabel}}\\n\\n> 类型：{{.Type}}\\n\\n> 域名：{{if .Domain}}{{.Domain}}{{else}}-{{end}}\\n\\n> 时间：{{.Time}}\\n\\n{{.Message}}",
		"singleTitle": "查看详情",
		"singleURL": "https://your-monitor.example.com/alerts"
	}
}
```

---

## 5) 飞书

### A. 消息卡片 JSON

前提：Feishu 通道 `templateMode = card_json`

```json
{
	"config": {
		"wide_screen_mode": true
	},
	"header": {
		"template": "orange",
		"title": {
			"tag": "plain_text",
			"content": "[{{.LevelLabel}}] {{.Title}}"
		}
	},
	"elements": [
		{
			"tag": "div",
			"text": {
				"tag": "lark_md",
				"content": "**类型**: {{.Type}}\\n**域名**: {{if .Domain}}{{.Domain}}{{else}}-{{end}}\\n**时间**: {{.Time}}\\n\\n{{.Message}}"
			}
		}
	]
}
```

### B. Markdown

前提：Feishu 通道 `templateMode = markdown`

```markdown
**{{.Title}}**

- 等级: {{.LevelLabel}}
- 类型: {{.Type}}
- 域名: {{if .Domain}}{{.Domain}}{{else}}-{{end}}
- 时间: {{.Time}}

{{.Message}}
```

---

## 6) 企业微信

### A. Markdown

前提：WeCom 通道 `templateMode = markdown`

```markdown
<font color="warning">【{{.LevelLabel}}】{{.Title}}</font>
> 类型：{{.Type}}
> 域名：{{if .Domain}}{{.Domain}}{{else}}-{{end}}
> 时间：{{.Time}}

{{.Message}}
```

### B. textcard

前提：WeCom 通道 `templateMode = textcard`

```json
{
	"title": "[{{.LevelLabel}}] {{.Title}}",
	"description": "类型：{{.Type}}<br/>域名：{{if .Domain}}{{.Domain}}{{else}}-{{end}}<br/>时间：{{.Time}}<br/><br/>{{.Message}}",
	"url": "https://your-monitor.example.com/alerts",
	"btntxt": "查看详情"
}
```

---

## 7) Slack

### A. Block Kit(JSON)

前提：Slack 通道 `templateMode = block_json`

```json
[
	{
		"type": "header",
		"text": {
			"type": "plain_text",
			"text": "[{{.LevelLabel}}] {{.Title}}"
		}
	},
	{
		"type": "section",
		"fields": [
			{
				"type": "mrkdwn",
				"text": "*类型*\\n{{.Type}}"
			},
			{
				"type": "mrkdwn",
				"text": "*域名*\\n{{if .Domain}}{{.Domain}}{{else}}-{{end}}"
			},
			{
				"type": "mrkdwn",
				"text": "*等级*\\n{{.LevelLabel}}"
			},
			{
				"type": "mrkdwn",
				"text": "*时间*\\n{{.Time}}"
			}
		]
	},
	{
		"type": "section",
		"text": {
			"type": "mrkdwn",
			"text": "{{.Message}}"
		}
	}
]
```

### B. mrkdwn

前提：Slack 通道 `templateMode = mrkdwn`

```markdown
*{{.Title}}*
• Level: {{.LevelLabel}}
• Type: {{.Type}}
• Domain: {{if .Domain}}{{.Domain}}{{else}}-{{end}}
• Time: {{.Time}}

{{.Message}}
```

---

## 8) 电话：纯文本（超短）

前提：Voice 通道 `templateMode = text_short`

### Body

```text
{{.LevelLabel}} {{.Type}} {{if .Domain}}{{.Domain}}{{else}}-{{end}}
```

说明：该模式会映射到语音模板参数中的 `content` 字段，建议保持非常短。


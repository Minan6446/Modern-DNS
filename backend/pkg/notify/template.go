package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"text/template"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"
)

// TemplateData is the variable bag exposed to operator-edited Go
// text/template strings. Field names are stable contract — renaming any
// of them silently breaks every customised template, so add but do not
// remove. Keep this type small; richer event metadata should ride along
// in Message rather than as new fields.
type TemplateData struct {
	Title      string
	Level      string // raw level: info / warning / critical
	LevelLabel string // localised label: 信息 / 警告 / 严重
	Type       string
	Domain     string
	Message    string
	Time       string // formatted YYYY-MM-DD HH:MM:SS in server local time
	Timestamp  int64  // Unix seconds, useful for json templates
}

// templateForEvent normalises an Event into the rendering data bag.
// Empty fields are kept as empty strings so that templates can still
// reference them without nil-pointer panics; it's the operator's job
// to guard with `{{if .Domain}}…{{end}}` if they want conditional output.
func templateForEvent(ev Event) TemplateData {
	when := ev.TriggeredAt
	if when.IsZero() {
		when = time.Now()
	}
	return TemplateData{
		Title:      ev.Title,
		Level:      ev.Level,
		LevelLabel: levelLabel(ev.Level),
		Type:       ev.Type,
		Domain:     ev.Domain,
		Message:    ev.Message,
		Time:       when.Format("2006-01-02 15:04:05"),
		Timestamp:  when.Unix(),
	}
}

// renderedTemplate is what every channel sender ultimately consumes.
// `Subject` is whatever the channel's natural "headline" is (email
// Subject header, chatbot card title, voice call's tts label). `Body`
// is the main payload text. Channels that need only one of the two
// can ignore the other.
type renderedTemplate struct {
	Subject string
	Body    string
}

// ─── Template cache ──────────────────────────────────────────────────────────
//
// We compile each operator-edited template once and keep the compiled
// *template.Template around so a flood of alerts doesn't re-parse the
// same source on every dispatch. The cache is invalidated on save (see
// InvalidateTemplates, called by the handler) and lazily after 30s as
// a safety net for cluster setups where a peer node updates the row.

type cachedTemplates struct {
	at      time.Time
	subject map[Channel]*template.Template
	body    map[Channel]*template.Template
	rows    map[Channel]model.NoticeTemplate // raw rows for the handler
}

var (
	tplMu     sync.RWMutex
	tplCached cachedTemplates
)

const tplCacheTTL = 30 * time.Second

// InvalidateTemplates forces the next render to reload from DB and
// recompile. Called from the notice-template handler after a save or
// reset so operator changes take effect instantly.
func InvalidateTemplates() {
	tplMu.Lock()
	tplCached = cachedTemplates{}
	tplMu.Unlock()
}

// PrewarmTemplates loads rows and pre-compiles subject/body templates for all
// channels so first alert dispatch does not pay parse cost.
func PrewarmTemplates() {
	for _, ch := range allChannels {
		subjSrc, bodySrc := effectiveTemplate(ch)
		if strings.TrimSpace(subjSrc) != "" {
			if _, err := getCompiled(ch, "subject", subjSrc); err != nil {
				log.Printf("[notify] prewarm %s subject template failed: %v", ch, err)
			}
		}
		if strings.TrimSpace(bodySrc) != "" {
			if _, err := getCompiled(ch, "body", bodySrc); err != nil {
				log.Printf("[notify] prewarm %s body template failed: %v", ch, err)
			}
		}
	}
}

func loadTemplateRows() map[Channel]model.NoticeTemplate {
	tplMu.RLock()
	if tplCached.rows != nil && time.Since(tplCached.at) < tplCacheTTL {
		out := tplCached.rows
		tplMu.RUnlock()
		return out
	}
	tplMu.RUnlock()

	tplMu.Lock()
	defer tplMu.Unlock()
	if tplCached.rows != nil && time.Since(tplCached.at) < tplCacheTTL {
		return tplCached.rows
	}

	out := make(map[Channel]model.NoticeTemplate, len(allChannels))
	if db.DB != nil {
		var rows []model.NoticeTemplate
		if err := db.DB.Find(&rows).Error; err != nil {
			log.Printf("[notify] load notice_templates failed: %v", err)
		} else {
			for _, r := range rows {
				out[Channel(r.Channel)] = r
			}
		}
	}
	tplCached = cachedTemplates{
		at:      time.Now(),
		rows:    out,
		subject: make(map[Channel]*template.Template),
		body:    make(map[Channel]*template.Template),
	}
	return out
}

// effectiveTemplate returns the operator-customised (subject, body) for
// `ch` when the row exists, falling back to the package default
// otherwise. Empty strings are treated as "use default" — that matches
// what the UI does (clearing the textarea = revert to default) and
// avoids surprising operators with blank notifications when they only
// meant to clear the subject but left the body untouched.
func effectiveTemplate(ch Channel) (subject, body string) {
	def, ok := defaultTemplates[ch]
	if !ok {
		def = templateSpec{}
	}
	rows := loadTemplateRows()
	row, hasRow := rows[ch]
	subject = strings.TrimSpace(row.Subject)
	if !hasRow || subject == "" {
		subject = def.subject
	}
	body = row.Body
	if !hasRow || strings.TrimSpace(body) == "" {
		body = def.body
	}
	return subject, body
}

// renderForChannel compiles (with caching) the channel's effective
// templates and executes them against the event data. The renderer
// silently swallows execution errors by falling back to the default
// template — surfacing a Go template panic into a paged operator
// during an outage would be the worst possible time. Errors are still
// logged so admins can investigate offline.
func renderForChannel(ch Channel, ev Event) renderedTemplate {
	subjSrc, bodySrc := effectiveTemplate(ch)
	data := templateForEvent(ev)
	out := renderedTemplate{
		Subject: executeTemplate(ch, "subject", subjSrc, data),
		Body:    executeTemplate(ch, "body", bodySrc, data),
	}
	return out
}

func executeTemplate(ch Channel, kind, src string, data TemplateData) string {
	if src == "" {
		return ""
	}
	tpl, err := getCompiled(ch, kind, src)
	if err != nil {
		log.Printf("[notify] %s %s template parse failed: %v — falling back to default", ch, kind, err)
		def := defaultTemplates[ch]
		fallback := def.subject
		if kind == "body" {
			fallback = def.body
		}
		if fallback == "" || fallback == src {
			return src // last resort: emit the raw source, better than empty
		}
		tpl, err = template.New(string(ch) + "-" + kind + "-default").Parse(fallback)
		if err != nil {
			return src
		}
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		log.Printf("[notify] %s %s template exec failed: %v", ch, kind, err)
		return src
	}
	return buf.String()
}

func getCompiled(ch Channel, kind, src string) (*template.Template, error) {
	tplMu.RLock()
	cache := tplCached.subject
	if kind == "body" {
		cache = tplCached.body
	}
	if cache != nil {
		if t, ok := cache[ch]; ok {
			tplMu.RUnlock()
			return t, nil
		}
	}
	tplMu.RUnlock()

	tplMu.Lock()
	defer tplMu.Unlock()
	// Re-create the maps if Invalidate was called between the RUnlock
	// and Lock — a small race with a manual save during a hot dispatch.
	if tplCached.subject == nil {
		tplCached.subject = make(map[Channel]*template.Template)
	}
	if tplCached.body == nil {
		tplCached.body = make(map[Channel]*template.Template)
	}
	cache = tplCached.subject
	if kind == "body" {
		cache = tplCached.body
	}
	if t, ok := cache[ch]; ok {
		return t, nil
	}
	t, err := template.New(string(ch) + "-" + kind).Option("missingkey=zero").Parse(src)
	if err != nil {
		return nil, err
	}
	cache[ch] = t
	return t, nil
}

// PreviewTemplate compiles the supplied subject/body strings and runs
// them against the synthetic preview event. Unlike renderForChannel
// this surfaces parse and exec errors back to the caller — the operator
// is in the editor and wants to see the failure, not have it papered
// over.
func PreviewTemplate(ch Channel, subjectSrc, bodySrc string) (renderedTemplate, error) {
	data := templateForEvent(previewEvent())
	out := renderedTemplate{}
	if s, err := execStandalone(string(ch)+"-preview-subject", subjectSrc, data); err != nil {
		return out, fmt.Errorf("subject 模板错误: %w", err)
	} else {
		out.Subject = s
	}
	if b, err := execStandalone(string(ch)+"-preview-body", bodySrc, data); err != nil {
		return out, fmt.Errorf("body 模板错误: %w", err)
	} else {
		out.Body = b
	}
	return out, nil
}

func execStandalone(name, src string, data TemplateData) (string, error) {
	if strings.TrimSpace(src) == "" {
		return "", nil
	}
	t, err := template.New(name).Option("missingkey=zero").Parse(src)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func previewEvent() Event {
	return testNotificationEvent()
}

// DefaultTemplate exposes the package-baked default for the given
// channel. Used by the handler so the UI can show defaults next to the
// editor and let operators "see what they would revert to".
func DefaultTemplate(ch Channel) (subject, body string) {
	def := defaultTemplates[ch]
	return def.subject, def.body
}

// renderAnyJSONTemplate renders the channel body template and parses
// it as arbitrary JSON (object or array). Empty body means "use
// sender default" and returns (nil, nil).
func renderAnyJSONTemplate(ch Channel, ev Event) (any, error) {
	rendered := renderForChannel(ch, ev)
	if strings.TrimSpace(rendered.Body) == "" {
		return nil, nil
	}
	var out any
	if err := json.Unmarshal([]byte(rendered.Body), &out); err != nil {
		return nil, fmt.Errorf("%s 模板未输出合法 JSON: %w", ch, err)
	}
	if out == nil {
		return nil, errors.New("模板渲染结果为 null")
	}
	return out, nil
}

// renderJSONTemplate is a convenience used by sms/voice senders where
// the template output must be a JSON object.
func renderJSONTemplate(ch Channel, ev Event) (map[string]any, error) {
	out, err := renderAnyJSONTemplate(ch, ev)
	if err != nil || out == nil {
		return nil, err
	}
	obj, ok := out.(map[string]any)
	if !ok {
		return nil, errors.New("模板渲染结果必须为 JSON 对象")
	}
	return obj, nil
}

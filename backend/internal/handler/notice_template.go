// Notice template CRUD handlers.
//
// Each notification channel can have its operator-edited subject/body
// rendering template stored in `notice_templates`. A row only exists
// once the operator has explicitly customised the channel — missing
// rows fall back to the package default in pkg/notify/template_defaults.go,
// so the table never holds noise. Resetting "to default" is therefore
// a single DELETE (see ResetNoticeTemplate).
//
// All routes are gated by the `setting:notice:edit` permission, the
// same gate as SaveNoticeChannelConfig — anyone who can edit a channel
// can edit its template.
package handler

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"modern-dns/internal/model"
	"modern-dns/middleware"
	"modern-dns/pkg/db"
	"modern-dns/pkg/notify"
	"modern-dns/pkg/resp"
)

// templateView is the row shape returned to the frontend. We always
// include both the operator-customised value and the package default
// so the UI can render a "currently using default" hint and a
// reset-to-default button without an extra round-trip.
type templateView struct {
	Channel        string `json:"channel"`
	Subject        string `json:"subject"`
	Body           string `json:"body"`
	DefaultSubject string `json:"defaultSubject"`
	DefaultBody    string `json:"defaultBody"`
	IsCustom       bool   `json:"isCustom"`
	UpdatedAt      string `json:"updatedAt,omitempty"`
}

// GET /api/setting/notice/templates
//
// Returns one entry per known channel (8 today). Channels without a
// row are still listed with `isCustom=false` so the UI can render the
// full grid in one pass.
func ListNoticeTemplates(c *gin.Context) {
	var rows []model.NoticeTemplate
	db.DB.Find(&rows)
	byChannel := make(map[string]model.NoticeTemplate, len(rows))
	for _, r := range rows {
		byChannel[r.Channel] = r
	}

	out := make([]templateView, 0, len(notify.AllChannels()))
	for _, ch := range notify.AllChannels() {
		defSubj, defBody := notify.DefaultTemplate(ch)
		v := templateView{
			Channel:        string(ch),
			DefaultSubject: defSubj,
			DefaultBody:    defBody,
		}
		if row, ok := byChannel[string(ch)]; ok {
			v.Subject = row.Subject
			v.Body = row.Body
			v.IsCustom = true
			if !row.UpdatedAt.IsZero() {
				v.UpdatedAt = row.UpdatedAt.Format("2006-01-02 15:04:05")
			}
		} else {
			v.Subject = defSubj
			v.Body = defBody
		}
		out = append(out, v)
	}
	resp.OK(c, gin.H{"items": out})
}

// PUT /api/setting/notice/templates/:channel
//
// Upserts the operator override. Empty subject/body strings are kept
// as-is on the wire — the renderer treats whitespace-only bodies as
// "use default" automatically (see effectiveTemplate), so an operator
// who clears both fields is effectively performing a reset without
// having to call the dedicated reset endpoint.
func UpdateNoticeTemplate(c *gin.Context) {
	channel := c.Param("channel")
	if !isKnownChannel(channel) {
		resp.BadRequest(c, "未知的通知渠道："+channel)
		return
	}
	var req struct {
		Subject string `json:"subject"`
		Body    string `json:"body"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}

	// Validate the supplied templates compile *before* persisting them
	// — there's no point letting a syntactically broken template land
	// in the DB only to fail at the next alert dispatch. PreviewTemplate
	// runs the same parser the dispatcher uses.
	if _, err := notify.PreviewTemplate(notify.Channel(channel), req.Subject, req.Body); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}

	var uid uint
	if claims := middleware.GetClaims(c); claims != nil {
		uid = claims.UserID
	}
	var existing model.NoticeTemplate
	if db.DB.Where("channel = ?", channel).First(&existing).Error != nil {
		db.DB.Create(&model.NoticeTemplate{
			Channel:   channel,
			Subject:   req.Subject,
			Body:      req.Body,
			UpdatedBy: uid,
		})
	} else {
		db.DB.Model(&model.NoticeTemplate{}).Where("channel = ?", channel).
			Updates(map[string]any{
				"subject":    req.Subject,
				"body":       req.Body,
				"updated_by": uid,
			})
	}
	notify.InvalidateTemplates()
	writeOpLogAuth(c, "配置", "通知设置",
		fmt.Sprintf("保存 %s 通道告警模板", channelDisplayName(channel)), "")
	resp.OK(c, gin.H{"channel": channel, "saved": true})
}

// POST /api/setting/notice/templates/:channel/reset
//
// Drops the row so the channel reverts to the built-in default. Idempotent
// — calling reset on a channel that's already on default is a no-op
// rather than an error, because that's what an operator clicking the
// "重置默认" button intuitively expects.
func ResetNoticeTemplate(c *gin.Context) {
	channel := c.Param("channel")
	if !isKnownChannel(channel) {
		resp.BadRequest(c, "未知的通知渠道："+channel)
		return
	}
	db.DB.Where("channel = ?", channel).Delete(&model.NoticeTemplate{})
	notify.InvalidateTemplates()
	writeOpLogAuth(c, "重置", "通知设置",
		fmt.Sprintf("重置 %s 通道告警模板为默认", channelDisplayName(channel)), "")
	resp.OK(c, gin.H{"channel": channel, "reset": true})
}

// POST /api/setting/notice/templates/:channel/preview
//
// Renders the supplied (subject, body) against a synthetic preview
// event so the operator can sanity-check Go template syntax and see
// what the result would look like before saving. Errors are surfaced
// verbatim — that's the *point* of preview, unlike the live dispatch
// path which silently falls back to defaults to keep alerts flowing.
func PreviewNoticeTemplate(c *gin.Context) {
	channel := c.Param("channel")
	if !isKnownChannel(channel) {
		resp.BadRequest(c, "未知的通知渠道："+channel)
		return
	}
	var req struct {
		Subject string `json:"subject"`
		Body    string `json:"body"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	out, err := notify.PreviewTemplate(notify.Channel(channel), req.Subject, req.Body)
	if err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	resp.OK(c, gin.H{
		"channel": channel,
		"subject": out.Subject,
		"body":    out.Body,
	})
}

// isKnownChannel guards path-param channels against typos and made-up
// names without round-tripping the DB. Centralised here so both the
// update/reset/preview handlers share a single source of truth that
// stays in sync with notify.AllChannels().
func isKnownChannel(channel string) bool {
	for _, c := range notify.AllChannels() {
		if string(c) == channel {
			return true
		}
	}
	return false
}

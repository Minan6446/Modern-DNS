package notify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// chatbotRequest carries the per-call inputs for postChatBot. Each chat
// platform sender (DingTalk / Feishu / WeCom / Slack) constructs one of
// these and lets the shared transport handle SSRF guarding, timeouts,
// retries on 5xx, and platform-specific 200-OK ack inspection.
//
// Why not reuse sendWebhook directly? sendWebhook is the operator-facing
// "raw HTTP" channel — it carries replay-protection signatures intended
// for our own receivers. Chat platforms use platform-native signing
// schemes (DingTalk URL-param sign, Feishu in-body sign, WeCom URL key,
// Slack none) so the shapes diverge enough that one big switch becomes
// harder to reason about than five small files sharing this helper.
type chatbotRequest struct {
	platform     string                              // "dingtalk" / "feishu" / "wecom" / "slack" — for error prefixes
	url          string                              // fully composed URL (already includes any URL-level signing)
	body         []byte                              // JSON body
	contentType  string                              // defaults to application/json; charset=utf-8
	extraHeaders map[string]string                   // optional, e.g. Authorization for token-gated bots
	timeoutSec   int                                 // HTTP timeout (default 10, max 60)
	allowPrivate bool                                // SSRF guard bypass — only for self-hosted IM
	ackInspect   func(status int, body []byte) error // optional 200-OK body checker
}

func postChatBot(req chatbotRequest) error {
	if strings.TrimSpace(req.url) == "" {
		return fmt.Errorf("%s URL 未配置", req.platform)
	}
	parsed, err := url.Parse(req.url)
	if err != nil {
		return fmt.Errorf("%s URL 无效: %w", req.platform, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%s URL 仅支持 http/https，收到: %s", req.platform, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%s URL 缺少主机名", req.platform)
	}
	if !req.allowPrivate {
		if err := guardSSRF(parsed.Hostname()); err != nil {
			return err
		}
	}

	timeout := time.Duration(req.timeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if timeout > 60*time.Second {
		timeout = 60 * time.Second
	}
	client := &http.Client{Timeout: timeout}

	contentType := req.contentType
	if contentType == "" {
		contentType = "application/json; charset=utf-8"
	}

	mkReq := func() (*http.Request, error) {
		r, err := http.NewRequest(http.MethodPost, req.url, bytes.NewReader(req.body))
		if err != nil {
			return nil, err
		}
		r.Header.Set("Content-Type", contentType)
		r.Header.Set("User-Agent", "Modern-DNS-Notify/1.0")
		for k, v := range req.extraHeaders {
			if strings.EqualFold(k, "Content-Type") || v == "" {
				continue
			}
			r.Header.Set(k, v)
		}
		return r, nil
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		r, err := mkReq()
		if err != nil {
			cancel()
			return err
		}
		resp, err := client.Do(r.WithContext(ctx))
		if err != nil {
			cancel()
			lastErr = fmt.Errorf("%s 请求失败: %w", req.platform, err)
			if attempt == 0 {
				time.Sleep(time.Second)
				continue
			}
			return lastErr
		}
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		cancel()
		if resp.StatusCode >= 500 && attempt == 0 {
			lastErr = fmt.Errorf("%s 返回 %d: %s", req.platform, resp.StatusCode, strings.TrimSpace(string(buf)))
			time.Sleep(time.Second)
			continue
		}
		if resp.StatusCode >= 400 {
			return fmt.Errorf("%s 返回 %d: %s", req.platform, resp.StatusCode, strings.TrimSpace(string(buf)))
		}
		// 2xx — let the platform-specific inspector check the body.
		if req.ackInspect != nil {
			if err := req.ackInspect(resp.StatusCode, buf); err != nil {
				return err
			}
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("unknown chatbot error")
	}
	return lastErr
}

// renderPlainAlert produces the plain-text body for the given chat-bot
// channel. It runs the operator-edited template (or the package
// default) so all three of {dispatch, test, preview} share one
// formatting code path. Each platform wraps the resulting string in its
// own card schema.
func renderPlainAlert(ch Channel, ev Event) string {
	out := renderForChannel(ch, ev)
	return out.Body
}

// renderPlainAlertSubject mirrors renderPlainAlert for the card title /
// header slot. Returns "" if the operator deliberately cleared the
// subject template (some platforms degrade gracefully without one).
func renderPlainAlertSubject(ch Channel, ev Event) string {
	out := renderForChannel(ch, ev)
	return out.Subject
}

package notify

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// sendEmail delivers an Event by SMTP. We support both plain (port 25 / 587
// with STARTTLS) and implicit TLS (port 465 / SMTPS) — the chooser is the
// port number, matching common provider conventions.
//
// Config keys (all string unless noted):
//
//	smtpHost   — hostname, required
//	smtpPort   — int, required (25 / 465 / 587 / 2525)
//	smtpUser   — auth username (often == sender)
//	smtpPass   — auth password / token
//	sender     — From: address; falls back to smtpUser when empty
//	receivers  — comma / semicolon / newline separated address list
func sendEmail(cfg map[string]any, ev Event) error {
	host := stringField(cfg, "smtpHost")
	port := intField(cfg, "smtpPort", 25)
	sender := stringField(cfg, "sender")
	fromName := strings.TrimSpace(stringField(cfg, "smtp_from_name"))
	mailMode := strings.ToLower(strings.TrimSpace(stringField(cfg, "templateMode")))
	if fromName == "" {
		fromName = strings.TrimSpace(stringField(cfg, "smtpFromName"))
	}

	// Accept either of the two common field-naming styles the UI ships with:
	//   smtpUser/smtpPass — split-username/password style
	//   sender/authCode   — "send-as + 邮箱授权码" style (used by the
	//                       current EmailTab.vue)
	user := stringField(cfg, "smtpUser")
	if user == "" {
		user = sender
	}
	pass := stringField(cfg, "smtpPass")
	if pass == "" {
		pass = stringField(cfg, "authCode")
	}
	receivers := splitMulti(stringField(cfg, "receivers"))

	if host == "" || port == 0 {
		return fmt.Errorf("SMTP host/port 未配置")
	}
	if sender == "" {
		return fmt.Errorf("SMTP 发件人未配置")
	}
	if len(receivers) == 0 {
		return fmt.Errorf("SMTP 收件人为空")
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	// Subject + body now come from the operator-customisable template
	// (see pkg/notify/template_defaults.go). The legacy buildSubject /
	// buildEmailBody helpers are kept around as last-resort fallbacks
	// in case the template renders to an empty string.
	rendered := renderForChannel(ChannelEmail, ev)
	subject := rendered.Subject
	if strings.TrimSpace(subject) == "" {
		subject = buildSubject(ev)
	}
	body := rendered.Body
	if strings.TrimSpace(body) == "" {
		body = buildEmailBody(ev)
	}
	msg := buildRFC822(sender, fromName, receivers, subject, body, mailMode == "html")

	var auth smtp.Auth
	if user != "" {
		auth = smtp.PlainAuth("", user, pass, host)
	}

	// Implicit TLS path (port 465 / SMTPS) — net/smtp's helper SendMail does
	// STARTTLS, not implicit TLS, so we drive the dialer manually.
	if port == 465 {
		return sendEmailImplicitTLS(addr, host, auth, sender, receivers, msg)
	}

	// Plain or STARTTLS — net/smtp.SendMail picks STARTTLS automatically
	// when the server advertises it.
	return smtp.SendMail(addr, auth, sender, receivers, msg)
}

func sendEmailImplicitTLS(addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: host})
	if err != nil {
		return fmt.Errorf("SMTPS dial: %w", err)
	}
	defer conn.Close()

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("SMTP client: %w", err)
	}
	defer c.Quit()

	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("SMTP MAIL FROM: %w", err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("SMTP RCPT TO %s: %w", rcpt, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("SMTP write body: %w", err)
	}
	return w.Close()
}

func buildSubject(ev Event) string {
	if ev.Type == "" {
		return "[Modern DNS] " + ev.Title
	}
	return fmt.Sprintf("[Modern DNS][%s] %s", ev.Type, ev.Title)
}

func buildEmailBody(ev Event) string {
	var b strings.Builder
	b.WriteString(ev.Message)
	b.WriteString("\r\n\r\n──────────────────\r\n")
	if ev.Level != "" {
		fmt.Fprintf(&b, "级别  : %s\r\n", ev.Level)
	}
	if ev.Type != "" {
		fmt.Fprintf(&b, "类型  : %s\r\n", ev.Type)
	}
	if ev.Domain != "" {
		fmt.Fprintf(&b, "域名  : %s\r\n", ev.Domain)
	}
	when := ev.TriggeredAt
	if when.IsZero() {
		when = time.Now()
	}
	fmt.Fprintf(&b, "时间  : %s\r\n", when.Format("2006-01-02 15:04:05"))
	b.WriteString("\r\n— Modern DNS 通知中心\r\n")
	return b.String()
}

func buildRFC822(from, fromName string, to []string, subject, body string, isHTML bool) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", formatFromHeader(fromName, from))
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", encodeMimeHeader(subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	if isHTML {
		b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	} else {
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

func formatFromHeader(name, email string) string {
	email = strings.TrimSpace(email)
	cleanName := sanitizeHeaderValue(name)
	if cleanName == "" {
		return email
	}
	return fmt.Sprintf("%s <%s>", encodeMimeHeader(cleanName), email)
}

func sanitizeHeaderValue(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return strings.TrimSpace(s)
}

// encodeMimeHeader wraps non-ASCII subjects with RFC 2047 base64 encoding so
// Chinese subjects render correctly on every mail client.
func encodeMimeHeader(s string) string {
	if isASCII(s) {
		return s
	}
	// Use the encoded-word form: =?UTF-8?B?<base64>?=
	enc := base64.StdEncoding.EncodeToString([]byte(s))
	return "=?UTF-8?B?" + enc + "?="
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}

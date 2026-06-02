package notify

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// sendAliyunSMS delivers an Event via Aliyun's dysmsapi POP endpoint. We
// intentionally avoid the alibaba-cloud-sdk-go module (~80 transitive deps)
// in favour of signing the request ourselves — the v2017-05-25 SendSms API
// only needs an HMAC-SHA1 signature over a canonicalised query string.
//
// Config keys:
//
//	accessKeyId     — Aliyun AccessKey ID
//	accessKeySecret — Aliyun AccessKey Secret
//	signName        — pre-approved 短信签名
//	templateCode    — pre-approved 模板号 (SMS_xxxxxxxx)
//	regionId        — optional, default "cn-hangzhou"
//	phones          — comma / newline separated 11-digit CN mobile numbers
//	templateParams  — optional JSON object whose values may embed
//	                  {title} / {level} / {type} / {domain} / {time}
//	                  placeholders. Empty falls back to {"code": <title>}.
//	minLevel        — info / warning / critical filter (default: info)
//	maxBatch        — int, max phones per outbound call (default: 1000,
//	                  hard-capped at the Aliyun documented limit)
//
// Severity filter and batch chunking matter especially for SMS: the
// channel is expensive, replies aren't free, and Aliyun rejects calls
// with more than 1000 phones in a single request. Splitting transparently
// keeps the API surface clean for operators who feed in larger lists.
func sendAliyunSMS(cfg map[string]any, ev Event) error {
	if !typeAllowed(cfg, ev.Type) {
		return nil
	}
	if !levelAllowed(cfg, ev.Level) {
		return nil
	}

	akID := strings.TrimSpace(stringField(cfg, "accessKeyId"))
	akSecret := strings.TrimSpace(stringField(cfg, "accessKeySecret"))
	signName := strings.TrimSpace(stringField(cfg, "signName"))
	tmpl := strings.TrimSpace(stringField(cfg, "templateCode"))
	region := strings.TrimSpace(stringField(cfg, "regionId"))
	rawPhones := splitMulti(stringField(cfg, "phones"))

	if akID == "" || akSecret == "" {
		return fmt.Errorf("阿里云 AccessKey 未配置")
	}
	if signName == "" || tmpl == "" {
		return fmt.Errorf("短信签名 / 模板号未配置")
	}
	if len(rawPhones) == 0 {
		return fmt.Errorf("收件号码为空")
	}
	if region == "" {
		region = "cn-hangzhou"
	}

	// Validate every phone up front so a single bad number doesn't bill
	// the operator for a partial send. Aliyun would reject the whole
	// batch anyway with an opaque "InvalidPhoneNumber" error.
	phones, invalid := validateCNMobiles(rawPhones)
	if len(invalid) > 0 {
		return fmt.Errorf("以下号码格式无效（要求 11 位国内手机号）：%s", strings.Join(invalid, ", "))
	}

	// Operator-edited body template (notice_templates row) overrides
	// the structured cfg.templateParams when present. The template
	// must render to a JSON object whose keys map to ${name} variables
	// in the approved Aliyun SMS template. Empty body → fall back to
	// the existing structured pipeline so legacy operators see no
	// change.
	var param string
	mode := strings.ToLower(strings.TrimSpace(stringField(cfg, "templateMode")))
	if mode == "text" || mode == "plain" || mode == "text_plain" {
		msg := shortenForSMS(ev)
		if rendered := strings.TrimSpace(renderForChannel(ChannelSMS, ev).Body); rendered != "" {
			msg = shortenText(rendered, 60)
		}
		raw, _ := json.Marshal(map[string]string{"content": msg})
		param = string(raw)
	} else if obj, terr := renderJSONTemplate(ChannelSMS, ev); terr != nil {
		return terr
	} else if obj != nil {
		raw, mErr := json.Marshal(obj)
		if mErr != nil {
			return fmt.Errorf("templateParams 模板序列化失败: %w", mErr)
		}
		param = string(raw)
	} else {
		var bErr error
		param, bErr = buildTemplateParam(cfg, ev)
		if bErr != nil {
			return fmt.Errorf("templateParams 解析失败: %w", bErr)
		}
	}

	// Chunk the phone list to respect the per-call cap. Default 1000
	// matches the Aliyun documented limit; operators can lower it (e.g.
	// 100) to spread cost spikes during incident bursts.
	batchSize := intField(cfg, "maxBatch", 1000)
	if batchSize <= 0 || batchSize > 1000 {
		batchSize = 1000
	}

	for i := 0; i < len(phones); i += batchSize {
		end := i + batchSize
		if end > len(phones) {
			end = len(phones)
		}
		if err := dispatchAliyunBatch(akID, akSecret, signName, tmpl, region, phones[i:end], param); err != nil {
			// Stop on the first batch failure so the operator sees a
			// clear error in the audit log rather than a partial send.
			return err
		}
	}
	return nil
}

// dispatchAliyunBatch signs and POSTs one ≤1000-phone batch to Aliyun.
// Split out so sendAliyunSMS can chunk transparently without duplicating
// the signing dance.
func dispatchAliyunBatch(akID, akSecret, signName, tmpl, region string, phones []string, param string) error {
	common := map[string]string{
		"AccessKeyId":      akID,
		"Action":           "SendSms",
		"Format":           "JSON",
		"PhoneNumbers":     strings.Join(phones, ","),
		"RegionId":         region,
		"SignName":         signName,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   randomNonce(),
		"SignatureVersion": "1.0",
		"TemplateCode":     tmpl,
		"TemplateParam":    param,
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"Version":          "2017-05-25",
	}
	common["Signature"] = signAliyun("GET", common, akSecret)

	endpoint := "https://dysmsapi.aliyuncs.com/?" + urlEncodeAliyun(common)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(endpoint)
	if err != nil {
		return fmt.Errorf("阿里云 SMS 请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var ack struct {
		Code      string `json:"Code"`
		Message   string `json:"Message"`
		RequestId string `json:"RequestId"`
		BizId     string `json:"BizId"`
	}
	if err := json.Unmarshal(body, &ack); err != nil {
		return fmt.Errorf("阿里云 SMS 返回解析失败: %s", strings.TrimSpace(string(body)))
	}
	if ack.Code != "OK" {
		return fmt.Errorf("阿里云 SMS 失败: %s (%s)", ack.Message, ack.Code)
	}
	return nil
}

// buildTemplateParam renders the templateParams config (if present) by
// substituting {title}/{level}/{type}/{domain}/{time} placeholders with
// the live event fields. Falls back to the legacy {"code": <title>}
// shape when no custom params are configured so old templates keep
// working without UI migration.
func buildTemplateParam(cfg map[string]any, ev Event) (string, error) {
	raw := strings.TrimSpace(stringField(cfg, "templateParams"))
	if raw == "" {
		// Legacy default: a single ${code} placeholder.
		out, _ := json.Marshal(map[string]string{"code": shortenForSMS(ev)})
		return string(out), nil
	}
	var tmpl map[string]string
	if err := json.Unmarshal([]byte(raw), &tmpl); err != nil {
		// Sometimes the UI ships values as numbers/bools; widen the
		// type and re-stringify so the substitution can run.
		var loose map[string]any
		if err := json.Unmarshal([]byte(raw), &loose); err != nil {
			return "", err
		}
		tmpl = make(map[string]string, len(loose))
		for k, v := range loose {
			tmpl[k] = fmt.Sprintf("%v", v)
		}
	}
	rep := strings.NewReplacer(
		"{title}", shortenForSMS(ev),
		"{level}", levelLabel(ev.Level),
		"{type}", nonEmpty(ev.Type, "告警"),
		"{domain}", nonEmpty(ev.Domain, "-"),
		"{time}", ev.TriggeredAt.Format("01-02 15:04"),
	)
	rendered := make(map[string]string, len(tmpl))
	for k, v := range tmpl {
		rendered[k] = rep.Replace(v)
	}
	out, _ := json.Marshal(rendered)
	return string(out), nil
}

// validateCNMobiles strips obvious noise (spaces, dashes, +86 prefix),
// then partitions the input into recognised CN-mobile numbers (11 digits
// starting with 1) and the rejects. Operators copy/paste from CRM lists
// where +86, hyphens, and trailing extension notes are common, so we
// normalise rather than fail-fast on cosmetic differences.
func validateCNMobiles(in []string) (ok []string, bad []string) {
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		s = strings.TrimPrefix(s, "+86")
		s = strings.TrimPrefix(s, "86")
		// Drop common cosmetic separators.
		s = strings.NewReplacer(" ", "", "-", "", ".", "").Replace(s)
		if isCNMobile(s) {
			ok = append(ok, s)
		} else {
			bad = append(bad, raw)
		}
	}
	return
}

func isCNMobile(s string) bool {
	if len(s) != 11 || s[0] != '1' {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// shortenForSMS produces a ≤20-char string for the {code} placeholder. SMS
// templates have strict length budgets; we truncate Title and fall back to
// Type to avoid blowing past the carrier limit.
func shortenForSMS(ev Event) string {
	src := ev.Title
	if src == "" {
		src = ev.Type
	}
	if src == "" {
		src = "ALERT"
	}
	rs := []rune(src)
	if len(rs) > 20 {
		rs = rs[:20]
	}
	return string(rs)
}

func shortenText(in string, max int) string {
	in = strings.TrimSpace(in)
	if in == "" {
		return "ALERT"
	}
	rs := []rune(in)
	if len(rs) > max {
		rs = rs[:max]
	}
	return string(rs)
}

// signAliyun implements the Aliyun POP v1.0 signing protocol:
//   - Canonicalise: percent-encode each k=v with the "aliyun" rules
//     (essentially RFC 3986 + treat space as %20 + escape * and ~).
//   - Sort by key ascending.
//   - StringToSign = HTTPMethod + "&" + pctEncode("/") + "&" + pctEncode(canonical).
//   - Signature = base64(HMAC-SHA1(StringToSign, AccessKeySecret + "&")).
func signAliyun(method string, params map[string]string, secret string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, pctEncodeAliyun(k)+"="+pctEncodeAliyun(params[k]))
	}
	canonical := strings.Join(parts, "&")
	stringToSign := strings.ToUpper(method) + "&" + pctEncodeAliyun("/") + "&" + pctEncodeAliyun(canonical)

	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// urlEncodeAliyun emits sorted "k=v&k=v" with the same percent-encoding the
// signature relies on; using net/url.Values would re-escape some chars
// differently and break the signature.
func urlEncodeAliyun(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, pctEncodeAliyun(k)+"="+pctEncodeAliyun(params[k]))
	}
	return strings.Join(parts, "&")
}

// pctEncodeAliyun: net/url.QueryEscape uses "+" for space and leaves * / ~
// unescaped, both of which break the Aliyun signature. This routine fixes
// those three deltas to match the official spec.
func pctEncodeAliyun(s string) string {
	enc := url.QueryEscape(s)
	enc = strings.ReplaceAll(enc, "+", "%20")
	enc = strings.ReplaceAll(enc, "*", "%2A")
	enc = strings.ReplaceAll(enc, "%7E", "~")
	return enc
}

func randomNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

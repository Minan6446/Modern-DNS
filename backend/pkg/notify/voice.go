package notify

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// sendAliyunVoice places one-or-more outbound TTS calls via Aliyun's
// dyvmsapi POP endpoint (Action SingleCallByTts). The signing flow is
// identical to the SMS sender — we reuse signAliyun / pctEncodeAliyun
// — but the API surface and quota model are different enough that
// keeping the senders in separate files is clearer than overloading
// sendAliyunSMS with a "channel" switch.
//
// dyvmsapi only accepts ONE phone per request, so the chunking model
// SMS uses doesn't apply: instead, we iterate the operator's phone list
// and place calls sequentially with a small inter-call delay. This is
// deliberately conservative because voice calls are billed per attempt
// and operators routinely include backup numbers — failing fast on the
// first error keeps surprise charges bounded.
//
// Config keys:
//
//	accessKeyId     — Aliyun AccessKey ID
//	accessKeySecret — Aliyun AccessKey Secret
//	calledShowNumber— optional pre-approved caller-ID number
//	ttsCode         — pre-approved TTS template ID (TTS_xxxxxxxx)
//	regionId        — optional, default "cn-hangzhou"
//	phones          — comma / newline separated 11-digit CN mobile numbers
//	ttsParam        — optional JSON object for template substitution,
//	                  using {title}/{level}/{type}/{domain}/{time}
//	playTimes       — optional int 1..3 (default 1) — how many times to
//	                  play the message during the call
//	volume          — optional int 0..100 (default 100)
//	minLevel        — info | warning | critical filter (default: pass-through)
//	maxCalls        — optional int cap on phones placed per Dispatch (default 5)
//	                  to keep accidental loops cheap.
func sendAliyunVoice(cfg map[string]any, ev Event) error {
	if !typeAllowed(cfg, ev.Type) {
		return nil
	}
	if !levelAllowed(cfg, ev.Level) {
		return nil
	}

	akID := strings.TrimSpace(stringField(cfg, "accessKeyId"))
	akSecret := strings.TrimSpace(stringField(cfg, "accessKeySecret"))
	tts := strings.TrimSpace(stringField(cfg, "ttsCode"))
	region := strings.TrimSpace(stringField(cfg, "regionId"))
	rawPhones := splitMulti(stringField(cfg, "phones"))

	if akID == "" || akSecret == "" {
		return fmt.Errorf("阿里云 AccessKey 未配置")
	}
	if tts == "" {
		return fmt.Errorf("语音模板号（ttsCode）未配置")
	}
	if len(rawPhones) == 0 {
		return fmt.Errorf("收件号码为空")
	}
	if region == "" {
		region = "cn-hangzhou"
	}

	phones, invalid := validateCNMobiles(rawPhones)
	if len(invalid) > 0 {
		return fmt.Errorf("以下号码格式无效（要求 11 位国内手机号）：%s", strings.Join(invalid, ", "))
	}

	// Operator-edited body template (notice_templates row) overrides
	// the structured cfg.ttsParam when present. The template must
	// render to a JSON object: keys map to ${name} variables in the
	// approved Aliyun voice template. Empty body → fall back to the
	// existing structured pipeline so legacy operators see no change.
	var param string
	mode := strings.ToLower(strings.TrimSpace(stringField(cfg, "templateMode")))
	if mode == "text" || mode == "plain" || mode == "text_short" {
		msg := shortenText(nonEmpty(ev.Title, ev.Type), 30)
		if rendered := strings.TrimSpace(renderForChannel(ChannelVoice, ev).Body); rendered != "" {
			msg = shortenText(rendered, 30)
		}
		raw, _ := json.Marshal(map[string]string{"content": msg})
		param = string(raw)
	} else if obj, terr := renderJSONTemplate(ChannelVoice, ev); terr != nil {
		return terr
	} else if obj != nil {
		raw, mErr := json.Marshal(obj)
		if mErr != nil {
			return fmt.Errorf("ttsParam 模板序列化失败: %w", mErr)
		}
		param = string(raw)
	} else {
		var bErr error
		param, bErr = buildTemplateParam(cfg, ev)
		if bErr != nil {
			return fmt.Errorf("ttsParam 解析失败: %w", bErr)
		}
	}

	playTimes := intField(cfg, "playTimes", 1)
	if playTimes < 1 {
		playTimes = 1
	}
	if playTimes > 3 {
		playTimes = 3
	}
	volume := intField(cfg, "volume", 100)
	if volume < 0 {
		volume = 0
	}
	if volume > 100 {
		volume = 100
	}
	calledShowNumber := strings.TrimSpace(stringField(cfg, "calledShowNumber"))

	// Cap how many calls a single Dispatch can fire to bound accidental
	// loops. 5 is a sane default for "primary + backup" rosters; ops
	// can lower or raise it explicitly.
	maxCalls := intField(cfg, "maxCalls", 5)
	if maxCalls <= 0 {
		maxCalls = 5
	}
	if len(phones) > maxCalls {
		phones = phones[:maxCalls]
	}

	for i, phone := range phones {
		if i > 0 {
			// Space calls out so the cluster doesn't ratelimit and the
			// backup numbers don't all ring at once.
			time.Sleep(500 * time.Millisecond)
		}
		if err := dispatchAliyunVoiceCall(akID, akSecret, region, phone, tts, param, calledShowNumber, playTimes, volume); err != nil {
			return fmt.Errorf("呼叫 %s 失败: %w", phone, err)
		}
	}
	return nil
}

func dispatchAliyunVoiceCall(akID, akSecret, region, phone, tts, param, calledShow string, playTimes, volume int) error {
	common := map[string]string{
		"AccessKeyId":      akID,
		"Action":           "SingleCallByTts",
		"CalledNumber":     phone,
		"Format":           "JSON",
		"PlayTimes":        fmt.Sprintf("%d", playTimes),
		"RegionId":         region,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   randomNonce(),
		"SignatureVersion": "1.0",
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"TtsCode":          tts,
		"TtsParam":         param,
		"Version":          "2017-05-25",
		"Volume":           fmt.Sprintf("%d", volume),
	}
	if calledShow != "" {
		common["CalledShowNumber"] = calledShow
	}
	common["Signature"] = signAliyun("GET", common, akSecret)

	endpoint := "https://dyvmsapi.aliyuncs.com/?" + urlEncodeAliyun(common)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(endpoint)
	if err != nil {
		return fmt.Errorf("阿里云 Voice 请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var ack struct {
		Code      string `json:"Code"`
		Message   string `json:"Message"`
		RequestId string `json:"RequestId"`
		CallId    string `json:"CallId"`
	}
	if err := json.Unmarshal(body, &ack); err != nil {
		return fmt.Errorf("阿里云 Voice 返回解析失败: %s", strings.TrimSpace(string(body)))
	}
	if ack.Code != "OK" {
		return fmt.Errorf("阿里云 Voice 失败: %s (%s)", ack.Message, ack.Code)
	}
	return nil
}

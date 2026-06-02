// Package sysmon hosts lightweight system-monitoring goroutines that
// run alongside the main HTTP/DNS servers. The NTP poller below
// queries an upstream NTP server periodically and writes the observed
// drift back into system_config so the General Settings UI can render
// it without a separate health endpoint.
//
// Why hand-roll an NTP client? Pulling github.com/beevik/ntp would be
// fine but the SNTPv4 wire format is small enough (48-byte fixed
// packet, two 8-byte timestamps we care about) that a focused
// implementation is cheaper than another supply-chain edge to audit.
// We do *not* attempt to slew the OS clock — that's the operating
// system's job; we only observe and surface.
package sysmon

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"
)

// NTP epoch starts in 1900; Unix in 1970. The 70-year offset (in
// seconds) is the constant that converts between the two.
const ntpEpochOffsetSec = 2208988800

var (
	ntpOnce   sync.Once
	ntpStopMu sync.Mutex
	ntpStop   chan struct{}
	// ntpKick wakes the loop early so an operator's config save can
	// trigger a fresh poll without waiting for the next tick. Buffered
	// to size 1 so concurrent kicks coalesce.
	ntpKick chan struct{}
)

// perServerTimeout caps a single NTP packet round-trip. We split the
// 3-second budget intentionally low: poolers behind it are public
// services that almost always reply in <100 ms, so a 1.5s ceiling is
// generous and still lets us iterate through a 3-server list within a
// single 5-second handler timeout when used synchronously.
const perServerTimeout = 1500 * time.Millisecond

// StartNTP spawns the singleton poller. Idempotent — repeated calls
// (e.g. after a reload) are no-ops; reconfiguration goes through the
// existing system_config row which the loop reads on every tick.
func StartNTP() {
	ntpOnce.Do(func() {
		ntpStopMu.Lock()
		ntpStop = make(chan struct{})
		ntpKick = make(chan struct{}, 1)
		ntpStopMu.Unlock()
		go runNTPLoop()
	})
}

// Kick asks the background loop to poll right away. Safe to call from
// any goroutine; if a poll is already pending the kick is dropped (the
// pending poll will pick up the latest config). Use this from the
// settings save handler so operators see fresh status within a few
// seconds of changing the server list, instead of after the full
// NTPCheckInterval.
func Kick() {
	ntpStopMu.Lock()
	ch := ntpKick
	ntpStopMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

// TestNow runs a synchronous poll using the supplied server list (or
// the persisted one when servers is empty) and returns the observed
// drift / error along with the server that answered. Used by the
// "立即测试" button on the settings UI to give immediate feedback
// without writing a new system_config row first.
//
// Important: this does NOT update the persisted ntp_last_* columns.
// The background loop owns those; otherwise a failing test query
// would override the last successful auto-poll's drift display.
func TestNow(servers []string) (server string, drift time.Duration, err error) {
	if len(servers) == 0 {
		cfg := loadCfg()
		servers = parseServerList(cfg.NTPServers)
	}
	if len(servers) == 0 {
		servers = defaultServers()
	}
	var lastErr error
	for _, s := range servers {
		d, e := queryNTP(s, perServerTimeout)
		if e == nil {
			return s, d, nil
		}
		lastErr = e
	}
	return "", 0, lastErr
}

// StopNTP halts the poller. Mostly for tests and graceful shutdown;
// operational toggling should use SystemConfig.NTPEnabled instead so
// the loop keeps running but skips network I/O.
func StopNTP() {
	ntpStopMu.Lock()
	defer ntpStopMu.Unlock()
	if ntpStop != nil {
		close(ntpStop)
		ntpStop = nil
		ntpOnce = sync.Once{} // allow restart after stop in tests
	}
}

func runNTPLoop() {
	// First poll runs after a short warm-up so the rest of the boot
	// sequence finishes wiring up DB connections / migrations before
	// we hit the network. Subsequent polls follow NTPCheckInterval,
	// or earlier if Kick() is called from a config-save handler.
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	for {
		ntpStopMu.Lock()
		stop := ntpStop
		kick := ntpKick
		ntpStopMu.Unlock()
		if stop == nil {
			return
		}

		select {
		case <-stop:
			return
		case <-timer.C:
		case <-kick:
			// Drain the timer if it was about to fire too; we'll
			// reset it below regardless.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}

		cfg := loadCfg()
		if cfg.NTPEnabled {
			pollOnce(cfg)
		}

		next := time.Duration(maxInt(cfg.NTPCheckInterval, 60)) * time.Second
		timer.Reset(next)
	}
}

// defaultServers returns the seed list used when system_config has
// no NTP servers configured. We pick public pools that all reply
// quickly over IPv4; ntp.aliyun.com works well in CN networks where
// pool.ntp.org can be slow.
func defaultServers() []string {
	return []string{"ntp.aliyun.com", "pool.ntp.org", "time.cloudflare.com"}
}

func loadCfg() model.SystemConfig {
	// FirstOrCreate (not First) so a brand-new install with no
	// system_config row yet still returns the GORM `default:` tag
	// values from the model — most importantly NTPEnabled=true. The
	// previous First() returned an empty struct on miss, which silently
	// disabled the poller until the operator hit Save once.
	var cfg model.SystemConfig
	db.DB.FirstOrCreate(&cfg, model.SystemConfig{ID: 1})
	return cfg
}

// pollOnce queries each configured server in order until one answers,
// records the drift, and persists it. We deliberately *don't* fail
// loudly when no server answers — the operator can see the error
// string surfaced in the UI and the previous good drift remains
// visible alongside it.
func pollOnce(cfg model.SystemConfig) {
	servers := parseServerList(cfg.NTPServers)
	if len(servers) == 0 {
		servers = defaultServers()
	}

	var (
		drift   time.Duration
		lastErr error
		ok      bool
	)
	for _, s := range servers {
		d, err := queryNTP(s, perServerTimeout)
		if err == nil {
			drift = d
			ok = true
			break
		}
		log.Printf("[ntp] poll %s failed: %v", s, err)
		lastErr = err
	}

	updates := map[string]any{}
	if ok {
		updates["ntp_last_sync"] = time.Now()
		updates["ntp_last_drift_ms"] = drift.Milliseconds()
		updates["ntp_last_error"] = ""
	} else if lastErr != nil {
		// Keep the previous successful drift visible; only the error
		// message gets refreshed so operators can see "last good poll
		// was N minutes ago, currently failing because X".
		msg := lastErr.Error()
		if len(msg) > 250 {
			msg = msg[:250]
		}
		updates["ntp_last_error"] = msg
	}
	if len(updates) > 0 {
		if err := db.DB.Model(&model.SystemConfig{}).Where("id = 1").Updates(updates).Error; err != nil {
			log.Printf("[ntp] update system_config: %v", err)
		}
	}
}

// queryNTP issues a minimal SNTPv4 request to host:port (port defaults
// to 123 when omitted) and returns the offset between the server's
// clock and the local clock. Positive drift means the local clock is
// ahead of the server.
//
// IPv4 preference: many corporate / CN ISPs advertise AAAA records but
// have no working IPv6 outbound. Naively dialing "udp" lets the kernel
// resolver pick whichever family it likes first — if it picks IPv6 and
// the route is dead, we eat a full timeout per attempt. Instead we
// resolve with the v4-only network first; only if no A record exists
// (rare for NTP services) do we fall back to v6.
func queryNTP(host string, timeout time.Duration) (time.Duration, error) {
	hostPort := normalizeHostPort(host)

	conn, dialErr := dialUDPPreferV4(hostPort, timeout)
	if dialErr != nil {
		return 0, fmt.Errorf("dial %s: %w", host, dialErr)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}

	// SNTPv4 client request: LI=0, VN=4, Mode=3 → 0b00_100_011 = 0x23.
	// Everything else is zeros except the Transmit Timestamp at offset
	// 40, which we use as a nonce/origin to correlate the response.
	req := make([]byte, 48)
	req[0] = 0x23

	originLocal := time.Now()
	originNTP := toNTPTime(originLocal)
	binary.BigEndian.PutUint32(req[40:], uint32(originNTP>>32))
	binary.BigEndian.PutUint32(req[44:], uint32(originNTP&0xFFFFFFFF))

	if _, err := conn.Write(req); err != nil {
		return 0, fmt.Errorf("write %s: %w", host, err)
	}
	resp := make([]byte, 48)
	if _, err := conn.Read(resp); err != nil {
		return 0, fmt.Errorf("%s timeout: %w", host, err)
	}
	destLocal := time.Now()

	// Parse the four interesting timestamps. We follow the standard
	// SNTPv4 offset formula:
	//   offset = ((T2 - T1) + (T3 - T4)) / 2
	// where T1 = origin (us), T2 = receive (server),
	//       T3 = transmit (server), T4 = destination (us).
	t2 := fromNTPBytes(resp[32:40])
	t3 := fromNTPBytes(resp[40:48])
	if t2.IsZero() || t3.IsZero() {
		return 0, fmt.Errorf("server returned zero timestamp (denied / unsynced?)")
	}
	offset := ((t2.Sub(originLocal)) + (t3.Sub(destLocal))) / 2
	return offset, nil
}

// toNTPTime converts a Go time to the 64-bit NTP timestamp format
// (32-bit seconds since 1900 + 32-bit fractional seconds).
func toNTPTime(t time.Time) uint64 {
	sec := uint64(t.Unix() + ntpEpochOffsetSec)
	frac := uint64(t.Nanosecond()) * (1 << 32) / 1_000_000_000
	return (sec << 32) | (frac & 0xFFFFFFFF)
}

func fromNTPBytes(b []byte) time.Time {
	if len(b) < 8 {
		return time.Time{}
	}
	sec := binary.BigEndian.Uint32(b[:4])
	frac := binary.BigEndian.Uint32(b[4:])
	if sec == 0 && frac == 0 {
		return time.Time{}
	}
	unixSec := int64(sec) - ntpEpochOffsetSec
	nsec := int64(frac) * 1_000_000_000 >> 32
	return time.Unix(unixSec, nsec)
}

// normalizeHostPort appends :123 when the operator entered a bare
// hostname or IPv4. IPv6 literals must be wrapped in square brackets,
// per RFC 3986; we detect that with a leading '[' rather than counting
// colons (since IPv6 addresses naturally contain colons).
func normalizeHostPort(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") {
		// already bracketed; append default port if missing
		if _, _, err := net.SplitHostPort(host); err != nil {
			return host + ":123"
		}
		return host
	}
	// Bare IPv6 literal? Wrap it.
	if strings.Count(host, ":") >= 2 && net.ParseIP(host) != nil {
		return "[" + host + "]:123"
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return host + ":123"
}

// dialUDPPreferV4 tries IPv4 first, falls back to v6 only if v4
// resolution fails entirely. We avoid the all-or-nothing behaviour of
// net.DialTimeout("udp", ...) which can land on a dead AAAA route.
func dialUDPPreferV4(hostPort string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	if c, err := d.Dial("udp4", hostPort); err == nil {
		return c, nil
	} else if !isNoIPv4Error(err) {
		return nil, err
	}
	return d.Dial("udp6", hostPort)
}

// isNoIPv4Error returns true when the v4 dial failed because the host
// has no A record (only AAAA), as opposed to a network error we should
// surface verbatim. We treat "no such host" + "no suitable address" as
// the v4-missing signal; everything else is a real failure.
func isNoIPv4Error(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "no suitable address") ||
		strings.Contains(s, "no such host") ||
		strings.Contains(s, "address family not supported")
}

func parseServerList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	// Accept comma, semicolon, or newline as separators so operators
	// can paste a wide range of pre-formatted server lists.
	rep := strings.NewReplacer(";", ",", "\n", ",", "\r", ",")
	parts := strings.Split(rep.Replace(raw), ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

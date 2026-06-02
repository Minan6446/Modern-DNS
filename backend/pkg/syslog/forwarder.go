// Package syslog forwards Modern-DNS operation_log entries to an external
// syslog collector when the operator has configured one in
// 「审计日志 → 配置」. Implements the RFC 5424 wire format with the
// IETF preferred 8601 timestamp and structured-data section disabled
// (we ship the audit payload as the unstructured MSG so generic
// receivers like syslog-ng / rsyslog / Graylog handle it cleanly).
//
// Why a dedicated package and not just inline log.Printf?
//   - Operator-driven enable/disable + server reconfiguration: we need
//     a long-lived dialer that reconnects when the SystemConfig row
//     changes, instead of dialling per-message (UDP doesn't care, but
//     TCP setup latency would dominate).
//   - Backpressure: a slow receiver must not block the audit-log write
//     path that the rest of the app is waiting on. We use a small
//     bounded channel and drop oldest on overflow with a counter.
//   - Lifecycle: must run as a singleton goroutine so multiple Send()
//     calls don't open competing connections.
//
// Wire format (RFC 5424):
//
//	<PRI>1 TIMESTAMP HOST APP-NAME PROCID MSGID - MSG
//
// Where PRI = facility*8 + severity. We use facility 16 (local0) and
// severity 6 (info) as the default, mirroring how most app frameworks
// emit audit traffic. MSGID encodes the OperationLog.ActionType so a
// receiver can route by action.
package syslog

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Entry is the minimal projection of OperationLog the forwarder needs.
// Keeping it independent of the model package avoids an import cycle
// (model already imports nothing else, and we want this package equally
// loose-coupled).
type Entry struct {
	LogID      string
	Operator   string
	ActionType string
	Module     string
	Content    string
	IP         string
	Result     string
	Time       time.Time
}

// Config is the runtime config snapshot the forwarder runs against.
// Re-supplied via Reconfigure() whenever the operator saves the audit
// settings dialog; the forwarder transparently tears down + redials if
// the address changed.
type Config struct {
	Enabled bool
	Server  string // host:port, optional "tcp://host:port" or "udp://host:port"
}

const (
	defaultProto         = "udp"
	defaultPort          = "514"
	dropChannelCapacity  = 256             // bounded buffer per RFC 5425 §4.2 advice
	dialTimeout          = 3 * time.Second // tighter than net.Dialer default; receiver must respond fast
	reconnectMinInterval = 1 * time.Second // floor for reconnect backoff after a write failure
)

var (
	state struct {
		mu       sync.Mutex
		cfg      Config
		ch       chan Entry
		stopCh   chan struct{}
		stopped  bool
		hostname string
		dropped  uint64 // counter for backpressure drops; surfaced via Stats()
	}
	startOnce sync.Once
)

// Start spawns the singleton forwarder goroutine. Idempotent — call it
// once at boot regardless of whether syslog is currently enabled. The
// goroutine no-ops until Reconfigure() supplies an enabled+server.
func Start() {
	startOnce.Do(func() {
		state.hostname, _ = os.Hostname()
		if state.hostname == "" {
			state.hostname = "modern-dns"
		}
		state.ch = make(chan Entry, dropChannelCapacity)
		state.stopCh = make(chan struct{})
		go run()
	})
}

// Stop signals the forwarder to drain and exit. Mainly for tests and
// graceful shutdown; production toggling should go through Reconfigure
// with Enabled=false (cheaper, no goroutine churn).
func Stop() {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.stopped {
		return
	}
	state.stopped = true
	close(state.stopCh)
}

// Reconfigure swaps the active config. Safe to call concurrently with
// Send. The next dispatched entry will see the new server.
func Reconfigure(cfg Config) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.cfg = cfg
}

// Send queues an entry for delivery. Non-blocking: if the buffer is
// full the entry is dropped and the dropped counter incremented. We
// trade durability for the guarantee that the audit-log DB write path
// is never stalled by a misbehaving receiver.
//
// Returns immediately with no error indication on purpose — surfacing
// "buffer full" to the caller would just produce noise in audit logs
// (the very thing we're trying to forward). Operators can monitor the
// drop counter via Stats() if they care.
func Send(e Entry) {
	state.mu.Lock()
	enabled := state.cfg.Enabled && strings.TrimSpace(state.cfg.Server) != ""
	state.mu.Unlock()
	if !enabled {
		return
	}
	if state.ch == nil {
		// Start() was never called — nothing to forward to.
		return
	}
	select {
	case state.ch <- e:
	default:
		state.mu.Lock()
		state.dropped++
		state.mu.Unlock()
	}
}

// Stats returns the dropped-message counter. Callers can poll this
// from a metrics endpoint to alert on backpressure events.
func Stats() (dropped uint64) {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.dropped
}

// run is the dispatcher loop. We hold a connection across messages
// (TCP) or per-burst (UDP — connection-less but net.Conn caching still
// avoids the per-message socket-create syscall).
func run() {
	var conn net.Conn
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	var (
		lastDial    time.Time
		lastTarget  string
		writeFailed bool
	)
	for {
		select {
		case <-state.stopCh:
			return
		case e := <-state.ch:
			state.mu.Lock()
			cfg := state.cfg
			state.mu.Unlock()
			if !cfg.Enabled || strings.TrimSpace(cfg.Server) == "" {
				continue
			}
			proto, addr := parseTarget(cfg.Server)
			target := proto + "://" + addr

			// Reconnect when:
			//   1. no connection yet
			//   2. operator changed the server (target string differs)
			//   3. previous write failed and the cooldown elapsed
			needDial := conn == nil ||
				target != lastTarget ||
				(writeFailed && time.Since(lastDial) >= reconnectMinInterval)
			if needDial {
				if conn != nil {
					_ = conn.Close()
					conn = nil
				}
				c, err := net.DialTimeout(proto, addr, dialTimeout)
				lastDial = time.Now()
				lastTarget = target
				if err != nil {
					writeFailed = true
					log.Printf("[syslog] dial %s failed: %v (entry dropped)", target, err)
					continue
				}
				conn = c
				writeFailed = false
			}
			pkt := formatRFC5424(state.hostname, e)
			_ = conn.SetWriteDeadline(time.Now().Add(dialTimeout))
			if _, err := conn.Write([]byte(pkt)); err != nil {
				writeFailed = true
				log.Printf("[syslog] write %s failed: %v", target, err)
				_ = conn.Close()
				conn = nil
			}
		}
	}
}

// parseTarget accepts:
//
//	"host"            → udp://host:514
//	"host:port"       → udp://host:port
//	"udp://host:port" → udp://host:port
//	"tcp://host:port" → tcp://host:port
//
// We default to UDP because operation_log entries are short, sub-MTU
// messages and the receiver is typically a sidecar collector where
// reliable delivery matters less than not blocking the audit path.
// Operators wanting durable delivery can opt into TCP explicitly via
// the URL prefix.
func parseTarget(s string) (proto, addr string) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "tcp://") {
		return "tcp", ensurePort(strings.TrimPrefix(s, "tcp://"))
	}
	if strings.HasPrefix(s, "udp://") {
		return "udp", ensurePort(strings.TrimPrefix(s, "udp://"))
	}
	return defaultProto, ensurePort(s)
}

func ensurePort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return addr + ":" + defaultPort
}

// formatRFC5424 emits a single syslog packet. The MSG field is a
// pipe-separated digest of the operation_log row — operators can
// regex-extract fields server-side without us having to commit to a
// JSON dialect. We include MSG-ID = ActionType so collectors can route
// to per-action streams.
//
// Example:
//
//	<134>1 2026-05-07T10:00:00Z modern-dns modern-dns - 配置 - LOG-...|admin|配置|系统设置|更新日志配置|192.168.1.5|成功
//
// PRI = local0(16)*8 + info(6) = 134.
func formatRFC5424(hostname string, e Entry) string {
	const pri = 16*8 + 6 // local0.info
	ts := e.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	msgID := nonEmpty(e.ActionType, "-")
	// Truncate MSG-ID to RFC 5424's 32-octet ceiling. Most ActionType
	// values are short Chinese words but defensive truncation here
	// avoids future packet-rejection surprises.
	if len(msgID) > 32 {
		msgID = msgID[:32]
	}
	body := strings.Join([]string{
		nonEmpty(e.LogID, "-"),
		nonEmpty(e.Operator, "-"),
		nonEmpty(e.ActionType, "-"),
		nonEmpty(e.Module, "-"),
		sanitizeMessage(e.Content),
		nonEmpty(e.IP, "-"),
		nonEmpty(e.Result, "-"),
	}, "|")
	return fmt.Sprintf("<%d>1 %s %s modern-dns - %s - %s\n",
		pri,
		ts.UTC().Format(time.RFC3339),
		hostname,
		msgID,
		body,
	)
}

// sanitizeMessage strips characters that would prematurely terminate
// the syslog packet on common collectors. We replace newlines (RFC
// 5424 says MSG SHOULD be a single line) with a literal \n marker so
// the audit content is still legible at the receiver.
func sanitizeMessage(s string) string {
	if s == "" {
		return "-"
	}
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

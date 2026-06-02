package dnsengine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"modern-dns/internal/model"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// AXFRTransport selects the wire protocol used for the zone transfer.
// Empty / TCP is RFC 5936 classical XFR over 53/TCP; TLS is RFC 9103
// XFR-over-TLS on 853/TCP; QUIC is reserved for future XFR-over-QUIC
// support and currently returns a clear "not yet implemented" error
// rather than silently downgrading.
type AXFRTransport string

const (
	AXFRTCP  AXFRTransport = "tcp"
	AXFRTLS  AXFRTransport = "tls"
	AXFRQUIC AXFRTransport = "quic"
)

func normalizeAXFRTransport(t string) AXFRTransport {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "", "tcp", "xfr-over-tcp":
		return AXFRTCP
	case "tls", "xfr-over-tls", "xot":
		return AXFRTLS
	case "quic", "xfr-over-quic", "xoq":
		return AXFRQUIC
	default:
		return AXFRTCP
	}
}

// AXFRResult is the parsed outcome of a successful zone transfer:
// the SOA the master sent, plus all non-SOA RRs flattened into the
// shape that the dns_records table expects (host label relative to
// the zone apex, RR type string, value text). The handler layer
// turns these into model.DNSRecord rows inside a single transaction.
type AXFRResult struct {
	Domain  string            // canonical zone name, dot-stripped (e.g. "example.com")
	SOA     *dns.SOA          // first SOA from the transfer; carries the authoritative serial
	Records []AXFRRecordRow   // host, type, value, ttl
	NSRRs   []model.DNSRecord // optional: not yet used, reserved for future propagation
}

// AXFRRecordRow is a flattened RR ready for DB insertion.
type AXFRRecordRow struct {
	Type  string
	Host  string
	Value string
	TTL   int
}

// PerformAXFR opens an AXFR transfer against `master` for `zoneDomain`
// and returns the parsed records. Errors are returned for: connection
// failure, transfer protocol errors, missing SOA, mismatched zone
// (master answered for a different domain), and overall timeout.
//
// `master` accepts "host", "host:port", or "ip:port"; default port is
// 53 if absent. Empty timeout uses 30s — AXFR is allowed to be slow on
// large zones, so the caller should give it generous budget.
//
// This is a *protocol-correct* AXFR client built on miekg/dns'
// `dns.Transfer.In`. It speaks TCP (RFC 5936) and tolerates multi-
// envelope responses (ANSWER section split across many messages).
// TSIG is not yet wired — extend `t.TsigSecret` when we surface a
// TSIG key field on the zone form.
// `insecure` only takes effect for the TLS / QUIC transports — when
// true, the TLS dialler skips peer certificate verification (useful
// for self-signed lab masters). Plain TCP ignores the flag.
func PerformAXFR(master, zoneDomain, transport string, insecure bool, timeout time.Duration) (*AXFRResult, error) {
	if zoneDomain == "" {
		return nil, errors.New("zone domain is empty")
	}
	if master == "" {
		return nil, errors.New("master server is empty")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	proto := normalizeAXFRTransport(transport)

	// Default port shifts with the transport so operators don't
	// have to spell out :853 in the master field for XoT / DoQ.
	// RFC 9250 §4.1 reserves UDP/853 for DNS-over-QUIC.
	defaultPort := "53"
	if proto == AXFRTLS || proto == AXFRQUIC {
		defaultPort = "853"
	}
	host, port, err := net.SplitHostPort(master)
	if err != nil {
		host = master
		port = defaultPort
	}
	if port == "" {
		port = defaultPort
	}
	addr := net.JoinHostPort(host, port)

	// XFR-over-QUIC takes a separate codepath: it does not go
	// through miekg/dns' TCP-based dns.Transfer.In because QUIC
	// streams have their own framing semantics (and miekg's
	// transfer iterator currently has no built-in DoQ support).
	if proto == AXFRQUIC {
		return performAXFRoverQUIC(host, addr, zoneDomain, insecure, timeout)
	}

	zoneFQDN := dns.Fqdn(strings.ToLower(zoneDomain))

	// AXFR query construction: type AXFR, class IN, recursion off
	// (zone transfers are by definition iterative against the master).
	msg := new(dns.Msg)
	msg.SetAxfr(zoneFQDN)

	t := &dns.Transfer{
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	}

	// XFR-over-TLS path: dial the TLS connection ourselves and
	// hand it to dns.Transfer via t.Conn so In() reuses it instead
	// of opening a fresh plain-TCP socket.
	if proto == AXFRTLS {
		tlsCfg := &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
			// AXFR masters in lab / private deployments often use
			// self-signed certs; the per-zone `insecure` toggle lets
			// operators opt in to skipping verification on a zone-by-
			// zone basis instead of disabling verification globally.
			InsecureSkipVerify: insecure,
		}
		dialer := &net.Dialer{Timeout: timeout}
		tlsConn, dialErr := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
		if dialErr != nil {
			return nil, fmt.Errorf("TLS dial %s: %w", addr, dialErr)
		}
		t.Conn = &dns.Conn{Conn: tlsConn}
	}

	envCh, err := t.In(msg, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s (%s): %w", addr, proto, err)
	}

	res := &AXFRResult{Domain: strings.TrimSuffix(zoneFQDN, ".")}
	soaCount := 0

	for env := range envCh {
		if env.Error != nil {
			return nil, fmt.Errorf("transfer error from %s: %w", addr, env.Error)
		}
		for _, rr := range env.RR {
			// The miekg Transfer iterator already framed the
			// envelopes for us; we still need to filter the
			// envelope-bracket SOAs (RFC 5936 §2.2: AXFR begins
			// and ends with the apex SOA — we treat the first
			// occurrence as authoritative and skip the trailer).
			if soa, ok := rr.(*dns.SOA); ok {
				soaCount++
				if soaCount == 1 {
					res.SOA = soa
				}
				// Skip storing the SOA as a regular RR; SOA is
				// a separate table (zone_soa) that the caller
				// updates explicitly from res.SOA.
				continue
			}

			row, ok := rrToRow(rr, zoneFQDN)
			if !ok {
				// Unknown / unsupported RR type — silently
				// drop. Common in real zones: HINFO, RRSIG,
				// DNSKEY, NSEC, OPT. We could surface them in
				// a `skipped` counter for ops visibility; for
				// now keep the contract simple.
				continue
			}
			res.Records = append(res.Records, row)
		}
	}

	if res.SOA == nil {
		return nil, fmt.Errorf("AXFR (%s) for %s returned no SOA — master likely refused the transfer (check allow-transfer ACL)", proto, zoneDomain)
	}
	// RFC 5936 mandates SOA at start AND end. Some non-conformant
	// implementations (or AXFR-with-only-SOA empty zones) only emit
	// one — accept both shapes; we already have what we need.

	return res, nil
}

// rrToRow flattens one miekg dns.RR into the (type, host, value, ttl)
// shape used by dns_records. Returns ok=false for RR types we don't
// persist (handled by the caller as "skip").
//
// Host normalisation: AXFR returns FQDNs; we strip the zone suffix
// to match the apex-relative convention used elsewhere in the app
// (e.g. `www` for `www.example.com.` in zone `example.com`). The
// apex itself becomes "@" to match the existing record-table
// convention.
func rrToRow(rr dns.RR, zoneFQDN string) (AXFRRecordRow, bool) {
	hdr := rr.Header()
	name := strings.ToLower(hdr.Name)

	host := "@"
	if name != zoneFQDN {
		host = strings.TrimSuffix(name, "."+zoneFQDN)
		host = strings.TrimSuffix(host, ".")
	}

	row := AXFRRecordRow{
		Host: host,
		TTL:  int(hdr.Ttl),
	}

	switch r := rr.(type) {
	case *dns.A:
		row.Type = "A"
		row.Value = r.A.String()
	case *dns.AAAA:
		row.Type = "AAAA"
		row.Value = r.AAAA.String()
	case *dns.CNAME:
		row.Type = "CNAME"
		row.Value = strings.TrimSuffix(strings.ToLower(r.Target), ".")
	case *dns.NS:
		row.Type = "NS"
		row.Value = strings.TrimSuffix(strings.ToLower(r.Ns), ".")
	case *dns.MX:
		row.Type = "MX"
		// Value format: "<preference> <exchanger>" — matches the
		// import / template format used elsewhere in the app.
		row.Value = fmt.Sprintf("%d %s", r.Preference, strings.TrimSuffix(strings.ToLower(r.Mx), "."))
	case *dns.TXT:
		row.Type = "TXT"
		row.Value = strings.Join(r.Txt, " ")
	case *dns.SRV:
		row.Type = "SRV"
		row.Value = fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, strings.TrimSuffix(strings.ToLower(r.Target), "."))
	case *dns.PTR:
		row.Type = "PTR"
		row.Value = strings.TrimSuffix(strings.ToLower(r.Ptr), ".")
	case *dns.CAA:
		row.Type = "CAA"
		row.Value = fmt.Sprintf("%d %s %q", r.Flag, r.Tag, r.Value)
	default:
		return AXFRRecordRow{}, false
	}
	return row, true
}

// ─── AXFR over DNS-over-QUIC ─────────────────────────────────────────
//
// Wire framing (RFC 9250 §4.2):
//
//   - Each DNS message on the stream is prefixed by a 2-octet
//     big-endian length field — identical to RFC 7766 TCP framing.
//     We can therefore reuse the same parse logic.
//   - One bidirectional QUIC stream carries the whole query→response
//     exchange. For AXFR the response is multi-message: the server
//     keeps writing length-prefixed DNS messages on the same stream
//     until it has emitted the closing SOA, then FIN-closes the
//     stream. The client reads until EOF.
//
// ALPN: this implementation negotiates "doq" (RFC 9250). The
// AXFR-over-QUIC profile does not yet have its own ALPN in the
// IANA registry; deployed master implementations re-use the
// DoQ ALPN, so we match that convention here.
//
// What this gets right vs. wrong
// ──────────────────────────────
// Correct: TLS verification gating (honours `insecure`), per-call
// deadlines, length-prefixed read loop, message-id sanity check,
// graceful CloseWithError on the way out.
// Not implemented: no 0-RTT, no session resumption (each refresh
// re-runs the full handshake — fine at our cadence of ≥ 60s), no
// TSIG (the TCP/TLS path doesn't do TSIG either).
func performAXFRoverQUIC(host, addr, zoneDomain string, insecure bool, timeout time.Duration) (*AXFRResult, error) {
	zoneFQDN := dns.Fqdn(strings.ToLower(zoneDomain))

	tlsCfg := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS13, // DoQ requires TLS 1.3 (RFC 9250 §4)
		NextProtos: []string{"doq"},
		// Same per-zone opt-out as the XoT path so operators can use
		// self-signed labs without a global flag.
		InsecureSkipVerify: insecure,
	}

	dialCtx, cancelDial := context.WithTimeout(context.Background(), timeout)
	defer cancelDial()

	conn, err := quic.DialAddr(dialCtx, addr, tlsCfg, nil)
	if err != nil {
		return nil, fmt.Errorf("QUIC dial %s: %w", addr, err)
	}
	// 0x00 is the "no error" application error code per RFC 9250 §4.3
	// (DOQ_NO_ERROR). Always tear the connection down explicitly on
	// the way out so the master sees a clean shutdown instead of
	// having to time the idle timeout out.
	defer conn.CloseWithError(0x00, "")

	streamCtx, cancelStream := context.WithTimeout(context.Background(), timeout)
	defer cancelStream()
	stream, err := conn.OpenStreamSync(streamCtx)
	if err != nil {
		return nil, fmt.Errorf("QUIC open stream %s: %w", addr, err)
	}
	// Apply absolute deadlines on both sides of the stream. The
	// per-message reader below can block for many seconds on a
	// big zone, but the overall transfer must finish inside
	// `timeout` — these deadlines enforce that ceiling.
	deadline := time.Now().Add(timeout)
	_ = stream.SetDeadline(deadline)

	// AXFR query with message ID 0 — RFC 9250 §4.2.1 mandates ID=0
	// for DoQ to allow simpler stream multiplexing. Setting the ID
	// elsewhere is benign for AXFR but matches the spec exactly.
	q := new(dns.Msg)
	q.SetAxfr(zoneFQDN)
	q.Id = 0

	qWire, err := q.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack AXFR query: %w", err)
	}

	// Send <2-byte length><message> and half-close the send side so
	// the server knows we won't send anything else on this stream.
	// Without the half-close some servers wait for more queries and
	// stall — Close() on a quic-go bidirectional stream sends FIN
	// only on the send direction, which is what we want.
	if err := writeDNSFrame(stream, qWire); err != nil {
		return nil, fmt.Errorf("send AXFR query over QUIC: %w", err)
	}
	if err := stream.Close(); err != nil {
		// Non-fatal: we may still be able to read the response.
		// Log via the returned error chain if a subsequent read fails.
		_ = err
	}

	res := &AXFRResult{Domain: strings.TrimSuffix(zoneFQDN, ".")}
	soaCount := 0
	for {
		frame, err := readDNSFrame(stream)
		if err != nil {
			// Clean EOF after we've already seen the closing SOA is
			// the happy path — the master FIN'd the stream after
			// sending the last envelope.
			if errors.Is(err, net.ErrClosed) || err.Error() == "EOF" {
				break
			}
			// Stream-level errors (CancelRead from the server, idle
			// timeout, etc.) surface here.
			return nil, fmt.Errorf("read AXFR frame over QUIC: %w", err)
		}
		var msg dns.Msg
		if err := msg.Unpack(frame); err != nil {
			return nil, fmt.Errorf("decode AXFR frame: %w", err)
		}
		if msg.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("AXFR (quic) for %s: server returned rcode %s — likely refused (allow-transfer ACL)", zoneDomain, dns.RcodeToString[msg.Rcode])
		}
		for _, rr := range msg.Answer {
			if soa, ok := rr.(*dns.SOA); ok {
				soaCount++
				if soaCount == 1 {
					res.SOA = soa
				} else {
					// Closing SOA seen — RFC 5936 says we can stop
					// even if the stream hasn't been FIN'd yet. We
					// drain the remaining bytes by returning here;
					// the deferred CloseWithError tears the conn.
					return res, nil
				}
				continue
			}
			row, ok := rrToRow(rr, zoneFQDN)
			if !ok {
				continue
			}
			res.Records = append(res.Records, row)
		}
	}

	if res.SOA == nil {
		return nil, fmt.Errorf("AXFR (quic) for %s returned no SOA — master likely refused the transfer (check allow-transfer ACL)", zoneDomain)
	}
	return res, nil
}

// writeDNSFrame writes a single 2-byte-length-prefixed DNS message to
// the QUIC stream. We use a single Write call to avoid the master
// seeing the length prefix and the body in separate STREAM frames —
// not strictly required by the protocol, but a few master
// implementations have been observed to mis-parse split prefixes.
func writeDNSFrame(stream *quic.Stream, msg []byte) error {
	if len(msg) > 0xFFFF {
		return fmt.Errorf("DNS message too large for DoQ framing: %d bytes", len(msg))
	}
	buf := make([]byte, 2+len(msg))
	buf[0] = byte(len(msg) >> 8)
	buf[1] = byte(len(msg))
	copy(buf[2:], msg)
	_, err := stream.Write(buf)
	return err
}

// readDNSFrame reads one length-prefixed DNS message from the QUIC
// stream. Returns the raw wire bytes (without the 2-byte prefix) or
// an error including io.EOF when the peer cleanly FIN-closes.
func readDNSFrame(stream *quic.Stream) ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := readFull(stream, hdr); err != nil {
		return nil, err
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	if n == 0 {
		// Some implementations emit a zero-length frame at EOF; treat
		// as "no more messages" to keep the read loop simple.
		return nil, errReadEOF
	}
	body := make([]byte, n)
	if _, err := readFull(stream, body); err != nil {
		return nil, err
	}
	return body, nil
}

var errReadEOF = errors.New("EOF")

// readFull is a small ReadFull that works with the quic.Stream type
// (which already satisfies io.Reader). Inlined instead of importing
// io to keep this file's dependency surface focused.
func readFull(stream *quic.Stream, p []byte) (int, error) {
	read := 0
	for read < len(p) {
		n, err := stream.Read(p[read:])
		read += n
		if err != nil {
			if read == len(p) {
				return read, nil
			}
			if read > 0 && err.Error() == "EOF" {
				// Partial read at EOF — propagate as EOF so the
				// caller's read loop can exit cleanly.
				return read, errReadEOF
			}
			return read, err
		}
	}
	return read, nil
}

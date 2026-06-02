// proto_clients.go houses the per-protocol query implementations the
// forwarder dispatches through. UDP and TCP delegate to miekg/dns;
// DoT reuses the same client with a TLS-enabled Net; DoH speaks
// RFC 8484 directly over net/http.
//
// All four entry points share the signature
//
//	queryXxx(msg *dns.Msg, host string, timeout time.Duration) (*dns.Msg, error)
//
// where `host` is the operator-supplied upstream string (typically a
// bare IP, IP:port, or hostname). Each client applies its own port
// default so the operator can reuse the same upstream list across all
// four transports without rewriting it for every protocol.
//
// Per-protocol port defaults match the IANA assignments:
//
//	UDP / TCP : 53
//	DoT       : 853
//	DoH       : 443  (path = /dns-query unless overridden via https:// URL)
package dnsengine

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// contextWithTimeout wraps context.WithTimeout but returns a no-op
// cancel for the (rare) "no deadline" path so callers can defer the
// cancel unconditionally without the linter shouting about it.
func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return context.Background(), func() {}
	}
	return context.WithTimeout(context.Background(), d)
}

// dohClient is the package-wide HTTP client used by every DoH query.
// We hold a single Transport with HTTP/2 + connection pooling so a
// busy forwarder doesn't pay the TLS-handshake cost on every query.
//
// Tunables (the defaults are sized for a small Modern-DNS deployment;
// operators with > 1k qps DoH should bump them upward):
//
//   - MaxIdleConnsPerHost = 32  : keeps enough warm conns to a single
//     upstream so HoL blocking is rare
//   - IdleConnTimeout     = 90s : long enough to amortise handshakes
//     across query bursts, short enough
//     to release sockets when the upstream
//     list changes
//   - ForceAttemptHTTP2   = true: nearly every public DoH provider
//     wants /2; saves us from re-doing
//     the multiplexing logic ourselves
//
// We deliberately do NOT set Timeout on the Client itself; per-query
// timeouts come from the forwarder's UpstreamTimeoutMs and are
// applied via context.WithTimeout in queryDoH.
var (
	dohClientOnce sync.Once
	dohClient     *http.Client
)

func getDoHClient() *http.Client {
	dohClientOnce.Do(func() {
		tr := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   3 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          128,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   3 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
		}
		dohClient = &http.Client{Transport: tr}
	})
	return dohClient
}

// padOutbound appends an EDNS0 Padding option to a query message that
// is about to be sent over an encrypted channel (DoT / DoH). RFC 8467
// recommends padding to a multiple of 128 bytes — we honour
// SystemConfig.DnsPaddingBlock when SystemConfig.DnsPaddingEnabled is
// on. Plain UDP/TCP queries skip this because padding wouldn't
// improve confidentiality on cleartext transports and would just waste
// bandwidth.
//
// We clone the message before mutating to avoid corrupting the caller's
// view (the same *dns.Msg is reused across protocols when the operator
// configures "udp,tcp,dot,doh"). For DoH/DoT failure paths the cloned
// padding bytes are discarded with the message itself.
func padOutbound(msg *dns.Msg) *dns.Msg {
	if msg == nil {
		return msg
	}
	pol := loadResponsePolicy()
	if !pol.paddingEnable || pol.paddingBlock == 0 {
		return msg
	}
	out := msg.Copy()
	opt := out.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096}}
		out.Extra = append(out.Extra, opt)
	}
	// Drop any pre-existing padding so re-padding stays idempotent
	// (an operator chaining padding into both inbound and outbound
	// paths shouldn't accumulate redundant Padding options).
	filtered := opt.Option[:0]
	for _, o := range opt.Option {
		if _, isPad := o.(*dns.EDNS0_PADDING); !isPad {
			filtered = append(filtered, o)
		}
	}
	opt.Option = filtered

	wire, err := out.Pack()
	if err != nil {
		return msg
	}
	const optionOverhead = 4
	current := len(wire) + optionOverhead
	block := int(pol.paddingBlock)
	target := ((current + block - 1) / block) * block
	padBytes := target - current
	if padBytes < 0 {
		padBytes = 0
	}
	opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, padBytes)})
	paddingOutboundMetric.Add(1)
	return out
}

// queryUDP is the existing forwarder behaviour, factored out so the
// dispatch table in forwarder.go can address it by name. Truncation
// fallback to TCP is preserved (RFC 1035 §4.2.1 contract).
func queryUDP(msg *dns.Msg, host string, timeout time.Duration) (*dns.Msg, error) {
	addr := ensurePort(host, "53")
	c := &dns.Client{Net: "udp", Timeout: timeout}
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.Truncated {
		return queryTCP(msg, host, timeout)
	}
	return resp, nil
}

// queryTCP forces TCP regardless of message size. Used either when the
// operator's protocol order explicitly lists tcp, or as the implicit
// fallback for a truncated UDP response.
func queryTCP(msg *dns.Msg, host string, timeout time.Duration) (*dns.Msg, error) {
	addr := ensurePort(host, "53")
	c := &dns.Client{Net: "tcp", Timeout: timeout}
	resp, _, err := c.Exchange(msg, addr)
	return resp, err
}

// queryDoT speaks DNS-over-TLS (RFC 7858). We rely on miekg's "tcp-tls"
// Net token for the TLS handshake; ServerName is derived from the
// operator-supplied host so cert validation works for proper hostname
// upstreams (cloudflare-dns.com, dns.google) and falls back to the
// IP literal for IP-only configurations (where validation will fail
// unless InsecureSkipVerify is on — we never set it; operators who
// genuinely need to point at an IP should configure a hostname-aware
// proxy).
//
// Outbound padding is applied here (not by the caller) so the same
// padOutbound() guard runs for both DoT and DoH without each caller
// remembering to do it.
func queryDoT(msg *dns.Msg, host string, timeout time.Duration) (*dns.Msg, error) {
	msg = padOutbound(msg)
	addr := ensurePort(host, "853")
	serverName, _, _ := net.SplitHostPort(addr)
	c := &dns.Client{
		Net:     "tcp-tls",
		Timeout: timeout,
		TLSConfig: &tls.Config{
			ServerName: serverName,
		},
	}
	resp, _, err := c.Exchange(msg, addr)
	return resp, err
}

// queryDoH speaks RFC 8484 (DNS-over-HTTPS) using POST and the
// `application/dns-message` media type. We POST rather than GET
// because POST avoids URL-length limits on long DNSSEC-laden queries
// and skips the base64url encoding overhead.
//
// The host string can be either:
//
//	"https://dns.google/dns-query"           — explicit URL, used as-is
//	"dns.google"                             — default to https://dns.google/dns-query
//	"1.1.1.1" / "1.1.1.1:443"                — default to https://<host>/dns-query
//
// We hold a single *http.Client per process (see getDoHClient) so the
// HTTP/2 connection pool + idle-conn cache survive across queries.
// Each call applies its own deadline via context.WithTimeout instead
// of mutating Client.Timeout (which would race across concurrent
// callers).
func queryDoH(msg *dns.Msg, host string, timeout time.Duration) (*dns.Msg, error) {
	msg = padOutbound(msg)
	endpoint := dohURL(host)
	wire, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}

	// Per-query deadline lives on the request context so the shared
	// http.Client keeps its idle-connection pool across calls. (Setting
	// Client.Timeout would limit *every* request through this client to
	// the most recent caller's budget.)
	ctx, cancel := contextWithTimeout(timeout)
	defer cancel()

	preferGET := loadUpstreamPolicy().dohPreferGET

	// Method preference order:
	//   - GET first when the operator pinned doh_prefer_get (typical
	//     for restrictive corporate networks)
	//   - POST first otherwise; on 4xx (most commonly 405 Method Not
	//     Allowed or 415 Unsupported Media Type — both indicate a
	//     proxy stripped the body) we transparently retry as GET.
	// 5xx and network errors do *not* fall back: those signal an
	// upstream / network problem the next forwarder iteration will
	// route around via its protocol order, not a method-incompatible
	// proxy.
	if preferGET {
		if out, err := doDoHGet(ctx, endpoint, wire); err == nil {
			return out, nil
		} else if !isMethodIncompatible(err) {
			return nil, err
		}
		// Pinned GET failed with a "method incompatible" hint —
		// fall through to POST as a final attempt.
	}

	out, postErr := doDoHPost(ctx, endpoint, wire)
	if postErr == nil {
		return out, nil
	}
	if !isMethodIncompatible(postErr) {
		return nil, postErr
	}
	// POST failed in a way that looks like a method-restriction (proxy
	// stripped body, 4xx). Try GET once before bubbling the error up.
	out, getErr := doDoHGet(ctx, endpoint, wire)
	if getErr == nil {
		return out, nil
	}
	// Surface the original POST error (more diagnostic) plus the GET
	// retry's verdict so operators can see both paths failed.
	return nil, fmt.Errorf("doh %s: POST: %v; GET retry: %v", endpoint, postErr, getErr)
}

// doDoHPost issues a POST application/dns-message request. Body is
// the raw wire-format DNS message.
func doDoHPost(ctx context.Context, endpoint string, wire []byte) (*dns.Msg, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	return doDoHRequest(req, endpoint)
}

// doDoHGet issues a GET request with `?dns=<base64url>` per RFC 8484
// §4.1.1. We use raw URL encoding (no padding) because spec-compliant
// resolvers expect the "base64url-no-padding" variant.
func doDoHGet(ctx context.Context, endpoint string, wire []byte) (*dns.Msg, error) {
	q := base64.RawURLEncoding.EncodeToString(wire)
	sep := "?"
	if strings.Contains(endpoint, "?") {
		sep = "&"
	}
	urlWithQuery := endpoint + sep + "dns=" + q
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlWithQuery, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	return doDoHRequest(req, endpoint)
}

func doDoHRequest(req *http.Request, endpoint string) (*dns.Msg, error) {
	hresp, err := getDoHClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh %s: HTTP %d", endpoint, hresp.StatusCode)
	}
	body, err := io.ReadAll(hresp.Body)
	if err != nil {
		return nil, err
	}
	out := &dns.Msg{}
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}
	return out, nil
}

// isMethodIncompatible heuristically detects errors that suggest the
// HTTP method (POST vs GET) was the problem rather than the upstream
// resolver itself. We trigger the cross-method fallback for HTTP
// status 4xx (especially 405/415/400) — those are the codes a method-
// restrictive proxy returns. Network errors (timeout, EOF, connection
// reset) are *not* method-related and shouldn't trigger fallback.
func isMethodIncompatible(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, marker := range []string{"HTTP 400", "HTTP 403", "HTTP 405", "HTTP 414", "HTTP 415"} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// dohURL canonicalises the operator-supplied host into a full DoH
// endpoint. Explicit https:// URLs are passed through (so operators
// can point at a non-standard path like /resolve), bare hostnames /
// IPs default to /dns-query on port 443.
func dohURL(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "https://") {
		return host
	}
	// If the operator typed a host:port, use it literally; otherwise
	// add :443 for DoH's default. We then attach the well-known path.
	if u, err := url.Parse("https://" + host); err == nil && u.Host != "" {
		if u.Port() == "" {
			u.Host = u.Host + ":443"
		}
		u.Path = "/dns-query"
		return u.String()
	}
	return "https://" + ensurePort(host, "443") + "/dns-query"
}

// ensurePort appends :defaultPort when the supplied address has no
// port. Bare IPv6 literals are wrapped in brackets so SplitHostPort
// agrees that the result is well-formed.
func ensurePort(host, defaultPort string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ":" + defaultPort
	}
	// Strip any scheme prefix the operator might have left behind so
	// downstream parsing sees a clean host[:port].
	host = strings.TrimPrefix(host, "udp://")
	host = strings.TrimPrefix(host, "tcp://")
	host = strings.TrimPrefix(host, "tls://")
	if strings.HasPrefix(host, "[") {
		if _, _, err := net.SplitHostPort(host); err == nil {
			return host
		}
		return host + ":" + defaultPort
	}
	if strings.Count(host, ":") >= 2 && net.ParseIP(host) != nil {
		// Bare IPv6 literal — wrap before adding the port.
		return "[" + host + "]:" + defaultPort
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return host + ":" + defaultPort
}

// dispatchProto routes a query to the right per-protocol implementation.
// Defined here (next to the implementations) so adding a new protocol
// is a single-file edit.
func dispatchProto(p protocol, msg *dns.Msg, host string, timeout time.Duration) (*dns.Msg, error) {
	switch p {
	case protoUDP:
		return queryUDP(msg, host, timeout)
	case protoTCP:
		return queryTCP(msg, host, timeout)
	case protoDoT:
		return queryDoT(msg, host, timeout)
	case protoDoH:
		return queryDoH(msg, host, timeout)
	}
	return nil, fmt.Errorf("unknown protocol: %s", p)
}

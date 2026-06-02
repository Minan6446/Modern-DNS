package dnsengine

import (
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

// handleDoH implements RFC 8484 DNS-over-HTTPS.
// Supported methods:
//   - GET  /dns-query?dns=<base64url-encoded wire-format>
//   - POST /dns-query  with Content-Type: application/dns-message body
func (e *Engine) handleDoH(w http.ResponseWriter, r *http.Request) {
	var wireReq []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		param := r.URL.Query().Get("dns")
		if param == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		wireReq, err = base64.RawURLEncoding.DecodeString(param)
		if err != nil {
			http.Error(w, "invalid base64url", http.StatusBadRequest)
			return
		}

	case http.MethodPost:
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/dns-message") {
			http.Error(w, "unsupported content-type", http.StatusUnsupportedMediaType)
			return
		}
		wireReq, err = io.ReadAll(io.LimitReader(r.Body, 65535))
		if err != nil {
			http.Error(w, "read body failed", http.StatusBadRequest)
			return
		}

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the wire-format DNS request
	dnsReq := new(dns.Msg)
	if err := dnsReq.Unpack(wireReq); err != nil {
		http.Error(w, "unpack dns msg failed", http.StatusBadRequest)
		return
	}

	// Build a synthetic ResponseWriter that captures the reply.
	dw := &dohWriter{
		remoteAddr: addrFromHTTPRequest(r),
	}

	e.serveDNS(dw, dnsReq)

	if dw.msg == nil {
		http.Error(w, "no response", http.StatusInternalServerError)
		return
	}

	wireResp, err := dw.msg.Pack()
	if err != nil {
		http.Error(w, "pack dns response failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	w.Write(wireResp)
}

// dohWriter implements dns.ResponseWriter so we can reuse serveDNS directly.
type dohWriter struct {
	msg        *dns.Msg
	remoteAddr net.Addr
}

func (d *dohWriter) LocalAddr() net.Addr         { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443} }
func (d *dohWriter) RemoteAddr() net.Addr        { return d.remoteAddr }
func (d *dohWriter) WriteMsg(msg *dns.Msg) error { d.msg = msg; return nil }
func (d *dohWriter) Write(b []byte) (int, error) { return len(b), nil }
func (d *dohWriter) Close() error                { return nil }
func (d *dohWriter) TsigStatus() error           { return nil }
func (d *dohWriter) TsigTimersOnly(b bool)       {}
func (d *dohWriter) Hijack()                     {}

// addrFromHTTPRequest extracts the remote address from an HTTP request.
func addrFromHTTPRequest(r *http.Request) net.Addr {
	host, portStr, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
		portStr = "0"
	}
	ip := net.ParseIP(host)
	port := 0
	if p, err2 := net.LookupPort("tcp", portStr); err2 == nil {
		port = p
	}
	if ip == nil {
		log.Printf("[doh] cannot parse remote IP from %s", r.RemoteAddr)
		ip = net.IPv4(127, 0, 0, 1)
	}
	return &net.TCPAddr{IP: ip, Port: port}
}

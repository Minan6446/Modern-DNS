package dnsengine

import (
	"net"
	"strconv"
	"time"

	"github.com/miekg/dns"
)

// ProbeUpstream sends a single canary DNS query to the given host using
// the configured protocol/port and reports the wall-clock latency. It is
// the public counterpart of the internal LB probe (probeOne) and is used
// by the global-forward health-check HTTP handler so the UI shows real
// per-protocol reachability instead of a UDP-only port-53 hack.
//
// Behaviour matches probeOne:
//
//   - Query is "." NS with RD=1 + EDNS0/4096 — the most cache-friendly
//     canary that public recursive resolvers will actually answer (the
//     historic "<random>.invalid" + RD=0 probe was silently dropped by
//     119.6.6.6 / 223.5.5.5 / 8.8.8.8 etc. and made every upstream look
//     dead).
//   - Any non-error response counts as "alive" — we measure DNS
//     reachability, not resolver correctness.
//   - The timeout is wall-clock end-to-end so callers can cap total
//     fan-out time deterministically.
//
// Returns the latency the call took regardless of err, so callers can
// surface "timed out after 2.0s" UX hints. ok==true iff err==nil.
func ProbeUpstream(host string, port int, protocol string, timeout time.Duration) (latencyMs int64, ok bool, err error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if port > 0 {
		host = net.JoinHostPort(host, strconv.Itoa(port))
	}

	msg := new(dns.Msg)
	msg.SetQuestion(lbProbeQuery, dns.TypeNS)
	msg.RecursionDesired = true
	msg.SetEdns0(4096, false)

	start := time.Now()
	_, err = dispatchProto(resolveProbeProto(protocol), msg, host, timeout)
	latencyMs = time.Since(start).Milliseconds()
	ok = err == nil
	return latencyMs, ok, err
}

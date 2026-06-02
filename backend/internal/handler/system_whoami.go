package handler

// GET /api/system/whoami — return the calling client's IP.
//
// Used by the UI's ACL editors to seed a rule with "my own IP" so the
// operator doesn't have to look it up out-of-band. The value is
// returned exactly as gin's ClientIP() resolves it, which respects the
// TrustedProxies allowlist configured in router setup — meaning a
// spoofed X-Forwarded-For from an untrusted upstream can never poison
// this endpoint (it falls back to the raw socket address).
//
// We deliberately do NOT include extra context (User-Agent, geoip,
// reverse-DNS) here:
//   - The endpoint is meant to be cheap and trivially correct.
//   - The caller already has their UA from the browser side.
//   - Reverse-DNS is unreliable enough that surfacing it would
//     mislead operators on flaky networks.

import (
	"modern-dns/pkg/resp"

	"github.com/gin-gonic/gin"
)

func Whoami(c *gin.Context) {
	resp.OK(c, gin.H{"ip": c.ClientIP()})
}

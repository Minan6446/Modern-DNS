package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Client posts JSON to peer cluster nodes with the cluster API token.
//
// `insecureSkipVerify=true` mirrors the spec's ignoreCertificateErrors knob —
// useful when peers are running self-signed certs in lab environments.
type Client struct {
	http               *http.Client
	insecureSkipVerify bool
}

// NewClient returns a Client with sensible production defaults: 8 second
// timeout, HTTP/1.1 keepalives, optional TLS verification bypass.
//
// The transport installs a per-host DialTLSContext that consults the cluster
// pin store: if a fingerprint is recorded for the target host, only a peer
// presenting that exact certificate is allowed; otherwise it falls back to
// either system-trust verification or insecure-skip-verify per the flag.
func NewClient(timeout time.Duration, insecureSkipVerify bool) *Client {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	baseTLS := &tls.Config{InsecureSkipVerify: insecureSkipVerify}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		TLSClientConfig:     baseTLS,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConnsPerHost: 4,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			rawConn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			cfg := withPinTLSConfig(baseTLS, addr)
			if cfg.ServerName == "" {
				host, _, _ := net.SplitHostPort(addr)
				cfg.ServerName = host
			}
			tlsConn := tls.Client(rawConn, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
	return &Client{
		http:               &http.Client{Timeout: timeout, Transport: tr},
		insecureSkipVerify: insecureSkipVerify,
	}
}

// Post serializes payload as JSON, attaches the cluster token header, and
// returns the decoded response or an error. The response struct must be a
// pointer or nil (to discard).
func (c *Client) Post(targetURL, token string, payload, into interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderClusterToken, token)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("post %s: %w", targetURL, err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("post %s: status=%d body=%s", targetURL, resp.StatusCode, truncate(string(rawBody), 200))
	}
	if into == nil {
		return nil
	}
	if err := json.Unmarshal(rawBody, into); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// Get is the read-only counterpart used for /state pulls.
func (c *Client) Get(targetURL, token string, into interface{}) error {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set(HeaderClusterToken, token)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("get %s: %w", targetURL, err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("get %s: status=%d body=%s", targetURL, resp.StatusCode, truncate(string(rawBody), 200))
	}
	if into == nil {
		return nil
	}
	return json.Unmarshal(rawBody, into)
}

// JoinURL appends path to base, ensuring exactly one slash between them and
// stripping trailing slashes from base for stability.
func JoinURL(base, path string) string {
	base = strings.TrimRight(base, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}

package cluster

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"strings"
	"time"
)

// SecondaryClient runs the spec's _heartbeatTimer + auto-join behaviour.
//
// On Start(), it:
//  1. POSTs to the primary's /api/cluster/internal/join (registers itself /
//     refreshes credentials).
//  2. Loops every HeartbeatInterval, POSTing /heartbeat with current resource
//     usage; on failure marks itself Unreachable and retries with backoff.
//
// Designed to run in a goroutine for the lifetime of the secondary process.
type SecondaryClient struct {
	PrimaryURL        string
	APIToken          string
	NodeID            string
	NodeName          string
	NodeURL           string
	IPAddresses       []string
	Zone              string
	Version           string
	HeartbeatInterval time.Duration
	IgnoreCertErrors  bool
	OwnCertPEM        string // PEM-encoded; sent on join so primary can pin us

	cli      *Client
	stopCh   chan struct{}
	doneCh   chan struct{}
	provided bool
}

// NewSecondary builds a client; either supply a NodeID (for re-join) or leave
// blank to have one generated.
func NewSecondary(primaryURL, token, nodeName, nodeURL string, ips []string, opts ...func(*SecondaryClient)) *SecondaryClient {
	sc := &SecondaryClient{
		PrimaryURL:        strings.TrimRight(primaryURL, "/"),
		APIToken:          strings.TrimSpace(token),
		NodeID:            randomNodeID(),
		NodeName:          nodeName,
		NodeURL:           nodeURL,
		IPAddresses:       ips,
		HeartbeatInterval: 5 * time.Second,
		stopCh:            make(chan struct{}),
		doneCh:            make(chan struct{}),
	}
	for _, opt := range opts {
		opt(sc)
	}
	sc.cli = NewClient(0, sc.IgnoreCertErrors)
	sc.provided = true
	return sc
}

// Start runs the secondary loop in the current goroutine. Blocks until Stop
// is called or the process exits.
func (s *SecondaryClient) Start() {
	defer close(s.doneCh)

	if err := s.join(); err != nil {
		log.Printf("[cluster-secondary] initial join failed: %v (will retry on heartbeat)", err)
	} else {
		log.Printf("[cluster-secondary] joined primary at %s as %s", s.PrimaryURL, s.NodeID)
	}

	ticker := time.NewTicker(s.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			s.leave()
			return
		case <-ticker.C:
			if err := s.heartbeat(); err != nil {
				log.Printf("[cluster-secondary] heartbeat failed: %v", err)
				// Try to (re-)join lazily so transient primary outages recover.
				_ = s.join()
			}
		}
	}
}

// Stop signals the loop to exit and waits for it to finish.
func (s *SecondaryClient) Stop() {
	close(s.stopCh)
	<-s.doneCh
}

func (s *SecondaryClient) join() error {
	// Trust-on-first-use: if no pin is recorded for the primary yet, fetch
	// its certificate and save the fingerprint so subsequent calls can verify
	// it even when IgnoreCertErrors is false.
	if host := extractHost(s.PrimaryURL); host != "" && GetPin(host) == "" {
		if fp, err := fetchServerFingerprint(host); err == nil {
			SetPin(host, fp)
		}
	}

	payload := map[string]interface{}{
		"secondaryNodeId":          s.NodeID,
		"secondaryName":            s.NodeName,
		"secondaryNodeUrl":         s.NodeURL,
		"secondaryNodeIpAddresses": s.IPAddresses,
		"secondaryNodeCertificate": s.OwnCertPEM,
		"zone":                     s.Zone,
		"version":                  s.Version,
	}
	return s.cli.Post(s.PrimaryURL+"/api/cluster/internal/join", s.APIToken, payload, nil)
}

func (s *SecondaryClient) leave() {
	payload := map[string]interface{}{"nodeId": s.NodeID}
	if err := s.cli.Post(s.PrimaryURL+"/api/cluster/internal/leave", s.APIToken, payload, nil); err != nil {
		log.Printf("[cluster-secondary] leave failed: %v", err)
	}
}

func (s *SecondaryClient) heartbeat() error {
	payload := map[string]interface{}{
		"nodeId":  s.NodeID,
		"version": s.Version,
	}
	return s.cli.Post(s.PrimaryURL+"/api/cluster/internal/heartbeat", s.APIToken, payload, nil)
}

func randomNodeID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

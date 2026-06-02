package cluster

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"sync"
)

// readFileSafe is a tiny wrapper used by LoadOwnCertPEM. Centralized so test
// code can stub the file system if needed.
func readFileSafe(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// Fingerprint returns the SHA-256 hex digest of a leaf certificate's DER bytes.
// This is the canonical "spki/cert pin" we ship between primary and secondary.
func Fingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// FingerprintPEM accepts a PEM-encoded certificate (the format we store on
// cluster_nodes.certificate) and returns its SHA-256 hex digest.
func FingerprintPEM(pemData string) string {
	pemData = strings.TrimSpace(pemData)
	if pemData == "" {
		return ""
	}
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return Fingerprint(cert)
}

// LoadOwnCertPEM reads the on-disk cluster cert and returns it as PEM.
// Used by secondaries to advertise their own cert during join.
func LoadOwnCertPEM(certPath string) (string, error) {
	if certPath == "" {
		return "", nil
	}
	data, err := readFileSafe(certPath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// pinStore holds peer certificate pins keyed by host (host:port). It powers
// the verifyPeerCertificate hook used by the cluster HTTP client.
type pinStore struct {
	mu   sync.RWMutex
	pins map[string]string // "host:port" → SHA-256 hex
}

var defaultPinStore = &pinStore{pins: make(map[string]string)}

// SetPin records the expected fingerprint for a remote peer. Empty fp clears
// any existing pin for that host. Host format must match the URL host (with
// port), e.g. "10.0.0.10:8443".
func SetPin(host, fp string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return
	}
	defaultPinStore.mu.Lock()
	defer defaultPinStore.mu.Unlock()
	if fp == "" {
		delete(defaultPinStore.pins, host)
		return
	}
	defaultPinStore.pins[strings.ToLower(host)] = strings.ToLower(strings.TrimSpace(fp))
}

// GetPin returns the recorded fingerprint for the host, or empty string when
// no pin is configured.
func GetPin(host string) string {
	defaultPinStore.mu.RLock()
	defer defaultPinStore.mu.RUnlock()
	return defaultPinStore.pins[strings.ToLower(strings.TrimSpace(host))]
}

// verifyPin returns a tls.Config VerifyPeerCertificate callback that succeeds
// only when the peer's leaf cert matches the pinned fingerprint (when one is
// recorded for the host being dialed). When no pin is set, it falls back to
// the default behaviour (allow if InsecureSkipVerify is true, otherwise
// validate against the system trust store as usual).
func verifyPin(host string) func([][]byte, [][]*x509.Certificate) error {
	expected := GetPin(host)
	if expected == "" {
		return nil
	}
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no peer certificate presented")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		actual := Fingerprint(cert)
		if !strings.EqualFold(actual, expected) {
			return errors.New("certificate fingerprint mismatch (expected " + expected + ", got " + actual + ")")
		}
		return nil
	}
}

// fetchServerFingerprint opens a TLS connection to host:port WITHOUT any
// pin/verify, captures the leaf certificate, and returns its SHA-256 hex
// digest. Used by secondaries during their first join (TOFU pinning).
func fetchServerFingerprint(addr string) (string, error) {
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("no peer certificates")
	}
	return Fingerprint(state.PeerCertificates[0]), nil
}

// withPinTLSConfig clones the supplied TLS config and installs a per-host pin
// callback. Used by the cluster Client when dialing peers.
func withPinTLSConfig(base *tls.Config, host string) *tls.Config {
	cfg := base.Clone()
	if cfg == nil {
		cfg = &tls.Config{}
	}
	if cb := verifyPin(host); cb != nil {
		cfg.VerifyPeerCertificate = cb
		// Pinning is the source of truth — we don't need the system trust
		// store to also approve the cert.
		cfg.InsecureSkipVerify = true
	}
	return cfg
}

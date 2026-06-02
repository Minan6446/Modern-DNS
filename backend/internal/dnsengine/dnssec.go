package dnsengine

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ── Key material held in memory per zone ─────────────────────────────────────

type zoneDNSSEC struct {
	KSK []*dnssecKeyPair
	ZSK []*dnssecKeyPair
	// Pre-built DNSKEY RRs so we can answer DNSKEY queries quickly.
	DNSKEYRRs []dns.RR
}

type dnssecKeyPair struct {
	DNSKEY     *dns.DNSKEY
	PrivateKey crypto.PrivateKey
	KeyTag     uint16
}

// ── Key generation (used by the HTTP handler) ────────────────────────────────

// GenerateDNSSECKeyPair creates a real ECDSA-P256-SHA256 DNSKEY for the given
// zone and key type ("KSK" or "ZSK").
// It returns:
//   - dnskeyText   : the full DNSKEY RR in zone-file text form
//   - privateKeyPEM: PEM-encoded ECDSA private key
//   - dsText        : DS record text (only meaningful for KSK)
//   - keyTag        : the computed DNSKEY key tag
//   - err
func GenerateDNSSECKeyPair(zoneName, keyType string) (dnskeyText, privateKeyPEM, dsText string, keyTag uint16, err error) {
	zone := dns.Fqdn(zoneName)

	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}

	if strings.ToUpper(keyType) == "KSK" {
		key.Flags = 257 // Secure Entry Point
	} else {
		key.Flags = 256 // Zone Signing Key
	}

	privKey, err := key.Generate(256) // 256-bit curve
	if err != nil {
		return "", "", "", 0, fmt.Errorf("generate DNSKEY: %w", err)
	}

	keyTag = key.KeyTag()
	dnskeyText = key.String()

	// PEM-encode the private key
	ecKey, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", "", "", 0, fmt.Errorf("unexpected private key type %T", privKey)
	}
	derBytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return "", "", "", 0, fmt.Errorf("marshal private key: %w", err)
	}
	privateKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derBytes,
	}))

	// DS record (SHA-256) — only useful for KSK, but we compute it anyway
	ds := key.ToDS(dns.SHA256)
	if ds != nil {
		dsText = ds.String()
	}

	return dnskeyText, privateKeyPEM, dsText, keyTag, nil
}

// ── Runtime key parsing ──────────────────────────────────────────────────────

// parseDNSKEY parses a stored DNSKEY RR text + PEM private key into a runtime
// key pair. Returns nil on any parse error (logged, not fatal).
func parseDNSKEY(dnskeyText, privateKeyPEM string) *dnssecKeyPair {
	if dnskeyText == "" || privateKeyPEM == "" {
		return nil
	}

	rr, err := dns.NewRR(dnskeyText)
	if err != nil {
		log.Printf("[dnssec] parse DNSKEY RR: %v", err)
		return nil
	}
	dnskey, ok := rr.(*dns.DNSKEY)
	if !ok {
		log.Printf("[dnssec] parsed RR is not DNSKEY")
		return nil
	}

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		log.Printf("[dnssec] decode PEM block failed")
		return nil
	}
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Printf("[dnssec] parse EC private key: %v", err)
		return nil
	}

	return &dnssecKeyPair{
		DNSKEY:     dnskey,
		PrivateKey: privKey,
		KeyTag:     dnskey.KeyTag(),
	}
}

// ── Signing ──────────────────────────────────────────────────────────────────

// signRRSet signs the given RR set with the provided ZSK.
// Returns the RRSIG RR, or nil on error.
func signRRSet(rrset []dns.RR, zone string, zsk *dnssecKeyPair) dns.RR {
	if zsk == nil || len(rrset) == 0 {
		return nil
	}

	now := time.Now().UTC()
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   rrset[0].Header().Name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    rrset[0].Header().Ttl,
		},
		TypeCovered: rrset[0].Header().Rrtype,
		Labels:      uint8(dns.CountLabel(rrset[0].Header().Name)),
		OrigTtl:     rrset[0].Header().Ttl,
		KeyTag:      zsk.KeyTag,
		SignerName:  dns.Fqdn(zone),
		Algorithm:   zsk.DNSKEY.Algorithm,
		Inception:   uint32(now.Add(-1 * time.Hour).Unix()),
		Expiration:  uint32(now.Add(30 * 24 * time.Hour).Unix()),
	}

	if err := sig.Sign(zsk.PrivateKey.(*ecdsa.PrivateKey), rrset); err != nil {
		log.Printf("[dnssec] sign failed: %v", err)
		return nil
	}
	return sig
}

// signDNSKEYSet signs the DNSKEY RRset with the KSK (self-signing).
func signDNSKEYSet(dnskeyRRs []dns.RR, zone string, ksk *dnssecKeyPair) dns.RR {
	if ksk == nil || len(dnskeyRRs) == 0 {
		return nil
	}

	zoneFQDN := dns.Fqdn(zone)
	now := time.Now().UTC()
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   zoneFQDN,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		TypeCovered: dns.TypeDNSKEY,
		Labels:      uint8(dns.CountLabel(zoneFQDN)),
		OrigTtl:     3600,
		KeyTag:      ksk.KeyTag,
		SignerName:  zoneFQDN,
		Algorithm:   ksk.DNSKEY.Algorithm,
		Inception:   uint32(now.Add(-1 * time.Hour).Unix()),
		Expiration:  uint32(now.Add(30 * 24 * time.Hour).Unix()),
	}

	if err := sig.Sign(ksk.PrivateKey.(*ecdsa.PrivateKey), dnskeyRRs); err != nil {
		log.Printf("[dnssec] sign DNSKEY set failed: %v", err)
		return nil
	}
	return sig
}

package acl

import (
	"net"
	"testing"
)

// These tests intentionally mirror frontend/src/utils/aclParser.test.ts
// case-for-case so a drift between the two parsers is loud and fast.
// When you add a case here, add the same case in TS, and vice versa.

func TestParseLine_EmptyAndComment(t *testing.T) {
	for _, in := range []string{"", "   ", "\t"} {
		if got := parseLine(in, 1); got.Kind != KindEmpty {
			t.Fatalf("expected KindEmpty for %q, got %v", in, got.Kind)
		}
	}
	for _, in := range []string{"# office subnet", "// office"} {
		if got := parseLine(in, 1); got.Kind != KindComment {
			t.Fatalf("expected KindComment for %q, got %v", in, got.Kind)
		}
	}
}

func TestParseLine_Macros(t *testing.T) {
	for _, m := range []string{"any", "none", "localhost", "localnets"} {
		got := parseLine(m, 1)
		if got.Kind != KindMacro || got.Error != "" || got.Macro != m {
			t.Fatalf("expected macro %q, got %+v", m, got)
		}
	}
}

func TestParseLine_IPv4(t *testing.T) {
	cases := []struct {
		in   string
		kind Kind
	}{
		{"192.0.2.1", KindIPv4},
		{"10.0.0.255", KindIPv4},
		{"256.0.0.1", KindUnknown}, // out of range -> error
		{"1.2.3", KindUnknown},     // missing octet -> error
	}
	for _, c := range cases {
		got := parseLine(c.in, 1)
		if c.kind == KindUnknown {
			if got.Error == "" {
				t.Fatalf("expected error for %q, got %+v", c.in, got)
			}
			continue
		}
		if got.Kind != c.kind {
			t.Fatalf("expected %v for %q, got %v (err=%q)", c.kind, c.in, got.Kind, got.Error)
		}
	}
}

func TestParseLine_IPv4CIDR(t *testing.T) {
	if got := parseLine("10.0.0.0/8", 1); got.Kind != KindIPv4CIDR {
		t.Fatalf("want ipv4-cidr, got %+v", got)
	}
	if got := parseLine("10.0.0.0/32", 1); got.Kind != KindIPv4CIDR {
		t.Fatalf("want ipv4-cidr /32, got %+v", got)
	}
	if got := parseLine("10.0.0.0/33", 1); got.Error == "" {
		t.Fatalf("expected error for /33, got %+v", got)
	}
}

func TestParseLine_IPv6(t *testing.T) {
	if got := parseLine("2001:db8::1", 1); got.Kind != KindIPv6 {
		t.Fatalf("want ipv6, got %+v", got)
	}
	if got := parseLine("::1", 1); got.Kind != KindIPv6 {
		t.Fatalf("want ipv6 ::1, got %+v", got)
	}
	if got := parseLine("2001:::1", 1); got.Error == "" {
		t.Fatalf("expected error for triple-colon, got %+v", got)
	}
}

func TestParseLine_IPv6CIDR(t *testing.T) {
	if got := parseLine("2001:db8::/32", 1); got.Kind != KindIPv6CIDR {
		t.Fatalf("want ipv6-cidr, got %+v", got)
	}
	if got := parseLine("::/0", 1); got.Kind != KindIPv6CIDR {
		t.Fatalf("want ipv6-cidr ::/0, got %+v", got)
	}
	if got := parseLine("2001:db8::/129", 1); got.Error == "" {
		t.Fatalf("expected error for /129, got %+v", got)
	}
}

func TestParseLine_Hostname(t *testing.T) {
	if got := parseLine("host.example.com", 1); got.Kind != KindHostname {
		t.Fatalf("want hostname, got %+v", got)
	}
	if got := parseLine("host.example.com.", 1); got.Kind != KindHostname {
		t.Fatalf("want hostname (trailing dot), got %+v", got)
	}
	// "localhost" is a macro, NOT a hostname — macros take precedence.
	if got := parseLine("localhost", 1); got.Kind != KindMacro {
		t.Fatalf("want macro for localhost, got %+v", got)
	}
	// Single label is rejected (parity with TS: ≥2 labels).
	if got := parseLine("justalabel", 1); got.Error == "" {
		t.Fatalf("expected error for single label, got %+v", got)
	}
}

func TestParseLine_Negation(t *testing.T) {
	got := parseLine("!192.0.2.1", 1)
	if got.Kind != KindIPv4 || !got.Negated || got.Error != "" {
		t.Fatalf("want negated ipv4, got %+v", got)
	}
	bad := parseLine("!", 1)
	if bad.Error == "" {
		t.Fatalf("expected error for lonely '!', got %+v", bad)
	}
}

func TestCompile_MixedSeparators(t *testing.T) {
	m := Compile("10.0.0.1\r\n10.0.0.2\r10.0.0.3\n10.0.0.4")
	valid := 0
	for _, e := range m.Entries() {
		if e.Error == "" && e.Kind != KindEmpty && e.Kind != KindComment {
			valid++
		}
	}
	if valid != 4 {
		t.Fatalf("want 4 valid entries across CRLF/CR/LF, got %d", valid)
	}
}

func TestCompile_ReportsErrorsAndValidCount(t *testing.T) {
	text := "# office\n" +
		"10.0.0.0/8\n" +
		"\n" +
		"192.168.1.0/24\n" +
		"!notanip\n" +
		"host.example.com"
	m := Compile(text)
	valid, errs := 0, 0
	var firstErrLine int
	for _, e := range m.Entries() {
		switch {
		case e.Error != "":
			errs++
			if firstErrLine == 0 {
				firstErrLine = e.LineNumber
			}
		case e.Kind != KindEmpty && e.Kind != KindComment:
			valid++
		}
	}
	if valid != 3 {
		t.Fatalf("want 3 valid entries, got %d", valid)
	}
	if errs != 1 {
		t.Fatalf("want 1 error, got %d", errs)
	}
	if firstErrLine != 5 {
		t.Fatalf("want first error on line 5, got %d", firstErrLine)
	}
}

func TestCompile_Empty(t *testing.T) {
	m := Compile("")
	if !m.Empty() {
		t.Fatalf("expected empty matcher")
	}
	if m.Match(net.ParseIP("10.0.0.1")) {
		t.Fatalf("empty matcher must default-deny")
	}
}

// ──────────────────────────────────────────────────────────────────────
// Matcher semantics — the part the TS suite doesn't cover because the
// frontend only validates, never matches. These pin the BIND-style
// "first match wins, default deny" contract the engine relies on.
// ──────────────────────────────────────────────────────────────────────

func TestMatch_FirstMatchWins(t *testing.T) {
	// Negation before broader allow: 10.0.0.5 should be denied even
	// though the /8 below it would otherwise allow it.
	m := Compile("!10.0.0.5\n10.0.0.0/8")
	if m.Match(net.ParseIP("10.0.0.5")) {
		t.Fatalf("negated entry must win over later /8")
	}
	if !m.Match(net.ParseIP("10.0.0.6")) {
		t.Fatalf("10.0.0.6 should be allowed by /8")
	}
	if m.Match(net.ParseIP("11.0.0.1")) {
		t.Fatalf("address outside any rule must default-deny")
	}
}

func TestMatch_Macros(t *testing.T) {
	m := Compile("any")
	if !m.Match(net.ParseIP("8.8.8.8")) || !m.Match(net.ParseIP("::1")) {
		t.Fatalf("'any' should match every IP")
	}
	none := Compile("none")
	if none.Match(net.ParseIP("8.8.8.8")) {
		t.Fatalf("'none' should match nothing")
	}
	lh := Compile("localhost")
	if !lh.Match(net.ParseIP("127.0.0.1")) || !lh.Match(net.ParseIP("::1")) {
		t.Fatalf("'localhost' should match loopback")
	}
	if lh.Match(net.ParseIP("8.8.8.8")) {
		t.Fatalf("'localhost' must not match a public IP")
	}
	ln := Compile("localnets")
	for _, ip := range []string{"10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1", "169.254.1.1", "fe80::1"} {
		if !ln.Match(net.ParseIP(ip)) {
			t.Fatalf("'localnets' should match %s", ip)
		}
	}
	if ln.Match(net.ParseIP("8.8.8.8")) {
		t.Fatalf("'localnets' must not match a public IP")
	}
}

func TestMatch_IPv6CIDR(t *testing.T) {
	m := Compile("2001:db8::/32")
	if !m.Match(net.ParseIP("2001:db8:1::1")) {
		t.Fatalf("v6 cidr should contain 2001:db8:1::1")
	}
	if m.Match(net.ParseIP("2001:db9::1")) {
		t.Fatalf("v6 cidr should not contain 2001:db9::1")
	}
}

func TestMatch_HostnameIsNoOp(t *testing.T) {
	// Hostnames are accepted at parse time (parity with TS) but the
	// matcher never resolves them — see package doc.
	m := Compile("host.example.com")
	if m.Match(net.ParseIP("10.0.0.1")) {
		t.Fatalf("hostname entries must be a no-op at match time")
	}
}

func TestMatch_NilSafety(t *testing.T) {
	var m *Matcher
	if m.Match(net.ParseIP("10.0.0.1")) {
		t.Fatalf("nil matcher must not match")
	}
	if !m.Empty() {
		t.Fatalf("nil matcher must report Empty()")
	}
	m2 := Compile("10.0.0.0/8")
	if m2.Match(nil) {
		t.Fatalf("nil ip must not match")
	}
}

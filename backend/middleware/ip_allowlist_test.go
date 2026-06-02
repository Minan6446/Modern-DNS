package middleware

import "testing"

// TestIPMatchesAllowlist covers the function used by SaveCommonConfig's
// self-lockout guard. The middleware itself has its own happy/sad paths
// in production, but the helper is the contract surface SaveCommonConfig
// relies on, so we pin it down here.
func TestIPMatchesAllowlist(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		ip   string
		want bool
	}{
		// Empty allowlist intentionally treated as "open" — SaveCommonConfig
		// short-circuits the call when raw == "", but the helper itself
		// must still return true so library users aren't surprised.
		{"empty allowlist", "", "10.0.0.1", true},
		// Loopback always wins so a local recovery shell can fix things
		// even after a self-lockout. This mirrors the runtime middleware.
		{"loopback bypass", "1.2.3.4", "127.0.0.1", true},
		// Plain IP equality — the most common case for small ops teams.
		{"exact ip match", "1.2.3.4", "1.2.3.4", true},
		{"exact ip mismatch", "1.2.3.4", "1.2.3.5", false},
		// CIDR — needed for VPN ranges + bastion subnets.
		{"cidr contains", "10.0.0.0/8", "10.5.6.7", true},
		{"cidr excludes", "10.0.0.0/8", "11.0.0.1", false},
		// Mixed entries with multiple separator styles. The textarea on
		// the General Settings page accepts newlines/commas/spaces, so
		// the splitter must normalise all of them.
		{"mixed separators", "10.0.0.0/8\n192.168.1.1, 172.16.0.0/12", "172.16.5.5", true},
		{"mixed separators excluded", "10.0.0.0/8;192.168.1.1", "8.8.8.8", false},
		// Garbage entries should not crash the matcher; they just don't
		// match anything. This lets operators paste mangled lists from
		// spreadsheets without first cleaning them up.
		{"garbage entry ignored", "not-an-ip, 1.2.3.4", "1.2.3.4", true},
		// IPv6 — both sides must parse for the compare to succeed.
		{"ipv6 exact match", "fe80::1", "fe80::1", true},
		// Empty IP — the helper must not panic on bogus callers.
		{"empty ip", "1.2.3.4", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IPMatchesAllowlist(tc.raw, tc.ip)
			if got != tc.want {
				t.Fatalf("IPMatchesAllowlist(%q, %q) = %v, want %v", tc.raw, tc.ip, got, tc.want)
			}
		})
	}
}

// TestSplitAllowlist asserts the textarea normaliser is forgiving of all
// the separator styles operators paste in. This is the single source of
// truth for both the runtime middleware and the IPMatchesAllowlist
// helper, so a regression here would silently break either flow.
func TestSplitAllowlist(t *testing.T) {
	got := SplitAllowlist("10.0.0.1\n10.0.0.2\r\n10.0.0.3,10.0.0.4; 10.0.0.5  10.0.0.6\t10.0.0.7")
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (got=%v)", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

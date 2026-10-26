package rules

import (
	"net/netip"
	"testing"

	"veil/internal/config"
)

// addr is a tiny helper so table entries stay readable.
func addr(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	return netip.MustParseAddr(s)
}

func TestCompiledMatch(t *testing.T) {
	tests := []struct {
		name string
		rule config.Rule
		meta Meta
		want bool
	}{
		// --- domain (exact, case-insensitive, trailing dot) ---
		{"domain exact", config.Rule{Type: "domain", Value: "example.com"}, Meta{Host: "example.com"}, true},
		{"domain case", config.Rule{Type: "domain", Value: "Example.COM"}, Meta{Host: "example.com"}, true},
		{"domain trailing dot", config.Rule{Type: "domain", Value: "example.com"}, Meta{Host: "example.com."}, true},
		{"domain no subdomain", config.Rule{Type: "domain", Value: "example.com"}, Meta{Host: "a.example.com"}, false},
		{"domain without host", config.Rule{Type: "domain", Value: "example.com"}, Meta{Dst: addr("10.0.0.1")}, false},

		// --- domain-suffix ---
		{"suffix sub", config.Rule{Type: "domain-suffix", Value: "example.com"}, Meta{Host: "a.example.com"}, true},
		{"suffix apex", config.Rule{Type: "domain-suffix", Value: "example.com"}, Meta{Host: "example.com"}, true},
		{"suffix dotted", config.Rule{Type: "domain-suffix", Value: ".example.com"}, Meta{Host: "a.example.com"}, true},
		{"suffix evil", config.Rule{Type: "domain-suffix", Value: "example.com"}, Meta{Host: "evilexample.com"}, false},
		{"suffix trailing dot", config.Rule{Type: "domain-suffix", Value: "example.com"}, Meta{Host: "a.example.com."}, true},

		// --- domain-keyword ---
		{"keyword hit", config.Rule{Type: "domain-keyword", Value: "google"}, Meta{Host: "www.google.com"}, true},
		{"keyword case", config.Rule{Type: "domain-keyword", Value: "Google"}, Meta{Host: "WWW.GOOGLE.COM"}, true},
		{"keyword miss", config.Rule{Type: "domain-keyword", Value: "google"}, Meta{Host: "example.com"}, false},

		// --- domain-regex ---
		{"regex hit", config.Rule{Type: "domain-regex", Value: `^ads?\d*\.`}, Meta{Host: "ads1.example.com"}, true},
		{"regex miss", config.Rule{Type: "domain-regex", Value: `^ads?\d*\.`}, Meta{Host: "www.example.com"}, false},

		// --- ip-cidr / ip-cidr6 ---
		{"cidr hit", config.Rule{Type: "ip-cidr", Value: "10.0.0.0/8"}, Meta{Dst: addr("10.1.2.3")}, true},
		{"cidr miss", config.Rule{Type: "ip-cidr", Value: "10.0.0.0/8"}, Meta{Dst: addr("11.1.2.3")}, false},
		{"cidr host bits", config.Rule{Type: "ip-cidr", Value: "10.1.2.3/8"}, Meta{Dst: addr("10.9.9.9")}, true},
		{"cidr bare ip", config.Rule{Type: "ip-cidr", Value: "10.1.2.3"}, Meta{Dst: addr("10.1.2.3")}, true},
		{"cidr invalid dst", config.Rule{Type: "ip-cidr", Value: "10.0.0.0/8"}, Meta{Host: "example.com"}, false},
		{"cidr6 hit", config.Rule{Type: "ip-cidr6", Value: "2001:db8::/32"}, Meta{Dst: addr("2001:db8::1")}, true},
		{"cidr6 miss", config.Rule{Type: "ip-cidr6", Value: "2001:db8::/32"}, Meta{Dst: addr("2001:db9::1")}, false},

		// --- geoip private ---
		{"geo private rfc1918", config.Rule{Type: "geoip", Value: "private"}, Meta{Dst: addr("192.168.1.1")}, true},
		{"geo private 10", config.Rule{Type: "geoip", Value: "private"}, Meta{Dst: addr("10.0.0.1")}, true},
		{"geo private loopback", config.Rule{Type: "geoip", Value: "private"}, Meta{Dst: addr("127.0.0.1")}, true},
		{"geo private linklocal", config.Rule{Type: "geoip", Value: "private"}, Meta{Dst: addr("169.254.1.1")}, true},
		{"geo private cgnat", config.Rule{Type: "geoip", Value: "private"}, Meta{Dst: addr("100.64.1.1")}, true},
		{"geo private ula", config.Rule{Type: "geoip", Value: "private"}, Meta{Dst: addr("fd00::1")}, true},
		{"geo private public", config.Rule{Type: "geoip", Value: "private"}, Meta{Dst: addr("1.1.1.1")}, false},
		{"geo private invalid", config.Rule{Type: "geoip", Value: "private"}, Meta{}, false},

		// --- geoip cn ---
		{"geo cn hit", config.Rule{Type: "geoip", Value: "cn"}, Meta{Dst: addr("223.5.5.5")}, true},
		{"geo cn hit 2", config.Rule{Type: "geoip", Value: "cn"}, Meta{Dst: addr("114.114.114.114")}, true},
		{"geo cn miss", config.Rule{Type: "geoip", Value: "cn"}, Meta{Dst: addr("8.8.8.8")}, false},
		{"geo cn ipv6", config.Rule{Type: "geoip", Value: "cn"}, Meta{Dst: addr("2400:3200::1")}, false},

		// --- port ---
		{"port single", config.Rule{Type: "port", Value: "443"}, Meta{Port: 443}, true},
		{"port single miss", config.Rule{Type: "port", Value: "443"}, Meta{Port: 80}, false},
		{"port range lo", config.Rule{Type: "port", Value: "1000-2000"}, Meta{Port: 1000}, true},
		{"port range hi", config.Rule{Type: "port", Value: "1000-2000"}, Meta{Port: 2000}, true},
		{"port range out", config.Rule{Type: "port", Value: "1000-2000"}, Meta{Port: 2001}, false},

		// --- network ---
		{"network tcp", config.Rule{Type: "network", Value: "tcp"}, Meta{Network: "tcp"}, true},
		{"network udp case", config.Rule{Type: "network", Value: "UDP"}, Meta{Network: "udp"}, true},
		{"network miss", config.Rule{Type: "network", Value: "tcp"}, Meta{Network: "udp"}, false},

		// --- process ---
		{"process base", config.Rule{Type: "process", Value: "curl"}, Meta{Process: "/usr/bin/curl"}, true},
		{"process rule path", config.Rule{Type: "process", Value: "/bin/curl"}, Meta{Process: "curl"}, true},
		{"process case", config.Rule{Type: "process", Value: "Curl"}, Meta{Process: "curl"}, true},
		{"process miss", config.Rule{Type: "process", Value: "curl"}, Meta{Process: "wget"}, false},
		{"process empty", config.Rule{Type: "process", Value: "curl"}, Meta{}, false},

		// --- final ---
		{"final anything", config.Rule{Type: "final", Action: "direct"}, Meta{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs, err := compile([]config.Rule{tt.rule})
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if got := cs[0].match(tt.meta); got != tt.want {
				t.Fatalf("match(%+v) = %v, want %v", tt.meta, got, tt.want)
			}
		})
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name string
		r    config.Rule
	}{
		{"bad regex", config.Rule{Type: "domain-regex", Value: "a(b"}},
		{"bad cidr", config.Rule{Type: "ip-cidr", Value: "10.0.0.0/99"}},
		{"bad cidr6", config.Rule{Type: "ip-cidr6", Value: "not-an-ip"}},
		{"bad port", config.Rule{Type: "port", Value: "http"}},
		{"bad port range", config.Rule{Type: "port", Value: "2000-1000"}},
		{"port overflow", config.Rule{Type: "port", Value: "70000"}},
		{"bad network", config.Rule{Type: "network", Value: "sctp"}},
		{"bad geoip", config.Rule{Type: "geoip", Value: "us"}},
		{"unknown type", config.Rule{Type: "nope", Value: "x"}},
		{"empty suffix", config.Rule{Type: "domain-suffix", Value: "."}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := compile([]config.Rule{tt.r}); err == nil {
				t.Fatalf("compile(%+v) = nil error, want error", tt.r)
			}
		})
	}

	// The error must carry the offending rule index.
	_, err := compile([]config.Rule{
		{Type: "domain", Value: "ok.com", Action: "direct"},
		{Type: "domain-regex", Value: "a("},
	})
	if err == nil {
		t.Fatal("want error")
	}
	if got := err.Error(); !contains(got, "rule 1") {
		t.Fatalf("error %q does not mention rule 1", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestActionFields(t *testing.T) {
	cs, err := compile([]config.Rule{
		{Type: "domain-suffix", Value: "example.com", Action: "proxy"},
		{Type: "domain", Value: "ads.example.org", Action: "reject"},
		{Type: "final", Value: "", Action: "direct"},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cs[0].action.Outbound != "proxy" || cs[0].action.Rule != "domain-suffix:example.com" || cs[0].action.Reject {
		t.Fatalf("unexpected action: %+v", cs[0].action)
	}
	if !cs[1].action.Reject || cs[1].action.Outbound != "reject" {
		t.Fatalf("reject not detected: %+v", cs[1].action)
	}
	if cs[2].action.Rule != "final" {
		t.Fatalf("final rule name = %q", cs[2].action.Rule)
	}
}

// TestEngineOrdering checks first-match-wins and that the first rule short
// circuits later ones.
func TestEngineOrdering(t *testing.T) {
	rs := []config.Rule{
		{Type: "domain-keyword", Value: "google", Action: "proxy"},
		{Type: "domain-suffix", Value: "google.com", Action: "reject"},
		{Type: "final", Action: "direct"},
	}
	e, err := New(rs, config.ModeRule, "proxy-default")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got := e.Match(Meta{Host: "www.google.com"})
	if got.Outbound != "proxy" || got.Rule != "domain-keyword:google" {
		t.Fatalf("first match wins broken: %+v", got)
	}

	got = e.Match(Meta{Host: "example.com"})
	if got.Outbound != "direct" || got.Rule != "final" {
		t.Fatalf("final rule not applied: %+v", got)
	}

	// Reversed order proves ordering is what decides, not specificity.
	e2, err := New([]config.Rule{rs[1], rs[0]}, config.ModeRule, "x")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := e2.Match(Meta{Host: "www.google.com"}); got.Rule != "domain-suffix:google.com" {
		t.Fatalf("reversed order = %+v", got)
	}
}

// TestEngineModes covers the mode short circuits in rules.go.
func TestEngineModes(t *testing.T) {
	rs := []config.Rule{{Type: "domain-suffix", Value: "example.com", Action: "reject"}}

	e, err := New(rs, config.ModeGlobal, "node-a")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := e.Match(Meta{Host: "example.com"}); got.Outbound != "node-a" || got.Rule != "global" {
		t.Fatalf("global mode = %+v", got)
	}

	e, err = New(rs, config.ModeDirect, "node-a")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := e.Match(Meta{Host: "example.com"}); got.Outbound != "direct" || got.Rule != "direct" {
		t.Fatalf("direct mode = %+v", got)
	}

	// Rule mode: rules apply, unmatched falls back to final with empty Rule.
	e, err = New(rs, config.ModeRule, "node-a")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := e.Match(Meta{Host: "example.com"}); !got.Reject || got.Rule != "domain-suffix:example.com" {
		t.Fatalf("rule mode matched = %+v", got)
	}
	if got := e.Match(Meta{Host: "other.com"}); got.Outbound != "node-a" || got.Rule != "" {
		t.Fatalf("rule mode default = %+v", got)
	}

	// Empty mode is treated as rule mode by rules.go's switch default.
	e, err = New(rs, "", "node-a")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := e.Match(Meta{Host: "other.com"}); got.Outbound != "node-a" {
		t.Fatalf("empty mode = %+v", got)
	}
}

func TestNewPropagatesCompileError(t *testing.T) {
	if _, err := New([]config.Rule{{Type: "domain-regex", Value: "["}}, config.ModeRule, "x"); err == nil {
		t.Fatal("want error from New")
	}
}

func BenchmarkEngineMatch(b *testing.B) {
	e, err := New([]config.Rule{
		{Type: "domain-suffix", Value: "cn", Action: "direct"},
		{Type: "domain-suffix", Value: "example.com", Action: "proxy"},
		{Type: "domain-keyword", Value: "ads", Action: "reject"},
		{Type: "domain-regex", Value: `^tracker\d+\.`},
		{Type: "ip-cidr", Value: "10.0.0.0/8", Action: "direct"},
		{Type: "geoip", Value: "private", Action: "direct"},
		{Type: "port", Value: "443", Action: "proxy"},
		{Type: "network", Value: "udp", Action: "reject"},
		{Type: "final", Action: "proxy"},
	}, config.ModeRule, "proxy")
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	m := Meta{Network: "tcp", Host: "www.example.com", Dst: addr("93.184.216.34"), Port: 443, Process: "curl"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := e.Match(m); got.Outbound != "proxy" {
			b.Fatalf("unexpected %+v", got)
		}
	}
}

// TestNoResolveIgnoresLookedUpDst covers Clash's `no-resolve`: an IP rule with
// the flag must not be satisfied by an address the router looked up itself (the
// engine flags that in Meta.DstFromLookup), while a rule without the flag uses
// it. A client-sent IP still satisfies either kind.
func TestNoResolveIgnoresLookedUpDst(t *testing.T) {
	tests := []struct {
		name string
		rule config.Rule
		meta Meta
		want bool
	}{
		{"cidr no-resolve skips looked-up", config.Rule{Type: "ip-cidr", Value: "223.5.5.5/32", NoResolve: true}, Meta{Host: "cn.example.com", Dst: addr("223.5.5.5"), DstFromLookup: true}, false},
		{"cidr no-resolve keeps client ip", config.Rule{Type: "ip-cidr", Value: "223.5.5.5/32", NoResolve: true}, Meta{Dst: addr("223.5.5.5")}, true},
		{"cidr with resolve skips nothing", config.Rule{Type: "ip-cidr", Value: "223.5.5.5/32"}, Meta{Host: "cn.example.com", Dst: addr("223.5.5.5"), DstFromLookup: true}, true},
		{"cidr6 no-resolve skips looked-up", config.Rule{Type: "ip-cidr6", Value: "2001:db8::/32", NoResolve: true}, Meta{Host: "v6.example.com", Dst: addr("2001:db8::1"), DstFromLookup: true}, false},
		{"cidr6 with resolve uses looked-up", config.Rule{Type: "ip-cidr6", Value: "2001:db8::/32"}, Meta{Host: "v6.example.com", Dst: addr("2001:db8::1"), DstFromLookup: true}, true},
		{"geoip cn no-resolve skips looked-up", config.Rule{Type: "geoip", Value: "cn", NoResolve: true}, Meta{Host: "cn.example.com", Dst: addr("223.5.5.5"), DstFromLookup: true}, false},
		{"geoip cn with resolve uses looked-up", config.Rule{Type: "geoip", Value: "cn"}, Meta{Host: "cn.example.com", Dst: addr("223.5.5.5"), DstFromLookup: true}, true},
		{"geoip private no-resolve skips looked-up", config.Rule{Type: "geoip", Value: "private", NoResolve: true}, Meta{Host: "nas.lan", Dst: addr("192.168.1.9"), DstFromLookup: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs, err := compile([]config.Rule{tt.rule})
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if got := cs[0].match(tt.meta); got != tt.want {
				t.Fatalf("match(%+v) = %v, want %v", tt.meta, got, tt.want)
			}
		})
	}
}

// TestNeedsIP pins down what makes the engine resolve: an IP rule that is
// allowed to use the answer, and nothing else.
func TestNeedsIP(t *testing.T) {
	tests := []struct {
		name  string
		rules []config.Rule
		want  bool
	}{
		{"empty", nil, false},
		{"domain only", []config.Rule{{Type: "domain-suffix", Value: "cn"}}, false},
		{"ip-cidr", []config.Rule{{Type: "ip-cidr", Value: "10.0.0.0/8"}}, true},
		{"ip-cidr uppercase", []config.Rule{{Type: "IP-CIDR", Value: "10.0.0.0/8"}}, true},
		{"ip-cidr6", []config.Rule{{Type: "ip-cidr6", Value: "2001:db8::/32"}}, true},
		{"geoip", []config.Rule{{Type: "geoip", Value: "cn"}}, true},
		{"no-resolve ip-cidr", []config.Rule{{Type: "ip-cidr", Value: "10.0.0.0/8", NoResolve: true}}, false},
		{"no-resolve geoip", []config.Rule{{Type: "geoip", Value: "cn", NoResolve: true}}, false},
		{"one resolvable among no-resolve", []config.Rule{
			{Type: "ip-cidr", Value: "10.0.0.0/8", NoResolve: true},
			{Type: "geoip", Value: "cn"},
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NeedsIP(tt.rules); got != tt.want {
				t.Fatalf("NeedsIP(%v) = %v, want %v", tt.rules, got, tt.want)
			}
		})
	}
}

// TestGeoIPCNCoversDomesticAllocations pins the generated APNIC snapshot: a
// domestic site that resolves to an unlisted range used to travel through the
// proxy, which is the most visible way this client differed from Clash.
func TestGeoIPCNCoversDomesticAllocations(t *testing.T) {
	m, err := New([]config.Rule{{Type: "geoip", Value: "cn", Action: "direct"}}, "rule", "direct")
	if err != nil {
		t.Fatal(err)
	}
	cn := []string{"58.222.20.36", "14.215.182.140", "182.61.201.163", "114.114.114.114", "223.5.5.5"}
	for _, s := range cn {
		if got := m.Match(Meta{Dst: netip.MustParseAddr(s)}); got.Rule != "geoip:cn" {
			t.Errorf("%s = %q, want geoip:cn (mainland allocation missing from the table)", s, got.Rule)
		}
	}
	notCN := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "103.235.46.96"}
	for _, s := range notCN {
		if got := m.Match(Meta{Dst: netip.MustParseAddr(s)}); got.Rule == "geoip:cn" {
			t.Errorf("%s matched geoip:cn, want no match", s)
		}
	}
}

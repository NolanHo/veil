package supervisor

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"veil/internal/config"
	"veil/internal/rpc"
	"veil/internal/rules"
)

// ownerProfile is the shape of the profile the owner actually runs on the desktop
// client: a proxy-provider airport, a chained Shadowsocks exit, a SOCKS5 home
// line behind a group, two WireGuard peers, eleven groups and fifty rules.
// Identifiers are replaced with examples; the structure is what this test pins.
func ownerProfile(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile("testdata/owner-profile.yaml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(body)
}

// A real profile has to survive import: every node, every group and every rule
// that the document states, with only the external rule-sets reported as
// unsupported. Anything less and the user's split tunnel has holes.
func TestOwnerProfileImportsWhole(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `
proxies:
  - {name: "HK 01", type: ss, server: 203.0.113.11, port: 8388, cipher: aes-128-gcm, password: pw}
  - {name: "JP 01", type: ss, server: 203.0.113.12, port: 8388, cipher: aes-128-gcm, password: pw}
`)
	}))
	defer srv.Close()

	doc := ownerProfile(t)
	// The fixture points the provider at an unroutable host; aim it at the fake
	// airport so the test exercises the fetch path rather than the failure path.
	doc = replaceProviderURL(doc, srv.URL)

	sup := newRuleSupervisor(t)
	res, err := sup.Import(rpc.ImportParams{Text: doc, Source: "owner"})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	cfg := sup.Config()
	// Five nodes: hy2, chained ss, socks5, two WireGuard peers, plus the two the
	// provider contributed.
	if len(cfg.Nodes) != 7 {
		tags := make([]string, 0, len(cfg.Nodes))
		for _, n := range cfg.Nodes {
			tags = append(tags, n.Tag)
		}
		t.Fatalf("nodes = %d %v, want 7 (5 in the document + 2 from the provider)", len(cfg.Nodes), tags)
	}
	// Eleven groups from the document plus the generated selector, which is what
	// gives an imported profile a default exit without editing the document.
	if len(cfg.Groups) != 12 {
		tags := make([]string, 0, len(cfg.Groups))
		for _, g := range cfg.Groups {
			tags = append(tags, g.Tag)
		}
		t.Fatalf("groups = %d %v, want 12 (11 stated + the generated selector)", len(cfg.Groups), tags)
	}
	// 48 rules land; the two RULE-SET lines are reported, not silently dropped.
	if len(cfg.Rules) != 48 {
		t.Fatalf("rules = %d, want 48", len(cfg.Rules))
	}
	ruleSetErrs := 0
	for _, e := range res.Errors {
		if containsAll(e, "RULE-SET") {
			ruleSetErrs++
		}
	}
	if ruleSetErrs != 2 {
		t.Fatalf("errors = %v, want exactly the two RULE-SET lines reported", res.Errors)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("imported config does not validate: %v", err)
	}

	// The provider's nodes reach the groups that only name it.
	airport := groupByTag(t, cfg.Groups, "机场节点")
	if len(airport.Members) != 2 {
		t.Fatalf("机场节点 members = %v, want the two provider nodes", airport.Members)
	}
	// The filter on 日本 keeps the JP node and drops the HK one.
	jp := groupByTag(t, cfg.Groups, "日本")
	if len(jp.Members) != 1 {
		t.Fatalf("日本 members = %v, want only the provider's JP node", jp.Members)
	}
	if !containsAll(jp.Members[0], "JP") {
		t.Fatalf("日本 members = %v, want the JP node", jp.Members)
	}
	// A chained node keeps the hop it was configured with.
	chained := nodeByTag(t, cfg.Nodes, "出口节点")
	if chained.DialerProxy != "mdev-hk" {
		t.Fatalf("出口节点 dialer-proxy = %q, want mdev-hk", chained.DialerProxy)
	}
}

func replaceProviderURL(doc, url string) string {
	return replaceOnce(doc, `url: "http://provider.invalid/sub"`, `url: "`+url+`"`)
}

func replaceOnce(s, old, new string) string {
	for i := 0; i+len(old) <= len(s); i++ {
		if s[i:i+len(old)] == old {
			return s[:i] + new + s[i+len(old):]
		}
	}
	return s
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		found := false
		for i := 0; i+len(p) <= len(s); i++ {
			if s[i:i+len(p)] == p {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// The imported table has to route the way the profile says, not just store the
// right number of lines.
func TestOwnerProfileRoutesAsConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `
proxies:
  - {name: "HK 01", type: ss, server: 203.0.113.11, port: 8388, cipher: aes-128-gcm, password: pw}
`)
	}))
	defer srv.Close()

	sup := newRuleSupervisor(t)
	if _, err := sup.Import(rpc.ImportParams{Text: replaceProviderURL(ownerProfile(t), srv.URL), Source: "owner"}); err != nil {
		t.Fatalf("Import: %v", err)
	}
	m, err := rules.New(sup.Config().Rules, config.ModeRule, "漏网之鱼")
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	cases := []struct {
		host string
		want string
	}{
		{"openai.com", "出口包装"},
		{"claude.ai", "出口包装"},
		{"dlsite.com", "日本家宽"},
		{"x.com", "出口包装"},
		{"some-unknown-site.example", "漏网之鱼"},
	}
	for _, c := range cases {
		got := m.Match(rules.Meta{Network: "tcp", Host: c.host, Port: 443}).Outbound
		if got != c.want {
			t.Errorf("route %s = %q, want %q", c.host, got, c.want)
		}
	}
}

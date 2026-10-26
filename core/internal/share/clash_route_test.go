package share

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"veil/internal/config"
	"veil/internal/rules"
)

// ownerRoutingYAML is the shape the owner's Clash Verge profile has, with every
// endpoint and credential replaced by a placeholder: a selector in front, a
// url-test and a second selector behind it, a fallback group over the homelab
// WireGuard peer, the domestic split (domain suffix + GEOIP), the homelab
// subnet rule, and the two rule-provider styles this build cannot honour.
func ownerRoutingYAML() string {
	return strings.NewReplacer("PRIV", testPrivKey, "PUB", testPubKey).Replace(`
proxies:
  - name: "homelab-wg"
    type: wireguard
    server: 203.0.113.10
    port: 51820
    ip: 10.173.91.13
    private-key: PRIV
    public-key: PUB
    allowed-ips: ['10.173.91.0/24']
    dns: [10.173.91.1]
    mtu: 1280
    udp: true
  - name: "hy2-hk"
    type: hysteria2
    server: hk.example.net
    port: 443
    password: placeholder
    sni: hk.example.net
    obfs: salamander
    obfs-password: placeholder
  - name: "hy2-jp"
    type: hysteria2
    server: jp.example.net
    port: 443
    password: placeholder
    sni: jp.example.net
proxy-groups:
  - name: 选择代理
    type: select
    proxies: [自动选择, 手动切换, DIRECT]
  - name: 自动选择
    type: url-test
    url: http://cp.cloudflare.com/generate_204
    interval: 300
    tolerance: 50
    proxies: [hy2-hk, hy2-jp]
  - name: 手动切换
    type: select
    proxies: [hy2-hk, hy2-jp, DIRECT]
  - name: homelab
    type: fallback
    proxies: [homelab-wg, DIRECT]
rules:
  - DOMAIN-SUFFIX,baidu.com,DIRECT
  - DOMAIN-SUFFIX,cn,DIRECT
  - GEOIP,CN,DIRECT
  - IP-CIDR,10.173.91.0/24,homelab,no-resolve
  - GEOSITE,geolocation-!cn,选择代理
  - RULE-SET,reject-list,REJECT
  - MATCH,选择代理
rule-providers:
  reject-list:
    type: http
    behavior: domain
    url: https://example.invalid/reject.yaml
    path: ./rules/reject.yaml
    interval: 86400
`)
}

func groupByTag(t *testing.T, groups []config.Group) map[string]config.Group {
	t.Helper()
	out := make(map[string]config.Group, len(groups))
	for _, g := range groups {
		out[g.Tag] = g
	}
	return out
}

// TestOwnerClashRoutingImports is the acceptance fixture: every group and every
// rule of the owner's profile shape must land with the right type, value,
// action and no-resolve flag, and the two external-rule-set lines must be
// reported instead of taking the import down.
func TestOwnerClashRoutingImports(t *testing.T) {
	cfg, errs := ParseClashConfig([]byte(ownerRoutingYAML()), "clash")

	if len(cfg.Nodes) != 3 {
		t.Fatalf("nodes = %d (%+v), want homelab-wg + two hysteria2 nodes", len(cfg.Nodes), cfg.Nodes)
	}

	// A group that lists another group must come after it: the engine builds
	// groups in order and drops one whose member outbound does not exist yet.
	var order []string
	for _, g := range cfg.Groups {
		order = append(order, g.Tag)
	}
	if want := []string{"自动选择", "手动切换", "选择代理", "homelab"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("group order = %v, want %v", order, want)
	}

	groups := groupByTag(t, cfg.Groups)
	wantGroups := map[string]config.Group{
		"自动选择": {Tag: "自动选择", Type: "url-test", Members: []string{"hy2-hk", "hy2-jp"},
			URL: "http://cp.cloudflare.com/generate_204", Interval: 300, Tolerance: 50},
		"手动切换": {Tag: "手动切换", Type: "select", Members: []string{"hy2-hk", "hy2-jp", "direct"}},
		// DIRECT is a built-in outbound here, not a member to import.
		"选择代理":    {Tag: "选择代理", Type: "select", Members: []string{"自动选择", "手动切换", "direct"}},
		"homelab": {Tag: "homelab", Type: "fallback", Members: []string{"homelab-wg", "direct"}},
	}
	for tag, want := range wantGroups {
		got, ok := groups[tag]
		if !ok {
			t.Fatalf("group %q missing from %v", tag, order)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("group %q = %+v, want %+v", tag, got, want)
		}
	}

	wantRules := []config.Rule{
		{Type: "domain-suffix", Value: "baidu.com", Action: "direct"},
		{Type: "domain-suffix", Value: "cn", Action: "direct"},
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "ip-cidr", Value: "10.173.91.0/24", Action: "homelab", NoResolve: true},
		{Type: "final", Action: "选择代理"},
	}
	if !reflect.DeepEqual(cfg.Rules, wantRules) {
		t.Fatalf("rules =\n%+v\nwant\n%+v", cfg.Rules, wantRules)
	}

	// The skips are named, so the user learns why two of their rules do nothing.
	if len(errs) != 2 {
		t.Fatalf("errs = %v, want one per external rule set", errs)
	}
	joined := errs[0].Error() + " | " + errs[1].Error()
	for _, want := range []string{"GEOSITE", "RULE-SET"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("errs = %v, want %q named", errs, want)
		}
	}

	// The result must be a configuration the app can store and start.
	c := config.Config{Nodes: cfg.Nodes, Groups: cfg.Groups, Rules: cfg.Rules}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestOwnerClashRouteDecisions runs the imported table through the matcher the
// engine uses for every connection: the homelab subnet must reach the WireGuard
// group, a domestic name must go direct, and everything else must land on the
// group MATCH names.
func TestOwnerClashRouteDecisions(t *testing.T) {
	cfg, _ := ParseClashConfig([]byte(ownerRoutingYAML()), "clash")
	final := ""
	for _, r := range cfg.Rules {
		if r.Type == "final" {
			final = r.Action
		}
	}
	if final != "选择代理" {
		t.Fatalf("final rule action = %q, want the 选择代理 group", final)
	}
	matcher, err := rules.New(cfg.Rules, config.ModeRule, final)
	if err != nil {
		t.Fatalf("rules.New on imported rules: %v", err)
	}

	cases := []struct {
		name string
		meta rules.Meta
		want string
		rule string
	}{
		{
			name: "homelab subnet",
			meta: rules.Meta{Network: "tcp", Dst: netip.MustParseAddr("10.173.91.20"), Port: 443},
			want: "homelab",
			rule: "ip-cidr:10.173.91.0/24",
		},
		{
			name: "domestic domain",
			meta: rules.Meta{Network: "tcp", Host: "www.baidu.com", Port: 443},
			want: "direct",
			rule: "domain-suffix:baidu.com",
		},
		{
			name: "everything else",
			meta: rules.Meta{Network: "tcp", Host: "example.org", Port: 443},
			want: "选择代理",
			rule: "final",
		},
	}
	for _, c := range cases {
		act := matcher.Match(c.meta)
		if act.Outbound != c.want || act.Rule != c.rule {
			t.Fatalf("%s: got outbound %q via %q, want %q via %q",
				c.name, act.Outbound, act.Rule, c.want, c.rule)
		}
	}
}

// TestClashGroupDropsUnknownMember covers the node this build cannot drive: the
// group keeps its other members and reports the one that vanished, instead of
// failing or importing a dangling reference.
func TestClashGroupDropsUnknownMember(t *testing.T) {
	doc := `
proxies:
  - name: "hy2-hk"
    type: hysteria2
    server: hk.example.net
    port: 443
    password: placeholder
  - name: "old-socks"
    type: socks5
    server: 198.51.100.7
    port: 1080
proxy-groups:
  - name: 手动切换
    type: select
    proxies: [hy2-hk, old-socks, DIRECT]
rules:
  - DOMAIN,blocked.example,old-socks
  - MATCH,DIRECT
`
	cfg, errs := ParseClashConfig([]byte(doc), "clash")
	groups := groupByTag(t, cfg.Groups)
	got := groups["手动切换"].Members
	if want := []string{"hy2-hk", "direct"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("members = %v, want %v", got, want)
	}
	// The rule that wanted the skipped node is dropped too: keeping it would
	// make the stored configuration invalid.
	if len(cfg.Rules) != 1 || cfg.Rules[0].Type != "final" {
		t.Fatalf("rules = %+v, want only the MATCH rule", cfg.Rules)
	}
	joined := ""
	for _, e := range errs {
		joined += e.Error() + "\n"
	}
	for _, want := range []string{"old-socks", "socks5"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("errs = %v, want %q named", errs, want)
		}
	}
}

// TestClashGroupCycleDropped covers a profile whose groups point at each other:
// a single-pass engine cannot build a cycle, so the back edge is dropped and
// the rest of both groups survives.
func TestClashGroupCycleDropped(t *testing.T) {
	doc := `
proxies:
  - name: "hy2-hk"
    type: hysteria2
    server: hk.example.net
    port: 443
    password: placeholder
proxy-groups:
  - name: a
    type: select
    proxies: [b]
  - name: b
    type: select
    proxies: [a, hy2-hk]
rules:
  - MATCH,a
`
	cfg, errs := ParseClashConfig([]byte(doc), "clash")
	groups := groupByTag(t, cfg.Groups)
	if want := []string{"b", "a"}; !reflect.DeepEqual([]string{cfg.Groups[0].Tag, cfg.Groups[1].Tag}, want) {
		t.Fatalf("group order = %v, want %v (b must exist before a)", cfg.Groups, want)
	}
	if got := groups["b"].Members; !reflect.DeepEqual(got, []string{"hy2-hk"}) {
		t.Fatalf("b members = %v, want the back edge dropped", got)
	}
	if got := groups["a"].Members; !reflect.DeepEqual(got, []string{"b"}) {
		t.Fatalf("a members = %v", got)
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "cycle") {
		t.Fatalf("errs = %v, want one about the cycle", errs)
	}
}

// TestClashRuleValuesRejectedBeforeStorage guards the engine: one rule the
// matcher cannot compile makes the whole rule list unloadable, which would look
// like "the tunnel stopped working" with nothing to point at in the UI.
func TestClashRuleValuesRejectedBeforeStorage(t *testing.T) {
	doc := `
proxies:
  - name: "hy2-hk"
    type: hysteria2
    server: hk.example.net
    port: 443
    password: placeholder
proxy-groups:
  - name: 选择代理
    type: select
    proxies: [hy2-hk, DIRECT]
rules:
  - IP-CIDR,10.0.0.0,DIRECT
  - IP-CIDR,10.0.0.0/33,DIRECT
  - DOMAIN-REGEX,([,DIRECT
  - GEOIP,US,DIRECT
  - NETWORK,icmp,DIRECT
  - DST-PORT,99999,DIRECT
  - DOMAIN-SUFFIX,ok.example,DIRECT
  - MATCH,选择代理
  - DOMAIN-SUFFIX,late.example,DIRECT
`
	cfg, errs := ParseClashConfig([]byte(doc), "clash")
	want := []config.Rule{
		// A bare address is a host prefix, which is what the matcher accepts.
		{Type: "ip-cidr", Value: "10.0.0.0", Action: "direct"},
		{Type: "domain-suffix", Value: "ok.example", Action: "direct"},
		{Type: "final", Action: "选择代理"},
	}
	if !reflect.DeepEqual(cfg.Rules, want) {
		t.Fatalf("rules =\n%+v\nwant\n%+v", cfg.Rules, want)
	}
	if len(errs) != 6 {
		t.Fatalf("errs = %v, want one per rejected rule", errs)
	}
	c := config.Config{Nodes: cfg.Nodes, Groups: cfg.Groups, Rules: cfg.Rules}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if _, err := rules.New(cfg.Rules, config.ModeRule, "选择代理"); err != nil {
		t.Fatalf("the kept rules must compile: %v", err)
	}
	joined := ""
	for _, e := range errs {
		joined += e.Error() + "\n"
	}
	for _, want := range []string{"10.0.0.0/33", "domain-regex", "GEOIP", "US", "icmp", "99999", "unreachable"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("errs = %v, want %q named", errs, want)
		}
	}
}

// TestParseClashYAMLStillReturnsNodes pins the old door: callers that only want
// nodes (subscription fetch) keep working.
func TestParseClashYAMLStillReturnsNodes(t *testing.T) {
	nodes, _ := ParseClashYAML([]byte(ownerRoutingYAML()), "clash")
	if len(nodes) != 3 {
		t.Fatalf("nodes = %d, want 3", len(nodes))
	}
	if nodes[0].Tag != "homelab-wg" || nodes[0].Type != "wireguard" {
		t.Fatalf("node 0 = %+v", nodes[0])
	}
}

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

// TestClashUncompilableRulesRejected is the S14 regression: these rules passed
// the importer's own value checks but the matcher rejects them at compile time,
// so the import reported success and the engine then refused the whole table at
// start — the tunnel simply would not come up, with nothing pointing at a rule.
func TestClashUncompilableRulesRejected(t *testing.T) {
	doc := `
proxies:
  - name: "hy2-hk"
    type: hysteria2
    server: hk.example.net
    port: 443
    password: placeholder
rules:
  - DST-PORT,2000-1000,DIRECT
  - DOMAIN-SUFFIX,.,DIRECT
  - PROCESS-NAME,.,DIRECT
  - DST-PORT,443,DIRECT
  - MATCH,DIRECT
`
	cfg, errs := ParseClashConfig([]byte(doc), "clash")

	want := []config.Rule{
		{Type: "port", Value: "443", Action: "direct"},
		{Type: "final", Action: "direct"},
	}
	if !reflect.DeepEqual(cfg.Rules, want) {
		t.Fatalf("rules =\n%+v\nwant only the compilable rows\n%+v", cfg.Rules, want)
	}
	if len(errs) != 3 {
		t.Fatalf("errs = %v, want one per uncompilable rule", errs)
	}
	joined := ""
	for _, e := range errs {
		joined += e.Error() + "\n"
	}
	for _, want := range []string{"2000-1000", "empty domain-suffix", "empty process name"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("errs = %v, want %q named", errs, want)
		}
	}

	// The point of the check: what survived is loadable by the engine, and the
	// stored configuration is valid.
	if _, err := rules.New(cfg.Rules, config.ModeRule, "direct"); err != nil {
		t.Fatalf("imported table must compile: %v", err)
	}
	c := config.Config{Nodes: cfg.Nodes, Groups: cfg.Groups, Rules: cfg.Rules}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestClashDedupedNameResolves is the S17 regression: two proxies with different
// names but the same connection identity are merged into one node. References
// that use the merged-away spelling used to be discarded as dangling, silently
// deleting the group members and rules the profile wrote.
func TestClashDedupedNameResolves(t *testing.T) {
	doc := `
proxies:
  - name: "hy2-hk"
    type: hysteria2
    server: hk.example.net
    port: 443
    password: placeholder
  - name: "hy2-hk%20mirror"
    type: hysteria2
    server: hk.example.net
    port: 443
    password: placeholder
proxy-groups:
  - name: 手动切换
    type: select
    proxies: [hy2-hk mirror, DIRECT]
rules:
  - DOMAIN-SUFFIX,example.com,hy2-hk mirror
  - MATCH,手动切换
`
	cfg, errs := ParseClashConfig([]byte(doc), "clash")
	if len(errs) != 0 {
		t.Fatalf("errs = %v, want none: a merged duplicate is not a problem", errs)
	}
	if len(cfg.Nodes) != 1 {
		t.Fatalf("nodes = %+v, want the two entries merged by identity", cfg.Nodes)
	}
	eq(t, "tag", cfg.Nodes[0].Tag, "hy2-hk")

	groups := groupByTag(t, cfg.Groups)
	if got, want := groups["手动切换"].Members, []string{"hy2-hk", "direct"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("members = %v, want %v: the merged-away name must resolve", got, want)
	}
	wantRules := []config.Rule{
		{Type: "domain-suffix", Value: "example.com", Action: "hy2-hk"},
		{Type: "final", Action: "手动切换"},
	}
	if !reflect.DeepEqual(cfg.Rules, wantRules) {
		t.Fatalf("rules =\n%+v\nwant\n%+v", cfg.Rules, wantRules)
	}

	c := config.Config{Nodes: cfg.Nodes, Groups: cfg.Groups, Rules: cfg.Rules}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if _, err := rules.New(cfg.Rules, config.ModeRule, "手动切换"); err != nil {
		t.Fatalf("imported table must compile: %v", err)
	}
}

// TestClashNameConflictsRejected is the S15 regression: nodes, groups and the
// built-in outbounds share one tag namespace. A collision used to be imported
// as-is, so either the stored configuration failed validation (duplicate tag) or
// a reference silently resolved to the other outbound. Every conflict is skipped
// and reported, and the entries that remain keep working.
func TestClashNameConflictsRejected(t *testing.T) {
	doc := `
proxies:
  - name: "node%20x"
    type: hysteria2
    server: a.example.net
    port: 443
    password: placeholder
  - name: "reject"
    type: hysteria2
    server: b.example.net
    port: 443
    password: placeholder
  - name: "node x"
    type: trojan
    server: c.example.net
    port: 443
    password: placeholder
proxy-groups:
  - name: "node x"
    type: select
    proxies: [node%20x, DIRECT]
  - name: "DIRECT"
    type: select
    proxies: [node%20x]
rules:
  - DOMAIN,blocked.example,node x
  - MATCH,node%20x
`
	cfg, errs := ParseClashConfig([]byte(doc), "clash")

	// node%20x normalises to "node x" and owns the name; the trojan entry that
	// spells the same name differently, the node named like a built-in, and both
	// colliding groups are gone.
	if len(cfg.Nodes) != 1 {
		t.Fatalf("nodes = %+v, want only the first node named \"node x\"", cfg.Nodes)
	}
	eq(t, "tag", cfg.Nodes[0].Tag, "node x")
	eq(t, "type", cfg.Nodes[0].Type, "hysteria2")
	if len(cfg.Groups) != 0 {
		t.Fatalf("groups = %+v, want none: both collide", cfg.Groups)
	}

	// References to the surviving name are not collateral damage: they still
	// resolve to the node that kept it.
	wantRules := []config.Rule{
		{Type: "domain", Value: "blocked.example", Action: "node x"},
		{Type: "final", Action: "node x"},
	}
	if !reflect.DeepEqual(cfg.Rules, wantRules) {
		t.Fatalf("rules =\n%+v\nwant\n%+v", cfg.Rules, wantRules)
	}

	if len(errs) != 4 {
		t.Fatalf("errs = %v, want one per conflict (node built-in, node duplicate, group vs node, group vs built-in)", errs)
	}
	joined := ""
	for _, e := range errs {
		joined += e.Error() + "\n"
	}
	for _, want := range []string{
		`built-in "reject" outbound`,
		"more than one node",
		`collides with the imported node "node x"`,
		`built-in "direct" outbound`,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("errs = %v, want %q named", errs, want)
		}
	}

	// Nothing was produced that overwrites another outbound.
	c := config.Config{Nodes: cfg.Nodes, Groups: cfg.Groups, Rules: cfg.Rules}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestClashRoutingPresenceFlags pins the S18 contract: an absent section and a
// stated-but-empty one both produce an empty slice, and only the presence bit
// tells a consumer which is which — "leave my table alone" versus "clear it".
func TestClashRoutingPresenceFlags(t *testing.T) {
	const base = `
proxies:
  - name: "hy2-hk"
    type: hysteria2
    server: hk.example.net
    port: 443
    password: placeholder
`
	cases := []struct {
		name        string
		doc         string
		wantRules   bool
		wantGroups  bool
		wantRuleLen int
		wantGrpLen  int
	}{
		{"absent", base, false, false, 0, 0},
		{"explicit empty", base + "rules: []\nproxy-groups: []\n", true, true, 0, 0},
		{"bare key", base + "rules:\nproxy-groups:\n", true, true, 0, 0},
		{"non-empty", base + `rules:
  - MATCH,DIRECT
proxy-groups:
  - name: g
    type: select
    proxies: [hy2-hk]
`, true, true, 1, 1},
	}
	for _, c := range cases {
		cfg, errs := ParseClashConfig([]byte(c.doc), "clash")
		if len(errs) != 0 {
			t.Fatalf("%s: errs = %v", c.name, errs)
		}
		if cfg.RulesProvided != c.wantRules {
			t.Fatalf("%s: RulesProvided = %v, want %v", c.name, cfg.RulesProvided, c.wantRules)
		}
		if cfg.GroupsProvided != c.wantGroups {
			t.Fatalf("%s: GroupsProvided = %v, want %v", c.name, cfg.GroupsProvided, c.wantGroups)
		}
		if len(cfg.Rules) != c.wantRuleLen {
			t.Fatalf("%s: rules = %+v, want %d", c.name, cfg.Rules, c.wantRuleLen)
		}
		if len(cfg.Groups) != c.wantGrpLen {
			t.Fatalf("%s: groups = %+v, want %d", c.name, cfg.Groups, c.wantGrpLen)
		}
	}

	// A stated section with the wrong shape is reported, not fatal: the node
	// still imports and the bit still says the document stated the section.
	cfg, errs := ParseClashConfig([]byte(base+"rules: not-a-list\n"), "clash")
	if !cfg.RulesProvided || len(cfg.Rules) != 0 || len(cfg.Nodes) != 1 {
		t.Fatalf("cfg = %+v, want the node imported, an empty stated rule table", cfg)
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "rules") {
		t.Fatalf("errs = %v, want one about the rules shape", errs)
	}
}

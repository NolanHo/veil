package share

import (
	"reflect"
	"strings"
	"testing"

	"veil/internal/config"
)

// providerYAML is the minimal document the parser has to understand: one
// subscription (an airport) in `proxy-providers:`, groups that collect it
// through `use:` instead of naming nodes, and rules that address those groups.
// Every key a real profile carries around the provider — override, health-check,
// proxy — is present so the fixture also pins that they are tolerated.
func providerYAML() string {
	return `
proxy-providers:
  airport:
    type: http
    url: "https://example.invalid/sub?token=t"
    path: ./airport.yaml
    interval: 86400
    filter: "(?i)Hong Kong|香港"
    exclude-filter: "(?i)Traffic|套餐"
    override:
      udp: true
    health-check:
      enable: true
      interval: 600
      url: https://www.gstatic.com/generate_204
    proxy: DIRECT
proxies:
  - name: "hy2-hk"
    type: vless
    server: hk.example.net
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
proxy-groups:
  - name: 机场节点
    type: select
    use:
      - airport
  - name: 选择代理
    type: select
    proxies: [机场节点, hy2-hk, DIRECT]
rules:
  - DOMAIN-SUFFIX,example.com,机场节点
  - MATCH,选择代理
`
}

// TestClashProviderDefinitionsAndUseGroups is the provider import contract: the
// definition lands with the fields that decide which nodes it will contribute,
// the group that only names it survives with that reference, and the rules that
// send traffic to the group keep their action.
func TestClashProviderDefinitionsAndUseGroups(t *testing.T) {
	cfg, errs := ParseClashConfig([]byte(providerYAML()), "clash")
	if len(errs) != 0 {
		t.Fatalf("errs = %v, want none: the ignored provider keys are not errors", errs)
	}

	want := []config.ProxyProvider{{
		Name:          "airport",
		Type:          "http",
		URL:           "https://example.invalid/sub?token=t",
		Path:          "./airport.yaml",
		Interval:      86400,
		Filter:        "(?i)Hong Kong|香港",
		ExcludeFilter: "(?i)Traffic|套餐",
	}}
	if !reflect.DeepEqual(cfg.Providers, want) {
		t.Fatalf("providers =\n%+v\nwant\n%+v", cfg.Providers, want)
	}

	// A group naming a provider as a member must still be placed before the
	// group that lists it, exactly like an inline member group.
	if got, wantOrder := groupTags(cfg.Groups), []string{"机场节点", "选择代理"}; !reflect.DeepEqual(got, wantOrder) {
		t.Fatalf("group order = %v, want %v", got, wantOrder)
	}
	groups := groupByTag(t, cfg.Groups)
	airport := groups["机场节点"]
	if !reflect.DeepEqual(airport.Providers, []string{"airport"}) {
		t.Fatalf("机场节点 providers = %v, want [airport]", airport.Providers)
	}
	// The members exist only after the provider is fetched; the parser must keep
	// the group with an empty (never nil) member list instead of dropping it.
	if airport.Members == nil || len(airport.Members) != 0 {
		t.Fatalf("机场节点 members = %v, want an empty list", airport.Members)
	}
	if got, wantMembers := groups["选择代理"].Members, []string{"机场节点", "hy2-hk", "direct"}; !reflect.DeepEqual(got, wantMembers) {
		t.Fatalf("选择代理 members = %v, want %v", got, wantMembers)
	}
	if len(groups["选择代理"].Providers) != 0 {
		t.Fatalf("选择代理 providers = %v, want none", groups["选择代理"].Providers)
	}

	// The action of a rule that names the provider group resolves to the group;
	// this used to be dropped as "not a node or group in this configuration".
	wantRules := []config.Rule{
		{Type: "domain-suffix", Value: "example.com", Action: "机场节点"},
		{Type: "final", Action: "选择代理"},
	}
	if !reflect.DeepEqual(cfg.Rules, wantRules) {
		t.Fatalf("rules =\n%+v\nwant\n%+v", cfg.Rules, wantRules)
	}

	// A group whose members come from a provider is a legal stored group: the
	// expansion fills Members, so validation must not demand them here.
	c := config.Config{Nodes: cfg.Nodes, Groups: cfg.Groups, Rules: cfg.Rules}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestClashProviderFileType covers the other kind a profile can use: no URL, a
// path to a local provider file.
func TestClashProviderFileType(t *testing.T) {
	doc := `
proxy-providers:
  local:
    type: file
    path: ./local-nodes.yaml
    interval: "3600"
proxies:
  - name: "hy2-hk"
    type: vless
    server: hk.example.net
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
proxy-groups:
  - name: local
    type: select
    use: [local]
`
	cfg, errs := ParseClashConfig([]byte(doc), "clash")
	if len(errs) != 0 {
		t.Fatalf("errs = %v, want none", errs)
	}
	want := []config.ProxyProvider{{Name: "local", Type: "file", Path: "./local-nodes.yaml", Interval: 3600}}
	if !reflect.DeepEqual(cfg.Providers, want) {
		t.Fatalf("providers =\n%+v\nwant\n%+v", cfg.Providers, want)
	}
	if len(cfg.Groups) != 1 || !reflect.DeepEqual(cfg.Groups[0].Providers, []string{"local"}) {
		t.Fatalf("groups = %+v, want the group with its provider reference", cfg.Groups)
	}
}

// TestClashProviderUnsupportedTypeRejected: this build can read a URL or a file.
// A provider of any other kind is skipped and named, because silently keeping it
// would leave the groups that use it empty with no reason given.
func TestClashProviderUnsupportedTypeRejected(t *testing.T) {
	doc := `
proxy-providers:
  scripted:
    type: script
    url: https://example.invalid/prov.js
  ok:
    type: http
    url: https://example.invalid/sub
proxies:
  - name: "hy2-hk"
    type: vless
    server: hk.example.net
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
`
	cfg, errs := ParseClashConfig([]byte(doc), "clash")
	if len(cfg.Providers) != 1 || cfg.Providers[0].Name != "ok" {
		t.Fatalf("providers = %+v, want only the http one", cfg.Providers)
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "script") {
		t.Fatalf("errs = %v, want one naming the unsupported provider type", errs)
	}
}

// TestClashGroupInlineAndProviderMembers covers a group that mixes both: the
// inline members survive as written, and the provider reference is kept beside
// them.
func TestClashGroupInlineAndProviderMembers(t *testing.T) {
	doc := `
proxy-providers:
  airport:
    type: http
    url: https://example.invalid/sub
proxies:
  - name: "hy2-hk"
    type: vless
    server: hk.example.net
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
proxy-groups:
  - name: mixed
    type: select
    proxies: [hy2-hk, DIRECT]
    use: [airport]
`
	cfg, errs := ParseClashConfig([]byte(doc), "clash")
	if len(errs) != 0 {
		t.Fatalf("errs = %v, want none", errs)
	}
	if len(cfg.Groups) != 1 {
		t.Fatalf("groups = %+v, want one", cfg.Groups)
	}
	g := cfg.Groups[0]
	if want := []string{"hy2-hk", "direct"}; !reflect.DeepEqual(g.Members, want) {
		t.Fatalf("members = %v, want %v", g.Members, want)
	}
	if want := []string{"airport"}; !reflect.DeepEqual(g.Providers, want) {
		t.Fatalf("providers = %v, want %v", g.Providers, want)
	}
}

// TestClashGroupWithNeitherMembersNorUse: a group that names nothing at all is
// still an empty group and is still reported — the provider change only stops a
// group with a provider from being dropped.
func TestClashGroupWithNeitherMembersNorUse(t *testing.T) {
	doc := `
proxies:
  - name: "hy2-hk"
    type: vless
    server: hk.example.net
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
proxy-groups:
  - name: empty
    type: select
    proxies: []
  - name: bare
    type: select
`
	cfg, errs := ParseClashConfig([]byte(doc), "clash")
	if len(cfg.Groups) != 0 {
		t.Fatalf("groups = %+v, want none", cfg.Groups)
	}
	joined := ""
	for _, e := range errs {
		joined += e.Error() + "\n"
	}
	if len(errs) != 2 || strings.Count(joined, "no members") != 2 {
		t.Fatalf("errs = %v, want one no-members error per empty group", errs)
	}
}

// TestClashProviderSectionShapes: an absent or bare section is "no providers",
// while a section of the wrong shape is reported without costing the document.
func TestClashProviderSectionShapes(t *testing.T) {
	const base = `
proxies:
  - name: "hy2-hk"
    type: vless
    server: hk.example.net
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
`
	for _, doc := range []string{base, base + "proxy-providers:\n", base + "proxy-providers: {}\n"} {
		cfg, errs := ParseClashConfig([]byte(doc), "clash")
		if len(errs) != 0 {
			t.Fatalf("%q: errs = %v, want none", doc, errs)
		}
		if len(cfg.Providers) != 0 || len(cfg.Nodes) != 1 {
			t.Fatalf("%q: cfg = %+v, want the node and no providers", doc, cfg)
		}
	}

	cfg, errs := ParseClashConfig([]byte(base+"proxy-providers: not-a-mapping\n"), "clash")
	if len(cfg.Nodes) != 1 || len(cfg.Providers) != 0 {
		t.Fatalf("cfg = %+v, want the node imported and no providers", cfg)
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "proxy-providers") {
		t.Fatalf("errs = %v, want one about the section shape", errs)
	}
}

// groupTags lists the tags of groups in import order.
func groupTags(groups []config.Group) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		out = append(out, g.Tag)
	}
	return out
}

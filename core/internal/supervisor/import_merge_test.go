package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"veil/internal/config"
	"veil/internal/rpc"
)

// clashDoc is one placeholder hysteria2 proxy plus whatever routing sections a
// test wants a document to state. The proxy sits on loopback port 9, so a
// group that resolves to it cannot be dialled: a test that wants observable
// traffic gives the group DIRECT as a member instead.
func clashDoc(extra string) string {
	return "proxies:\n" +
		"  - name: \"hy2-hk\"\n" +
		"    type: hysteria2\n" +
		"    server: 127.0.0.1\n" +
		"    port: 9\n" +
		"    password: placeholder\n" + extra
}

func groupTags(groups []config.Group) []string {
	out := make([]string, len(groups))
	for i, g := range groups {
		out[i] = g.Tag
	}
	return out
}

func groupByTag(t *testing.T, groups []config.Group, tag string) config.Group {
	t.Helper()
	for _, g := range groups {
		if g.Tag == tag {
			return g
		}
	}
	t.Fatalf("group %q not found in %v", tag, groupTags(groups))
	return config.Group{}
}

// TestMergedGroupOrderPutsDependenciesFirst is S16: the stored selector points at
// a group the pasted profile brings with it. Each half is valid on its own, so
// only the order of the *merged* set decides whether the engine can build the
// parent at all — it builds groups in one pass and drops the ones whose member
// does not exist yet.
func TestMergedGroupOrderPutsDependenciesFirst(t *testing.T) {
	echoAddr := startEchoOn(t, "127.0.0.1")
	sup := newRuleSupervisor(t)
	cfg := sup.Config()
	cfg.Groups = []config.Group{{Tag: "parent", Type: "select", Members: []string{"child"}}}
	if _, err := sup.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if _, err := sup.Import(rpc.ImportParams{
		Text: clashDoc("proxy-groups:\n" +
			"  - name: child\n" +
			"    type: select\n" +
			"    proxies: [DIRECT]\n" +
			"rules:\n" +
			"  - MATCH,parent\n"),
		Source: "clash",
	}); err != nil {
		t.Fatalf("Import: %v", err)
	}

	want := []string{"child", "parent"}
	if got := groupTags(sup.Config().Groups); !reflect.DeepEqual(got, want) {
		t.Fatalf("stored group order = %v, want %v (a group must follow the groups it lists)", got, want)
	}
	// The engine's build order is the stored order, so it has to survive a save.
	reopened, err := New(sup.cfgPath, sup.log)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := groupTags(reopened.Config().Groups); !reflect.DeepEqual(got, want) {
		t.Fatalf("persisted group order = %v, want %v", got, want)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx, -1); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sup.Stop(context.Background())

	now := map[string]string{}
	for _, g := range sup.Groups() {
		now[g.Tag] = g.Now
	}
	if now["parent"] != "child" {
		t.Fatalf("engine groups = %v, want the parent built over its child", now)
	}
	if !socksCarried(t, sup.Status().Inbounds[0].Addr, echoAddr, "through-parent") {
		t.Fatal("the merged parent group did not carry a connection")
	}
}

// TestRoutingSectionsClearOnlyWhenStated is S18: an explicitly empty section is a
// statement ("this profile has no rules"), a missing section is silence ("leave
// what is stored alone"). Both arrive at the merger as an empty slice, so the
// presence bits are the whole difference.
func TestRoutingSectionsClearOnlyWhenStated(t *testing.T) {
	t.Run("explicit empty rules clears the table", func(t *testing.T) {
		sup := newRuleSupervisor(t)
		if before := sup.Config().Rules; len(before) == 0 {
			t.Fatal("fixture has no rules to clear")
		}
		res, err := sup.Import(rpc.ImportParams{Text: clashDoc("rules: []\n"), Source: "clash"})
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		if got := sup.Config().Rules; len(got) != 0 {
			t.Fatalf("rules = %+v, want an empty table", got)
		}
		if res.Rules != 0 {
			t.Fatalf("ImportResult.Rules = %d, want 0", res.Rules)
		}
		if !hasWarning(res, "empty rules list") {
			t.Fatalf("clearing the table was not reported: %v", res.Warnings)
		}
	})

	t.Run("missing rules keeps the table", func(t *testing.T) {
		sup := newRuleSupervisor(t)
		before := append([]config.Rule(nil), sup.Config().Rules...)
		if _, err := sup.Import(rpc.ImportParams{Text: clashDoc(""), Source: "clash"}); err != nil {
			t.Fatalf("Import: %v", err)
		}
		if got := sup.Config().Rules; !reflect.DeepEqual(got, before) {
			t.Fatalf("rules =\n%+v\nwant the stored table\n%+v", got, before)
		}
	})

	t.Run("explicit empty group list drops curated groups", func(t *testing.T) {
		sup := newRuleSupervisor(t)
		cfg := sup.Config()
		cfg.Groups = []config.Group{{Tag: "curated", Type: "select", Members: []string{"direct"}}}
		if _, err := sup.SetConfig(cfg); err != nil {
			t.Fatalf("SetConfig: %v", err)
		}
		if _, err := sup.Import(rpc.ImportParams{Text: clashDoc("proxy-groups: []\n"), Source: "clash"}); err != nil {
			t.Fatalf("Import: %v", err)
		}
		if got := groupTags(sup.Config().Groups); len(got) != 0 {
			t.Fatalf("groups = %v, want none", got)
		}
	})

	t.Run("missing group list keeps stored groups", func(t *testing.T) {
		sup := newRuleSupervisor(t)
		cfg := sup.Config()
		cfg.Groups = []config.Group{{Tag: "curated", Type: "select", Members: []string{"direct"}}}
		if _, err := sup.SetConfig(cfg); err != nil {
			t.Fatalf("SetConfig: %v", err)
		}
		if _, err := sup.Import(rpc.ImportParams{Text: clashDoc(""), Source: "clash"}); err != nil {
			t.Fatalf("Import: %v", err)
		}
		if got := groupTags(sup.Config().Groups); !reflect.DeepEqual(got, []string{"curated"}) {
			t.Fatalf("groups = %v, want the stored group", got)
		}
	})
}

// TestNodeImportGrowsOnlyGeneratedGroups is S19: a group the user or a profile
// defined keeps the members it was given — its membership *is* the routing
// decision for fallback/url-test — while the generated selector keeps collecting
// whatever is imported later.
func TestNodeImportGrowsOnlyGeneratedGroups(t *testing.T) {
	const (
		alpha = "vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443#alpha"
		beta  = "vless://11111111-2222-3333-4444-555555555555@3.3.3.3:443#beta"
	)

	t.Run("generated selector collects every node", func(t *testing.T) {
		sup := newRuleSupervisor(t)
		if _, err := sup.Import(rpc.ImportParams{Text: alpha}); err != nil {
			t.Fatalf("Import alpha: %v", err)
		}
		if _, err := sup.Import(rpc.ImportParams{Text: beta}); err != nil {
			t.Fatalf("Import beta: %v", err)
		}
		groups := sup.Config().Groups
		if len(groups) != 1 {
			t.Fatalf("groups = %v, want exactly the generated selector", groupTags(groups))
		}
		proxy := groupByTag(t, groups, config.AutoGroupTag)
		if !proxy.Auto {
			t.Fatal("the generated selector is not marked auto, so a later import would stop growing it")
		}
		if want := []string{"alpha", "beta"}; !reflect.DeepEqual(proxy.Members, want) {
			t.Fatalf("selector members = %v, want %v", proxy.Members, want)
		}
		// The marker is what makes the behaviour survive a restart, so it has to
		// reach the file, not just memory.
		raw, err := os.ReadFile(sup.cfgPath)
		if err != nil {
			t.Fatalf("read config: %v", err)
		}
		if !strings.Contains(string(raw), `"auto": true`) {
			t.Fatalf("persisted config has no auto marker:\n%s", raw)
		}
		reopened, err := New(sup.cfgPath, sup.log)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		if g := groupByTag(t, reopened.Config().Groups, config.AutoGroupTag); !g.Auto {
			t.Fatal("the auto marker did not survive a reload")
		}
	})

	t.Run("a client that drops the marker does not freeze the selector", func(t *testing.T) {
		// What the UI does today: it models the configuration itself, so a field
		// it does not know is dropped when it sends the config back.
		sup := newRuleSupervisor(t)
		if _, err := sup.Import(rpc.ImportParams{Text: alpha}); err != nil {
			t.Fatalf("Import alpha: %v", err)
		}
		stripped := sup.Config()
		stripped.Groups[0].Auto = false
		if _, err := sup.SetConfig(stripped); err != nil {
			t.Fatalf("SetConfig: %v", err)
		}
		if _, err := sup.Import(rpc.ImportParams{Text: beta}); err != nil {
			t.Fatalf("Import beta: %v", err)
		}
		proxy := groupByTag(t, sup.Config().Groups, config.AutoGroupTag)
		if want := []string{"alpha", "beta"}; !reflect.DeepEqual(proxy.Members, want) {
			t.Fatalf("selector members after a stripped round-trip = %v, want %v", proxy.Members, want)
		}
	})

	t.Run("curated group keeps its membership", func(t *testing.T) {
		sup := newRuleSupervisor(t)
		if _, err := sup.Import(rpc.ImportParams{
			Text: clashDoc("proxy-groups:\n" +
				"  - name: only-reject\n" +
				"    type: fallback\n" +
				"    proxies: [REJECT]\n" +
				"rules:\n" +
				"  - MATCH,only-reject\n"),
			Source: "clash",
		}); err != nil {
			t.Fatalf("Import profile: %v", err)
		}
		if _, err := sup.Import(rpc.ImportParams{Text: alpha}); err != nil {
			t.Fatalf("Import alpha: %v", err)
		}
		groups := sup.Config().Groups
		curated := groupByTag(t, groups, "only-reject")
		if curated.Auto {
			t.Fatal("a group imported from a profile was marked auto")
		}
		if want := []string{"reject"}; !reflect.DeepEqual(curated.Members, want) {
			t.Fatalf("curated members = %v, want %v (the fallback target must not move)", curated.Members, want)
		}
		// The generated selector in the same configuration still grows, so this
		// is a distinction between groups and not a blanket freeze.
		if proxy := groupByTag(t, groups, config.AutoGroupTag); !contains(proxy.Members, "alpha") {
			t.Fatalf("generated selector members = %v, want alpha appended", proxy.Members)
		}
	})
}

// TestSubscriptionAppliesGroupsAndRules is S4: a subscription URL is one more
// door for a document, so the groups and rules it carries have to be merged the
// same way a pasted profile's are. A link-list subscription stays node-only.
func TestSubscriptionAppliesGroupsAndRules(t *testing.T) {
	var body atomic.Value
	body.Store(routingYAML())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body.Load().(string))
	}))
	defer srv.Close()

	t.Run("import urls", func(t *testing.T) {
		sup := newRuleSupervisor(t)
		res, err := sup.Import(rpc.ImportParams{URLs: []string{srv.URL}, Source: "sub"})
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		if res.Added != 1 || res.Groups != 2 || res.Rules != 3 {
			t.Fatalf("ImportResult = %+v, want 1 node, 2 groups, 3 rules", res)
		}
		groups := sup.Config().Groups
		if got := groupByTag(t, groups, "homelab-wg").Members; !reflect.DeepEqual(got, []string{"direct", "hy2-hk"}) {
			t.Fatalf("homelab-wg members = %v", got)
		}
		wantRules := []config.Rule{
			{Type: "domain-suffix", Value: "localhost", Action: "direct", Source: "sub"},
			{Type: "ip-cidr", Value: "127.0.0.1/32", Action: "homelab-wg", NoResolve: true, Source: "sub"},
			{Type: "final", Action: "选择代理", Source: "sub"},
		}
		if got := sup.Config().Rules; !reflect.DeepEqual(got, wantRules) {
			t.Fatalf("rules =\n%+v\nwant\n%+v", got, wantRules)
		}
	})

	t.Run("sub_add and sub_update", func(t *testing.T) {
		sup := newRuleSupervisor(t)
		ctx := context.Background()
		params, err := json.Marshal(rpc.SubParams{Name: "s", URL: srv.URL})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, err := sup.Call(ctx, rpc.MethodSubAdd, params); err != nil {
			t.Fatalf("sub_add: %v", err)
		}
		if got := groupTags(sup.Config().Groups); !reflect.DeepEqual(got, []string{"homelab-wg", "选择代理"}) {
			// The generated selector is only created when a config has no groups
			// at all; here the document arrives together with the first nodes, so
			// the count itself is the assertion that the groups were merged.
			t.Fatalf("groups after sub_add = %v", got)
		}

		body.Store(clashDoc("proxy-groups:\n" +
			"  - name: only-reject\n" +
			"    type: fallback\n" +
			"    proxies: [REJECT]\n" +
			"rules:\n" +
			"  - MATCH,only-reject\n"))
		update, err := json.Marshal(rpc.SubUpdateParams{Name: "s"})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, err := sup.Call(ctx, rpc.MethodSubUpdate, update); err != nil {
			t.Fatalf("sub_update: %v", err)
		}
		groups := sup.Config().Groups
		if got := groupByTag(t, groups, "only-reject").Members; !reflect.DeepEqual(got, []string{"reject"}) {
			t.Fatalf("only-reject members = %v", got)
		}
		wantRules := []config.Rule{{Type: "final", Action: "only-reject", Source: "s"}}
		if got := sup.Config().Rules; !reflect.DeepEqual(got, wantRules) {
			t.Fatalf("rules after sub_update =\n%+v\nwant\n%+v", got, wantRules)
		}
	})
}

// TestImportResultReportsGroupsAndRules is S5: the UI shows what an import did,
// so the counts (and the warnings) have to be the real ones and their JSON names
// have to stay put.
func TestImportResultReportsGroupsAndRules(t *testing.T) {
	sup := newRuleSupervisor(t)
	res, err := sup.Import(rpc.ImportParams{Text: routingYAML(), Source: "clash"})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if res.Groups != 2 || res.Rules != 3 {
		t.Fatalf("ImportResult = %+v, want 2 groups and 3 rules", res)
	}

	blob, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(blob, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for field, want := range map[string]float64{"groups": 2, "rules": 3} {
		got, ok := wire[field]
		if !ok {
			t.Fatalf("ImportResult JSON misses %q: %s", field, blob)
		}
		if got != want {
			t.Fatalf("ImportResult JSON %q = %v, want %v", field, got, want)
		}
	}

	// A node-only import contributes no routing entries, and says so instead of
	// leaving the fields out.
	only := newRuleSupervisor(t)
	link, err := only.Import(rpc.ImportParams{Text: "vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443#alpha"})
	if err != nil {
		t.Fatalf("Import link: %v", err)
	}
	if link.Groups != 0 || link.Rules != 0 {
		t.Fatalf("link ImportResult = %+v, want zero groups and rules", link)
	}
	blob, err = json.Marshal(link)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(blob), `"groups":0`) || !strings.Contains(string(blob), `"rules":0`) {
		t.Fatalf("ImportResult JSON = %s, want explicit zero counts", blob)
	}

	// Warnings travel with the result so the UI can explain a surprising table.
	empty, err := only.Import(rpc.ImportParams{Text: clashDoc("rules: []\n"), Source: "clash"})
	if err != nil {
		t.Fatalf("Import empty rules: %v", err)
	}
	if !hasWarning(empty, "empty rules list") {
		t.Fatalf("warnings = %v, want the cleared-table note", empty.Warnings)
	}
}

// TestImportWhileRunningMakesNewGroupsUsable is S6 from the supervisor's side:
// an import while the engine is up goes through Reload, not a restart, so the
// new groups have to be visible and routable afterwards.
func TestImportWhileRunningMakesNewGroupsUsable(t *testing.T) {
	echoAddr := startEchoOn(t, "127.0.0.1")
	sup := newRuleSupervisor(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx, -1); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sup.Stop(context.Background())
	if got := groupTags(sup.Config().Groups); len(got) != 0 {
		t.Fatalf("groups before import = %v, want none", got)
	}
	inbound := sup.Status().Inbounds[0].Addr

	res, err := sup.Import(rpc.ImportParams{Text: routingYAML(), Source: "clash"})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if res.Groups != 2 || res.Rules != 3 {
		t.Fatalf("ImportResult = %+v", res)
	}

	now := map[string]string{}
	for _, g := range sup.Groups() {
		now[g.Tag] = g.Now
	}
	if now["homelab-wg"] != "direct" || now["选择代理"] != "reject" {
		t.Fatalf("engine groups after reload = %v, want both imported groups", now)
	}
	// The rule table changed too: the subnet goes to the selector whose member is
	// DIRECT, and nothing else matches except the final, which refuses.
	if !socksCarried(t, inbound, echoAddr, "reloaded-rule") {
		t.Fatal("the imported rule did not survive the reload")
	}
}

func hasWarning(res rpc.ImportResult, want string) bool {
	for _, w := range res.Warnings {
		if strings.Contains(w, want) {
			return true
		}
	}
	return false
}

// TestOrderGroupsKeepsCyclesAndReportsThem pins the part of the ordering that is
// a judgement call: a member cycle cannot be ordered at all, so the merge keeps
// both groups and says why one of them will not be built.
func TestOrderGroupsKeepsCyclesAndReportsThem(t *testing.T) {
	groups := []config.Group{
		{Tag: "a", Type: "select", Members: []string{"b"}},
		{Tag: "b", Type: "select", Members: []string{"a"}},
	}
	ordered, warnings := orderGroups(groups)
	if len(ordered) != 2 {
		t.Fatalf("ordered = %v, want both groups kept", groupTags(ordered))
	}
	if len(warnings) == 0 {
		t.Fatal("a member cycle was ordered silently")
	}
	// Not a cycle: the dependency is moved in front, and order is stable.
	ordered, warnings = orderGroups([]config.Group{
		{Tag: "top", Type: "select", Members: []string{"mid"}},
		{Tag: "leaf", Type: "select", Members: []string{"direct"}},
		{Tag: "mid", Type: "select", Members: []string{"leaf"}},
	})
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if got := groupTags(ordered); !reflect.DeepEqual(got, []string{"leaf", "mid", "top"}) {
		t.Fatalf("ordered = %v, want leaf, mid, top", got)
	}
}

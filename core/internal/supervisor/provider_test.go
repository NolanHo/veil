package supervisor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"veil/internal/config"
	"veil/internal/rpc"
	"veil/internal/state"
)

// An airport profile keeps its nodes outside the document: `proxy-providers:`
// says where they live and the group that routes collects them with `use:`. The
// tests here feed the real import path a real document served by a real HTTP
// server, so the whole chain runs — parse, store, fetch, expand — and the group
// that every rule in the profile names ends up with the members it takes to route
// traffic.

// providerServer serves one node list and counts the fetches, so a test can tell
// "the provider was downloaded again" from "it was left alone".
type providerServer struct {
	*httptest.Server
	mu   sync.Mutex
	body string
	hits int
}

func newProviderServer(t *testing.T, body string) *providerServer {
	t.Helper()
	s := &providerServer{body: body}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		body := s.body
		s.hits++
		s.mu.Unlock()
		w.Header().Set("Content-Type", "text/yaml")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *providerServer) setBody(body string) {
	s.mu.Lock()
	s.body = body
	s.mu.Unlock()
}

func (s *providerServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

// airportBody is what an airport serves: a Clash node list with the names the
// profile filters on. vless keeps the body free of protocol credentials.
func airportBody(tags ...string) string {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i, tag := range tags {
		// One port per node: the parser folds two nodes with the same endpoint
		// and credentials into one, and a real airport serves distinct endpoints.
		fmt.Fprintf(&b, "  - name: %q\n    type: vless\n    server: 127.0.0.1\n    port: %d\n"+
			"    uuid: 6f4d3f2e-1c1b-4a49-8b3a-000000000001\n", tag, 10443+i)
	}
	return b.String()
}

// airportProfile is the owner's profile shape: no inline node at all, one
// provider, and the selector plus the catch-all rule addressing a group that
// collects the provider through `use:`.
func airportProfile(providerURL string, providerLines ...string) string {
	var b strings.Builder
	b.WriteString("proxy-providers:\n  airport:\n    type: http\n")
	fmt.Fprintf(&b, "    url: %s\n", providerURL)
	for _, line := range providerLines {
		b.WriteString("    " + line + "\n")
	}
	b.WriteString(`
proxy-groups:
  - name: 选择代理
    type: select
    use: [airport]
rules:
  - DOMAIN-SUFFIX,example.com,选择代理
  - MATCH,选择代理
`)
	return b.String()
}

// groupByTag returns one stored group.
func storedGroup(cfg config.Config, tag string) (config.Group, bool) {
	for _, g := range cfg.Groups {
		if g.Tag == tag {
			return g, true
		}
	}
	return config.Group{}, false
}

// TestImportExpandsProviderIntoUsedGroup is acceptance 1: a document whose only
// node source is a `proxy-providers:` entry, with a `use:` group, imports to a
// group that has the provider's nodes, and its rules address that group.
func TestImportExpandsProviderIntoUsedGroup(t *testing.T) {
	srv := newProviderServer(t, airportBody("airport-hk-1", "airport-hk-2", "airport-jp-1"))
	sup := newRuleSupervisor(t)

	res, err := sup.Import(rpc.ImportParams{Text: airportProfile(srv.URL), Source: "clash"})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("warnings = %v, want none", res.Warnings)
	}
	if got := srv.count(); got != 1 {
		t.Fatalf("provider fetched %d time(s), want 1", got)
	}

	cfg := sup.Config()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	group, ok := storedGroup(cfg, "选择代理")
	if !ok {
		t.Fatalf("group 选择代理 is missing; groups = %+v", cfg.Groups)
	}
	want := []string{"airport-hk-1", "airport-hk-2", "airport-jp-1"}
	if !reflect.DeepEqual(group.Members, want) {
		t.Fatalf("group members = %v, want %v", group.Members, want)
	}
	if !reflect.DeepEqual(group.Providers, []string{"airport"}) {
		t.Fatalf("group providers = %v, want [airport]", group.Providers)
	}
	// Every node the provider served is stored under its name, which is what a
	// later refresh and a later delete work off.
	if len(cfg.Nodes) != 3 {
		t.Fatalf("nodes = %+v, want the provider's three", cfg.Nodes)
	}
	for _, n := range cfg.Nodes {
		if n.Source != "airport" {
			t.Fatalf("node %q source = %q, want airport", n.Tag, n.Source)
		}
	}
	// The rule actions resolved to the group the profile named.
	wantRules := []config.Rule{
		{Type: "domain-suffix", Value: "example.com", Action: "选择代理", Source: "clash"},
		{Type: "final", Action: "选择代理", Source: "clash"},
	}
	if !reflect.DeepEqual(cfg.Rules, wantRules) {
		t.Fatalf("rules =\n%+v\nwant\n%+v", cfg.Rules, wantRules)
	}

	// The live engine has to build the group, or the rules above address an
	// outbound that does not exist: the engine drops a group with a missing
	// member without saying so.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx, -1); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sup.Stop(context.Background())
	var live *config.Group
	for _, g := range sup.Groups() {
		if g.Tag == "选择代理" {
			gg := g
			live = &config.Group{Tag: gg.Tag, Type: gg.Type, Members: memberTags(gg)}
		}
	}
	if live == nil {
		t.Fatalf("the engine did not build the provider group: %+v", sup.Groups())
	}
	if !reflect.DeepEqual(live.Members, want) {
		t.Fatalf("engine group members = %v, want %v", live.Members, want)
	}
}

// TestReimportOfSameProfileKeepsOneFetch guards the other direction of the same
// rule: a profile imported twice must not fetch an unchanged provider again, and
// must not stack its nodes.
func TestReimportOfSameProfileKeepsOneFetch(t *testing.T) {
	srv := newProviderServer(t, airportBody("airport-hk-1", "airport-hk-2"))
	sup := newRuleSupervisor(t)
	doc := airportProfile(srv.URL, "interval: 3600")
	if _, err := sup.Import(rpc.ImportParams{Text: doc, Source: "clash"}); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if _, err := sup.Import(rpc.ImportParams{Text: doc, Source: "clash"}); err != nil {
		t.Fatalf("re-import: %v", err)
	}
	if got := srv.count(); got != 1 {
		t.Fatalf("fetches after re-importing an unchanged provider = %d, want 1", got)
	}
	cfg := sup.Config()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(cfg.Providers) != 1 {
		t.Fatalf("providers = %+v, want the one definition", cfg.Providers)
	}
	if len(cfg.Nodes) != 2 {
		t.Fatalf("nodes = %+v, want the provider's two and no duplicates", cfg.Nodes)
	}
	group, ok := storedGroup(cfg, "选择代理")
	if !ok {
		t.Fatalf("group missing: %+v", cfg.Groups)
	}
	if want := []string{"airport-hk-1", "airport-hk-2"}; !reflect.DeepEqual(group.Members, want) {
		t.Fatalf("group members = %v, want %v (no duplicates)", group.Members, want)
	}
}

// memberTags turns the engine's status view back into tags.
func memberTags(g state.GroupStatus) []string {
	out := make([]string, 0, len(g.Members))
	for _, m := range g.Members {
		out = append(out, m.Tag)
	}
	return out
}

// TestProviderFilterSelectsNodes is acceptance 2: the profile's `filter` and
// `exclude-filter` decide which of the provider's nodes reach the group.
func TestProviderFilterSelectsNodes(t *testing.T) {
	srv := newProviderServer(t, airportBody("airport-hk-1", "airport-hk-9", "airport-jp-1"))
	sup := newRuleSupervisor(t)

	profile := airportProfile(srv.URL, `filter: "hk"`, `exclude-filter: "hk-9"`)
	res, err := sup.Import(rpc.ImportParams{Text: profile, Source: "clash"})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("warnings = %v, want none", res.Warnings)
	}
	cfg := sup.Config()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	group, _ := storedGroup(cfg, "选择代理")
	if want := []string{"airport-hk-1"}; !reflect.DeepEqual(group.Members, want) {
		t.Fatalf("group members = %v, want %v (filter hk, exclude hk-9)", group.Members, want)
	}
	if len(cfg.Nodes) != 1 || cfg.Nodes[0].Tag != "airport-hk-1" {
		t.Fatalf("stored nodes = %+v, want only the node the filter kept", cfg.Nodes)
	}
}

// TestProviderFetchFailureKeepsTheImport is acceptance 3: an airport that is down
// costs its members and a warning, never the import.
func TestProviderFetchFailureKeepsTheImport(t *testing.T) {
	srv := newProviderServer(t, "proxies: []\n")
	srv.Close() // a refused connection, the shape of an unreachable airport
	sup := newRuleSupervisor(t)

	res, err := sup.Import(rpc.ImportParams{Text: airportProfile(srv.URL), Source: "clash"})
	if err != nil {
		t.Fatalf("Import failed because one provider was down: %v", err)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("no warning reported for the failed provider")
	}
	joined := strings.Join(res.Warnings, "\n")
	if !strings.Contains(joined, "airport") {
		t.Fatalf("warnings do not name the provider:\n%s", joined)
	}
	if !strings.Contains(joined, "connect") && !strings.Contains(joined, "refused") &&
		!strings.Contains(joined, "EOF") {
		t.Fatalf("warnings do not carry the reason:\n%s", joined)
	}

	cfg := sup.Config()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate after a failed fetch: %v", err)
	}
	// The group and its rules survive: the provider is configured, so a later
	// refresh can still fill it, and deleting the group would delete the target
	// of every rule that names it.
	group, ok := storedGroup(cfg, "选择代理")
	if !ok {
		t.Fatalf("the group was dropped with its provider: %+v", cfg.Groups)
	}
	if len(group.Members) != 0 || !reflect.DeepEqual(group.Providers, []string{"airport"}) {
		t.Fatalf("group after failed fetch = %+v, want providers kept and no members", group)
	}
	if len(cfg.Rules) != 2 {
		t.Fatalf("rules = %+v, want the profile's two kept", cfg.Rules)
	}
	if len(cfg.Providers) != 1 || cfg.Providers[0].Name != "airport" {
		t.Fatalf("providers = %+v, want the definition stored", cfg.Providers)
	}
}

// TestProviderFileTypeWarnsAndKeepsGoing covers the other kind that cannot be
// fetched here: a file provider has no local file to read.
func TestProviderFileTypeWarnsAndKeepsGoing(t *testing.T) {
	sup := newRuleSupervisor(t)
	profile := `
proxy-providers:
  local:
    type: file
    path: ./airport.yaml
proxy-groups:
  - name: 选择代理
    type: select
    use: [local]
    proxies: [DIRECT]
rules:
  - MATCH,选择代理
`
	res, err := sup.Import(rpc.ImportParams{Text: profile, Source: "clash"})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	joined := strings.Join(res.Warnings, "\n")
	if !strings.Contains(joined, "local") || !strings.Contains(joined, "file") {
		t.Fatalf("warnings do not report the file provider:\n%s", joined)
	}
	cfg := sup.Config()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	group, ok := storedGroup(cfg, "选择代理")
	if !ok {
		t.Fatalf("group dropped: %+v", cfg.Groups)
	}
	// The inline member still routes, so the group is usable.
	if want := []string{"direct"}; !reflect.DeepEqual(group.Members, want) {
		t.Fatalf("group members = %v, want %v", group.Members, want)
	}
}

// TestDeletingProviderCleansGroupsAndRules is acceptance 4, both ways the owner
// can delete: the provider itself, and one of the nodes it brought.
func TestDeletingProviderCleansGroupsAndRules(t *testing.T) {
	t.Run("provider", func(t *testing.T) {
		srv := newProviderServer(t, airportBody("airport-hk-1", "airport-hk-2"))
		sup := newRuleSupervisor(t)
		if _, err := sup.Import(rpc.ImportParams{Text: airportProfile(srv.URL), Source: "clash"}); err != nil {
			t.Fatalf("Import: %v", err)
		}
		cfg := sup.Config()
		cfg.Providers = nil // the UI saves the configuration without it
		if _, err := sup.SetConfig(cfg); err != nil {
			t.Fatalf("SetConfig without the provider: %v", err)
		}
		got := sup.Config()
		if err := got.Validate(); err != nil {
			t.Fatalf("Validate after deleting the provider: %v", err)
		}
		if len(got.Nodes) != 0 {
			t.Fatalf("the provider's nodes survived it: %+v", got.Nodes)
		}
		if _, ok := storedGroup(got, "选择代理"); ok {
			t.Fatalf("the group survived with nothing that can fill it: %+v", got.Groups)
		}
		for _, r := range got.Rules {
			if r.Action == "选择代理" {
				t.Fatalf("a rule still addresses the removed group: %+v", got.Rules)
			}
		}
	})

	t.Run("node", func(t *testing.T) {
		srv := newProviderServer(t, airportBody("airport-hk-1", "airport-hk-2"))
		sup := newRuleSupervisor(t)
		if _, err := sup.Import(rpc.ImportParams{Text: airportProfile(srv.URL), Source: "clash"}); err != nil {
			t.Fatalf("Import: %v", err)
		}
		if err := sup.Delete("airport-hk-1"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		got := sup.Config()
		if err := got.Validate(); err != nil {
			t.Fatalf("Validate after deleting a provider node: %v", err)
		}
		group, ok := storedGroup(got, "选择代理")
		if !ok {
			t.Fatalf("group dropped by a node delete: %+v", got.Groups)
		}
		if want := []string{"airport-hk-2"}; !reflect.DeepEqual(group.Members, want) {
			t.Fatalf("group members = %v, want %v", group.Members, want)
		}
	})
}

// TestProviderRefreshesOnlyWhenDue is acceptance 5: a provider whose interval has
// elapsed is fetched again and replaces its own nodes; one that is not due is left
// alone — and the refresh runs through the same one-shot pass as subscriptions,
// so nothing here needs a timer.
func TestProviderRefreshesOnlyWhenDue(t *testing.T) {
	srv := newProviderServer(t, airportBody("airport-hk-1", "airport-hk-2"))
	sup := newRuleSupervisor(t)
	profile := airportProfile(srv.URL, "interval: 3600")
	if _, err := sup.Import(rpc.ImportParams{Text: profile, Source: "clash"}); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if got := srv.count(); got != 1 {
		t.Fatalf("fetches after import = %d, want 1", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Not due: the import just fetched it.
	sup.refreshDueSubscriptions(ctx)
	sup.loops.Wait()
	if got := srv.count(); got != 1 {
		t.Fatalf("fetches after a not-yet-due refresh = %d, want 1", got)
	}

	// Make it due by moving the recorded fetch an interval into the past, then
	// serve a different node list: the refresh must replace the provider's nodes
	// and nothing else.
	srv.setBody(airportBody("airport-sg-1", "airport-sg-2", "airport-sg-3"))
	sup.mu.Lock()
	rec := sup.providerFetched["airport"]
	rec.at = time.Now().Add(-2 * time.Hour)
	sup.providerFetched["airport"] = rec
	sup.mu.Unlock()

	sup.refreshDueSubscriptions(ctx)
	sup.loops.Wait()
	if got := srv.count(); got != 2 {
		t.Fatalf("fetches after the interval elapsed = %d, want 2", got)
	}

	cfg := sup.Config()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate after refresh: %v", err)
	}
	group, ok := storedGroup(cfg, "选择代理")
	if !ok {
		t.Fatalf("group disappeared on refresh: %+v", cfg.Groups)
	}
	want := []string{"airport-sg-1", "airport-sg-2", "airport-sg-3"}
	if !reflect.DeepEqual(group.Members, want) {
		t.Fatalf("group members after refresh = %v, want %v", group.Members, want)
	}
	var tags []string
	for _, n := range cfg.Nodes {
		if n.Source != "airport" {
			t.Fatalf("node %q source = %q, want airport", n.Tag, n.Source)
		}
		tags = append(tags, n.Tag)
	}
	if !reflect.DeepEqual(tags, want) {
		t.Fatalf("stored nodes after refresh = %v, want %v (the old ones replaced)", tags, want)
	}
}

// TestProviderRefetchOnStartRefillsEmptyGroup covers the recovery path: a start
// after a failed fetch downloads the provider again and fills the group, without
// a second import.
func TestProviderRefetchOnStartRefillsEmptyGroup(t *testing.T) {
	srv := newProviderServer(t, airportBody("airport-hk-1"))
	// No interval: the definition alone does not ask for periodic refreshes,
	// but a provider this run never fetched is still due once.
	sup := newRuleSupervisor(t)
	if _, err := sup.Import(rpc.ImportParams{Text: airportProfile(srv.URL), Source: "clash"}); err != nil {
		t.Fatalf("Import: %v", err)
	}
	// Simulate the failed first fetch by dropping what it brought.
	cfg := sup.Config()
	cfg.Nodes = nil
	if _, err := sup.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	sup.mu.Lock()
	delete(sup.providerFetched, "airport")
	sup.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup.refreshDueSubscriptions(ctx)
	sup.loops.Wait()

	got := sup.Config()
	group, ok := storedGroup(got, "选择代理")
	if !ok {
		t.Fatalf("group disappeared: %+v", got.Groups)
	}
	if want := []string{"airport-hk-1"}; !reflect.DeepEqual(group.Members, want) {
		t.Fatalf("group members = %v, want %v", group.Members, want)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestProviderNodeTagCollisionIsRenamed pins the tag rule for the third place
// nodes arrive from: a provider node whose name another source already holds is
// stored under a disambiguated name, and the group collects the renamed tag.
func TestProviderNodeTagCollisionIsRenamed(t *testing.T) {
	srv := newProviderServer(t, airportBody("airport-hk-1", "airport-hk-2"))
	sup := newRuleSupervisor(t)

	// A subscription already owns the name airport-hk-1.
	if _, err := sup.Import(rpc.ImportParams{
		Text:   "vless://6f4d3f2e-1c1b-4a49-8b3a-00000000000f@127.0.0.1:8443?type=tcp#airport-hk-1",
		Source: "sub",
	}); err != nil {
		t.Fatalf("first import: %v", err)
	}
	res, err := sup.Import(rpc.ImportParams{Text: airportProfile(srv.URL), Source: "clash"})
	if err != nil {
		t.Fatalf("provider import: %v", err)
	}
	joined := strings.Join(res.Warnings, "\n")
	if !strings.Contains(joined, "airport-hk-1") {
		t.Fatalf("the rename was not reported:\n%s", joined)
	}

	cfg := sup.Config()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	const renamed = "airport-hk-1 (airport)"
	sources := map[string]string{}
	for _, n := range cfg.Nodes {
		sources[n.Tag] = n.Source
	}
	if sources["airport-hk-1"] != "sub" {
		t.Fatalf("the subscription lost its tag: %+v", cfg.Nodes)
	}
	if sources[renamed] != "airport" {
		t.Fatalf("the provider node was not stored under a disambiguated tag: %+v", cfg.Nodes)
	}
	group, ok := storedGroup(cfg, "选择代理")
	if !ok {
		t.Fatalf("group missing: %+v", cfg.Groups)
	}
	if want := []string{renamed, "airport-hk-2"}; !reflect.DeepEqual(group.Members, want) {
		t.Fatalf("group members = %v, want %v", group.Members, want)
	}
}

// TestUndefinedProviderWarnsAndKeepsGroup covers the `use:` list naming a provider
// the configuration does not define: the import says so and the group survives,
// because the rules address it by tag.
func TestUndefinedProviderWarnsAndKeepsGroup(t *testing.T) {
	sup := newRuleSupervisor(t)
	profile := `
proxy-groups:
  - name: 选择代理
    type: select
    use: [airport]
rules:
  - DOMAIN-SUFFIX,example.com,选择代理
  - MATCH,选择代理
`
	res, err := sup.Import(rpc.ImportParams{Text: profile, Source: "clash"})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	joined := strings.Join(res.Warnings, "\n")
	if !strings.Contains(joined, "airport") {
		t.Fatalf("the missing provider was not reported:\n%s", joined)
	}
	cfg := sup.Config()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	group, ok := storedGroup(cfg, "选择代理")
	if !ok {
		t.Fatalf("the group was dropped instead of reported: %+v", cfg.Groups)
	}
	if len(group.Members) != 0 || !reflect.DeepEqual(group.Providers, []string{"airport"}) {
		t.Fatalf("group = %+v, want the use: reference kept for a later provider", group)
	}
	for _, r := range cfg.Rules {
		if r.Action != "选择代理" {
			t.Fatalf("rules were rewritten around the missing provider: %+v", cfg.Rules)
		}
	}
}

// TestProviderOnlyRulesProfileGetsGeneratedSelector covers the profile that has
// no `proxy-groups:` at all: the merge sees no node (they are all behind the
// provider) and must not store an empty generated selector, while the selector it
// creates once the provider lands has to hold those nodes.
func TestProviderOnlyRulesProfileGetsGeneratedSelector(t *testing.T) {
	srv := newProviderServer(t, airportBody("airport-hk-1", "airport-hk-2"))
	doc := fmt.Sprintf(`
proxy-providers:
  airport:
    type: http
    url: %s
rules:
  - DOMAIN-SUFFIX,example.com,DIRECT
  - MATCH,DIRECT
`, srv.URL)
	sup := newRuleSupervisor(t)
	res, err := sup.Import(rpc.ImportParams{Text: doc, Source: "clash"})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("warnings = %v, want none", res.Warnings)
	}
	cfg := sup.Config()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(cfg.Groups) != 1 || cfg.Groups[0].Tag != config.AutoGroupTag || !cfg.Groups[0].Auto {
		t.Fatalf("groups = %+v, want only the generated selector", cfg.Groups)
	}
	want := []string{"airport-hk-1", "airport-hk-2"}
	if !reflect.DeepEqual(cfg.Groups[0].Members, want) {
		t.Fatalf("generated selector members = %v, want %v", cfg.Groups[0].Members, want)
	}
}

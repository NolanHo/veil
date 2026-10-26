package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"veil/internal/config"
	"veil/internal/rpc"
)

// subServer serves one Clash document per URL path, so a test can run two
// subscriptions and change one of them without touching the other.
type subServer struct {
	mu     sync.Mutex
	bodies map[string]string
	srv    *httptest.Server
}

func newSubServer(t *testing.T) *subServer {
	t.Helper()
	s := &subServer{bodies: make(map[string]string)}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		body, ok := s.bodies[r.URL.Path]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *subServer) set(path, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bodies[path] = body
}

func (s *subServer) url(path string) string { return s.srv.URL + path }

// subCall drives the subscription RPCs the way the UI does, so the tests below
// exercise the real entry points and not just the helpers behind them.
func subCall(t *testing.T, sup *Supervisor, method string, params any) {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal %s params: %v", method, err)
	}
	if _, err := sup.Call(context.Background(), method, raw); err != nil {
		t.Fatalf("%s: %v", method, err)
	}
}

func subAdd(t *testing.T, sup *Supervisor, name, url string) {
	t.Helper()
	subCall(t, sup, rpc.MethodSubAdd, rpc.SubParams{Name: name, URL: url})
}

func subUpdate(t *testing.T, sup *Supervisor, name string) {
	t.Helper()
	subCall(t, sup, rpc.MethodSubUpdate, rpc.SubUpdateParams{Name: name})
}

func subDelete(t *testing.T, sup *Supervisor, name string) {
	t.Helper()
	subCall(t, sup, rpc.MethodSubDelete, rpc.SubUpdateParams{Name: name})
}

// docFor renames the placeholder proxy in clashDoc, so a test can install two
// subscriptions without their node tags colliding.
func docFor(name, extra string) string {
	return strings.Replace(clashDoc(extra), "hy2-hk", name, 1)
}

// ruleValues flattens a rule table so an assertion about order reads as the
// order itself. The final rule has no value, so its action is the whole of it.
func ruleValues(rules []config.Rule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		if r.Type == "final" {
			out = append(out, "final:"+r.Action)
			continue
		}
		out = append(out, r.Type+":"+r.Value+"->"+r.Action)
	}
	return out
}

// writeRules adds hand-written rules above the table's catch-all, which is where
// a reachable rule belongs: below it nothing can match.
func writeRules(cfg config.Config, rules ...config.Rule) config.Config {
	at := finalIndex(cfg.Rules)
	out := make([]config.Rule, 0, len(cfg.Rules)+len(rules))
	out = append(out, cfg.Rules[:at]...)
	out = append(out, rules...)
	out = append(out, cfg.Rules[at:]...)
	cfg.Rules = out
	return cfg
}

func sourcesOf(rules []config.Rule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.Source
	}
	return out
}

// TestSubscriptionRefreshReplacesOnlyItsOwnRows is acceptance (a): a refresh
// replaces the three rules and the group the subscription brought last time with
// the two rules and the group it brings now, and the hand-written rule and
// hand-built group are still there afterwards.
func TestSubscriptionRefreshReplacesOnlyItsOwnRows(t *testing.T) {
	srv := newSubServer(t)
	srv.set("/a", clashDoc("proxy-groups:\n"+
		"  - name: sub-a\n"+
		"    type: select\n"+
		"    proxies: [DIRECT]\n"+
		"rules:\n"+
		"  - DOMAIN,a1.test,DIRECT\n"+
		"  - DOMAIN,a2.test,DIRECT\n"+
		"  - MATCH,sub-a\n"))

	sup := newRuleSupervisor(t)
	subAdd(t, sup, "A", srv.url("/a"))

	// What the user wrote while the subscription was installed: one rule and one
	// group of their own.
	cfg := sup.Config()
	cfg = writeRules(cfg, config.Rule{Type: "domain-suffix", Value: "mine.test", Action: "direct"})
	cfg.Groups = append(cfg.Groups, config.Group{Tag: "mine", Type: "select", Members: []string{"direct"}})
	if _, err := sup.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig(hand-written rows): %v", err)
	}

	// The provider now serves two rules and a differently named group.
	srv.set("/a", clashDoc("proxy-groups:\n"+
		"  - name: sub-a2\n"+
		"    type: select\n"+
		"    proxies: [DIRECT]\n"+
		"rules:\n"+
		"  - DOMAIN,b1.test,DIRECT\n"+
		"  - MATCH,sub-a2\n"))
	subUpdate(t, sup, "A")

	wantRules := []string{
		"domain:b1.test->direct",
		"domain-suffix:mine.test->direct",
		"final:sub-a2",
	}
	if got := ruleValues(sup.Config().Rules); !reflect.DeepEqual(got, wantRules) {
		t.Fatalf("rules after refresh =\n%v\nwant\n%v", got, wantRules)
	}
	wantSources := []string{"A", "", "A"}
	if got := sourcesOf(sup.Config().Rules); !reflect.DeepEqual(got, wantSources) {
		t.Fatalf("rule sources after refresh = %v, want %v", got, wantSources)
	}

	groups := map[string]config.Group{}
	for _, g := range sup.Config().Groups {
		if _, dup := groups[g.Tag]; dup {
			t.Fatalf("group %q appears twice", g.Tag)
		}
		groups[g.Tag] = g
	}
	if _, still := groups["sub-a"]; still {
		t.Fatalf("the group the subscription no longer defines is still stored: %v", groupTags(sup.Config().Groups))
	}
	if got := groups["sub-a2"].Source; got != "A" {
		t.Fatalf("sub-a2 source = %q, want %q", got, "A")
	}
	if got := groups["mine"].Source; got != "" {
		t.Fatalf("the hand-built group was labelled with source %q", got)
	}
}

// TestDeleteSubscriptionRemovesOnlyItsRows is acceptance (b): deleting a
// subscription takes its rules and groups with it, keeps the user's rows and
// the other subscription's, and leaves a configuration Validate accepts.
func TestDeleteSubscriptionRemovesOnlyItsRows(t *testing.T) {
	srv := newSubServer(t)
	srv.set("/a", clashDoc("proxy-groups:\n"+
		"  - name: sub-a\n"+
		"    type: select\n"+
		"    proxies: [DIRECT]\n"+
		"rules:\n"+
		"  - DOMAIN,a1.test,DIRECT\n"+
		"  - MATCH,sub-a\n"))
	srv.set("/b", docFor("hy2-b", "proxy-groups:\n"+
		"  - name: sub-b\n"+
		"    type: select\n"+
		"    proxies: [DIRECT]\n"+
		"rules:\n"+
		"  - DOMAIN,b1.test,DIRECT\n"))

	sup := newRuleSupervisor(t)
	subAdd(t, sup, "A", srv.url("/a"))
	subAdd(t, sup, "B", srv.url("/b"))

	cfg := sup.Config()
	cfg = writeRules(cfg, config.Rule{Type: "domain-suffix", Value: "mine.test", Action: "direct"})
	cfg.Groups = append(cfg.Groups, config.Group{Tag: "mine", Type: "select", Members: []string{"direct"}})
	if _, err := sup.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig(hand-written rows): %v", err)
	}
	if before := ruleValues(sup.Config().Rules); !contains(before, "domain:b1.test->direct") {
		t.Fatalf("subscription B's rule was not stored: %v", before)
	}

	subDelete(t, sup, "A")

	cfg = sup.Config()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config is invalid after deleting the subscription: %v", err)
	}
	wantRules := []string{
		"domain:b1.test->direct",
		"domain-suffix:mine.test->direct",
	}
	if got := ruleValues(cfg.Rules); !reflect.DeepEqual(got, wantRules) {
		t.Fatalf("rules after delete =\n%v\nwant\n%v", got, wantRules)
	}
	for _, r := range cfg.Rules {
		if r.Source == "A" {
			t.Fatalf("rule %+v survived the delete of its subscription", r)
		}
	}
	tags := groupTags(cfg.Groups)
	for _, gone := range []string{"sub-a"} {
		if contains(tags, gone) {
			t.Fatalf("group %q survived the delete of its subscription: %v", gone, tags)
		}
	}
	for _, kept := range []string{"sub-b", "mine"} {
		if !contains(tags, kept) {
			t.Fatalf("group %q was removed by another subscription's delete: %v", kept, tags)
		}
	}
	// The same configuration has to survive a reload, not just hold in memory.
	reopened, err := New(sup.cfgPath, sup.log)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := ruleValues(reopened.Config().Rules); !reflect.DeepEqual(got, wantRules) {
		t.Fatalf("persisted rules after delete =\n%v\nwant\n%v", got, wantRules)
	}
}

// TestRefreshKeepsLegacyRowsWithoutSource is acceptance (c): a configuration
// written before rows carried a source cannot tell a subscription's old rules
// from the user's, and the safe reading is "these are the user's": a refresh
// must leave them alone.
func TestRefreshKeepsLegacyRowsWithoutSource(t *testing.T) {
	srv := newSubServer(t)
	srv.set("/a", clashDoc("rules:\n  - DOMAIN,a1.test,DIRECT\n"))

	sup := newRuleSupervisor(t)
	cfg := sup.Config()
	cfg.Subscriptions = []config.Subscription{{Name: "A", URL: srv.url("/a"), Interval: 86400}}
	cfg.Rules = []config.Rule{
		{Type: "domain-suffix", Value: "legacy1.test", Action: "direct"},
		{Type: "domain-suffix", Value: "legacy2.test", Action: "direct"},
		{Type: "final"},
	}
	if _, err := sup.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig(legacy rows): %v", err)
	}

	subUpdate(t, sup, "A")

	wantRules := []string{
		"domain-suffix:legacy1.test->direct",
		"domain-suffix:legacy2.test->direct",
		"domain:a1.test->direct",
		"final:",
	}
	if got := ruleValues(sup.Config().Rules); !reflect.DeepEqual(got, wantRules) {
		t.Fatalf("rules after refreshing a legacy config =\n%v\nwant\n%v", got, wantRules)
	}
	wantSources := []string{"", "", "A", ""}
	if got := sourcesOf(sup.Config().Rules); !reflect.DeepEqual(got, wantSources) {
		t.Fatalf("rule sources = %v, want %v (legacy rows must stay hand-written)", got, wantSources)
	}
}

// TestRefreshKeepsHandWrittenRuleOrder is acceptance (d): the subscription's
// block keeps its place in the table, so a refresh leaves the hand-written rules
// in their order and ahead of the subscription's rules.
func TestRefreshKeepsHandWrittenRuleOrder(t *testing.T) {
	srv := newSubServer(t)
	srv.set("/a", clashDoc("rules:\n"+
		"  - DOMAIN,a1.test,DIRECT\n"+
		"  - DOMAIN,a2.test,DIRECT\n"+
		"  - MATCH,DIRECT\n"))

	sup := newRuleSupervisor(t)
	cfg := sup.Config()
	cfg.Rules = []config.Rule{
		{Type: "domain-suffix", Value: "m1.test", Action: "direct"},
		{Type: "domain-keyword", Value: "m2", Action: "reject"},
		{Type: "domain", Value: "m3.test", Action: "direct"},
		{Type: "final"},
	}
	if _, err := sup.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig(hand-written rows): %v", err)
	}
	subAdd(t, sup, "A", srv.url("/a"))

	// Sanity: on the first refresh the subscription's rules are stored above the
	// catch-all, or none of them could ever match.
	if got := ruleValues(sup.Config().Rules); got[len(got)-1] != "final:direct" {
		t.Fatalf("rules after add = %v, want the catch-all last", got)
	}

	srv.set("/a", clashDoc("rules:\n"+
		"  - DOMAIN,b1.test,DIRECT\n"+
		"  - MATCH,DIRECT\n"))
	subUpdate(t, sup, "A")

	wantRules := []string{
		"domain-suffix:m1.test->direct",
		"domain-keyword:m2->reject",
		"domain:m3.test->direct",
		"domain:b1.test->direct",
		"final:direct",
	}
	if got := ruleValues(sup.Config().Rules); !reflect.DeepEqual(got, wantRules) {
		t.Fatalf("rules after refresh =\n%v\nwant the hand-written rules in their order, then the refreshed block\n%v", got, wantRules)
	}
}

// TestSubscriptionRefreshReroutesLiveTraffic is the end-to-end counterpart of
// the table assertions above: after a refresh the engine must route by the rules
// the new document states, while a rule the user wrote keeps working.
func TestSubscriptionRefreshReroutesLiveTraffic(t *testing.T) {
	carriedEcho := startEchoOn(t, "127.0.0.1")
	manualEcho := startEchoOn(t, "127.0.0.2")

	srv := newSubServer(t)
	srv.set("/a", clashDoc("proxy-groups:\n"+
		"  - name: sub-a\n"+
		"    type: select\n"+
		"    proxies: [DIRECT]\n"+
		"  - name: sub-off\n"+
		"    type: select\n"+
		"    proxies: [REJECT]\n"+
		"rules:\n"+
		"  - IP-CIDR,127.0.0.1/32,sub-a,no-resolve\n"+
		"  - MATCH,sub-a\n"))

	sup := newRuleSupervisor(t)
	subAdd(t, sup, "A", srv.url("/a"))

	// One rule of the user's own, sent to the group that carries.
	cfg := sup.Config()
	cfg = writeRules(cfg, config.Rule{Type: "ip-cidr", Value: "127.0.0.2/32", Action: "sub-a", NoResolve: true})
	if _, err := sup.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig(hand-written rule): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx, -1); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sup.Stop(context.Background())
	inbound := sup.Status().Inbounds[0].Addr

	if !socksCarried(t, inbound, carriedEcho, "before-refresh") {
		t.Fatal("the subscription's first rule did not carry the subnet before the refresh")
	}

	// The provider moves the subnet to the group that refuses.
	srv.set("/a", clashDoc("proxy-groups:\n"+
		"  - name: sub-a\n"+
		"    type: select\n"+
		"    proxies: [DIRECT]\n"+
		"  - name: sub-off\n"+
		"    type: select\n"+
		"    proxies: [REJECT]\n"+
		"rules:\n"+
		"  - IP-CIDR,127.0.0.1/32,sub-off,no-resolve\n"+
		"  - MATCH,sub-off\n"))
	subUpdate(t, sup, "A")

	if socksCarried(t, inbound, carriedEcho, "after-refresh") {
		t.Fatal("after the refresh the subnet is still carried by the subscription's old rule")
	}
	if !socksCarried(t, inbound, manualEcho, "hand-written-rule") {
		t.Fatal("the hand-written rule stopped routing after a subscription refresh")
	}
}

// TestPasteImportStillOwnsTheTable pins the half of the semantics this change
// deliberately leaves alone: a pasted profile states a complete rule table, so it
// replaces the table — including rows a subscription and the user contributed.
func TestPasteImportStillOwnsTheTable(t *testing.T) {
	srv := newSubServer(t)
	srv.set("/a", clashDoc("rules:\n  - DOMAIN,a1.test,DIRECT\n"))

	sup := newRuleSupervisor(t)
	subAdd(t, sup, "A", srv.url("/a"))
	cfg := sup.Config()
	cfg = writeRules(cfg, config.Rule{Type: "domain-suffix", Value: "mine.test", Action: "direct"})
	if _, err := sup.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig(hand-written rule): %v", err)
	}

	if _, err := sup.Import(rpc.ImportParams{
		Text:   clashDoc("rules:\n  - DOMAIN,pasted.test,DIRECT\n"),
		Source: "paste",
	}); err != nil {
		t.Fatalf("Import: %v", err)
	}

	// The document has no MATCH, so the app's own placeholder final is appended;
	// it carries no source because the document did not say it.
	wantRules := []string{
		"domain:pasted.test->direct",
		"final:",
	}
	if got := ruleValues(sup.Config().Rules); !reflect.DeepEqual(got, wantRules) {
		t.Fatalf("rules after paste import =\n%v\nwant the whole table replaced\n%v", got, wantRules)
	}
	wantSources := []string{"paste", ""}
	if got := sourcesOf(sup.Config().Rules); !reflect.DeepEqual(got, wantSources) {
		t.Fatalf("rule sources = %v, want %v", got, wantSources)
	}
}

// TestRefreshKeepsTheUsersFinalRule pins the one placement the merge refuses to
// make on its own: when the stored table already falls through to a target the
// user picked, a subscription's MATCH rule does not take that slot over.
func TestRefreshKeepsTheUsersFinalRule(t *testing.T) {
	srv := newSubServer(t)
	srv.set("/a", clashDoc("rules:\n"+
		"  - DOMAIN,a1.test,DIRECT\n"+
		"  - MATCH,DIRECT\n"))

	sup := newRuleSupervisor(t)
	cfg := sup.Config()
	cfg.Groups = []config.Group{{Tag: "mine", Type: "select", Members: []string{"direct"}}}
	cfg.Rules = []config.Rule{{Type: "final", Action: "mine"}}
	if _, err := sup.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig(user final): %v", err)
	}

	subAdd(t, sup, "A", srv.url("/a"))

	wantRules := []string{
		"domain:a1.test->direct",
		"final:mine",
	}
	if got := ruleValues(sup.Config().Rules); !reflect.DeepEqual(got, wantRules) {
		t.Fatalf("rules =\n%v\nwant the user's final to stay the fallback\n%v", got, wantRules)
	}
	if got := sourcesOf(sup.Config().Rules); got[1] != "" {
		t.Fatalf("the user's final rule was labelled with source %q", got[1])
	}
}

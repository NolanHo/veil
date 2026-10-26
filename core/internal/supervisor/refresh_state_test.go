package supervisor

import (
	"reflect"
	"strings"
	"testing"

	"veil/internal/config"
	"veil/internal/logx"
	"veil/internal/rpc"
)

// logsContain reports whether the supervisor's ring buffer holds a line with
// want. Warnings travel through the log rather than an RPC reply on the refresh
// path, so this is how a test observes them.
func logsContain(sup *Supervisor, want string) bool {
	for _, e := range sup.log.Snapshot(0, 512) {
		if strings.Contains(e.Msg, want) {
			return true
		}
	}
	return false
}

// TestRefreshKeepsTheUsersSelection is acceptance (1a): the group tag is the
// group's identity, so a refreshed document that redefines the same tag must
// inherit the member the user pinned. Before this, mergeRoutingTable dropped the
// source's old groups and inserted the new ones, which zeroed Selected — and
// with the refresh-on-start path that reset the user's choice every day.
func TestRefreshKeepsTheUsersSelection(t *testing.T) {
	srv := newSubServer(t)
	srv.set("/a", clashDoc("proxy-groups:\n"+
		"  - name: pick\n"+
		"    type: select\n"+
		"    proxies: [DIRECT, hy2-hk]\n"))

	sup := newRuleSupervisor(t)
	subAdd(t, sup, "A", srv.url("/a"))
	subCall(t, sup, rpc.MethodSelect, rpc.SelectParams{Group: "pick", Tag: "direct"})
	if got := groupByTag(t, sup.Config().Groups, "pick").Selected; got != "direct" {
		t.Fatalf("Select did not pin the group: Selected = %q", got)
	}

	// The provider serves the same group again, as a daily refresh would.
	subUpdate(t, sup, "A")

	if got := groupByTag(t, sup.Config().Groups, "pick").Selected; got != "direct" {
		t.Fatalf("Selected after a refresh = %q, want %q (the pin must survive a refresh)", got, "direct")
	}
	// The pin is stored state, so it has to reach the file too.
	reopened, err := New(sup.cfgPath, sup.log)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := groupByTag(t, reopened.Config().Groups, "pick").Selected; got != "direct" {
		t.Fatalf("persisted Selected = %q, want %q", got, "direct")
	}
}

// TestRefreshClearsASelectionWhoseMemberIsGone is acceptance (1b): inheriting
// the pin is only valid while the member still exists. When the provider drops
// it, the selection is cleared — and said out loud, because a silently unpinned
// group changes where the user's traffic exits.
func TestRefreshClearsASelectionWhoseMemberIsGone(t *testing.T) {
	srv := newSubServer(t)
	srv.set("/a", docFor("hy2-a", "proxy-groups:\n"+
		"  - name: pick\n"+
		"    type: select\n"+
		"    proxies: [DIRECT, hy2-a]\n"))

	sup := newRuleSupervisor(t)
	sup.log.SetLevel(logx.Warn)
	subAdd(t, sup, "A", srv.url("/a"))
	subCall(t, sup, rpc.MethodSelect, rpc.SelectParams{Group: "pick", Tag: "hy2-a"})

	// The provider drops the pinned node from the group.
	srv.set("/a", docFor("hy2-a", "proxy-groups:\n"+
		"  - name: pick\n"+
		"    type: select\n"+
		"    proxies: [DIRECT]\n"))
	subUpdate(t, sup, "A")

	pick := groupByTag(t, sup.Config().Groups, "pick")
	if want := []string{"direct"}; !reflect.DeepEqual(pick.Members, want) {
		t.Fatalf("pick members = %v, want %v", pick.Members, want)
	}
	if pick.Selected != "" {
		t.Fatalf("Selected = %q, want empty: the pinned member is gone", pick.Selected)
	}
	if !logsContain(sup, "selection was cleared") {
		t.Fatalf("clearing the selection was not reported, log = %v", sup.log.Snapshot(0, 512))
	}
}

// TestPastedGroupWithTheGeneratedNameKeepsCollectingNodes is acceptance (1c) for
// the auto marker: a document that redefines the generated selector channel
// (same tag) keeps Auto, so a later import still lands in it instead of freezing
// the group as user-curated.
func TestPastedGroupWithTheGeneratedNameKeepsCollectingNodes(t *testing.T) {
	const (
		alpha = "vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443#alpha"
		beta  = "vless://11111111-2222-3333-4444-555555555555@3.3.3.3:443#beta"
	)

	sup := newRuleSupervisor(t)
	if _, err := sup.Import(rpc.ImportParams{Text: alpha}); err != nil {
		t.Fatalf("Import alpha: %v", err)
	}
	// An unnamed paste that redefines the generated selector by tag.
	if _, err := sup.Import(rpc.ImportParams{Text: clashDoc("proxy-groups:\n" +
		"  - name: " + config.AutoGroupTag + "\n" +
		"    type: select\n" +
		"    proxies: [alpha, DIRECT]\n")}); err != nil {
		t.Fatalf("Import profile: %v", err)
	}
	if got := groupByTag(t, sup.Config().Groups, config.AutoGroupTag); !got.Auto {
		t.Fatalf("the redefined selector lost its auto marker: %+v", got)
	}

	if _, err := sup.Import(rpc.ImportParams{Text: beta}); err != nil {
		t.Fatalf("Import beta: %v", err)
	}
	proxy := groupByTag(t, sup.Config().Groups, config.AutoGroupTag)
	if !contains(proxy.Members, "beta") {
		t.Fatalf("selector members = %v, want beta appended (the selector froze)", proxy.Members)
	}
}

// TestMergeInheritsSelectionAndAutoByTag pins the merge contract underneath the
// probes above, so a regression shows up here and not only through the RPC path.
func TestMergeInheritsSelectionAndAutoByTag(t *testing.T) {
	cfg := config.Default()
	cfg.Groups = []config.Group{{
		Tag:      "pick",
		Type:     "select",
		Members:  []string{"direct"},
		Selected: "direct",
		Auto:     true,
	}}
	table := routingTable{
		GroupsProvided: true,
		Groups:         []config.Group{{Tag: "pick", Type: "select", Members: []string{"direct", "hy2"}}},
	}
	// An unnamed document speaks for the user, so it redefines the tag in place
	// (a named one would be disambiguated; see resolveIncomingTags).
	_, _, warnings := mergeRoutingTable(&cfg, table, routingOrigin{OwnsTable: true})
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	got := groupByTag(t, cfg.Groups, "pick")
	if got.Selected != "direct" || !got.Auto {
		t.Fatalf("merged group = %+v, want Selected %q and Auto true inherited by tag", got, "direct")
	}
}

// TestRefreshClearsASelectionTheNodeListDropped covers the other way a pin loses
// its member: the document still lists it in the group, but stopped defining the
// node. The membership rebuild removes it after the merge, so the selection has
// to be cleaned up after that, not only at merge time.
func TestRefreshClearsASelectionTheNodeListDropped(t *testing.T) {
	srv := newSubServer(t)
	srv.set("/a", docFor("hy2-a", "proxy-groups:\n"+
		"  - name: pick\n"+
		"    type: select\n"+
		"    proxies: [DIRECT, hy2-a]\n"))

	sup := newRuleSupervisor(t)
	sup.log.SetLevel(logx.Warn)
	subAdd(t, sup, "A", srv.url("/a"))
	subCall(t, sup, rpc.MethodSelect, rpc.SelectParams{Group: "pick", Tag: "hy2-a"})

	// The provider renames its node and forgets to update the group.
	srv.set("/a", docFor("hy2-b", "proxy-groups:\n"+
		"  - name: pick\n"+
		"    type: select\n"+
		"    proxies: [DIRECT, hy2-a]\n"))
	subUpdate(t, sup, "A")

	pick := groupByTag(t, sup.Config().Groups, "pick")
	if want := []string{"direct"}; !reflect.DeepEqual(pick.Members, want) {
		t.Fatalf("pick members = %v, want %v", pick.Members, want)
	}
	if pick.Selected != "" {
		t.Fatalf("Selected = %q, want empty: the pinned node is gone", pick.Selected)
	}
	if !logsContain(sup, "selection was cleared") {
		t.Fatalf("clearing the selection was not reported, log = %v", sup.log.Snapshot(0, 512))
	}
}

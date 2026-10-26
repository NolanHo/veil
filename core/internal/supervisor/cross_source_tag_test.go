package supervisor

import (
	"context"
	"reflect"
	"testing"

	"veil/internal/config"
	"veil/internal/rpc"
)

// sameDocument, pasted first and subscribed afterwards, carries a node, a group
// that collects it, and a rule that sends a name to it.
const collisionDoc = "proxy-groups:\n" +
	"  - name: pick\n" +
	"    type: select\n" +
	"    proxies: [hy2-hk]\n" +
	"rules:\n" +
	"  - DOMAIN,node.test,hy2-hk\n" +
	"  - MATCH,pick\n"

func nodeByTag(t *testing.T, nodes []config.Node, tag string) config.Node {
	t.Helper()
	for _, n := range nodes {
		if n.Tag == tag {
			return n
		}
	}
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = n.Tag
	}
	t.Fatalf("node %q not found in %v", tag, out)
	return config.Node{}
}

// TestSubscribingToADocumentThatWasAlreadyPasted is acceptance (2): the pasted
// copy owns "hy2-hk", so the subscription's copy needs a tag of its own instead
// of an import that fails validation forever. `sub_add` used to commit the
// subscription entry and then fail with `duplicate outbound tag "hy2-hk"`, so
// every retry failed the same way and the subscription could never be used.
func TestSubscribingToADocumentThatWasAlreadyPasted(t *testing.T) {
	srv := newSubServer(t)
	srv.set("/a", clashDoc(collisionDoc))

	sup := newRuleSupervisor(t)
	res, err := sup.Import(rpc.ImportParams{Text: clashDoc(collisionDoc)})
	if err != nil {
		t.Fatalf("Import (paste): %v", err)
	}
	if res.Failed != 0 {
		t.Fatalf("the paste reported %d failure(s): %v", res.Failed, res.Errors)
	}
	if want := []string{"hy2-hk"}; !reflect.DeepEqual(res.Tags, want) {
		t.Fatalf("pasted tags = %v, want %v", res.Tags, want)
	}

	// The probe: the same document again, this time as a subscription.
	subAdd(t, sup, "A", srv.url("/a"))

	cfg := sup.Config()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the configuration is invalid after subscribing: %v", err)
	}
	pasted := nodeByTag(t, cfg.Nodes, "hy2-hk")
	if pasted.Source != "" {
		t.Fatalf("the pasted node was overwritten by source %q", pasted.Source)
	}
	subscribed := nodeByTag(t, cfg.Nodes, "hy2-hk (A)")
	if subscribed.Source != "A" {
		t.Fatalf("the subscription's node carries source %q, want %q", subscribed.Source, "A")
	}

	// The subscription's own rows must address its own node, not the pasted one.
	if got := groupByTag(t, cfg.Groups, "pick (A)").Members; !reflect.DeepEqual(got, []string{"hy2-hk (A)"}) {
		t.Fatalf("pick (A) members = %v, want the renamed node", got)
	}
	if got := groupByTag(t, cfg.Groups, "pick").Members; !reflect.DeepEqual(got, []string{"hy2-hk"}) {
		t.Fatalf("the pasted group's members = %v, want the pasted node", got)
	}
	for _, r := range cfg.Rules {
		if r.Source != "A" || r.Type != "domain" {
			continue
		}
		if r.Action != "hy2-hk (A)" {
			t.Fatalf("the subscription's rule points at %q, want its own node", r.Action)
		}
	}

	// A second refresh must land on the same tags and must still succeed: the
	// generated tag is derived from the source, not from an arrival counter.
	before := nodeTags(sup.Config().Nodes)
	subUpdate(t, sup, "A")
	again := sup.Config()
	if after := nodeTags(again.Nodes); !reflect.DeepEqual(after, before) {
		t.Fatalf("node tags after a second refresh = %v, want %v", after, before)
	}
	if got := groupTags(again.Groups); !reflect.DeepEqual(got, []string{"proxy", "pick", "pick (A)"}) {
		t.Fatalf("groups after a second refresh = %v, want the generated selector and both pick groups", got)
	}
}

// TestImportingTheSameDocumentTwiceUnderOneSourceKeepsUpdating is the other half
// of the rule: within one source a repeated tag still means "update", so the
// disambiguation must not fire there.
func TestImportingTheSameDocumentTwiceUnderOneSourceKeepsUpdating(t *testing.T) {
	sup := newRuleSupervisor(t)
	for i := 0; i < 2; i++ {
		res, err := sup.Import(rpc.ImportParams{Text: clashDoc(collisionDoc), Source: "clash"})
		if err != nil {
			t.Fatalf("Import #%d: %v", i+1, err)
		}
		if i == 1 && (res.Added != 0 || res.Updated != 1) {
			t.Fatalf("re-import of one source = %+v, want the node updated in place", res)
		}
	}
	if got := nodeTags(sup.Config().Nodes); !reflect.DeepEqual(got, []string{"hy2-hk"}) {
		t.Fatalf("node tags = %v, want the single node updated", got)
	}
}

// TestTwoSubscriptionsKeepTheirOwnGroupOfTheSameName is acceptance (3): two
// subscriptions that both define `shared` each own a group, and deleting one
// leaves the other's groups and rules untouched. Before this, B took A's group
// over by tag; deleting B then removed the group and pruneRouting took A's rules
// with it, leaving the user with no routing at all.
func TestTwoSubscriptionsKeepTheirOwnGroupOfTheSameName(t *testing.T) {
	srv := newSubServer(t)
	srv.set("/a", docFor("hy2-a", "proxy-groups:\n"+
		"  - name: shared\n"+
		"    type: select\n"+
		"    proxies: [DIRECT]\n"+
		"  - name: refuse\n"+
		"    type: select\n"+
		"    proxies: [REJECT]\n"+
		"rules:\n"+
		"  - DOMAIN,a.test,shared\n"+
		"  - MATCH,refuse\n"))
	srv.set("/b", docFor("hy2-b", "proxy-groups:\n"+
		"  - name: shared\n"+
		"    type: select\n"+
		"    proxies: [REJECT]\n"+
		"rules:\n"+
		"  - DOMAIN,b.test,shared\n"+
		"  - MATCH,shared\n"))

	sup := newRuleSupervisor(t)
	subAdd(t, sup, "A", srv.url("/a"))
	subAdd(t, sup, "B", srv.url("/b"))

	cfg := sup.Config()
	if got := groupByTag(t, cfg.Groups, "shared"); got.Source != "A" || !reflect.DeepEqual(got.Members, []string{"direct"}) {
		t.Fatalf("group shared = %+v, want the group of A over direct", got)
	}
	if got := groupByTag(t, cfg.Groups, "shared (B)"); got.Source != "B" || !reflect.DeepEqual(got.Members, []string{"reject"}) {
		t.Fatalf("group shared (B) = %+v, want the group of B over reject", got)
	}
	// Each rule still addresses the group its own document defines.
	wantRules := []string{
		"domain:a.test->shared",
		"domain:b.test->shared (B)",
		"final:refuse",
	}
	if got := ruleValues(cfg.Rules); !reflect.DeepEqual(got, wantRules) {
		t.Fatalf("rules =\n%v\nwant\n%v", got, wantRules)
	}

	// A refresh of B keeps its own tag instead of moving it again.
	subUpdate(t, sup, "B")
	if got := groupTags(sup.Config().Groups); !reflect.DeepEqual(got, []string{"shared", "refuse", "shared (B)"}) {
		t.Fatalf("groups after refreshing B = %v", got)
	}

	// Deleting B must leave A's routing whole.
	subDelete(t, sup, "B")
	cfg = sup.Config()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the configuration is invalid after deleting B: %v", err)
	}
	wantRules = []string{
		"domain:a.test->shared",
		"final:refuse",
	}
	if got := ruleValues(cfg.Rules); !reflect.DeepEqual(got, wantRules) {
		t.Fatalf("A's rules after deleting B =\n%v\nwant\n%v", got, wantRules)
	}
	if got := groupTags(cfg.Groups); !reflect.DeepEqual(got, []string{"shared", "refuse"}) {
		t.Fatalf("groups after deleting B = %v, want A's groups intact", got)
	}
	for _, r := range cfg.Rules {
		if r.Source == "B" {
			t.Fatalf("rule %+v survived the delete of its subscription", r)
		}
	}

	// And the engine still builds A's group, so the rule's target exists at
	// runtime rather than only on paper.
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
	if now["shared"] != "direct" {
		t.Fatalf("engine groups = %v, want A's shared group built over direct", now)
	}
	if _, gone := now["shared (B)"]; gone {
		t.Fatalf("engine groups = %v, want B's group gone", now)
	}
}

// nodeTags flattens the node tags in stored order.
func nodeTags(nodes []config.Node) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = n.Tag
	}
	return out
}

package supervisor

import (
	"testing"

	"veil/internal/config"
	"veil/internal/rules"
)

// subDoc is one subscription body: a placeholder node on loopback port 9 —
// nothing listens there, so a rule that sends a stream to it carries nothing —
// plus the sections the test states.
func subDoc(node, sections string) string {
	return "proxies:\n" +
		"  - name: \"" + node + "\"\n" +
		"    type: vless\n" +
		"    server: 127.0.0.1\n" +
		"    port: 9\n" +
		"    uuid: 00000000-0000-0000-0000-000000000001\n" +
		"    network: tcp\n" + sections
}

// firstRuleFor returns the first stored rule that can match domain. Rule order
// is the routing semantics ("first match wins"), so this row is the decision.
func firstRuleFor(rules []config.Rule, domain string) (config.Rule, bool) {
	for _, r := range rules {
		if r.Type == "domain" && r.Value == domain {
			return r, true
		}
	}
	return config.Rule{}, false
}

// routeDecision asks the engine's own matcher what the stored table decides for
// one domain in rule mode — the same question the engine asks per connection,
// without starting one.
func routeDecision(t *testing.T, cfg config.Config, domain string) rules.Action {
	t.Helper()
	final := ""
	for i := len(cfg.Rules) - 1; i >= 0; i-- {
		if cfg.Rules[i].Type == "final" {
			final = cfg.Rules[i].Action
			break
		}
	}
	router, err := rules.New(cfg.Rules, cfg.Mode, final)
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	return router.Match(rules.Meta{Network: "tcp", Host: domain})
}

// TestRefreshKeepsSubscriptionRulePosition is acceptance (2): a refresh replaces
// the subscription's block where that block already sits, so the relative order
// of the user's rules and the subscription's rules survives the refresh.
//
// The block has to be anchored even when the refresh itself empties it: the
// provider renames its node, and the block's rule addressed that node, so the
// prune ahead of the merge took the whole block away. The fresh rules then had
// no span to replace and landed just above the catch-all — below the user's rule
// for the same domain. That rule started winning where the subscription's rule
// had won, i.e. the same domain silently changed destination.
func TestRefreshKeepsSubscriptionRulePosition(t *testing.T) {
	srv := newSubServer(t)
	srv.set("/a", subDoc("subnode",
		"proxy-groups:\n"+
			"  - name: sub-ref\n"+
			"    type: select\n"+
			"    proxies: [REJECT]\n"+
			"rules:\n"+
			"  - DOMAIN,localhost,subnode\n"+
			"  - MATCH,sub-ref\n"))

	sup := newRuleSupervisor(t)
	subAdd(t, sup, "A", srv.url("/a"))

	// The user's own rule for the same domain, written below the subscription's
	// block and sending it to a target of their choosing.
	cfg := sup.Config()
	cfg = writeRules(cfg, config.Rule{Type: "domain", Value: "localhost", Action: "direct"})
	if _, err := sup.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig(hand-written rule): %v", err)
	}

	before, ok := firstRuleFor(sup.Config().Rules, "localhost")
	if !ok || before.Source != "A" {
		t.Fatalf("before the refresh the first rule for the domain = %+v, want the subscription's", before)
	}
	if got := routeDecision(t, sup.Config(), "localhost"); got.Outbound != "subnode" {
		t.Fatalf("before the refresh the domain routes to %q, want the subscription's rule target %q", got.Outbound, "subnode")
	}

	// The provider renames its node; the block's rule is dropped with it unless
	// the merge runs before the prune.
	srv.set("/a", subDoc("subnode2",
		"proxy-groups:\n"+
			"  - name: sub-ref\n"+
			"    type: select\n"+
			"    proxies: [REJECT]\n"+
			"rules:\n"+
			"  - DOMAIN,localhost,sub-ref\n"+
			"  - MATCH,sub-ref\n"))
	subUpdate(t, sup, "A")

	after := sup.Config()
	first, ok := firstRuleFor(after.Rules, "localhost")
	if !ok {
		t.Fatalf("after the refresh no rule addresses the domain: %v", ruleValues(after.Rules))
	}
	if first.Source != "A" {
		t.Fatalf("after the refresh the first rule for the domain is %+v (the user's), want the subscription's block in its old place: %v",
			first, ruleValues(after.Rules))
	}
	// The first match for that domain is still the subscription's decision.
	if got := routeDecision(t, after, "localhost"); got.Outbound != "sub-ref" {
		t.Fatalf("after the refresh the domain routes to %q, want %q — the subscription's block moved across the user's rule: %v",
			got.Outbound, "sub-ref", ruleValues(after.Rules))
	}
	if err := after.Validate(); err != nil {
		t.Fatalf("config is invalid after the refresh: %v", err)
	}
}

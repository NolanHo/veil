package engine

import (
	"context"
	"testing"

	"veil/internal/config"
	"veil/internal/rules"
)

// TestLazyDomainHitCostsNoQuery is acceptance (a) at the engine level: the
// first rule classifies the flow by domain, so the routing DNS server is never
// asked — the table also containing GEOIP must not matter.
func TestLazyDomainHitCostsNoQuery(t *testing.T) {
	up := newTestDNS(t, cnAddr)
	res := newTestResolver(t, up.addr())
	eng := newRouteEngine(t, []config.Rule{
		{Type: "domain-suffix", Value: "example.com", Action: "proxy"},
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "final", Action: "proxy"},
	}, res)
	// Warm the fake-IP mapping without sending a routing lookup (the tunnel DNS
	// answers it, not the upstream).
	target := fakeTarget(t, res, "www.example.com")

	ob, action, got, err := eng.route(context.Background(), "tcp", target)
	if err != nil {
		t.Fatalf("route: %v", err)
	}
	if action.Rule != "domain-suffix:example.com" || ob.Tag() != "proxy" {
		t.Fatalf("route = %s/%q, want proxy/domain-suffix:example.com", ob.Tag(), action.Rule)
	}
	if got != "www.example.com:443" {
		t.Fatalf("target = %q, want the hostname", got)
	}
	if n := up.aCount.Load(); n != 0 {
		t.Fatalf("A queries = %d, want 0: a domain rule decided the connection", n)
	}
}

// The same for a rejected flow: no dial, no lookup.
func TestLazyDomainRejectCostsNoQuery(t *testing.T) {
	up := newTestDNS(t, cnAddr)
	res := newTestResolver(t, up.addr())
	eng := newRouteEngine(t, []config.Rule{
		{Type: "domain-suffix", Value: "ads.example", Action: "reject"},
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "final", Action: "proxy"},
	}, res)

	_, _, _, err := eng.route(context.Background(), "tcp", fakeTarget(t, res, "x.ads.example"))
	if err == nil {
		t.Fatal("route returned no error, want the reject")
	}
	if n := up.aCount.Load(); n != 0 {
		t.Fatalf("A queries = %d, want 0", n)
	}
}

// Acceptance (b): a domain rule that misses must not stop GEOIP from working,
// and the lookup happens exactly once, at the IP rule.
func TestLazyGeoIPAfterDomainMissIsOneQuery(t *testing.T) {
	up := newTestDNS(t, cnAddr)
	res := newTestResolver(t, up.addr())
	eng := newRouteEngine(t, []config.Rule{
		{Type: "domain-suffix", Value: "corp.example", Action: "direct"},
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "final", Action: "proxy"},
	}, res)

	ob, action, got, err := eng.route(context.Background(), "tcp", fakeTarget(t, res, cnName))
	if err != nil {
		t.Fatalf("route: %v", err)
	}
	if action.Rule != "geoip:cn" || ob.Tag() != "direct" {
		t.Fatalf("route = %s/%q, want direct/geoip:cn", ob.Tag(), action.Rule)
	}
	if want := cnAddr.String() + ":443"; got != want {
		t.Fatalf("target = %q, want the resolved address %q", got, want)
	}
	if n := up.aCount.Load(); n != 1 {
		t.Fatalf("A queries = %d, want 1", n)
	}
}

// Acceptance (e) at the engine level: several IP rules in one walk still cost a
// single lookup.
func TestLazySeveralIPRulesOneQuery(t *testing.T) {
	up := newTestDNS(t, cnAddr)
	res := newTestResolver(t, up.addr())
	eng := newRouteEngine(t, []config.Rule{
		{Type: "ip-cidr", Value: "10.0.0.0/8", Action: "reject"},
		{Type: "ip-cidr", Value: "192.168.0.0/16", Action: "reject"},
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "final", Action: "proxy"},
	}, res)

	_, action, _, err := eng.route(context.Background(), "tcp", fakeTarget(t, res, cnName))
	if err != nil {
		t.Fatalf("route: %v", err)
	}
	if action.Rule != "geoip:cn" {
		t.Fatalf("rule = %q, want geoip:cn", action.Rule)
	}
	if n := up.aCount.Load(); n != 1 {
		t.Fatalf("A queries = %d, want 1", n)
	}
}

// A direct decision still hands the outbound a real address, not the fake one
// and not a name that only exists inside our DNS: the lookup happens at the
// dial, once, because a local dial cannot do without an address.
func TestLazyDirectDecisionResolvesForTheDial(t *testing.T) {
	up := newTestDNS(t, cnAddr)
	res := newTestResolver(t, up.addr())
	eng := newRouteEngine(t, []config.Rule{
		{Type: "domain-suffix", Value: "example.com", Action: "direct"},
		{Type: "final", Action: "proxy"},
	}, res)

	ob, action, got, err := eng.route(context.Background(), "tcp", fakeTarget(t, res, "www.example.com"))
	if err != nil {
		t.Fatalf("route: %v", err)
	}
	if action.Rule != "domain-suffix:example.com" || ob.Tag() != "direct" {
		t.Fatalf("route = %s/%q, want direct/domain-suffix:example.com", ob.Tag(), action.Rule)
	}
	if want := cnAddr.String() + ":443"; got != want {
		t.Fatalf("target = %q, want the resolved address %q", got, want)
	}
	if n := up.aCount.Load(); n != 1 {
		t.Fatalf("A queries = %d, want 1 (the dial needs an address)", n)
	}
}

// MODE DIRECT ignores the table; a fake-IP flow out of it still dials an
// address, and still costs one lookup, not zero and not two.
func TestLazyDirectModeResolvesForTheDial(t *testing.T) {
	up := newTestDNS(t, cnAddr)
	res := newTestResolver(t, up.addr())
	eng := newRouteEngine(t, []config.Rule{
		{Type: "geoip", Value: "cn", Action: "proxy"},
	}, res)
	router, err := rules.New([]config.Rule{{Type: "geoip", Value: "cn", Action: "proxy"}}, config.ModeDirect, "proxy")
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	eng.router = router

	ob, action, got, err := eng.route(context.Background(), "tcp", fakeTarget(t, res, cnName))
	if err != nil {
		t.Fatalf("route: %v", err)
	}
	if ob.Tag() != "direct" || action.Rule != "direct" {
		t.Fatalf("route = %s/%q, want direct", ob.Tag(), action.Rule)
	}
	if want := cnAddr.String() + ":443"; got != want {
		t.Fatalf("target = %q, want the resolved address %q", got, want)
	}
	if n := up.aCount.Load(); n != 1 {
		t.Fatalf("A queries = %d, want 1", n)
	}
}

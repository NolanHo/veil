package engine

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"veil/internal/config"
	"veil/internal/dns"
)

// dnsConfigFor is the DNS section a reload switches to in these tests: one plain
// UDP upstream, the same shape Start uses.
func dnsConfigFor(upstream string) config.DNSConfig {
	return config.DNSConfig{
		Enable:  true,
		Final:   "test",
		Servers: []config.DNSServer{{Tag: "test", Addr: upstream}},
	}
}

// runningForReload marks the engine as started so Reload performs the swap
// (Reload with a stopped engine only stores the config).
func runningForReload(t *testing.T, eng *Engine) {
	t.Helper()
	eng.mu.Lock()
	eng.running = true
	eng.mu.Unlock()
	t.Cleanup(func() {
		eng.mu.Lock()
		eng.running = false
		eng.mu.Unlock()
	})
}

// TestReloadKeepsFakeAddresses is acceptance 1: after a reload, the addresses the
// outgoing resolver handed out still resolve to their own domain, and the
// incoming resolver cannot reissue one of them for another name — not even when
// the outgoing resolver keeps allocating after the swap.
func TestReloadKeepsFakeAddresses(t *testing.T) {
	up := newTestDNS(t, cnAddr)
	res := newTestResolver(t, up.addr())
	eng := newRouteEngine(t, []config.Rule{
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "final", Action: "proxy"},
	}, res)
	runningForReload(t, eng)

	early := res.FakeFor(cnName)
	if !early.IsValid() {
		t.Fatal("no fake address before the reload")
	}

	cfg := eng.Config()
	cfg.DNS = dnsConfigFor(up.addr())
	if err := eng.Reload(cfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	eng.mu.RLock()
	live := eng.resolver
	eng.mu.RUnlock()
	if live == nil || live == res {
		t.Fatalf("reload kept resolver %p, want a new one", res)
	}

	// A connection that snapshotted the outgoing resolver is still being served
	// by it, and it allocates after the swap.
	late := res.FakeFor("late.test")
	next := live.FakeFor("other.test")
	if !late.IsValid() || !next.IsValid() {
		t.Fatalf("allocation failed: late=%v next=%v", late, next)
	}
	if next == early || next == late {
		t.Fatalf("the incoming resolver reissued %v (early=%v late=%v): two names, one address",
			next, early, late)
	}

	// One pool: every address maps back to its own domain whichever resolver is
	// asked, in both directions.
	for _, r := range []*dns.Resolver{res, live} {
		for ip, want := range map[netip.Addr]string{
			early: cnName,
			late:  "late.test",
			next:  "other.test",
		} {
			host, ok := r.HostFor(ip)
			if !ok || host != want {
				t.Fatalf("HostFor(%v) = %q,%v, want %q", ip, host, ok, want)
			}
		}
	}

	// A client still dialling the address it was given before the reload is
	// routed by the name that address stands for.
	for _, tc := range []struct {
		ip   netip.Addr
		want string
	}{{early, cnName}, {late, "late.test"}} {
		target := net.JoinHostPort(tc.ip.String(), "443")
		_, action, got, err := eng.route(context.Background(), "tcp", target)
		if err != nil {
			t.Fatalf("route %s after reload: %v", target, err)
		}
		if action.Rule != "geoip:cn" {
			t.Fatalf("route %s classified by %q, want geoip:cn (name %q)", target, action.Rule, tc.want)
		}
		if want := cnAddr.String() + ":443"; got != want {
			t.Fatalf("route %s dialled %q, want %q", target, got, want)
		}
	}
}

// TestReloadDropsOldRouteAnswers is acceptance 2: the same name, the same fake
// address, but after a reload that points DNS at another upstream the rule walk
// must use the new answer — the previous configuration's cached address must not
// survive the swap.
func TestReloadDropsOldRouteAnswers(t *testing.T) {
	const foreignAddr = "8.8.8.8"
	upCN := newTestDNS(t, cnAddr)
	upFar := newTestDNS(t, netip.MustParseAddr(foreignAddr))
	res := newTestResolver(t, upCN.addr())
	eng := newRouteEngine(t, []config.Rule{
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "final", Action: "proxy"},
	}, res)
	runningForReload(t, eng)

	target := fakeTarget(t, res, cnName) // the address the client already holds
	_, action, got, err := eng.route(context.Background(), "tcp", target)
	if err != nil {
		t.Fatalf("route before reload: %v", err)
	}
	if action.Rule != "geoip:cn" || got != cnAddr.String()+":443" {
		t.Fatalf("route before reload = %q/%q, want geoip:cn/%s:443", action.Rule, got, cnAddr)
	}
	if n := upCN.aCount.Load(); n != 1 {
		t.Fatalf("old upstream A queries = %d, want 1", n)
	}

	cfg := eng.Config()
	cfg.DNS = dnsConfigFor(upFar.addr())
	if err := eng.Reload(cfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	_, action, got, err = eng.route(context.Background(), "tcp", target)
	if err != nil {
		t.Fatalf("route after reload: %v", err)
	}
	if action.Rule != "final" {
		t.Fatalf("route after reload classified by %q, want final (the answer came from the new resolver)", action.Rule)
	}
	if want := foreignAddr + ":443"; got != want {
		t.Fatalf("route after reload dialled %q, want %q", got, want)
	}
	if n := upFar.aCount.Load(); n != 1 {
		t.Fatalf("new upstream A queries = %d, want 1", n)
	}
	if n := upCN.aCount.Load(); n != 1 {
		t.Fatalf("old upstream A queries = %d after reload, want still 1", n)
	}
}

// TestRouteCacheReserveIsOneDecision is acceptance 3, at the seam: "cached, or
// join a flight, or start one" is a single call, so a second caller cannot miss
// the cache and still conclude that it has to go upstream.
func TestRouteCacheReserveIsOneDecision(t *testing.T) {
	var c routeAddrCache
	gen := c.advance()
	now := time.Now()

	_, hit, f, leader := c.reserve(gen, cnName, now)
	if hit || !leader || f == nil {
		t.Fatalf("first reserve = hit=%v leader=%v flight=%v, want a new flight", hit, leader, f)
	}
	if _, hit, f2, leader := c.reserve(gen, cnName, now); hit || leader || f2 != f {
		t.Fatalf("second reserve = hit=%v leader=%v flight=%v, want to join %v", hit, leader, f2, f)
	}

	c.finish(gen, cnName, f, routeAddrEntry{
		addrs:   []netip.Addr{cnAddr},
		expires: now.Add(time.Minute),
	}, now, true)
	ent, hit, _, leader := c.reserve(gen, cnName, now)
	if !hit || leader {
		t.Fatalf("reserve after the flight = hit=%v leader=%v, want a cache hit", hit, leader)
	}
	if len(ent.addrs) != 1 || ent.addrs[0] != cnAddr {
		t.Fatalf("cached addrs = %v, want [%v]", ent.addrs, cnAddr)
	}
}

// TestRouteCacheGenerationIsolation is the other half of acceptance 2: an answer,
// and a flight's answer, belong to the generation that produced them. A reload
// makes both unreadable, and a flight that was already running when the reload
// happened cannot publish into the new generation.
func TestRouteCacheGenerationIsolation(t *testing.T) {
	var c routeAddrCache
	now := time.Now()

	gen0 := c.advance()
	f0, _ := mustLead(t, &c, gen0, cnName, now)
	c.finish(gen0, cnName, f0, routeAddrEntry{
		addrs:   []netip.Addr{cnAddr},
		expires: now.Add(time.Minute),
	}, now, true)
	if _, ok := c.get(cnName, now); !ok {
		t.Fatal("generation 0 answer was not cached")
	}

	// A reload: new generation, and a lookup that was in flight before it.
	f1, leader := mustLead(t, &c, gen0, "inflight.test", now)
	if !leader {
		t.Fatal("expected to lead the in-flight lookup")
	}
	gen1 := c.advance()
	if gen1 == gen0 {
		t.Fatalf("advance kept generation %d", gen0)
	}
	if _, ok := c.get(cnName, now); ok {
		t.Fatal("the previous generation's answer is still readable after the reload")
	}
	c.finish(gen0, "inflight.test", f1, routeAddrEntry{
		addrs:   []netip.Addr{cnAddr},
		expires: now.Add(time.Minute),
	}, now, true)
	if _, ok := c.get("inflight.test", now); ok {
		t.Fatal("a flight from the previous generation published into the new one")
	}
}

// mustLead reserves a fresh lookup and requires that the caller leads it.
func mustLead(t *testing.T, c *routeAddrCache, gen uint64, host string, now time.Time) (*routeFlight, bool) {
	t.Helper()
	_, hit, f, leader := c.reserve(gen, host, now)
	if hit || f == nil {
		t.Fatalf("reserve(%s) = hit=%v flight=%v, want a flight", host, hit, f)
	}
	return f, leader
}

// TestConcurrentLookupsAfterReloadQueryOnce is acceptance 3 end to end: sixteen
// connections dial the same name right after a reload, the routing lookup
// collapses into one upstream query, and every decision agrees.
func TestConcurrentLookupsAfterReloadQueryOnce(t *testing.T) {
	up := newTestDNS(t, cnAddr)
	res := newTestResolver(t, up.addr())
	eng := newRouteEngine(t, []config.Rule{
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "final", Action: "proxy"},
	}, res)
	runningForReload(t, eng)

	target := fakeTarget(t, res, cnName)
	cfg := eng.Config()
	cfg.DNS = dnsConfigFor(up.addr())
	if err := eng.Reload(cfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan string, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, action, got, err := eng.route(context.Background(), "tcp", target)
			if err != nil {
				errs <- err.Error()
				return
			}
			if action.Rule != "geoip:cn" || got != cnAddr.String()+":443" {
				errs <- action.Rule + " -> " + got
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatalf("concurrent route disagreed: %s", e)
	}
	if n := up.aCount.Load(); n != 1 {
		t.Fatalf("upstream A queries = %d, want 1 (the flight must be atomic)", n)
	}
}

// TestRouteCacheWarmsAgainAfterRestart guards the generation handshake in the
// other direction: Start builds a resolver outside a reload (generation 0), and
// after a reload the table's generation is higher. A fresh resolver must still be
// able to fill the table — otherwise every connection after a restart would pay
// a DNS round trip until the next reload.
func TestRouteCacheWarmsAgainAfterRestart(t *testing.T) {
	up := newTestDNS(t, cnAddr)
	res := newTestResolver(t, up.addr())
	eng := newRouteEngine(t, []config.Rule{
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "final", Action: "proxy"},
	}, res)
	runningForReload(t, eng)

	target := fakeTarget(t, res, cnName)
	cfg := eng.Config()
	cfg.DNS = dnsConfigFor(up.addr())
	if err := eng.Reload(cfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// A resolver built outside a reload — the way Start builds one — carries no
	// generation stamp of its own, so it lands one generation behind the table.
	restarted, err := dns.NewWithPool(dnsConfigFor(up.addr()), nil, eng.routeCache.fakePool(nil))
	if err != nil {
		t.Fatalf("NewWithPool: %v", err)
	}
	if restarted.Generation() == eng.routeCache.gen {
		t.Fatalf("test setup: the restarted resolver already carries generation %d", restarted.Generation())
	}
	eng.mu.Lock()
	eng.resolver = restarted
	eng.mu.Unlock()

	if _, _, _, err := eng.route(context.Background(), "tcp", target); err != nil {
		t.Fatalf("route: %v", err)
	}
	if n := up.aCount.Load(); n != 1 {
		t.Fatalf("A queries after restart = %d, want 1", n)
	}
	if _, _, _, err := eng.route(context.Background(), "tcp", target); err != nil {
		t.Fatalf("route: %v", err)
	}
	if n := up.aCount.Load(); n != 1 {
		t.Fatalf("A queries after restart = %d, want 1: the routing cache stopped filling", n)
	}
}

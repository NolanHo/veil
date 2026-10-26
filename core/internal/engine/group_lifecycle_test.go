package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"veil/internal/config"
	"veil/internal/logx"
	"veil/internal/outbound"
)

// probeURL is a probe target that refuses immediately: a probe then costs no
// time and no network, and the test only needs to see that it happened. probeAddr
// is the address the member is asked to dial for it.
const (
	probeURL  = "http://127.0.0.1:1/generate_204"
	probeAddr = "127.0.0.1:1"
)

// countingOutbound records every address it is asked to dial and refuses, so a
// test can count probes without a socket.
type countingOutbound struct {
	tag   string
	mu    sync.Mutex
	dials map[string]int
}

func newCounting(tag string) *countingOutbound {
	return &countingOutbound{tag: tag, dials: make(map[string]int)}
}

func (o *countingOutbound) Tag() string  { return o.tag }
func (o *countingOutbound) Type() string { return "counting" }
func (o *countingOutbound) Close() error { return nil }

func (o *countingOutbound) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	o.record(address)
	return nil, errors.New("counting outbound: no dial")
}

func (o *countingOutbound) record(address string) {
	o.mu.Lock()
	o.dials[address]++
	o.mu.Unlock()
}

func (o *countingOutbound) count(address string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.dials[address]
}

// localOutbound resolves on this device, the way the built-in direct does.
type localOutbound struct{ *countingOutbound }

func (o localOutbound) DialsLocally() bool { return true }

// packetOutbound carries UDP as well, which a group's DialPacket needs.
type packetOutbound struct{ *countingOutbound }

func (o packetOutbound) DialPacket(context.Context, string) (outbound.PacketConn, error) {
	o.record("udp")
	return stubPacketConn{}, nil
}

// stubPacketConn is an association nobody reads from.
type stubPacketConn struct{}

func (stubPacketConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, errors.New("stub packet conn")
}
func (stubPacketConn) WriteTo([]byte, netip.AddrPort) (int, error) {
	return 0, errors.New("stub packet conn")
}
func (stubPacketConn) Close() error                { return nil }
func (stubPacketConn) SetDeadline(time.Time) error { return nil }

// mustGroup builds a group over obs and stops it when the test ends.
func mustGroup(t *testing.T, g config.Group, obs map[string]outbound.Outbound) *Group {
	t.Helper()
	grp, err := newGroup(g, obs, nil, logx.New(logx.Debug, 64))
	if err != nil {
		t.Fatalf("newGroup(%s): %v", g.Tag, err)
	}
	grp.setParent(context.Background())
	t.Cleanup(func() { grp.stop() })
	return grp
}

// probeState reads the probe-loop lifecycle under its lock.
func probeState(g *Group) (armed, stopped, hasCancel bool) {
	g.lifeMu.Lock()
	defer g.lifeMu.Unlock()
	return g.armed, g.stopped, g.cancel != nil
}

// waitProbes waits until ob recorded at least want dials of address.
func waitProbes(t *testing.T, ob *countingOutbound, address string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ob.count(address) >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("probe dials to %s = %d, want >= %d", address, ob.count(address), want)
}

// TestGroupFirstDialsArmOneProbeLoop is acceptance 1: many connections that
// arrive at a fresh url-test group at the same moment arm exactly one probe
// loop. Under -race it also proves the parent context of that loop is not read
// and written concurrently.
func TestGroupFirstDialsArmOneProbeLoop(t *testing.T) {
	ob := newCounting("a")
	grp := mustGroup(t, config.Group{
		Tag: "auto", Type: "url-test", Members: []string{"a"},
		URL: probeURL, Interval: 3600,
	}, map[string]outbound.Outbound{"a": ob})

	const dialers = 24
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < dialers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// The member refuses, so every dial fails; the arming before the
			// dispatch is what this test is about.
			if _, err := grp.DialContext(context.Background(), "tcp", "example.test:443"); err == nil {
				t.Errorf("dial through a refusing member succeeded")
			}
		}()
	}
	close(start)
	wg.Wait()

	waitProbes(t, ob, probeAddr, 1)
	// A second loop would tick immediately as well, so give one a chance to show
	// up before asserting the count.
	time.Sleep(150 * time.Millisecond)
	if got := ob.count(probeAddr); got != 1 {
		t.Fatalf("probe dials = %d, want exactly 1 (one probe loop for %d concurrent first dials)", got, dialers)
	}
	armed, stopped, _ := probeState(grp)
	if !armed || stopped {
		t.Fatalf("armed=%v stopped=%v, want an armed and live group", armed, stopped)
	}
	t.Logf("dialers=%d probe dials=%d armed=%v", dialers, ob.count(probeAddr), armed)
}

// TestGroupStopIsPermanent is acceptance 2: after Close (what both Engine.Stop
// and a reload do) a late dial from a connection that still holds the group must
// not create a probe loop the engine can no longer cancel.
func TestGroupStopIsPermanent(t *testing.T) {
	ob := newCounting("a")
	grp := mustGroup(t, config.Group{
		Tag: "auto", Type: "url-test", Members: []string{"a"},
		URL: probeURL, Interval: 3600,
	}, map[string]outbound.Outbound{"a": ob})

	if _, err := grp.DialContext(context.Background(), "tcp", "first.test:443"); err == nil {
		t.Fatal("dial through a refusing member succeeded")
	}
	waitProbes(t, ob, probeAddr, 1)
	before := ob.count(probeAddr)

	if err := grp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, stopped, hasCancel := probeState(grp); !stopped || hasCancel {
		t.Fatalf("after Close: stopped=%v cancel=%v, want stopped with no live loop", stopped, hasCancel)
	}

	if _, err := grp.DialContext(context.Background(), "tcp", "late.test:443"); err == nil {
		t.Fatal("dial through a refusing member succeeded")
	}
	time.Sleep(150 * time.Millisecond)
	if got := ob.count(probeAddr); got != before {
		t.Fatalf("probe dials after stop = %d, want %d unchanged", got, before)
	}
	if _, _, hasCancel := probeState(grp); hasCancel {
		t.Fatal("a dial after stop re-armed the probe loop")
	}
	t.Logf("probe dials before stop=%d after stop+redial=%d", before, ob.count(probeAddr))
}

// TestGroupStoppedBeforeFirstDial is the other half of acceptance 2, and the
// shape the old bug took: a reload stops a group nobody has dialed yet, so there
// is no loop to cancel — the stop has to be remembered anyway, or the next dial
// starts a loop that outlives the engine.
func TestGroupStoppedBeforeFirstDial(t *testing.T) {
	ob := newCounting("a")
	grp := mustGroup(t, config.Group{
		Tag: "auto", Type: "url-test", Members: []string{"a"},
		URL: probeURL, Interval: 3600,
	}, map[string]outbound.Outbound{"a": ob})

	grp.stop() // what a reload does to the group it replaces
	if _, stopped, hasCancel := probeState(grp); !stopped || hasCancel {
		t.Fatalf("after stop: stopped=%v cancel=%v, want stopped with nothing running", stopped, hasCancel)
	}

	if _, err := grp.DialContext(context.Background(), "tcp", "late.test:443"); err == nil {
		t.Fatal("dial through a refusing member succeeded")
	}
	time.Sleep(150 * time.Millisecond)
	if got := ob.count(probeAddr); got != 0 {
		t.Fatalf("probe dials = %d, want 0: a late dial re-armed a stopped group", got)
	}
	if _, _, hasCancel := probeState(grp); hasCancel {
		t.Fatal("a late dial started a probe loop on a stopped group")
	}
	t.Logf("probe dials after stop-then-dial=%d", ob.count(probeAddr))
}

// TestReloadStopsRetiredGroupForGood is acceptance 2 at the engine level: the
// group a reload retires stays retired, even though connections routed to it can
// still dial it while they unwind.
func TestReloadStopsRetiredGroupForGood(t *testing.T) {
	log := logx.New(logx.Debug, 256)
	cfg := testConfig(
		[]config.Group{{
			Tag: "auto", Type: "url-test", Members: []string{"sink"},
			URL: probeURL, Interval: 3600,
		}},
		[]config.Rule{{Type: "final", Action: "auto"}},
	)
	cfg.Nodes = []config.Node{{Tag: "sink", Type: "reject", Server: "127.0.0.1", Port: 9}}
	e := newReloadingEngine(t, cfg, log)
	if err := e.Reload(cfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	retired := e.outbounds["auto"].(*Group)
	if _, err := retired.DialContext(context.Background(), "tcp", "example.test:443"); err == nil {
		t.Fatal("dial through a rejecting member succeeded")
	}
	if armed, _, _ := probeState(retired); !armed {
		t.Fatal("the group was not armed by a user dial")
	}

	if err := e.Reload(cfg); err != nil {
		t.Fatalf("second Reload: %v", err)
	}
	if _, stopped, hasCancel := probeState(retired); !stopped || hasCancel {
		t.Fatalf("retired group: stopped=%v cancel=%v, want stopped with no live loop", stopped, hasCancel)
	}
	if _, err := retired.DialContext(context.Background(), "tcp", "late.test:443"); err == nil {
		t.Fatal("dial through a rejecting member succeeded")
	}
	if _, _, hasCancel := probeState(retired); hasCancel {
		t.Fatal("a dial re-armed the group the reload retired")
	}
	if live, ok := e.outbounds["auto"].(*Group); !ok || live == retired {
		t.Fatalf("the reload did not publish a replacement group: %v", e.outbounds["auto"])
	}
}

// TestGroupDialPacketArmsProbeLoop is acceptance 3: a group that only ever
// carries UDP is in use just as much as one carrying TCP.
func TestGroupDialPacketArmsProbeLoop(t *testing.T) {
	ob := packetOutbound{newCounting("a")}
	grp := mustGroup(t, config.Group{
		Tag: "auto", Type: "url-test", Members: []string{"a"},
		URL: probeURL, Interval: 3600,
	}, map[string]outbound.Outbound{"a": ob})

	if _, err := grp.DialPacket(context.Background(), "1.1.1.1:53"); err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	waitProbes(t, ob.countingOutbound, probeAddr, 1)
	armed, stopped, _ := probeState(grp)
	if !armed || stopped {
		t.Fatalf("armed=%v stopped=%v, want the UDP dial to arm the loop", armed, stopped)
	}
	if got := ob.count("udp"); got != 1 {
		t.Fatalf("udp dials = %d, want 1", got)
	}
	t.Logf("probe dials=%d udp dials=%d armed=%v", ob.count(probeAddr), ob.count("udp"), armed)
}

// TestSelfCheckDoesNotArmGroups is acceptance 4: Engine.Start probes the default
// outbound to prove it works, and that self-check is not user traffic. A url-test
// group reached only by it must stay asleep — no ticker, no probe, no delay
// recorded (AGENTS.md invariant 7).
func TestSelfCheckDoesNotArmGroups(t *testing.T) {
	log := logx.New(logx.Debug, 256)
	cfg := config.Default()
	cfg.Mixed = ""
	cfg.DNS.Enable = false
	// A reject node answers instantly, so the self-check needs no network.
	cfg.Nodes = []config.Node{{Tag: "sink", Type: "reject", Server: "127.0.0.1", Port: 9}}
	cfg.Groups = []config.Group{{
		Tag: "auto", Type: "url-test", Members: []string{"sink"},
		URL: probeURL, Interval: 3600,
	}}
	cfg.Rules = []config.Rule{{Type: "final", Action: "auto"}}

	e, err := New(cfg, log)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	if err := e.Start(context.Background(), -1); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = e.Stop(context.Background()) })

	selfCheckLines := func() int {
		n := 0
		for _, entry := range log.Snapshot(0, 0) {
			if strings.Contains(entry.Msg, "出站自检") {
				n++
			}
		}
		return n
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && selfCheckLines() < 3 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := selfCheckLines(); got != 3 {
		t.Fatalf("self-check lines = %d, want 3: the self-check did not run through the group", got)
	}

	grp := e.outbounds["auto"].(*Group)
	if armed, _, hasCancel := probeState(grp); armed || hasCancel {
		t.Fatalf("the self-check armed the group (armed=%v cancel=%v)", armed, hasCancel)
	}
	grp.mu.RLock()
	measured := len(grp.delays)
	grp.mu.RUnlock()
	if measured != 0 {
		t.Fatalf("probe results recorded = %d, want 0", measured)
	}
	t.Logf("self-check lines=%d armed=false probe results=%d", selfCheckLines(), measured)
}

// TestGroupDialsLocallyIsConservative is acceptance 5: a group only claims to
// dial locally when every member it could use does, because the router must not
// substitute an address into a flow a proxy member carries.
func TestGroupDialsLocallyIsConservative(t *testing.T) {
	direct, proxy, direct2 := localOutbound{newCounting("direct")}, newCounting("proxy"), localOutbound{newCounting("direct2")}
	obs := map[string]outbound.Outbound{"direct": direct, "proxy": proxy, "direct2": direct2}

	cases := []struct {
		name    string
		typ     string
		members []string
		want    bool
	}{
		{"fallback mixing direct and proxy", "fallback", []string{"direct", "proxy"}, false},
		{"fallback all local", "fallback", []string{"direct", "direct2"}, true},
		{"load-balance mixing direct and proxy", "load-balance", []string{"proxy", "direct"}, false},
		{"url-test mixing direct and proxy", "url-test", []string{"direct", "proxy"}, false},
		// A select group dials exactly the member it reports, so a mixed list
		// answers for the member that is pinned (the first one here): pinning a
		// selector to DIRECT is a normal Clash profile and used to dial nothing.
		{"select mixing direct and proxy", "select", []string{"direct", "proxy"}, true},
		{"select pinned past the direct member", "select", []string{"proxy", "direct"}, false},
		{"select all local", "select", []string{"direct", "direct2"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			grp := mustGroup(t, config.Group{Tag: "g", Type: c.typ, Members: c.members}, obs)
			got := grp.DialsLocally()
			if got != c.want {
				t.Fatalf("DialsLocally() = %v, want %v for %s over %v", got, c.want, c.typ, c.members)
			}
			t.Logf("%s %v: DialsLocally=%v", c.typ, c.members, got)
		})
	}

	// A group of groups answers for the whole set it could use: every nested
	// member dialing locally keeps the outer group's claim, one proxy anywhere in
	// the chain drops it.
	inner := mustGroup(t, config.Group{Tag: "inner", Type: "select", Members: []string{"direct", "direct2"}},
		map[string]outbound.Outbound{"direct": direct, "direct2": direct2})
	nested := mustGroup(t, config.Group{Tag: "outer", Type: "select", Members: []string{"inner", "direct"}},
		map[string]outbound.Outbound{"inner": inner, "direct": direct})
	if !nested.DialsLocally() {
		t.Fatal("a group of two local groups must dial locally")
	}
	mixed := mustGroup(t, config.Group{Tag: "outer-mixed", Type: "fallback", Members: []string{"inner", "proxy"}},
		map[string]outbound.Outbound{"inner": inner, "proxy": proxy})
	if mixed.DialsLocally() {
		t.Fatal("a group holding a proxy member must not claim to dial locally")
	}
	t.Logf("nested all-local=%v nested with proxy=%v", nested.DialsLocally(), mixed.DialsLocally())
}

// TestRouteFakeIPLocalDialWithoutAddressFails is acceptance 6: a fake address
// cannot be handed to a dial that resolves on this device, and neither can the
// name — that would reach the system resolver, which answers with the same
// placeholder. The decision must fail with the reason instead.
func TestRouteFakeIPLocalDialWithoutAddressFails(t *testing.T) {
	// An unparsable upstream makes every lookup fail at once (no timeout to wait
	// out), which is the "resolver is down" shape of the bug.
	res := newTestResolver(t, "bogus://127.0.0.1:9")
	eng := newRouteEngine(t, []config.Rule{
		{Type: "domain-suffix", Value: "example.com", Action: "direct"},
		{Type: "final", Action: "direct"},
	}, res)

	ob, _, got, err := eng.route(context.Background(), "tcp", fakeTarget(t, res, "www.example.com"))
	if err == nil {
		t.Fatalf("route succeeded with target %q through %v; a local dial has no address", got, ob)
	}
	if ob != nil {
		t.Fatalf("route returned outbound %v with the error", ob)
	}
	for _, want := range []string{"www.example.com", "dials locally", "resolve"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want it to mention %q", err, want)
		}
	}
	t.Logf("route error: %v", err)

	// The proxy side of the same pair still keeps the name: the exit node is the
	// authority for DNS, so nothing is substituted for it.
	proxyEng := newRouteEngine(t, []config.Rule{{Type: "final", Action: "proxy"}}, res)
	ob, _, target, err := proxyEng.route(context.Background(), "tcp", fakeTarget(t, res, "www.example.com"))
	if err != nil {
		t.Fatalf("route through a proxy: %v", err)
	}
	if ob.Tag() != "proxy" || target != "www.example.com:443" {
		t.Fatalf("proxy route = %s/%q, want proxy with the hostname", ob.Tag(), target)
	}
	t.Logf("proxy route keeps %q", target)
}

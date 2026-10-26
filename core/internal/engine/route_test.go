package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"veil/internal/config"
	"veil/internal/dns"
	"veil/internal/logx"
	"veil/internal/outbound"
	"veil/internal/rules"
)

// cnName is the domain every test pretends to dial; cnAddr is an address inside
// the geoip:cn snapshot in internal/rules, so `GEOIP,CN` has something to match.
const cnName = "cn.example.com"

var cnAddr = netip.MustParseAddr("223.5.5.5")

// testOutbound is an outbound that only carries its tag, so a test can tell
// which rule's action was applied.
type testOutbound struct{ tag string }

func (o testOutbound) Tag() string  { return o.tag }
func (o testOutbound) Type() string { return "test" }
func (o testOutbound) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("test outbound: no dial")
}
func (o testOutbound) Close() error { return nil }

// testDNS is a local UDP DNS server; it answers every A query with one address
// and counts the A queries that reached it, which is how the tests prove how
// many lookups actually happened.
type testDNS struct {
	pc     net.PacketConn
	srv    *mdns.Server
	aCount atomic.Int64
}

func newTestDNS(t *testing.T, answer netip.Addr) *testDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	s := &testDNS{pc: pc}
	h := mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(req)
		m.RecursionAvailable = true
		if len(req.Question) == 1 && req.Question[0].Qtype == mdns.TypeA {
			s.aCount.Add(1)
			m.Answer = append(m.Answer, &mdns.A{
				Hdr: mdns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: mdns.TypeA,
					Class:  mdns.ClassINET,
					Ttl:    60,
				},
				A: net.IP(answer.AsSlice()),
			})
		}
		_ = w.WriteMsg(m)
	})
	s.srv = &mdns.Server{PacketConn: pc, Handler: h, UDPSize: 4096}
	go func() { _ = s.srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = pc.Close() })
	return s
}

func (s *testDNS) addr() string { return s.pc.LocalAddr().String() }

// newTestResolver builds a resolver pointed at upstream. Cache is off on
// purpose: the engine's routing cache must stand on its own.
func newTestResolver(t *testing.T, upstream string) *dns.Resolver {
	t.Helper()
	r, err := dns.New(config.DNSConfig{
		Enable: true,
		Cache:  false,
		Final:  "test",
		Servers: []config.DNSServer{
			{Tag: "test", Addr: upstream},
		},
	}, logx.New(logx.Debug, 64))
	if err != nil {
		t.Fatalf("dns.New: %v", err)
	}
	return r
}

// newRouteEngine builds the smallest engine that can answer route(): a matcher,
// tagged outbounds and (optionally) a resolver. Start is not called — route()
// needs none of the sockets.
func newRouteEngine(t *testing.T, rs []config.Rule, resolver *dns.Resolver) *Engine {
	t.Helper()
	cfg := config.Default()
	cfg.Rules = rs
	// A direct-typed node needs no server, so validation accepts a tag that the
	// rules can point at.
	cfg.Nodes = []config.Node{{Tag: "proxy", Type: "direct"}}
	e, err := New(cfg, logx.New(logx.Debug, 512))
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	router, err := rules.New(rs, config.ModeRule, "proxy")
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	e.router = router
	e.resolver = resolver
	e.defaultTag = "proxy"
	e.outbounds = map[string]outbound.Outbound{
		"direct": testOutbound{"direct"},
		"proxy":  testOutbound{"proxy"},
	}
	e.defaultOB = e.outbounds["proxy"]
	return e
}

// fakeAddr asks the resolver for the fake-IP address it hands out for host, the
// same way the tunnel DNS server answers a client.
func fakeAddr(t *testing.T, r *dns.Resolver, host string) netip.Addr {
	t.Helper()
	q := new(mdns.Msg)
	q.SetQuestion(mdns.Fqdn(host), mdns.TypeA)
	raw, err := q.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	resp, err := r.Exchange(context.Background(), raw)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	var m mdns.Msg
	if err := m.Unpack(resp); err != nil {
		t.Fatalf("unpack reply: %v", err)
	}
	for _, rr := range m.Answer {
		if a, ok := rr.(*mdns.A); ok {
			addr, ok := netip.AddrFromSlice(a.A)
			if !ok {
				t.Fatalf("bad A record %v", a.A)
			}
			return addr.Unmap()
		}
	}
	t.Fatalf("no fake A record for %s: %v", host, m.Answer)
	return netip.Addr{}
}

// fakeTarget is what a client dials after the tunnel answered its DNS query.
func fakeTarget(t *testing.T, r *dns.Resolver, host string) string {
	t.Helper()
	return net.JoinHostPort(fakeAddr(t, r, host).String(), "443")
}

// TestRouteFakeIPGeoIPCN is acceptance (a): a fake-IP flow whose name resolves
// into a CN address must hit `GEOIP,CN,DIRECT` instead of falling through to
// MATCH.
func TestRouteFakeIPGeoIPCN(t *testing.T) {
	up := newTestDNS(t, cnAddr)
	res := newTestResolver(t, up.addr())
	eng := newRouteEngine(t, []config.Rule{
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "final", Action: "proxy"},
	}, res)

	ob, action, target, err := eng.route(context.Background(), "tcp", fakeTarget(t, res, cnName))
	if err != nil {
		t.Fatalf("route: %v", err)
	}
	if action.Rule != "geoip:cn" || ob.Tag() != "direct" {
		t.Fatalf("fake-ip geoip route = %s/%q, want DIRECT/geoip:cn", ob.Tag(), action.Rule)
	}
	// The outbound still receives the name: the exit node does the real lookup.
	if want := cnName + ":443"; target != want {
		t.Fatalf("target = %q, want %q", target, want)
	}
	if got := up.aCount.Load(); got != 1 {
		t.Fatalf("A queries = %d, want 1", got)
	}
}

// TestRouteFakeIPNoResolveSkips is acceptance (b): a `no-resolve` IP rule must
// neither trigger a lookup nor match the address the router would have found.
func TestRouteFakeIPNoResolveSkips(t *testing.T) {
	up := newTestDNS(t, cnAddr)
	res := newTestResolver(t, up.addr())
	eng := newRouteEngine(t, []config.Rule{
		{Type: "ip-cidr", Value: cnAddr.String() + "/32", Action: "reject", NoResolve: true},
		{Type: "final", Action: "proxy"},
	}, res)

	ob, action, _, err := eng.route(context.Background(), "tcp", fakeTarget(t, res, cnName))
	if err != nil {
		t.Fatalf("route: %v (the no-resolve rule fired)", err)
	}
	if action.Rule != "final" || ob.Tag() != "proxy" {
		t.Fatalf("route = %s/%q, want PROXY/final", ob.Tag(), action.Rule)
	}
	if got := up.aCount.Load(); got != 0 {
		t.Fatalf("A queries = %d, want 0: no-resolve must not resolve", got)
	}
}

// TestRouteNoResolveNotFedByLookup keeps the flag honest when the table also
// holds a rule that does want an address: the one lookup must not satisfy the
// no-resolve rule sitting in front of it.
func TestRouteNoResolveNotFedByLookup(t *testing.T) {
	up := newTestDNS(t, cnAddr)
	res := newTestResolver(t, up.addr())
	eng := newRouteEngine(t, []config.Rule{
		{Type: "ip-cidr", Value: cnAddr.String() + "/32", Action: "reject", NoResolve: true},
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "final", Action: "proxy"},
	}, res)

	ob, action, _, err := eng.route(context.Background(), "tcp", fakeTarget(t, res, cnName))
	if err != nil {
		t.Fatalf("route: %v (the no-resolve rule was fed by the lookup)", err)
	}
	if action.Rule != "geoip:cn" || ob.Tag() != "direct" {
		t.Fatalf("route = %s/%q, want DIRECT/geoip:cn", ob.Tag(), action.Rule)
	}
	if got := up.aCount.Load(); got != 1 {
		t.Fatalf("A queries = %d, want 1", got)
	}
}

// TestRouteFakeIPCIDRWithoutNoResolve is acceptance (c): the same rule without
// the flag matches the resolved address.
func TestRouteFakeIPCIDRWithoutNoResolve(t *testing.T) {
	up := newTestDNS(t, cnAddr)
	res := newTestResolver(t, up.addr())
	eng := newRouteEngine(t, []config.Rule{
		{Type: "ip-cidr", Value: cnAddr.String() + "/32", Action: "direct"},
		{Type: "final", Action: "proxy"},
	}, res)

	ob, action, _, err := eng.route(context.Background(), "tcp", fakeTarget(t, res, cnName))
	if err != nil {
		t.Fatalf("route: %v", err)
	}
	if want := "ip-cidr:" + cnAddr.String() + "/32"; action.Rule != want || ob.Tag() != "direct" {
		t.Fatalf("route = %s/%q, want DIRECT/%q", ob.Tag(), action.Rule, want)
	}
}

// TestRouteResolveFailureFallsThrough is acceptance (d): a dead resolver must
// not panic or abort the decision; evaluation continues with no address, the
// failure is logged at debug, and it is remembered briefly.
func TestRouteResolveFailureFallsThrough(t *testing.T) {
	// An unparsable upstream scheme makes the resolver fail immediately, which
	// keeps the test fast and deterministic (no timeout to wait out).
	res := newTestResolver(t, "bogus://127.0.0.1:9")
	eng := newRouteEngine(t, []config.Rule{
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "final", Action: "proxy"},
	}, res)

	target := fakeTarget(t, res, cnName)
	// The placeholder address must never leave the device, even when the lookup
	// failed: route hands the name back for the outbound to dial.
	wantTarget := cnName + ":443"
	for i := 0; i < 2; i++ {
		ob, action, got, err := eng.route(context.Background(), "tcp", target)
		if err != nil {
			t.Fatalf("call %d: route: %v", i, err)
		}
		if action.Rule != "final" || ob.Tag() != "proxy" {
			t.Fatalf("call %d: route = %s/%q, want proxy/final", i, ob.Tag(), action.Rule)
		}
		if got != wantTarget {
			t.Fatalf("call %d: target = %q, want %q", i, got, wantTarget)
		}
	}

	var logged bool
	for _, e := range eng.log.Snapshot(0, 512) {
		if strings.Contains(e.Msg, "resolve "+cnName+" for routing failed") {
			logged = true
			break
		}
	}
	if !logged {
		t.Fatal("no debug log for the failed routing lookup")
	}

	// The failure is cached negatively, so a page load does not pay the timeout
	// once per connection.
	ent, ok := eng.routeCache.get(cnName, time.Now())
	if !ok || ent.err == nil {
		t.Fatalf("negative cache entry = %+v (ok=%v), want the recorded error", ent, ok)
	}
}

// TestRouteLookupCached is acceptance (e): repeated connections to one name cost
// one upstream lookup.
func TestRouteLookupCached(t *testing.T) {
	up := newTestDNS(t, cnAddr)
	res := newTestResolver(t, up.addr())
	eng := newRouteEngine(t, []config.Rule{
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "final", Action: "proxy"},
	}, res)
	target := fakeTarget(t, res, cnName)

	for i := 0; i < 5; i++ {
		_, action, _, err := eng.route(context.Background(), "tcp", target)
		if err != nil {
			t.Fatalf("call %d: route: %v", i, err)
		}
		if action.Rule != "geoip:cn" {
			t.Fatalf("call %d: rule = %q, want geoip:cn", i, action.Rule)
		}
	}
	if got := up.aCount.Load(); got != 1 {
		t.Fatalf("A queries = %d, want 1 (the routing cache did not hold)", got)
	}
}

// TestRouteLookupConcurrent exercises the same path from many goroutines; the
// race detector must stay quiet and the answers must agree.
func TestRouteLookupConcurrent(t *testing.T) {
	up := newTestDNS(t, cnAddr)
	res := newTestResolver(t, up.addr())
	eng := newRouteEngine(t, []config.Rule{
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "final", Action: "proxy"},
	}, res)
	target := fakeTarget(t, res, cnName)

	var wg sync.WaitGroup
	errs := make(chan string, 32)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ob, action, _, err := eng.route(context.Background(), "tcp", target)
			if err != nil {
				errs <- err.Error()
				return
			}
			if action.Rule != "geoip:cn" || ob.Tag() != "direct" {
				errs <- ob.Tag() + "/" + action.Rule
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatalf("concurrent route disagreed: %s", e)
	}
	if got := up.aCount.Load(); got != 1 {
		t.Fatalf("A queries = %d, want 1 (concurrent lookups must collapse)", got)
	}
}

// TestRouteWithoutResolver checks the fallback to the pre-resolution behaviour:
// no resolver, no lookup, IP rules simply do not match.
func TestRouteWithoutResolver(t *testing.T) {
	eng := newRouteEngine(t, []config.Rule{
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "final", Action: "proxy"},
	}, nil)

	ob, action, target, err := eng.route(context.Background(), "tcp", cnName+":443")
	if err != nil {
		t.Fatalf("route: %v", err)
	}
	if action.Rule != "final" || ob.Tag() != "proxy" {
		t.Fatalf("route = %s/%q, want PROXY/final", ob.Tag(), action.Rule)
	}
	if target != cnName+":443" {
		t.Fatalf("target = %q", target)
	}
}

package dns

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	mdns "github.com/miekg/dns"

	"veil/internal/config"
)

// TestBypassFakeIP pins the names the tunnel must not answer with a synthetic
// address: they resolve inside the local network (mDNS, the router, a corporate
// suffix), so an exit node has no way to look them up and a 198.18.x answer is
// simply a dead end.
func TestBypassFakeIP(t *testing.T) {
	bypass := []string{
		"nas",    // single label: the local search suffix and mDNS own it
		"NAS",    // case does not matter
		"notlan", // still single label
		"nas.lan",
		"printer.local",
		"x.internal",
		"router.home.arpa",
		"home.arpa",
		"loopback.localhost",
		"localhost",
		"nas.lan.", // trailing root dot
	}
	for _, host := range bypass {
		if !bypassFakeIP(host, nil) {
			t.Errorf("bypassFakeIP(%q) = false, want true", host)
		}
	}
	// Only whole suffixes are matched: ".local" is not a substring rule, and a
	// name with no dot is handled before the suffix list.
	fake := []string{
		"www.google.com",
		"local.example.com",
		"lan.example.com",
		"internal.example.com",
		"home.arpa.example.com",
		"localhost.example.com",
	}
	for _, host := range fake {
		if bypassFakeIP(host, nil) {
			t.Errorf("bypassFakeIP(%q) = true, want false", host)
		}
	}
}

// lanUpstream answers a fixed table of names with IPv4 addresses and everything
// else with NXDOMAIN. It records which names reached it, so a test can tell a
// real upstream answer from a locally synthesized one.
type lanUpstream struct {
	pc      net.PacketConn
	srv     *mdns.Server
	answers map[string]netip.Addr

	mu      sync.Mutex
	queried []string
}

func newLanUpstream(t *testing.T, answers map[string]netip.Addr) *lanUpstream {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	u := &lanUpstream{pc: pc, answers: answers}
	h := mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(req)
		m.RecursionAvailable = true
		if len(req.Question) != 1 {
			m.Rcode = mdns.RcodeFormatError
			_ = w.WriteMsg(m)
			return
		}
		q := req.Question[0]
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		u.record(name)
		addr, known := u.answers[name]
		if !known || q.Qtype != mdns.TypeA {
			m.Rcode = mdns.RcodeNameError
			_ = w.WriteMsg(m)
			return
		}
		m.Answer = append(m.Answer, &mdns.A{
			Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
			A:   net.IP(addr.AsSlice()),
		})
		_ = w.WriteMsg(m)
	})
	u.srv = &mdns.Server{PacketConn: pc, Handler: h, UDPSize: 4096}
	go func() { _ = u.srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = pc.Close() })
	return u
}

func (u *lanUpstream) addr() string { return u.pc.LocalAddr().String() }

func (u *lanUpstream) record(name string) {
	u.mu.Lock()
	u.queried = append(u.queried, name)
	u.mu.Unlock()
}

func (u *lanUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.queried)
}

// answerA asks r for the A record of name and returns the first address in the
// reply (invalid when there is none) together with the reply code.
func answerA(t *testing.T, r *Resolver, name string) (netip.Addr, int) {
	t.Helper()
	q := new(mdns.Msg)
	q.SetQuestion(mdns.Fqdn(name), mdns.TypeA)
	raw, err := q.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	resp, err := r.Exchange(context.Background(), raw)
	if err != nil {
		t.Fatalf("Exchange(%s): %v", name, err)
	}
	var m mdns.Msg
	if err := m.Unpack(resp); err != nil {
		t.Fatalf("unpack reply: %v", err)
	}
	for _, rr := range m.Answer {
		if a, ok := rr.(*mdns.A); ok {
			addr, ok := netip.AddrFromSlice(a.A)
			if !ok {
				t.Fatalf("%s: bad A record %v", name, a.A)
			}
			return addr.Unmap(), m.Rcode
		}
	}
	return netip.Addr{}, m.Rcode
}

// TestFakeIPFilterFallsThroughToUpstream is acceptance 3: a LAN name gets the
// real upstream answer instead of a fake address, an unknown LAN name gets a
// real NXDOMAIN, and an ordinary name still gets a fake address with no upstream
// query at all.
func TestFakeIPFilterFallsThroughToUpstream(t *testing.T) {
	lan := map[string]netip.Addr{
		"nas":              netip.MustParseAddr("192.168.1.20"),
		"nas.lan":          netip.MustParseAddr("192.168.1.21"),
		"printer.local":    netip.MustParseAddr("192.168.1.22"),
		"x.internal":       netip.MustParseAddr("192.168.1.23"),
		"router.home.arpa": netip.MustParseAddr("192.168.1.1"),
	}
	up := newLanUpstream(t, lan)
	r, err := New(config.DNSConfig{
		Enable:  true,
		Final:   "lan",
		Servers: []config.DNSServer{{Tag: "lan", Addr: up.addr()}},
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for name, want := range lan {
		got, rcode := answerA(t, r, name)
		if rcode != mdns.RcodeSuccess || got != want {
			t.Fatalf("%s -> %v (rcode %s), want the upstream answer %v",
				name, got, mdns.RcodeToString[rcode], want)
		}
		if r.IsFake(got) {
			t.Fatalf("%s was answered with the fake address %v", name, got)
		}
	}

	// A LAN name nobody knows is still not faked: the client gets the real
	// NXDOMAIN, which is a fact about the local network instead of a pointer to
	// an address the exit node cannot reach.
	if got, rcode := answerA(t, r, "unknown.lan"); rcode != mdns.RcodeNameError || got.IsValid() {
		t.Fatalf("unknown.lan -> %v (rcode %s), want NXDOMAIN", got, mdns.RcodeToString[rcode])
	}

	// An ordinary name is still answered locally: a fake address, mapped back to
	// the name, with no upstream query.
	before := up.count()
	got, rcode := answerA(t, r, "www.google.com")
	if rcode != mdns.RcodeSuccess || !r.IsFake(got) {
		t.Fatalf("www.google.com -> %v (rcode %s), want a fake address", got, mdns.RcodeToString[rcode])
	}
	if host, ok := r.HostFor(got); !ok || host != "www.google.com" {
		t.Fatalf("HostFor(%v) = %q,%v, want www.google.com", got, host, ok)
	}
	if after := up.count(); after != before {
		t.Fatalf("www.google.com reached the upstream (%d -> %d queries)", before, after)
	}
	t.Logf("LAN names answered upstream, www.google.com -> %v, upstream queries = %d", got, up.count())
}

// A configured list extends the built-in one; both the plain and the wildcard
// spelling a profile uses must work.
func TestBypassFakeIPHonoursConfiguredSuffixes(t *testing.T) {
	configured := []string{"corp.example", "+.search.example", "*.lan2", " Mixed.Example. "}
	for _, host := range []string{"nas.corp.example", "printer.search.example", "box.lan2", "x.mixed.example"} {
		if !bypassFakeIP(host, configured) {
			t.Errorf("bypassFakeIP(%q) = false, want true (configured suffix)", host)
		}
	}
	if bypassFakeIP("www.google.com", configured) {
		t.Error("a public name bypassed the fake pool because of a configured suffix")
	}
}

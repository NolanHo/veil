package factory

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"veil/internal/config"
	"veil/internal/outbound"
	"veil/internal/transport"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// testVLESSServer is a VLESS TCP endpoint good enough to prove a data path: it
// reads the request header and then either echoes the payload (a server) or
// dials the requested destination and splices (the "upstream" a chain exits
// through). It records what it was asked for and what it dialed, which is the
// evidence a chained connection went where it should.
type testVLESSServer struct {
	ln    net.Listener
	relay bool

	mu    sync.Mutex
	asked []string // destinations clients put in the request header
	dials []string // destinations this server itself dialed
}

func startVLESSServer(t *testing.T, relay bool) *testVLESSServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &testVLESSServer{ln: ln, relay: relay}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *testVLESSServer) Addr() string { return s.ln.Addr().String() }

func (s *testVLESSServer) served() (asked, dials []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.asked...), append([]string(nil), s.dials...)
}

func (s *testVLESSServer) serve(c net.Conn) {
	defer c.Close()
	dest, err := readVLESSTarget(c)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.asked = append(s.asked, dest)
	s.mu.Unlock()

	// Response header: version 0, no addons. The client waits for it before it
	// reports the stream open.
	if _, err := c.Write([]byte{0x00, 0x00}); err != nil {
		return
	}
	if !s.relay {
		io.Copy(c, c)
		return
	}
	up, err := net.DialTimeout("tcp", dest, 5*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	s.mu.Lock()
	s.dials = append(s.dials, dest)
	s.mu.Unlock()
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); done <- struct{}{} }()
	go func() { io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// readVLESSTarget parses one VLESS TCP request header (see
// internal/proxy/vless/header.go) and returns its destination address.
func readVLESSTarget(r io.Reader) (string, error) {
	head := make([]byte, 1+16) // version, user id
	if _, err := io.ReadFull(r, head); err != nil {
		return "", err
	}
	var n [1]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return "", err
	}
	if n[0] > 0 {
		if _, err := io.ReadFull(r, make([]byte, n[0])); err != nil {
			return "", err
		}
	}
	var cmd [1]byte
	if _, err := io.ReadFull(r, cmd[:]); err != nil {
		return "", err
	}
	if cmd[0] != 1 {
		return "", fmt.Errorf("vless test server: command %d, want tcp", cmd[0])
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", err
	}
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", err
	}
	var host string
	switch atyp[0] {
	case 1: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	case 2: // domain
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return "", err
		}
		host = string(name)
	case 3: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	default:
		return "", fmt.Errorf("vless test server: address type %d", atyp[0])
	}
	return net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(port[:]))), nil
}

// fakeUpstream is an outbound that records the connection it was asked to make
// and reaches a local test server instead: the "another outbound" a chain names.
type fakeUpstream struct {
	tag   string
	reach string

	mu    sync.Mutex
	dials []string
}

func (f *fakeUpstream) Tag() string  { return f.tag }
func (f *fakeUpstream) Type() string { return "fake" }
func (f *fakeUpstream) Close() error { return nil }

func (f *fakeUpstream) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	f.dials = append(f.dials, network+" "+address)
	f.mu.Unlock()
	var d net.Dialer
	return d.DialContext(ctx, network, f.reach)
}

func (f *fakeUpstream) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dials...)
}

// fakeGroup is a policy outbound whose member is switched by the test: the chain
// must ask it on every dial, not once at build time.
type fakeGroup struct {
	tag string

	mu  sync.Mutex
	cur outbound.Outbound
}

func (g *fakeGroup) Tag() string  { return g.tag }
func (g *fakeGroup) Type() string { return "select" }
func (g *fakeGroup) Close() error { return nil }

func (g *fakeGroup) selectMember(ob outbound.Outbound) {
	g.mu.Lock()
	g.cur = ob
	g.mu.Unlock()
}

func (g *fakeGroup) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	g.mu.Lock()
	cur := g.cur
	g.mu.Unlock()
	if cur == nil {
		return nil, fmt.Errorf("group %q: no member", g.tag)
	}
	return cur.DialContext(ctx, network, address)
}

func dialAndEcho(t *testing.T, ob outbound.Outbound, dest, payload string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := ob.DialContext(ctx, "tcp", dest)
	if err != nil {
		t.Fatalf("dial %s: %v", dest, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != payload {
		t.Fatalf("echo = %q, want %q", buf, payload)
	}
}

// A chained node's base TCP connection must be the chain's DialContext, asked for
// the chained node's own server — never the destination the node was dialing —
// and the protocol stream above it must still work end to end.
func TestChainedNodeDialGoesThroughDialerProxy(t *testing.T) {
	echo := startVLESSServer(t, false)
	upstream := &fakeUpstream{tag: "mdev-hk", reach: echo.Addr()}

	cfg := config.Config{
		Nodes: []config.Node{{
			Tag: "出口节点", Type: "vless",
			Server: "154.50.110.12", Port: 3306, UUID: testUUID,
			DialerProxy: "mdev-hk",
		}},
		// A group target is resolved through the engine's map on every dial; the
		// test supplies that map below.
		Groups: []config.Group{{Tag: "mdev-hk", Type: "select", Members: []string{"mdev-hk"}}},
	}
	lookup := func(tag string) outbound.Outbound {
		if tag == "mdev-hk" {
			return upstream
		}
		return nil
	}

	obs, errs := Build(cfg, lookup)
	if len(errs) != 0 {
		t.Fatalf("Build: %v", errs)
	}
	exit, ok := obs["出口节点"]
	if !ok {
		t.Fatalf("chained node was not built; built = %v", tags(obs))
	}

	const payload = "hello through the chain"
	dialAndEcho(t, exit, "example.com:80", payload)

	dials := upstream.recorded()
	if len(dials) != 1 || dials[0] != "tcp 154.50.110.12:3306" {
		t.Fatalf("chain dialed %v, want one dial of \"tcp 154.50.110.12:3306\"", dials)
	}
	asked, _ := echo.served()
	if len(asked) != 1 || asked[0] != "example.com:80" {
		t.Fatalf("server was asked for %v, want [example.com:80]", asked)
	}
}

// The chain target can be a node, and it is built before the node that chains
// through it even when the configuration lists them the other way round.
func TestChainToNodeBuildsTargetFirst(t *testing.T) {
	inner := startVLESSServer(t, false) // 出口节点's own server
	outer := startVLESSServer(t, true)  // mdev-hk: relays whatever it is asked for

	exitHost, exitPort := splitAddr(t, inner.Addr())
	upHost, upPort := splitAddr(t, outer.Addr())

	cfg := config.Config{Nodes: []config.Node{
		// Deliberately listed before its own chain target.
		{Tag: "出口节点", Type: "vless", Server: exitHost, Port: exitPort, UUID: testUUID, DialerProxy: "mdev-hk"},
		{Tag: "mdev-hk", Type: "vless", Server: upHost, Port: upPort, UUID: testUUID},
	}}

	obs, errs := Build(cfg, nil)
	if len(errs) != 0 {
		t.Fatalf("Build: %v", errs)
	}
	exit, ok := obs["出口节点"]
	if !ok {
		t.Fatalf("chained node was not built; built = %v", tags(obs))
	}

	const payload = "two hops"
	dialAndEcho(t, exit, "example.com:80", payload)

	// The outer server was told to reach the chained node's server: the inner
	// VLESS stream travelled through the outer one.
	_, dials := outer.served()
	if len(dials) != 1 || dials[0] != inner.Addr() {
		t.Fatalf("chain exit dialed %v, want [%s]", dials, inner.Addr())
	}
	asked, _ := inner.served()
	if len(asked) != 1 || asked[0] != "example.com:80" {
		t.Fatalf("inner server was asked for %v, want [example.com:80]", asked)
	}
}

// A chain naming a group follows the group's selection: every new connection
// goes through whoever the group points at when it is made.
func TestChainToGroupFollowsSelection(t *testing.T) {
	echo := startVLESSServer(t, false)
	first := &fakeUpstream{tag: "mdev-hk", reach: echo.Addr()}
	second := &fakeUpstream{tag: "日本", reach: echo.Addr()}
	group := &fakeGroup{tag: "日本家宽入口", cur: first}

	cfg := config.Config{
		Nodes: []config.Node{{
			Tag: "日本家宽", Type: "vless",
			Server: "198.51.100.7", Port: 10001, UUID: testUUID,
			DialerProxy: "日本家宽入口",
		}},
		Groups: []config.Group{{Tag: "日本家宽入口", Type: "select", Members: []string{"mdev-hk", "日本"}}},
	}
	lookup := func(tag string) outbound.Outbound {
		if tag == "日本家宽入口" {
			return group
		}
		return nil
	}

	obs, errs := Build(cfg, lookup)
	if len(errs) != 0 {
		t.Fatalf("Build: %v", errs)
	}
	home, ok := obs["日本家宽"]
	if !ok {
		t.Fatalf("chained node was not built; built = %v", tags(obs))
	}

	dialAndEcho(t, home, "example.com:80", "first exit")
	if got := first.recorded(); len(got) != 1 || got[0] != "tcp 198.51.100.7:10001" {
		t.Fatalf("selected member dialed %v, want one dial of the node's server", got)
	}

	group.selectMember(second)
	dialAndEcho(t, home, "example.com:80", "second exit")
	if got := second.recorded(); len(got) != 1 || got[0] != "tcp 198.51.100.7:10001" {
		t.Fatalf("after switching, the new member dialed %v, want one dial of the node's server", got)
	}
	if got := first.recorded(); len(got) != 1 {
		t.Fatalf("the old member dialed again: %v", got)
	}
}

// A chain that comes back to the node must be reported for every node on the
// loop and must not be built at all — no panic, no deadlock, no direct dial.
func TestDialerProxyCycleIsReportedNotDialled(t *testing.T) {
	cfg := config.Config{Nodes: []config.Node{
		{Tag: "a", Type: "vless", Server: "a.example", Port: 443, UUID: testUUID, DialerProxy: "b"},
		{Tag: "b", Type: "vless", Server: "b.example", Port: 443, UUID: testUUID, DialerProxy: "a"},
	}}

	type result struct {
		obs  map[string]outbound.Outbound
		errs []error
	}
	done := make(chan result, 1)
	go func() {
		obs, errs := Build(cfg, nil)
		done <- result{obs, errs}
	}()

	var got result
	select {
	case got = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Build deadlocked on a dialer-proxy cycle")
	}

	if len(got.errs) != 2 {
		t.Fatalf("errs = %v, want one per node on the loop", got.errs)
	}
	for _, want := range []string{"a -> b -> a", "b -> a -> b"} {
		found := 0
		for _, err := range got.errs {
			if strings.Contains(err.Error(), want) {
				found++
			}
		}
		if found != 1 {
			t.Fatalf("errs = %v, want exactly one naming %q", got.errs, want)
		}
	}
	for _, tag := range []string{"a", "b"} {
		if _, built := got.obs[tag]; built {
			t.Fatalf("node %q on a chain cycle was built", tag)
		}
	}
}

// A transport that is not TCP cannot hand a connection over: the node is
// reported and skipped, never dialled directly.
func TestChainRejectedForNonTCPTransports(t *testing.T) {
	wg := wgNode("wireguard")
	wg.Tag = "wg"
	wg.DialerProxy = "mdev-hk"

	cfg := config.Config{Nodes: []config.Node{
		{Tag: "hy", Type: "hysteria2", Server: "hy.example", Port: 443, Password: "secret", DialerProxy: "mdev-hk"},
		wg,
	}}

	obs, errs := Build(cfg, nil)
	if len(errs) != 2 {
		t.Fatalf("errs = %v, want one per unsupported node", errs)
	}
	for _, want := range []string{"hysteria2", "wireguard"} {
		found := false
		for _, err := range errs {
			if strings.Contains(err.Error(), "dialer-proxy") && strings.Contains(err.Error(), want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("errs = %v, want a dialer-proxy error naming %s", errs, want)
		}
	}
	for _, tag := range []string{"hy", "wg"} {
		if _, built := obs[tag]; built {
			t.Fatalf("node %q with a chained %s transport was built", tag, tag)
		}
	}
}

// Building one node alone cannot resolve a chain, so it is refused rather than
// dialled directly.
func TestNewRefusesChainedNode(t *testing.T) {
	_, err := New(config.Node{
		Tag: "exit", Type: "vless", Server: "203.0.113.9", Port: 443,
		UUID: testUUID, DialerProxy: "mdev-hk",
	})
	if err == nil || !strings.Contains(err.Error(), "dialer-proxy") {
		t.Fatalf("New = %v, want a dialer-proxy refusal", err)
	}
}

func splitAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	var p int
	if _, err := fmt.Sscanf(port, "%d", &p); err != nil {
		t.Fatalf("port %q: %v", port, err)
	}
	return host, p
}

func tags(obs map[string]outbound.Outbound) []string {
	out := make([]string, 0, len(obs))
	for tag := range obs {
		out = append(out, tag)
	}
	return out
}

// The same seam with Shadowsocks — the protocol the owner's chained node uses:
// its salt and request header must land on the connection the chain opened, not
// on a socket this device dialled itself.
func TestChainedSSTransportUsesBaseDialer(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	t.Cleanup(func() {
		clientEnd.Close()
		serverEnd.Close()
	})

	var dials int
	base := transport.DialerFunc(func(context.Context) (net.Conn, error) {
		dials++
		return clientEnd, nil
	})
	ob, err := buildOne(config.Node{
		Tag: "出口节点", Type: "ss",
		Server: "154.50.110.12", Port: 3306,
		Method: "aes-256-gcm", Password: "secret",
	}, base)
	if err != nil {
		t.Fatalf("buildOne: %v", err)
	}

	// net.Pipe has no buffer: the client's first write is what completes the
	// dial, so the read side has to be draining.
	head := make(chan int, 1)
	go func() {
		buf := make([]byte, 128)
		n, _ := serverEnd.Read(buf)
		head <- n
		// Keep draining: the client writes the salt and then the first chunk as
		// separate writes, and an unbuffered pipe blocks on each.
		io.Copy(io.Discard, serverEnd)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := ob.DialContext(ctx, "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	select {
	case n := <-head:
		// aes-256-gcm: the salt alone is 32 bytes, written before the first
		// encrypted chunk.
		if n < 32 {
			t.Fatalf("chained connection carried %d bytes, want at least the ss salt", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the ss stream never wrote to the chained connection")
	}
	if dials != 1 {
		t.Fatalf("base dialed %d times, want 1", dials)
	}
}

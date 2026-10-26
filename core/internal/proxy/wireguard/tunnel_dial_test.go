package wireguard

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"veil/internal/transport"
)

// TestDialNameWithoutTunnelDNS is the B5 regression, reproduced from the device:
//
//	wireguard homelab-wg: resolve www.baidu.com in tunnel:
//	  lookup www.baidu.com: cannot marshal DNS message
//
// A node without `dns` has no resolver inside the userspace stack, and asking it
// anyway fails with that message for every name — which is what the owner's real
// Clash node looks like (no dns key). The name must be resolved outside the
// tunnel through the protected dialer instead, and the tunnel only carries the
// resulting IP, which is WireGuard's normal model.
func TestDialNameWithoutTunnelDNS(t *testing.T) {
	clientPriv, clientPub := keyPair(t)
	serverPriv, serverPub := keyPair(t)

	srv := startWGServer(t, serverPriv, clientPub)
	tcpPort := startTCPEcho(t, srv.stack)

	// A name that only this resolver knows; it answers with the peer's tunnel
	// address, which is what a homelab name would resolve to.
	dnsAddr, queries := startTestDNS(t, netip.MustParseAddr(serverAddr))
	prevDial := resolverDial
	resolverDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return transport.NewDialer().DialContext(ctx, network, dnsAddr)
	}
	t.Cleanup(func() { resolverDial = prevDial })

	// clientNode carries no DNS, exactly like the node that failed on device.
	node := clientNode(t, srv.port, clientPriv, serverPub)
	if len(node.DNS) != 0 {
		t.Fatalf("fixture must have no dns, got %v", node.DNS)
	}
	c, err := New(node)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	target := net.JoinHostPort("homelab.internal", strconv.Itoa(tcpPort))
	conn, err := c.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("DialContext(%s) without a tunnel resolver: %v", target, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("echo = %q", got)
	}
	if n := queries(); n == 0 {
		t.Fatal("the target name was never resolved")
	}
}

// TestDialNameInTunnelWhenDNSConfigured keeps the other half of the semantics
// honest: a node that *does* name a resolver resolves inside the tunnel, so a
// split-horizon name that only the peer side knows still works.
func TestDialNameInTunnelWhenDNSConfigured(t *testing.T) {
	clientPriv, clientPub := keyPair(t)
	serverPriv, serverPub := keyPair(t)

	srv := startWGServer(t, serverPriv, clientPub)
	tcpPort := startTCPEcho(t, srv.stack)

	// A resolver that only exists on the peer side of the tunnel, i.e. the
	// split-horizon case `dns =` exists for. It listens on the stack of the test
	// peer, so a host resolver could never reach it.
	dnsPC, err := srv.stack.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(serverAddr), 53))
	if err != nil {
		t.Fatalf("listen dns in peer stack: %v", err)
	}
	t.Cleanup(func() { _ = dnsPC.Close() })
	queries := serveDNS(dnsPC, netip.MustParseAddr(serverAddr))

	node := clientNode(t, srv.port, clientPriv, serverPub)
	node.DNS = []string{serverAddr}
	c, err := New(node)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	target := net.JoinHostPort("split.horizon.internal", strconv.Itoa(tcpPort))
	conn, err := c.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("DialContext(%s) with an in-tunnel resolver: %v", target, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("hi")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if n := queries(); n == 0 {
		t.Fatal("the name was not resolved inside the tunnel")
	}
}

// TestDialOutsideAllowedIPsFailsFast is the second half of B5: a peer whose
// allowed_ips only cover the homelab cannot carry public destinations. The device
// drops those packets without an error, so the dial would hang until its deadline;
// the dial reports it instead.
func TestDialOutsideAllowedIPsFailsFast(t *testing.T) {
	priv, pub := keyPair(t)
	node := clientNode(t, 51820, priv, pub) // allowed_ips: 10.9.9.0/32 only
	c, err := New(node)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	_, err = c.DialContext(ctx, "tcp", "93.184.216.34:80")
	if err == nil {
		t.Fatal("dial to a destination outside allowed_ips succeeded")
	}
	if !strings.Contains(err.Error(), "allowed_ips") {
		t.Fatalf("error %q does not explain that the peer cannot carry the destination", err)
	}
	if waited := time.Since(started); waited > 2*time.Second {
		t.Fatalf("the check took %v: it waited for the dial deadline instead of failing fast", waited)
	}

	// UDP goes through the same check.
	if _, err := c.DialPacket(ctx, "93.184.216.34:53"); err == nil || !strings.Contains(err.Error(), "allowed_ips") {
		t.Fatalf("DialPacket outside allowed_ips = %v, want an allowed_ips error", err)
	}
}

// TestTunnelLookupHonoursCancel is the cancellation regression for in-tunnel
// names.
//
// The stack's own resolver only derives a socket deadline from the context, so
// cancelling a lookup left the caller waiting out the resolver's retry budget
// (review: still running 200ms after cancel). The query socket now belongs to
// the lookup, so cancelling closes it and the dial returns at once.
func TestTunnelLookupHonoursCancel(t *testing.T) {
	clientPriv, clientPub := keyPair(t)
	serverPriv, serverPub := keyPair(t)
	srv := startWGServer(t, serverPriv, clientPub)

	// An in-tunnel nameserver that consumes queries and never answers.
	dnsPC, err := srv.stack.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(serverAddr), 53))
	if err != nil {
		t.Fatalf("listen dns in peer stack: %v", err)
	}
	t.Cleanup(func() { _ = dnsPC.Close() })
	querySeen := make(chan struct{})
	var once sync.Once
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := dnsPC.ReadFrom(buf); err != nil {
				return
			}
			once.Do(func() { close(querySeen) })
		}
	}()

	node := clientNode(t, srv.port, clientPriv, serverPub)
	node.DNS = []string{serverAddr}
	c, err := New(node)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialErr := make(chan error, 1)
	go func() {
		_, err := c.DialContext(ctx, "tcp", net.JoinHostPort("split.horizon.internal", "80"))
		dialErr <- err
	}()

	select {
	case <-querySeen:
	case <-time.After(20 * time.Second):
		t.Fatal("the in-tunnel resolver was never asked")
	}

	cancelled := time.Now()
	cancel()
	select {
	case <-dialErr:
		if waited := time.Since(cancelled); waited > 100*time.Millisecond {
			t.Fatalf("the lookup returned %v after cancel, want under 100ms", waited)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the in-tunnel lookup ignored the caller's cancel")
	}
}

// TestDialSurvivesSilentInTunnelResolver is the same budget rule one level
// down: a node may list several in-tunnel resolvers, and the first one being
// silent must not keep the second from being asked before the dial deadline.
func TestDialSurvivesSilentInTunnelResolver(t *testing.T) {
	const (
		silentAddr = "10.9.9.1"
		answering  = "10.9.9.5"
	)
	clientPriv, clientPub := keyPair(t)
	serverPriv, serverPub := keyPair(t)
	srv := startWGServerAddrs(t, serverPriv, clientPub, []netip.Addr{
		netip.MustParseAddr(silentAddr), netip.MustParseAddr(answering),
	})
	tcpPort, _ := startTCPEchoCountAt(t, srv.stack, netip.MustParseAddr(answering))

	// The first resolver consumes queries and never answers.
	silent, err := srv.stack.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(silentAddr), 53))
	if err != nil {
		t.Fatalf("listen silent dns in peer stack: %v", err)
	}
	t.Cleanup(func() { _ = silent.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := silent.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	// The second one answers with itself, which the peer carries.
	good, err := srv.stack.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(answering), 53))
	if err != nil {
		t.Fatalf("listen answering dns in peer stack: %v", err)
	}
	t.Cleanup(func() { _ = good.Close() })
	serveDNS(good, netip.MustParseAddr(answering))

	node := clientNode(t, srv.port, clientPriv, serverPub)
	node.DNS = []string{silentAddr, answering}
	node.AllowedIPs = []string{"10.9.9.0/24"}
	c, err := New(node)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	const budget = 3 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	target := net.JoinHostPort("homelab.secondresolver.internal", strconv.Itoa(tcpPort))
	started := time.Now()
	conn, err := c.DialContext(ctx, "tcp", target)
	took := time.Since(started)
	if err != nil {
		t.Fatalf("DialContext(%s) with a silent first resolver: %v (after %v)", target, err, took)
	}
	defer conn.Close()
	echoOnce(t, conn, "second resolver")
	if took >= budget {
		t.Fatalf("the dial took %v of its %v deadline: the silent resolver kept the budget for itself", took, budget)
	}
}

// TestDialWithoutAllowedIPsFailsFast covers the other unreachable shape: a node
// with no allowed_ips at all (a .conf without AllowedIPs) can carry nothing.
func TestDialWithoutAllowedIPsFailsFast(t *testing.T) {
	priv, pub := keyPair(t)
	node := clientNode(t, 51820, priv, pub)
	node.AllowedIPs = nil
	c, err := New(node)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.DialContext(ctx, "tcp", net.JoinHostPort(serverAddr, "80")); err == nil ||
		!strings.Contains(err.Error(), "allowed_ips") {
		t.Fatalf("DialContext without allowed_ips = %v, want an allowed_ips error", err)
	}
}

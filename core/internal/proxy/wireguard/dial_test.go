package wireguard

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// startWGServerAddrs brings a peer up with several tunnel addresses, so a test
// can put a name's candidates on the same peer and leave the first one without a
// listener.
func startWGServerAddrs(t *testing.T, serverPriv, clientPub string, addrs []netip.Addr) *wgServer {
	t.Helper()
	tun, ns, err := netstack.CreateNetTUN(addrs, nil, tunnelMTU)
	if err != nil {
		t.Fatalf("create server stack: %v", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wgserver: "))
	t.Cleanup(dev.Close)
	conf := "private_key=" + mustHexKey(t, serverPriv) + "\n" +
		"public_key=" + mustHexKey(t, clientPub) + "\n" +
		"allowed_ip=" + clientAddr + "/32\n"
	if err := dev.IpcSet(conf); err != nil {
		t.Fatalf("server IpcSet: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("server up: %v", err)
	}
	uapi, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("server IpcGet: %v", err)
	}
	return &wgServer{dev: dev, stack: ns, port: listenPort(t, uapi)}
}

// startTCPEchoAt runs a TCP echo server on the peer's stack at ip and reports
// its port.
func startTCPEchoAt(t *testing.T, ns *netstack.Net, ip netip.Addr) int {
	t.Helper()
	port, _ := startTCPEchoCountAt(t, ns, ip)
	return port
}

// startTCPEchoCountAt is startTCPEchoAt plus a counter of accepted connections,
// so a test can prove a dial actually reached this candidate.
func startTCPEchoCountAt(t *testing.T, ns *netstack.Net, ip netip.Addr) (port int, accepted func() int64) {
	t.Helper()
	ln, err := ns.ListenTCPAddrPort(netip.AddrPortFrom(ip, 0))
	if err != nil {
		t.Fatalf("listen tcp at %s in stack: %v", ip, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var seen int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt64(&seen, 1)
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() int64 { return atomic.LoadInt64(&seen) }
}

// echoOnce writes payload through conn and reads the echo back.
func echoOnce(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

// TestDialHonoursAddressFamily is the address-family regression.
//
// The userspace stack derives the socket family from the address it is handed,
// so DialContext(ctx, "tcp6", <IPv4 literal>) used to come back with a working
// IPv4 stream: the caller asked for a family the connection does not belong to.
func TestDialHonoursAddressFamily(t *testing.T) {
	clientPriv, clientPub := keyPair(t)
	serverPriv, serverPub := keyPair(t)
	srv := startWGServer(t, serverPriv, clientPub)
	tcpPort := startTCPEcho(t, srv.stack)

	node := clientNode(t, srv.port, clientPriv, serverPub)
	// A v6 prefix the peer may carry, so the family check — not allowed_ips — is
	// what rejects the v6 target below.
	node.AllowedIPs = []string{serverAddr + "/32", "fd00::/64"}
	c, err := New(node)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	target := net.JoinHostPort(serverAddr, strconv.Itoa(tcpPort))
	if conn, err := c.DialContext(ctx, "tcp6", target); err == nil {
		_ = conn.Close()
		t.Fatalf("tcp6 dial of the IPv4 target %s returned a connection", target)
	} else if !strings.Contains(err.Error(), "tcp6") {
		t.Fatalf("tcp6 dial of an IPv4 target = %v, want an address-family error", err)
	}

	// The reverse holds too: no IPv4 socket for a v6 destination.
	v6Target := net.JoinHostPort("fd00::1", "80")
	started := time.Now()
	if conn, err := c.DialContext(ctx, "tcp4", v6Target); err == nil {
		_ = conn.Close()
		t.Fatalf("tcp4 dial of the IPv6 target %s returned a connection", v6Target)
	} else if !strings.Contains(err.Error(), "tcp4") {
		t.Fatalf("tcp4 dial of an IPv6 target = %v, want an address-family error", err)
	}
	if waited := time.Since(started); waited > 2*time.Second {
		t.Fatalf("the family check took %v: it waited for the dial deadline instead of failing fast", waited)
	}

	// The same target over plain "tcp" still works: the constraint is the
	// caller's, not a ban on IPv4 destinations.
	conn, err := c.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("DialContext(tcp, %s): %v", target, err)
	}
	echoOnce(t, conn, "family")
	_ = conn.Close()
}

// TestDialTriesEveryCandidate is the multi-candidate regression.
//
// A name may answer with several addresses while only one of them is reachable
// through the peer. The dial used to take the first candidate and stop, so this
// name failed even though the service was up on the second address.
func TestDialTriesEveryCandidate(t *testing.T) {
	const (
		firstAddr  = "10.9.9.1" // the peer, but nothing listens on the target port
		secondAddr = "10.9.9.5"
	)
	clientPriv, clientPub := keyPair(t)
	serverPriv, serverPub := keyPair(t)
	srv := startWGServerAddrs(t, serverPriv, clientPub, []netip.Addr{
		netip.MustParseAddr(firstAddr), netip.MustParseAddr(secondAddr),
	})
	tcpPort := startTCPEchoAt(t, srv.stack, netip.MustParseAddr(secondAddr))

	// The resolver lives on the peer side, so the candidate order is exactly the
	// order this test wrote into the answer (no host resolver to reorder it).
	dnsPC, err := srv.stack.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(firstAddr), 53))
	if err != nil {
		t.Fatalf("listen dns in peer stack: %v", err)
	}
	t.Cleanup(func() { _ = dnsPC.Close() })
	serveDNSMulti(dnsPC, []netip.Addr{
		netip.MustParseAddr(firstAddr), netip.MustParseAddr(secondAddr),
	})

	node := clientNode(t, srv.port, clientPriv, serverPub)
	node.DNS = []string{firstAddr}
	node.AllowedIPs = []string{"10.9.9.0/24"}
	c, err := New(node)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	target := net.JoinHostPort("homelab.multi.internal", strconv.Itoa(tcpPort))
	conn, err := c.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("DialContext(%s) with the service on the second candidate: %v", target, err)
	}
	defer conn.Close()
	echoOnce(t, conn, "second candidate")
}

// TestDialBlackholeCandidateDoesNotEatTheDeadline is the deadline regression of
// that same walk.
//
// Every candidate used to be dialed with the caller's full context, so a first
// candidate that silently drops the SYN — the peer carries the prefix but no
// host owns the address, so not even an RST comes back — spent the whole
// deadline and the reachable candidate behind it was never dialed (review: "1s
// later: context deadline exceeded", with the service up on the second
// address). Each candidate now gets its own share of what is left, so the dial
// still ends at the caller's deadline while the second candidate is reached.
func TestDialBlackholeCandidateDoesNotEatTheDeadline(t *testing.T) {
	const (
		peerAddr      = "10.9.9.1"
		serviceAddr   = "10.9.9.5"
		blackholeAddr = "10.9.9.200" // inside allowed_ips, owned by no host: SYN is dropped
	)
	clientPriv, clientPub := keyPair(t)
	serverPriv, serverPub := keyPair(t)
	srv := startWGServerAddrs(t, serverPriv, clientPub, []netip.Addr{
		netip.MustParseAddr(peerAddr), netip.MustParseAddr(serviceAddr),
	})
	tcpPort, accepted := startTCPEchoCountAt(t, srv.stack, netip.MustParseAddr(serviceAddr))

	dnsPC, err := srv.stack.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(peerAddr), 53))
	if err != nil {
		t.Fatalf("listen dns in peer stack: %v", err)
	}
	t.Cleanup(func() { _ = dnsPC.Close() })
	serveDNSMulti(dnsPC, []netip.Addr{
		netip.MustParseAddr(blackholeAddr), netip.MustParseAddr(serviceAddr),
	})

	node := clientNode(t, srv.port, clientPriv, serverPub)
	node.DNS = []string{peerAddr}
	node.AllowedIPs = []string{"10.9.9.0/24"}
	c, err := New(node)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	const budget = 3 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	target := net.JoinHostPort("homelab.blackhole.internal", strconv.Itoa(tcpPort))
	started := time.Now()
	conn, err := c.DialContext(ctx, "tcp", target)
	took := time.Since(started)
	if err != nil {
		t.Fatalf("DialContext(%s) with the service on the second candidate: %v (after %v)", target, err, took)
	}
	defer conn.Close()
	echoOnce(t, conn, "second candidate")

	if took >= budget {
		t.Fatalf("the dial took %v of its %v deadline: the blackhole candidate kept the budget for itself", took, budget)
	}
	if took < time.Second {
		t.Fatalf("the dial took %v: the blackhole candidate was skipped instead of tried", took)
	}
	if n := accepted(); n == 0 {
		t.Fatal("the reachable candidate never saw a connection")
	}
}

// TestCloseCancelsTargetResolution is the cancellation regression.
//
// After the device is up, a name dial is resolved outside the tunnel. A resolver
// read only ends when its socket does — cancelling the context passed to
// LookupNetIP does not interrupt it — so Close used to return with the query
// still running against a nameserver that never answers.
func TestCloseCancelsTargetResolution(t *testing.T) {
	clientPriv, clientPub := keyPair(t)
	serverPriv, serverPub := keyPair(t)
	// The endpoint is a literal, so the bring-up needs no name lookup: the only
	// query in this test is the dial target's.
	srv := startWGServer(t, serverPriv, clientPub)

	// A nameserver that reads queries and never answers.
	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen stub nameserver: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	querySeen := make(chan struct{})
	var once sync.Once
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := sink.ReadFrom(buf); err != nil {
				return
			}
			once.Do(func() { close(querySeen) })
		}
	}()
	sinkAddr := sink.LocalAddr().String()

	c, err := New(clientNode(t, srv.port, clientPriv, serverPub))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	// Aim this client's resolver at the stub nameserver, through the same
	// registration path production uses. The package-level resolverDial seam is
	// not touched here: cancelling the caller leaves the resolver's own goroutine
	// running for a moment, and restoring a package variable under it is a race.
	c.resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		conn, err := d.DialContext(ctx, network, sinkAddr)
		if err != nil {
			return nil, err
		}
		return c.trackDNS(conn)
	}}

	dialErr := make(chan error, 1)
	go func() {
		_, err := c.DialContext(context.Background(), "tcp", "homelab.internal:80")
		dialErr <- err
	}()

	select {
	case <-querySeen:
	case <-time.After(10 * time.Second):
		t.Fatal("the target name was never resolved, so Close was never tested")
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-dialErr:
		if err == nil {
			t.Fatal("the dial reported success after Close")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("the target lookup was still running 300ms after Close returned")
	}
}

// serveDNSMulti answers every A query arriving on pc with ips, in order.
func serveDNSMulti(pc net.PacketConn, ips []netip.Addr) {
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := dnsAnswerAll(buf[:n], ips); resp != nil {
				_, _ = pc.WriteTo(resp, from)
			}
		}
	}()
}

// dnsAnswerAll is dnsAnswer with one A record per address, keeping the order.
func dnsAnswerAll(query []byte, ips []netip.Addr) []byte {
	if len(query) < 12 {
		return nil
	}
	i := 12
	for i < len(query) && query[i] != 0 {
		i += int(query[i]) + 1
	}
	if i+5 > len(query) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(query[i+1 : i+3])
	question := query[12 : i+5]

	resp := make([]byte, 12, 12+len(question)+16*len(ips))
	copy(resp[0:2], query[0:2]) // ID
	resp[2] = 0x81              // QR | RD
	resp[3] = 0x80              // RA
	binary.BigEndian.PutUint16(resp[4:6], 1)
	resp = append(resp, question...)
	if qtype != 1 { // not A
		return resp
	}
	binary.BigEndian.PutUint16(resp[6:8], uint16(len(ips)))
	for _, ip := range ips {
		a := ip.As4()
		resp = append(resp, 0xC0, 0x0C)             // name pointer to the question
		resp = append(resp, 0x00, 0x01, 0x00, 0x01) // A, IN
		resp = append(resp, 0x00, 0x00, 0x00, 0x3C) // TTL 60
		resp = append(resp, 0x00, 0x04)
		resp = append(resp, a[:]...)
	}
	return resp
}

// TestCloseClosesResolverSockets pins the other half of the cancellation: the
// dial caller returning is not enough, the query socket itself has to be closed.
// Cancelling the context passed to LookupNetIP returns to the caller but leaves
// the resolver's read blocked on the nameserver until its own timeout, so Close
// owns those sockets (see trackDNS).
func TestCloseClosesResolverSockets(t *testing.T) {
	priv, pub := keyPair(t)
	c, err := New(clientNode(t, 51820, priv, pub))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen stub nameserver: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	query, err := c.dialDNS(context.Background(), "udp", sink.LocalAddr().String())
	if err != nil {
		t.Fatalf("dialDNS: %v", err)
	}
	if _, err := query.Write([]byte("query")); err != nil {
		t.Fatalf("send query: %v", err)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_ = query.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := query.Read(make([]byte, 1500)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("reading the query socket after Close = %v, want %v", err, net.ErrClosed)
	}
	if n := len(c.dnsConns); n != 0 {
		t.Fatalf("Close left %d resolver sockets registered", n)
	}
}

package wireguard

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"veil/internal/transport"
)

// startTestDNS runs a DNS server on loopback that answers every A query with ip,
// so an endpoint name resolves without the host's resolver. It returns the server
// address and a counter of queries received.
func startTestDNS(t *testing.T, ip netip.Addr) (addr string, queries func() int64) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dns: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String(), serveDNS(pc, ip)
}

// serveDNS answers every A query arriving on pc with ip. pc may be a host socket
// or one inside the test peer's userspace stack, which is how the in-tunnel
// resolver path is exercised.
func serveDNS(pc net.PacketConn, ip netip.Addr) (queries func() int64) {
	var seen int64
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			atomic.AddInt64(&seen, 1)
			if resp := dnsAnswer(buf[:n], ip); resp != nil {
				_, _ = pc.WriteTo(resp, from)
			}
		}
	}()
	return func() int64 { return atomic.LoadInt64(&seen) }
}

// dnsAnswer builds a minimal response: the header, the question echoed back and,
// for an A query, one address record. Other query types get an empty answer so
// the resolver keeps the A result instead of failing the lookup.
func dnsAnswer(query []byte, ip netip.Addr) []byte {
	if len(query) < 12 {
		return nil
	}
	// Walk the uncompressed QNAME that starts every query.
	i := 12
	for i < len(query) && query[i] != 0 {
		i += int(query[i]) + 1
	}
	if i+5 > len(query) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(query[i+1 : i+3])
	question := query[12 : i+5]

	resp := make([]byte, 12, 12+len(question)+16)
	copy(resp[0:2], query[0:2]) // ID
	resp[2] = 0x81              // QR | RD
	resp[3] = 0x80              // RA
	binary.BigEndian.PutUint16(resp[4:6], 1)
	resp = append(resp, question...)
	if qtype != 1 { // not A
		return resp
	}
	binary.BigEndian.PutUint16(resp[6:8], 1)
	a := ip.As4()
	resp = append(resp, 0xC0, 0x0C)             // name pointer to the question
	resp = append(resp, 0x00, 0x01, 0x00, 0x01) // A, IN
	resp = append(resp, 0x00, 0x00, 0x00, 0x3C) // TTL 60
	resp = append(resp, 0x00, 0x04)
	return append(resp, a[:]...)
}

// TestEndpointNameResolvesThroughProtect is the S1 regression.
//
// A resolver creates its own sockets; the dialer's Control hook only protects
// sockets the dialer creates. Resolving the peer name with a plain resolver
// therefore opens DNS sockets that never reach transport.ProtectFD, and on
// HarmonyOS those queries are captured by the tun we own. The endpoint name here
// only resolves through the protected resolver the test installs.
func TestEndpointNameResolvesThroughProtect(t *testing.T) {
	clientPriv, clientPub := keyPair(t)
	serverPriv, serverPub := keyPair(t)

	srv := startWGServer(t, serverPriv, clientPub)
	tcpPort := startTCPEcho(t, srv.stack)

	dnsAddr, queries := startTestDNS(t, netip.MustParseAddr("127.0.0.1"))
	prevDial := resolverDial
	resolverDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		// The same dialer production uses, so the protector still sees the
		// descriptor; only the nameserver is redirected to the test server.
		return transport.NewDialer().DialContext(ctx, network, dnsAddr)
	}
	t.Cleanup(func() { resolverDial = prevDial })

	protected := protectForTest(t)

	// .invalid never resolves (RFC 2606): a tunnel that comes up here got its
	// endpoint from the protected resolver and nowhere else.
	node := clientNode(t, srv.port, clientPriv, serverPub)
	node.Server = "wg.homelab.invalid"
	c, err := New(node)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// The name must resolve to the peer the fake DNS answered with, not to
	// anything the host's resolver could know.
	ap, err := c.endpointAddr(ctx)
	if err != nil {
		t.Fatalf("endpointAddr: %v", err)
	}
	if want := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(srv.port)); ap != want {
		t.Fatalf("endpointAddr = %v, want %v", ap, want)
	}

	target := net.JoinHostPort(serverAddr, strconv.Itoa(tcpPort))
	conn, err := c.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("DialContext(%s) with a name endpoint: %v", target, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 5)
	if _, err := conn.Read(got); err != nil {
		t.Fatalf("read: %v", err)
	}

	if n := queries(); n == 0 {
		t.Fatal("the endpoint name was never resolved through the protected resolver")
	}
	if calls := atomic.LoadInt64(&protected.calls); calls == 0 {
		t.Fatal("resolving the endpoint opened sockets that never reached the protect hook")
	}
}

// TestUnresolvableEndpointFailsLoudly is the second half of S1: a name that
// cannot be resolved protected must report that failure, not fall back to a
// resolver whose sockets bypass the hook.
func TestUnresolvableEndpointFailsLoudly(t *testing.T) {
	prevDial := resolverDial
	resolverDial = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("resolver unreachable")
	}
	t.Cleanup(func() { resolverDial = prevDial })

	priv, pub := keyPair(t)
	node := clientNode(t, 51820, priv, pub)
	node.Server = "wg.homelab.invalid"
	c, err := New(node)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = c.DialContext(ctx, "tcp", "10.9.9.1:80")
	if err == nil {
		t.Fatal("dial succeeded with an unresolvable endpoint")
	}
	if !strings.Contains(err.Error(), "wg.homelab.invalid") {
		t.Fatalf("error %q does not name the unresolvable endpoint", err)
	}
	if !strings.Contains(err.Error(), "resolver unreachable") {
		t.Fatalf("error %q does not carry the resolver failure", err)
	}
}

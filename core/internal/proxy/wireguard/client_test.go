package wireguard

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"veil/internal/config"
	"veil/internal/transport"
)

const (
	// serverAddr is the peer's address inside the tunnel; the client is given
	// 10.9.9.2/32 and only 10.9.9.1/32 as allowed route.
	serverAddr = "10.9.9.1"
	clientAddr = "10.9.9.2"
	tunnelMTU  = 1420
)

// wgServer is a real WireGuard peer running inside the test process: a device
// over its own userspace stack, reachable over loopback UDP. Nothing here needs
// root, an OS tun device, or a network beyond 127.0.0.1.
type wgServer struct {
	dev   *device.Device
	stack *netstack.Net
	port  int
}

// startWGServer brings a peer up at the fixture's tunnel address and reports the
// UDP port it listens on.
func startWGServer(t *testing.T, serverPriv, clientPub string) *wgServer {
	t.Helper()
	return startWGServerAddrs(t, serverPriv, clientPub, []netip.Addr{netip.MustParseAddr(serverAddr)})
}

// listenPort reads the port the device's bind actually chose.
func listenPort(t *testing.T, uapi string) int {
	t.Helper()
	for _, line := range strings.Split(uapi, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, err := strconv.Atoi(v)
			if err != nil {
				t.Fatalf("bad listen_port %q: %v", v, err)
			}
			return port
		}
	}
	t.Fatalf("no listen_port in %q", uapi)
	return 0
}

// startTCPEcho runs a TCP echo server inside the peer's stack at the fixture's
// tunnel address and reports its port. Bytes written by the client must come
// back unchanged.
func startTCPEcho(t *testing.T, ns *netstack.Net) int {
	t.Helper()
	return startTCPEchoAt(t, ns, netip.MustParseAddr(serverAddr))
}

// startUDPEcho runs a datagram echo server inside the peer's stack.
func startUDPEcho(t *testing.T, ns *netstack.Net) int {
	t.Helper()
	pc, err := ns.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(serverAddr), 0))
	if err != nil {
		t.Fatalf("listen udp in stack: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// keyPair generates a WireGuard (X25519) key pair in the base64 form config.Node
// stores.
func keyPair(t *testing.T) (priv, pub string) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()),
		base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

func mustHexKey(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		t.Fatalf("bad key %q: %v", b64, err)
	}
	return hex.EncodeToString(raw)
}

// clientNode describes the outbound under test: loopback endpoint, the keys the
// wall clock of the test generated, and the tunnel addressing above.
func clientNode(t *testing.T, port int, priv, peerPub string) config.Node {
	t.Helper()
	return config.Node{
		Tag:           "wgtest",
		Type:          "wireguard",
		Server:        "127.0.0.1",
		Port:          port,
		PrivateKey:    priv,
		PeerPublicKey: peerPub,
		Addresses:     []string{clientAddr + "/32"},
		AllowedIPs:    []string{serverAddr + "/32"},
		MTU:           tunnelMTU,
		KeepAlive:     1,
	}
}

// protection records the calls the peer socket made into the protect hook.
type protection struct {
	calls int64
	fd    int64
}

// protectForTest installs a protector, so the test can prove the peer socket
// went through transport rather than around it.
func protectForTest(t *testing.T) *protection {
	t.Helper()
	p := &protection{}
	transport.SetProtector(func(fd uintptr) error {
		atomic.AddInt64(&p.calls, 1)
		atomic.StoreInt64(&p.fd, int64(fd))
		return nil
	})
	t.Cleanup(func() { transport.SetProtector(nil) })
	return p
}

func TestDialThroughTunnel(t *testing.T) {
	clientPriv, clientPub := keyPair(t)
	serverPriv, serverPub := keyPair(t)

	protected := protectForTest(t)
	srv := startWGServer(t, serverPriv, clientPub)
	tcpPort := startTCPEcho(t, srv.stack)
	udpPort := startUDPEcho(t, srv.stack)

	c, err := New(clientNode(t, srv.port, clientPriv, serverPub))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// TCP: a byte-exact round trip through the tunnel.
	tcpTarget := net.JoinHostPort(serverAddr, strconv.Itoa(tcpPort))
	conn, err := c.DialContext(ctx, "tcp", tcpTarget)
	if err != nil {
		t.Fatalf("DialContext(%s): %v", tcpTarget, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	payload := []byte("hello over wireguard")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("tcp write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("tcp read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("tcp echo = %q, want %q", got, payload)
	}

	// UDP: the same round trip through outbound.PacketConn.
	udpTarget := net.JoinHostPort(serverAddr, strconv.Itoa(udpPort))
	pc, err := c.DialPacket(ctx, udpTarget)
	if err != nil {
		t.Fatalf("DialPacket(%s): %v", udpTarget, err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(15 * time.Second))
	dst := netip.MustParseAddrPort(udpTarget)
	if _, err := pc.WriteTo(payload, dst); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	buf := make([]byte, 1500)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("udp read: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("udp echo = %q, want %q", buf[:n], payload)
	}
	if from != dst {
		t.Fatalf("udp echo from %s, want %s", from, dst)
	}

	// The peer socket must have gone through the protect hook: on HarmonyOS a
	// socket that skips it loops the tunnel into our own tun.
	if calls := atomic.LoadInt64(&protected.calls); calls == 0 {
		t.Fatal("peer socket was not protected")
	}
	if fd := atomic.LoadInt64(&protected.fd); fd <= 2 {
		t.Fatalf("protector saw fd %d, want a real descriptor", fd)
	}
}

func TestWrongPeerKeyFails(t *testing.T) {
	clientPriv, clientPub := keyPair(t)
	serverPriv, _ := keyPair(t)
	_, wrongPub := keyPair(t)

	srv := startWGServer(t, serverPriv, clientPub)
	tcpPort := startTCPEcho(t, srv.stack)

	// The client believes the peer has another key, so the handshake never
	// completes. The dial must fail instead of returning a connection that
	// silently carries nothing.
	c, err := New(clientNode(t, srv.port, clientPriv, wrongPub))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	target := net.JoinHostPort(serverAddr, strconv.Itoa(tcpPort))
	conn, err := c.DialContext(ctx, "tcp", target)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("DialContext(%s) with a wrong peer key succeeded", target)
	}
}

func TestCloseStopsDials(t *testing.T) {
	priv, pub := keyPair(t)
	c, err := New(clientNode(t, 51820, priv, pub))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := c.DialContext(context.Background(), "tcp", "10.9.9.1:80"); err == nil {
		t.Fatal("DialContext after Close succeeded")
	}
	if _, err := c.DialPacket(context.Background(), "10.9.9.1:53"); err == nil {
		t.Fatal("DialPacket after Close succeeded")
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	priv, pub := keyPair(t)
	base := clientNode(t, 51820, priv, pub)

	short := base
	short.PrivateKey = base64.StdEncoding.EncodeToString([]byte("too short"))
	if _, err := New(short); err == nil {
		t.Fatal("New accepted a short private key")
	}

	noAddr := base
	noAddr.Addresses = nil
	if _, err := New(noAddr); err == nil {
		t.Fatal("New accepted a node without addresses")
	}

	badAllowed := base
	badAllowed.AllowedIPs = []string{"not-a-cidr"}
	if _, err := New(badAllowed); err == nil {
		t.Fatal("New accepted a bad allowed_ips entry")
	}

	ok, err := New(base)
	if err != nil {
		t.Fatalf("New(base): %v", err)
	}
	_ = ok.Close()
}

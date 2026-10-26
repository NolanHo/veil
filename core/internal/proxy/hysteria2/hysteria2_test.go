package hysteria2

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2/hpack"

	"veil/internal/config"
	"veil/internal/transport"
)

// ---------------------------------------------------------------------------
// A small Hysteria2 server: HTTP/3 auth endpoint, TCP stream echo and datagram
// echo, all on one QUIC listener.
// ---------------------------------------------------------------------------

type testServer struct {
	t        *testing.T
	ln       *quic.Listener
	addr     string
	password string

	conns   atomic.Int32
	streams atomic.Int32
	auths   atomic.Int32
	authErr atomic.Int32
}

func newTestServer(t *testing.T, password string) *testServer {
	t.Helper()
	return newTestServerWith(t, password, selfSignedCert(t), nil)
}

// newTestServerWithCert is newTestServer with a caller-supplied certificate, so
// a test can pin that exact certificate's digest.
func newTestServerWithCert(t *testing.T, password string, cert tls.Certificate) *testServer {
	t.Helper()
	return newTestServerWith(t, password, cert, nil)
}

// newTestServerObfs runs the server behind salamander obfuscation, so a client
// only completes the QUIC handshake if its obfs implementation matches.
func newTestServerObfs(t *testing.T, password, obfsPassword string) *testServer {
	t.Helper()
	obfs, err := newSalamander(obfsPassword)
	if err != nil {
		t.Fatalf("newSalamander: %v", err)
	}
	return newTestServerWith(t, password, selfSignedCert(t), obfs)
}

func newTestServerWith(t *testing.T, password string, cert tls.Certificate, obfs *salamander) *testServer {
	t.Helper()
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpnH3},
		MinVersion:   tls.VersionTLS13,
	}
	pkt, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	var conn net.PacketConn = pkt
	if obfs != nil {
		conn = newSalamanderConn(pkt, obfs)
	}
	ln, err := quic.Listen(conn, tlsConf, &quic.Config{EnableDatagrams: true})
	if err != nil {
		_ = conn.Close()
		t.Fatalf("quic listen: %v", err)
	}
	s := &testServer{t: t, ln: ln, addr: ln.Addr().String(), password: password}
	go s.acceptLoop()
	t.Cleanup(func() {
		_ = ln.Close()
		_ = conn.Close()
	})
	return s
}

func (s *testServer) acceptLoop() {
	for {
		conn, err := s.ln.Accept(context.Background())
		if err != nil {
			return
		}
		s.conns.Add(1)
		go s.handleConn(conn)
	}
}

func (s *testServer) handleConn(conn *quic.Conn) {
	go func() {
		// Drain the client's unidirectional HTTP/3 streams.
		for {
			if _, err := conn.AcceptUniStream(context.Background()); err != nil {
				return
			}
		}
	}()
	go s.echoDatagrams(conn)
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		s.streams.Add(1)
		go s.handleStream(stream)
	}
}

func (s *testServer) handleStream(stream *quic.Stream) {
	defer stream.Close()
	vr := quicvarint.NewReader(stream)
	frameType, err := quicvarint.Read(vr)
	if err != nil {
		return
	}
	switch frameType {
	case frameTypeTCPRequest:
		addr, err := readTCPRequestFrom(stream)
		if err != nil {
			return
		}
		_ = addr
		if err := writeTCPResponse(stream, true, ""); err != nil {
			return
		}
		buf := make([]byte, 4096)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				if _, werr := stream.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	case frameHeaders:
		s.handleAuthRequest(stream)
	default:
		s.t.Logf("test server: unexpected frame type %#x", frameType)
	}
}

// handleAuthRequest decodes the QPACK header block of the auth request and
// answers 233 when the credential matches.
func (s *testServer) handleAuthRequest(stream *quic.Stream) {
	vr := quicvarint.NewReader(stream)
	length, err := quicvarint.Read(vr)
	if err != nil {
		return
	}
	block := make([]byte, length)
	if _, err := io.ReadFull(stream, block); err != nil {
		return
	}
	fields, err := decodeFieldSection(block)
	if err != nil {
		s.t.Logf("test server: decode request headers: %v", err)
		return
	}
	// A real HTTP/3 server answers an uppercase field name with
	// H3_MESSAGE_ERROR (0x10e), so this server rejects one too: left to itself
	// the suite would keep passing a wire format no server accepts.
	for _, f := range fields {
		if f.name != strings.ToLower(f.name) {
			s.t.Errorf("test server: client sent the field name %q; HTTP/3 requires lowercase names", f.name)
			return
		}
	}
	var status int
	if headerValue(fields, ":path") == authPath && headerValue(fields, headerAuth) == s.password {
		status = statusAuth
		s.auths.Add(1)
	} else {
		status = 401
		s.authErr.Add(1)
	}
	resp := encodeFieldSection([]headerField{
		{":status", fmt.Sprint(status)},
		{headerUDPEnabled, "true"},
	})
	frame := quicvarint.Append(nil, frameHeaders)
	frame = quicvarint.Append(frame, uint64(len(resp)))
	frame = append(frame, resp...)
	_, _ = stream.Write(frame)
}

func readTCPRequestFrom(r io.Reader) (string, error) {
	vr := quicvarint.NewReader(r)
	addrLen, err := quicvarint.Read(vr)
	if err != nil {
		return "", err
	}
	if addrLen == 0 || addrLen > maxAddressLength {
		return "", fmt.Errorf("bad address length %d", addrLen)
	}
	addr := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addr); err != nil {
		return "", err
	}
	padLen, err := quicvarint.Read(vr)
	if err != nil {
		return "", err
	}
	if padLen > maxPaddingLength {
		return "", fmt.Errorf("bad padding length %d", padLen)
	}
	if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
		return "", err
	}
	return string(addr), nil
}

func writeTCPResponse(w io.Writer, ok bool, msg string) error {
	buf := make([]byte, 0, 8+len(msg))
	if ok {
		buf = append(buf, 0)
	} else {
		buf = append(buf, 1)
	}
	buf = quicvarint.Append(buf, uint64(len(msg)))
	buf = append(buf, msg...)
	buf = quicvarint.Append(buf, 0) // padding
	_, err := w.Write(buf)
	return err
}

func (s *testServer) echoDatagrams(conn *quic.Conn) {
	for {
		data, err := conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		if _, err := parseUDPMessage(data); err != nil {
			continue
		}
		_ = conn.SendDatagram(data)
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// ---------------------------------------------------------------------------
// Client tests
// ---------------------------------------------------------------------------

func serverNode(t *testing.T, srv *testServer, password string) config.Node {
	t.Helper()
	host, portStr, err := net.SplitHostPort(srv.addr)
	if err != nil {
		t.Fatalf("server addr: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("server port: %v", err)
	}
	return config.Node{
		Tag:      "hy2",
		Type:     "hysteria2",
		Server:   host,
		Port:     port,
		Password: password,
		TLS:      &config.TLS{Enabled: true, Insecure: true},
	}
}

func TestTCPEcho(t *testing.T) {
	srv := newTestServer(t, "s3cret")
	client, err := New(serverNode(t, srv, "s3cret"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := client.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello hysteria2")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}
	if srv.auths.Load() != 1 {
		t.Fatalf("expected 1 successful auth, got %d", srv.auths.Load())
	}
}

func TestConnectionReuse(t *testing.T) {
	srv := newTestServer(t, "pw")
	client, err := New(serverNode(t, srv, "pw"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		conn, err := client.DialContext(ctx, "tcp", "1.2.3.4:80")
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		if _, err := conn.Write([]byte("x")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		buf := make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		_ = conn.Close()
	}
	if n := srv.conns.Load(); n != 1 {
		t.Fatalf("expected a single QUIC connection, got %d", n)
	}
	if n := srv.auths.Load(); n != 1 {
		t.Fatalf("expected a single auth, got %d", n)
	}
}

func TestQUICSocketIsProtected(t *testing.T) {
	srv := newTestServer(t, "pw")

	// Record every descriptor the client hands to the protector. On HarmonyOS
	// this call is what keeps the QUIC socket off our own tun, so it must happen
	// for the socket the client actually sends from.
	var mu sync.Mutex
	var protected []uintptr
	transport.SetProtector(func(fd uintptr) error {
		mu.Lock()
		protected = append(protected, fd)
		mu.Unlock()
		return nil
	})
	t.Cleanup(func() { transport.SetProtector(nil) })

	client, err := New(serverNode(t, srv, "pw"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		t.Fatalf("read: %v", err)
	}

	client.mu.Lock()
	pkt := client.pktConn
	client.mu.Unlock()
	if pkt == nil {
		t.Fatal("client has no underlay socket")
	}
	sc, ok := pkt.(syscall.Conn)
	if !ok {
		t.Fatalf("underlay socket %T exposes no syscall handle", pkt)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var want uintptr
	if err := rc.Control(func(fd uintptr) { want = fd }); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if want == 0 {
		t.Fatal("underlay socket reported fd 0")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(protected) == 0 {
		t.Fatal("protector was never called: the QUIC socket bypasses transport")
	}
	for _, fd := range protected {
		if fd == 0 {
			t.Fatalf("protector called with fd 0 (all calls: %v)", protected)
		}
	}
	for _, fd := range protected {
		if fd == want {
			return
		}
	}
	t.Fatalf("protector saw fds %v, none of them the QUIC socket fd %d", protected, want)
}

// TestCertPinAcceptsMatchingFingerprint covers the self-signed-plus-pin node
// shape (skip-cert-verify=false, fingerprint set): the digest is the only thing
// that can validate the server, and both spellings — openssl-style colon-hex
// with upper case, and bare lower case — must be accepted.
func TestCertPinAcceptsMatchingFingerprint(t *testing.T) {
	cert := selfSignedCert(t)
	srv := newTestServerWithCert(t, "pw", cert)
	sum := sha256.Sum256(cert.Certificate[0])

	for _, tc := range []struct{ name, pin string }{
		{"colon upper", colonHex(sum[:])},
		{"colon lower", strings.ToLower(colonHex(sum[:]))},
		{"bare lower", hex.EncodeToString(sum[:])},
		{"bare upper", strings.ToUpper(hex.EncodeToString(sum[:]))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := serverNode(t, srv, "pw")
			node.TLS.Insecure = false
			node.TLS.Fingerprint = tc.pin
			client, err := New(node)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer client.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, "tcp", "example.com:443")
			if err != nil {
				t.Fatalf("DialContext with pinned certificate: %v", err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, err := io.ReadFull(conn, make([]byte, 4)); err != nil {
				t.Fatalf("read echo: %v", err)
			}
		})
	}
}

func TestCertPinRejectsWrongFingerprint(t *testing.T) {
	cert := selfSignedCert(t)
	srv := newTestServerWithCert(t, "pw", cert)
	sum := sha256.Sum256(cert.Certificate[0])
	wrong := sum
	wrong[0] ^= 0xff

	node := serverNode(t, srv, "pw")
	node.TLS.Insecure = false
	node.TLS.Fingerprint = colonHex(wrong[:])
	client, err := New(node)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := client.DialContext(ctx, "tcp", "example.com:443"); err == nil {
		t.Fatal("a mismatched certificate fingerprint was accepted")
	} else if !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("expected a fingerprint mismatch, got %v", err)
	}
	if n := srv.auths.Load(); n != 0 {
		t.Fatalf("server authenticated %d connections, want 0", n)
	}
}

func TestCertPinParsing(t *testing.T) {
	valid := make([]byte, sha256.Size)
	for i := range valid {
		valid[i] = byte(i)
	}
	for _, tc := range []struct {
		name    string
		in      string
		wantPin bool
		wantErr bool
	}{
		{"empty", "", false, false},
		{"utls name", "chrome", false, false},
		{"utls name upper", "CHROME", false, false},
		{"utls name with digits", "randomized", false, false},
		// A value that is neither a legal digest nor a profile name transport
		// knows is a malformed pin, not "no pin": guessing the latter silently
		// drops the certificate constraint.
		{"malformed trailing letter", strings.Repeat("0", 63) + "g", false, true},
		{"malformed colon octet", colonHex(valid[:31]) + ":zz", false, true},
		{"unknown profile name", "chromium", false, true},
		{"hpkp spelling", "sha256/" + hex.EncodeToString(valid), false, true},
		{"colon upper", colonHex(valid), true, false},
		{"bare lower", hex.EncodeToString(valid), true, false},
		{"spaced upper", "DE 5D FC", false, true},
		{"truncated", colonHex(valid[:16]), false, true},
		{"odd digits", hex.EncodeToString(valid)[:63], false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pin, err := certPin(tc.in)
			if tc.wantErr != (err != nil) {
				t.Fatalf("certPin(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if tc.wantPin != (pin != nil) {
				t.Fatalf("certPin(%q) = %x, want pin %v", tc.in, pin, tc.wantPin)
			}
			if pin != nil && !bytes.Equal(pin, valid) {
				t.Fatalf("certPin(%q) = %x, want %x", tc.in, pin, valid)
			}
		})
	}
}

// colonHex renders a digest the way openssl / Clash print a certificate
// fingerprint: upper-case bytes separated by colons.
func colonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02X", c)
	}
	return strings.Join(parts, ":")
}

func TestAuthFailure(t *testing.T) {
	srv := newTestServer(t, "right-password")
	client, err := New(serverNode(t, srv, "wrong-password"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_, err = client.DialContext(ctx, "tcp", "example.com:443")
	if err == nil {
		t.Fatal("expected an authentication error, got a connection")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("auth failure took too long: %v", elapsed)
	}
	if srv.authErr.Load() == 0 {
		t.Fatal("server never saw the rejected credential")
	}
	t.Logf("auth error: %v", err)
}

func TestCancelledContextFailsFast(t *testing.T) {
	srv := newTestServer(t, "pw")
	client, err := New(serverNode(t, srv, "pw"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	// An already-cancelled context must fail before any handshake work.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.DialContext(ctx, "tcp", "example.com:443"); err == nil {
		t.Fatal("expected a context error")
	}
	if srv.conns.Load() != 0 {
		t.Fatalf("expected no QUIC connection, got %d", srv.conns.Load())
	}
}

func TestUDPEcho(t *testing.T) {
	srv := newTestServer(t, "pw")
	client, err := New(serverNode(t, srv, "pw"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pc, err := client.DialPacket(ctx, "")
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	defer pc.Close()

	dst := netip.MustParseAddrPort("8.8.8.8:53")
	if _, err := pc.WriteTo([]byte("dns query"), dst); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if err := pc.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	buf := make([]byte, 2048)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "dns query" {
		t.Fatalf("unexpected payload %q", buf[:n])
	}
	if from != dst {
		t.Fatalf("unexpected source %s", from)
	}
}

func TestUDPFragmentation(t *testing.T) {
	srv := newTestServer(t, "pw")
	client, err := New(serverNode(t, srv, "pw"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pc, err := client.DialPacket(ctx, "")
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	defer pc.Close()

	// 4 KiB definitely exceeds a single QUIC datagram, so the client has to
	// fragment and the server echoes the fragments back.
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}
	dst := netip.MustParseAddrPort("9.9.9.9:53")
	if _, err := pc.WriteTo(payload, dst); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if err := pc.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	got := make([]byte, 8192)
	n, _, err := pc.ReadFrom(got)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("reassembled %d bytes, want %d", n, len(payload))
	}
	for i := range payload {
		if got[i] != payload[i] {
			t.Fatalf("byte %d mismatch: %d != %d", i, got[i], payload[i])
		}
	}
}

func TestUDPDeadline(t *testing.T) {
	srv := newTestServer(t, "pw")
	client, err := New(serverNode(t, srv, "pw"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pc, err := client.DialPacket(ctx, "")
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	defer pc.Close()

	if err := pc.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	buf := make([]byte, 128)
	if _, _, err := pc.ReadFrom(buf); err == nil {
		t.Fatal("expected a timeout")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("expected a timeout error, got %v", err)
	}
}

func TestInvalidNodes(t *testing.T) {
	cases := []struct {
		name string
		node config.Node
	}{
		{"missing password", config.Node{Tag: "a", Type: "hysteria2", Server: "127.0.0.1", Port: 443}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.node); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestNormalizeAddr(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"example.com:443", "example.com:443", false},
		{"1.2.3.4:80", "1.2.3.4:80", false},
		{"[::1]:8080", "[::1]:8080", false},
		{"::1:8080", "[::1]:8080", false}, // last colon is the port separator
		{"example.com", "", true},
		{"example.com:", "", true},
		{"", "", true},
	}
	for _, tc := range cases {
		got, err := normalizeAddr(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("normalizeAddr(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeAddr(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("normalizeAddr(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestQPackFieldSection pins the encoder/decoder agreement and checks the
// documented byte layout: the Encoded Field Section Prefix, a static-table match
// and a literal header.
func TestQPackFieldSection(t *testing.T) {
	fields := []headerField{
		{":method", "POST"},
		{":scheme", "https"},
		{":authority", "hysteria"},
		{":path", "/auth"},
		{"hysteria-auth", "pw"},
		{"hysteria-cc-rx", "0"},
	}
	block := encodeFieldSection(fields)
	got, err := decodeFieldSection(block)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != len(fields) {
		t.Fatalf("field count %d, want %d", len(got), len(fields))
	}
	for i := range fields {
		if got[i] != fields[i] {
			t.Fatalf("field %d = %+v, want %+v", i, got[i], fields[i])
		}
	}
	// RFC 9204 §4.5.1: Encoded Field Section Prefix, Required Insert Count = 0
	// and Delta Base = 0.
	if !bytes.HasPrefix(block, []byte{0x00, 0x00}) {
		t.Fatalf("expected the 00 00 field section prefix, got %x", block)
	}
	// ":method: POST" is static entry 20, so it is one indexed field line.
	if block[2] != 0xD4 {
		t.Fatalf("expected indexed field line 0xD4, got %#x", block[2])
	}
	// ":authority" is static entry 0: name reference with a literal value.
	if block[4] != 0x50 {
		t.Fatalf("expected name reference 0x50, got %#x", block[4])
	}
}

// TestEncodeFieldSectionPrefix pins the wire prefix a real server required:
// without it the server read our first field line as the prefix and answered
// QPACK_DECOMPRESSION_FAILED (0x200), so every auth request failed.
func TestEncodeFieldSectionPrefix(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields []headerField
	}{
		{"empty", nil},
		{"static match", []headerField{{":method", "POST"}}},
		{"literal", []headerField{{"hysteria-auth", "pw"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			block := encodeFieldSection(tc.fields)
			if !bytes.HasPrefix(block, []byte{0x00, 0x00}) {
				t.Fatalf("encodeFieldSection(%v) = %x, want the 00 00 Encoded Field Section Prefix", tc.fields, block)
			}
			if _, err := decodeFieldSection(block); err != nil {
				t.Fatalf("round trip: %v", err)
			}
		})
	}
}

// TestEncodeFieldSectionLowercasesNames pins the other wire rule a real server
// enforces: HTTP/3 field names are lowercase, an uppercase one is rejected with
// H3_MESSAGE_ERROR (0x10e). The package's constants keep hysteria's canonical
// spelling, so the encoder normalises before the static-table lookup.
func TestEncodeFieldSectionLowercasesNames(t *testing.T) {
	block := encodeFieldSection([]headerField{
		{":Method", "POST"},
		{"Hysteria-Auth", "pw"},
		{"Hysteria-Padding", "xxxxxxxx"},
	})
	// The literal name is written as-is, so it must be lowercase on the wire.
	if !bytes.Contains(block, []byte("hysteria-auth")) || bytes.Contains(block, []byte("Hysteria")) {
		t.Fatalf("literal field name was not lowercased: %x", block)
	}
	got, err := decodeFieldSection(block)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []headerField{
		{":method", "POST"},
		{"hysteria-auth", "pw"},
		{"hysteria-padding", "xxxxxxxx"},
	}
	if len(got) != len(want) {
		t.Fatalf("field count %d, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("field %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestDecodeFieldSectionConsumesPrefix pins the decode side: a real server's
// response also starts with the Encoded Field Section Prefix, and treating that
// 0x00 as a field line produced "unsupported qpack representation 0x00".
func TestDecodeFieldSectionConsumesPrefix(t *testing.T) {
	// 00 00 = prefix, 0xD4 = indexed static entry 20 (":method: POST").
	got, err := decodeFieldSection([]byte{0x00, 0x00, 0xD4})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0] != (headerField{":method", "POST"}) {
		t.Fatalf("decoded %+v, want :method POST", got)
	}
	// Field lines without the prefix are not a valid section any more: 0xD4 read
	// as Required Insert Count is nonzero and is rejected.
	if _, err := decodeFieldSection([]byte{0xD4}); err == nil {
		t.Fatal("a field section without the Encoded Field Section Prefix was accepted")
	}
	// Required Insert Count != 0 means dynamic-table entries, which we never
	// announced (SETTINGS carries a capacity of 0).
	_, err = decodeFieldSection([]byte{0x01, 0x00, 0xD4})
	if err == nil || !strings.Contains(err.Error(), "required insert count") {
		t.Fatalf("nonzero Required Insert Count: err = %v, want a required-insert-count error", err)
	}
}

// TestDecodeFieldSectionBaseSign is the QPACK negative-Base regression.
//
// RFC 9204 §4.5.1.2 makes the Delta Base field a sign bit followed by a 7-bit
// integer, and Base = Required Insert Count + Delta Base when Sign is 0, or
// Required Insert Count - Delta Base - 1 when Sign is 1. With a required insert
// count of 0 and Sign 1 the Base is -1, which names a dynamic-table insertion
// that cannot exist; a conforming encoder never emits it. The decoder used to
// consume the 7-bit integer and ignore the sign bit, so 00 80 d9 was read as a
// valid field section and decoded into ":status: 200".
func TestDecodeFieldSectionBaseSign(t *testing.T) {
	// 0xD9 is the indexed static field line for entry 25 (":status: 200").
	const status200 = 0xD9

	// Required Insert Count 0, Sign 1, Delta Base 0 → Base = -1.
	if fields, err := decodeFieldSection([]byte{0x00, 0x80, status200}); err == nil {
		t.Fatalf("a field section with Base = -1 was accepted and decoded into %+v", fields)
	} else if !strings.Contains(err.Error(), "base") {
		t.Fatalf("error %q does not name the invalid base", err)
	}

	// Base = 0 is the static-table case: no dynamic reference at all.
	fields, err := decodeFieldSection([]byte{0x00, 0x00, status200})
	if err != nil {
		t.Fatalf("Base = 0: %v", err)
	}
	if len(fields) != 1 || fields[0] != (headerField{":status", "200"}) {
		t.Fatalf("Base = 0 decoded %+v, want :status 200", fields)
	}

	// A non-zero, non-negative Base is legal as well: Sign 0 with Delta Base 64
	// gives Base = 64. Treating the prefix as the constant 00 00 would reject it.
	fields, err = decodeFieldSection([]byte{0x00, 0x40, status200})
	if err != nil {
		t.Fatalf("Base = 64: %v", err)
	}
	if len(fields) != 1 || fields[0] != (headerField{":status", "200"}) {
		t.Fatalf("Base = 64 decoded %+v, want :status 200", fields)
	}

	// The prefix is still required: a section that stops after the required
	// insert count has no Delta Base byte.
	if _, err := decodeFieldSection([]byte{0x00}); err == nil {
		t.Fatal("a field section without a Delta Base was accepted")
	}
}

// TestHeaderValueIsCaseInsensitive pins the lookup of server headers: the wire
// spells them lowercase, the package keeps hysteria's canonical spelling.
func TestHeaderValueIsCaseInsensitive(t *testing.T) {
	fields := []headerField{{name: "hysteria-udp", value: "false"}}
	if got := headerValue(fields, headerUDPEnabled); got != "false" {
		t.Fatalf("headerValue(%q, %q) = %q, want \"false\"", headerUDPEnabled, "hysteria-udp", got)
	}
	if got := headerValue(fields, ":status"); got != "" {
		t.Fatalf("headerValue(:status) = %q, want \"\"", got)
	}
}

func TestHuffmanValueDecoding(t *testing.T) {
	// ":status: 233" encoded as a literal with a Huffman-coded value. The bytes
	// come from x/net/http2/hpack's encoder so the decoder is exercised against
	// an independent implementation.
	buf := []byte{0x00, 0x00}              // Encoded Field Section Prefix: no dynamic table
	buf = appendQPACKInt(buf, 25, 4, 0x50) // :status (static 25 = ":status 200")
	dst := hpack.AppendHuffmanString(nil, "233")
	buf = appendQPACKInt(buf, uint64(len(dst)), 7, 0x80)
	buf = append(buf, dst...)
	fields, err := decodeFieldSection(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(fields) != 1 || fields[0].name != ":status" || fields[0].value != "233" {
		t.Fatalf("decoded %+v", fields)
	}
}

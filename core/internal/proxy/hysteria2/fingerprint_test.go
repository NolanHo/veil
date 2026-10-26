package hysteria2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"veil/internal/config"
	"veil/internal/transport"
)

// TestCertPinRejectsMalformedFingerprint is the regression test for a
// certificate pin that is not spelled as hex. certPin used to report "no pin"
// for every value with a non-hex character, so a mistyped digest (63 hex digits
// plus a stray "g") silently turned a pin-and-verify node into a node that
// authenticates nothing: with tls.insecure the client then talks to any
// self-signed peer.
//
// A malformed pin is not a uTLS profile name. The only values that may mean
// "not a pin" are the profile names transport accepts; everything else has to
// fail while the node is built, where the UI can still explain it.
func TestCertPinRejectsMalformedFingerprint(t *testing.T) {
	zero := make([]byte, sha256.Size)
	cases := []struct{ name, fingerprint string }{
		// The exact value the review used to reproduce the hole.
		{"reviewer value", strings.Repeat("0", 63) + "g"},
		// Same shape in the openssl/Clash colon spelling.
		{"colon form with a bad octet", colonHex(zero) + ":zz"},
		{"hpkp spelling", "sha256/" + hex.EncodeToString(zero)},
		{"0x prefix", "0x" + hex.EncodeToString(zero)},
		// A misspelled profile name: not a pin, and not a name transport knows,
		// so guessing "must be a fingerprint" would drop authentication again.
		{"unknown profile name", "chromium"},
	}
	for _, tc := range cases {
		for _, insecure := range []bool{true, false} {
			t.Run(tc.name+"/insecure="+boolName(insecure), func(t *testing.T) {
				node := config.Node{
					Tag:      "hy2",
					Type:     "hysteria2",
					Server:   "127.0.0.1",
					Port:     443,
					Password: "pw",
					TLS:      &config.TLS{Enabled: true, Insecure: insecure, Fingerprint: tc.fingerprint},
				}
				client, err := New(node)
				if err == nil {
					client.Close()
					t.Fatalf("New accepted tls.fingerprint %q (insecure=%v): a malformed pin must fail at construction instead of turning the node into an unauthenticated one",
						tc.fingerprint, insecure)
				}
				if !strings.Contains(err.Error(), "fingerprint") {
					t.Fatalf("New rejected %q with an error that does not name the field: %v", tc.fingerprint, err)
				}
			})
		}
	}
}

// TestCertPinAcceptsKnownUTLSFingerprints pins the behaviour that stays: a known
// uTLS profile name is not a certificate pin. This package dials with crypto/tls
// and cannot speak the profile, so the value is ignored exactly as before and
// tls.insecure / the CA chain still decides whether the peer is trusted.
func TestCertPinAcceptsKnownUTLSFingerprints(t *testing.T) {
	names := append([]string(nil), utlsFingerprintNames...)
	// transport trims and lowercases the name, so spellings like these are the
	// same profile and must not be rejected.
	names = append(names, "CHROME", " Firefox ", "Randomized")
	for _, name := range names {
		for _, insecure := range []bool{true, false} {
			t.Run(strings.TrimSpace(name)+"/insecure="+boolName(insecure), func(t *testing.T) {
				node := config.Node{
					Tag:      "hy2",
					Type:     "hysteria2",
					Server:   "127.0.0.1",
					Port:     443,
					Password: "pw",
					TLS:      &config.TLS{Enabled: true, Insecure: insecure, Fingerprint: name},
				}
				client, err := New(node)
				if err != nil {
					t.Fatalf("New(tls.fingerprint=%q): %v", name, err)
				}
				defer client.Close()
				if got := client.tlsConfig.InsecureSkipVerify; got != insecure {
					t.Fatalf("InsecureSkipVerify = %v, want %v", got, insecure)
				}
				if client.tlsConfig.VerifyPeerCertificate != nil {
					t.Fatalf("a uTLS name %q installed certificate pin verification", name)
				}
			})
		}
	}
}

func boolName(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// TestResolveServerProtectsDNSSocket covers the other socket hysteria2 opens
// besides the QUIC one: the nameserver socket used to turn a node's host into an
// address. net.DefaultResolver dials it with an unpatched net.Dialer, so on
// HarmonyOS the query would be captured by our own tun (AGENTS.md invariant 1).
// resolveServer therefore takes the resolver it should use, and the production
// one (dnsResolver) dials through transport.
func TestResolveServerProtectsDNSSocket(t *testing.T) {
	dnsAddr := startTestDNS(t)

	var mu sync.Mutex
	var protected []uintptr
	transport.SetProtector(func(fd uintptr) error {
		mu.Lock()
		protected = append(protected, fd)
		mu.Unlock()
		return nil
	})
	t.Cleanup(func() { transport.SetProtector(nil) })

	// Point the resolver at the local server but keep the production dial hook,
	// so the assertion is about the socket the resolver really connects on.
	var dialed []uintptr
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			conn, err := protectedDial(ctx, network, dnsAddr)
			if err != nil {
				return nil, err
			}
			if sc, ok := conn.(syscall.Conn); ok {
				if rc, err := sc.SyscallConn(); err == nil {
					_ = rc.Control(func(fd uintptr) {
						mu.Lock()
						dialed = append(dialed, fd)
						mu.Unlock()
					})
				}
			}
			return conn, nil
		},
	}

	c := &Client{tag: "hy2", serverAddr: "endpoint.test:8443"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addr, err := c.resolveServer(ctx, resolver)
	if err != nil {
		t.Fatalf("resolveServer: %v", err)
	}
	want := netip.MustParseAddrPort("203.0.113.7:8443")
	if got := addr.AddrPort(); got != want {
		t.Fatalf("resolveServer = %s, want %s", got, want)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(dialed) == 0 {
		t.Fatal("resolver never dialed the nameserver")
	}
	for _, fd := range dialed {
		if !containsFD(protected, fd) {
			t.Fatalf("nameserver socket fd %d was never handed to the protector (protector saw %v)", fd, protected)
		}
	}
}

func containsFD(fds []uintptr, want uintptr) bool {
	for _, fd := range fds {
		if fd == want {
			return true
		}
	}
	return false
}

// startTestDNS serves A queries with 203.0.113.7 and answers everything else
// with an empty NOERROR, which is all the Go resolver needs to finish a
// LookupNetIP. It returns the address to point a resolver at.
func startTestDNS(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp dns: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if resp := dnsTestAnswer(buf[:n]); resp != nil {
				_, _ = pc.WriteToUDP(resp, from)
			}
		}
	}()
	return pc.LocalAddr().String()
}

// dnsTestAnswer builds a minimal reply: the question is echoed, and an A query
// also gets one A record. Both sections are hand-encoded so the test needs no
// DNS dependency.
func dnsTestAnswer(query []byte) []byte {
	if len(query) < 12 || query[2]&0x80 != 0 {
		return nil
	}
	// Walk the question name to find qtype/qclass: labels until a zero length.
	off := 12
	for {
		if off >= len(query) {
			return nil
		}
		l := int(query[off])
		off++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 {
			return nil // compression is not valid in a question
		}
		off += l
		if off > len(query) {
			return nil
		}
	}
	if off+4 > len(query) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(query[off:])
	end := off + 4
	resp := make([]byte, end, end+16)
	copy(resp, query[:end])
	resp[2] = 0x81                           // QR = response, RD
	resp[3] = 0x80                           // RA, RCODE 0
	binary.BigEndian.PutUint16(resp[6:], 0)  // ANCOUNT
	binary.BigEndian.PutUint16(resp[8:], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(resp[10:], 0) // ARCOUNT
	if qtype != 1 {                          // only A carries an address
		return resp
	}
	binary.BigEndian.PutUint16(resp[6:], 1)
	answer := []byte{
		0xC0, 0x0C, // name: pointer to the question name
		0x00, 0x01, // type A
		0x00, 0x01, // class IN
		0x00, 0x00, 0x00, 0x3C, // TTL 60s
		0x00, 0x04, // RDLENGTH
		203, 0, 113, 7,
	}
	return append(resp, answer...)
}

// TestDNSTestAnswer checks the helper above really encodes the reply the
// resolver test depends on, so a broken helper cannot make that test pass for
// the wrong reason.
func TestDNSTestAnswer(t *testing.T) {
	query := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x08, 'e', 'n', 'd', 'p', 'o', 'i', 'n', 't',
		0x04, 't', 'e', 's', 't',
		0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	resp := dnsTestAnswer(query)
	if resp == nil {
		t.Fatal("no answer")
	}
	if !bytes.Equal(resp[:2], query[:2]) {
		t.Fatalf("response id %x, want %x", resp[:2], query[:2])
	}
	if resp[2]&0x80 == 0 || resp[3]&0x0F != 0 {
		t.Fatalf("bad flags %#x %#x", resp[2], resp[3])
	}
	if n := binary.BigEndian.Uint16(resp[6:]); n != 1 {
		t.Fatalf("ANCOUNT = %d, want 1", n)
	}
	if !bytes.HasSuffix(resp, []byte{203, 0, 113, 7}) {
		t.Fatalf("response does not end in the A record: %x", resp)
	}
	// A AAAA query is answered without records, not dropped.
	q6 := append([]byte(nil), query...)
	q6[len(q6)-3] = 0x1C // qtype AAAA
	resp6 := dnsTestAnswer(q6)
	if resp6 == nil || binary.BigEndian.Uint16(resp6[6:]) != 0 {
		t.Fatalf("AAAA answer = %x, want a NOERROR with no records", resp6)
	}
}

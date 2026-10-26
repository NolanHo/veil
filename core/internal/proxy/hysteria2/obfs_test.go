package hysteria2

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"veil/internal/config"
)

// TestSalamanderKnownAnswerVector pins the wire format against packets produced
// by the reference implementation, github.com/apernet/hysteria/extras/v2@v2.13.0
// (obfs.WrapPacketConnSalamander), which is what Hysteria2 clients and servers
// run. The salt is random per packet, so each vector is [salt][ciphertext] and
// only the sealing step is deterministic; the second payload spans more than two
// 32-byte keystream blocks, which pins the tiling. Generator: /tmp/obfsref/main.go.
func TestSalamanderKnownAnswerVector(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string
		plain    string
		saltHex  string
		wireHex  string
	}{
		{
			name:     "one block and a bit",
			password: "average_password",
			plain:    "hysteria2 salamander known-answer vector",
			saltHex:  "245a89111d1eee64",
			wireHex: "245a89111d1eee64a17452cd2a8b01c7bb28c2bcfe59c5efab1d013a96cfe4c4" +
				"712d666fb4c6a6d1bb2d57dc2c8d07d4",
		},
		{
			name:     "three blocks",
			password: "another-obfs-pw",
			plain: "a longer payload that spans more than two keystream blocks: " +
				"0123456789abcdef0123456789abcdef0123456789",
			saltHex: "85995fe6f4968a33",
			wireHex: "85995fe6f4968a339a22af6c8a2c1d9bbdcaf9f65238bcc0702f752c19cfe97e" +
				"c0bb0094f62ac555db76ab628a6b0c9ef29af3ea4724a9d6353a706d0f83f56d" +
				"caa64994ab748503cf37f534dc72198bfedefde90e66ef97646e2b7a55d6fb6c" +
				"c2b116d2ab748503cf37f534dc72",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, want := len(tc.wireHex), 2*(len(tc.plain)+salamanderSaltLen); got != want {
				t.Fatalf("vector is malformed: %d hex chars, want %d", got, want)
			}
			obfs, err := newSalamander(tc.password)
			if err != nil {
				t.Fatalf("newSalamander: %v", err)
			}
			salt, err := hex.DecodeString(tc.saltHex)
			if err != nil {
				t.Fatalf("decode salt: %v", err)
			}
			out := make([]byte, salamanderBufSize)
			copy(out, salt)
			if got := hex.EncodeToString(obfs.seal([]byte(tc.plain), out)); got != tc.wireHex {
				t.Fatalf("wire format drifted from the reference:\n got %s\nwant %s", got, tc.wireHex)
			}

			// A packet produced by the reference must also decode with ours.
			wire, err := hex.DecodeString(tc.wireHex)
			if err != nil {
				t.Fatalf("decode wire: %v", err)
			}
			back := make([]byte, salamanderBufSize)
			if got := obfs.deobfuscate(wire, back); string(got) != tc.plain {
				t.Fatalf("deobfuscate = %q, want %q", got, tc.plain)
			}
		})
	}
}

func TestSalamanderRoundTrip(t *testing.T) {
	obfs, err := newSalamander("correct horse battery staple")
	if err != nil {
		t.Fatalf("newSalamander: %v", err)
	}
	out := make([]byte, salamanderBufSize)
	back := make([]byte, salamanderBufSize)
	for _, size := range []int{1, 8, 32, 33, 1200, 1500} {
		plain := make([]byte, size)
		if _, err := rand.Read(plain); err != nil {
			t.Fatalf("rand: %v", err)
		}
		wire, err := obfs.obfuscate(plain, out)
		if err != nil {
			t.Fatalf("obfuscate(%d): %v", size, err)
		}
		if len(wire) != size+salamanderSaltLen {
			t.Fatalf("wire length %d, want %d", len(wire), size+salamanderSaltLen)
		}
		if bytes.Equal(wire[salamanderSaltLen:], plain) {
			t.Fatalf("payload of %d bytes was not obfuscated", size)
		}
		if got := obfs.deobfuscate(wire, back); !bytes.Equal(got, plain) {
			t.Fatalf("round trip of %d bytes lost the payload", size)
		}
	}

	// The salt is per packet, so the same payload never looks the same twice.
	plain := []byte("repeated payload")
	first, err := obfs.obfuscate(plain, out)
	if err != nil {
		t.Fatalf("obfuscate: %v", err)
	}
	firstCopy := append([]byte(nil), first...)
	second, err := obfs.obfuscate(plain, out)
	if err != nil {
		t.Fatalf("obfuscate: %v", err)
	}
	if bytes.Equal(firstCopy[:salamanderSaltLen], second[:salamanderSaltLen]) {
		t.Fatal("salt was reused between packets")
	}
	if bytes.Equal(firstCopy, second) {
		t.Fatal("two packets of the same payload are identical on the wire")
	}

	// A wrong password yields garbage, never the payload.
	other, err := newSalamander("wrong password")
	if err != nil {
		t.Fatalf("newSalamander: %v", err)
	}
	if got := other.deobfuscate(firstCopy, back); bytes.Equal(got, plain) {
		t.Fatal("a mismatched obfs password recovered the payload")
	}
}

// TestSalamanderConnOverUDP exercises the net.PacketConn wrapper on real sockets:
// the wire carries salt + ciphertext, and a packet too short to be obfuscated is
// dropped instead of surfacing as a QUIC packet.
func TestSalamanderConnOverUDP(t *testing.T) {
	obfs, err := newSalamander("obfs-password")
	if err != nil {
		t.Fatalf("newSalamander: %v", err)
	}
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen peer: %v", err)
	}
	defer peer.Close()
	raw, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen raw: %v", err)
	}
	conn := newSalamanderConn(raw, obfs)
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	plain := []byte("ping through obfs")
	if n, err := conn.WriteTo(plain, peer.LocalAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	} else if n != len(plain) {
		t.Fatalf("WriteTo reported %d bytes, want %d", n, len(plain))
	}

	if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("peer SetReadDeadline: %v", err)
	}
	buf := make([]byte, 2048)
	n, _, err := peer.ReadFrom(buf)
	if err != nil {
		t.Fatalf("peer ReadFrom: %v", err)
	}
	wire := buf[:n]
	if n != len(plain)+salamanderSaltLen {
		t.Fatalf("wire packet is %d bytes, want %d", n, len(plain)+salamanderSaltLen)
	}
	if bytes.Equal(wire[salamanderSaltLen:], plain) {
		t.Fatal("wire payload equals the plaintext")
	}
	back := make([]byte, 2048)
	if got := obfs.deobfuscate(wire, back); !bytes.Equal(got, plain) {
		t.Fatalf("wire payload deobfuscated to %q, want %q", got, plain)
	}

	// Junk first, then a valid packet: the wrapper must skip the junk.
	if _, err := peer.WriteTo([]byte{0x00, 0x01}, conn.LocalAddr()); err != nil {
		t.Fatalf("peer WriteTo junk: %v", err)
	}
	sealed, err := obfs.obfuscate([]byte("pong"), make([]byte, salamanderBufSize))
	if err != nil {
		t.Fatalf("obfuscate: %v", err)
	}
	if _, err := peer.WriteTo(sealed, conn.LocalAddr()); err != nil {
		t.Fatalf("peer WriteTo pong: %v", err)
	}
	n, _, err = conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom after junk: %v", err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("ReadFrom = %q, want %q", buf[:n], "pong")
	}
}

func TestNewObfsConfig(t *testing.T) {
	withHeaders := func(kv map[string]string) *config.Transport {
		return &config.Transport{Headers: kv}
	}
	for _, tc := range []struct {
		name      string
		transport *config.Transport
		wantObfs  bool
		wantErr   bool
	}{
		{"no transport", nil, false, false},
		{"obfs none", withHeaders(map[string]string{"obfs": "none", "obfs-password": "whatever"}), false, false},
		{"empty obfs", withHeaders(map[string]string{"obfs": ""}), false, false},
		{"salamander", withHeaders(map[string]string{"obfs": "salamander", "obfs-password": "obfspw"}), true, false},
		{"case insensitive", withHeaders(map[string]string{"obfs": "Salamander", "obfs-password": "obfspw"}), true, false},
		{"missing password", withHeaders(map[string]string{"obfs": "salamander"}), false, true},
		{"short password", withHeaders(map[string]string{"obfs": "salamander", "obfs-password": "abc"}), false, true},
		{"unknown type", withHeaders(map[string]string{"obfs": "gecko", "obfs-password": "obfspw"}), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := config.Node{
				Tag:       "hy2",
				Type:      "hysteria2",
				Server:    "127.0.0.1",
				Port:      443,
				Password:  "pw",
				TLS:       &config.TLS{Enabled: true, Insecure: true},
				Transport: tc.transport,
			}
			client, err := New(node)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if got := client.obfs != nil; got != tc.wantObfs {
				t.Fatalf("obfs enabled = %v, want %v", got, tc.wantObfs)
			}
		})
	}
}

// TestObfsSalamanderE2E runs the local Hysteria2 server behind the same obfs
// implementation, so the client has to obfuscate correctly for the QUIC
// handshake, the HTTP/3 auth and the TCP echo to work at all.
func TestObfsSalamanderE2E(t *testing.T) {
	srv := newTestServerObfs(t, "pw", "obfs-password")
	node := serverNode(t, srv, "pw")
	node.Transport = &config.Transport{Headers: map[string]string{
		"obfs":          "salamander",
		"obfs-password": "obfs-password",
	}}
	client, err := New(node)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext through obfs: %v", err)
	}
	defer conn.Close()
	payload := []byte("obfuscated hello")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}
	if n := srv.auths.Load(); n != 1 {
		t.Fatalf("expected 1 successful auth, got %d", n)
	}
}

// TestObfsIsRequired pins the other direction: without the obfuscation the same
// server is unreachable, which is why nodes with obfs used to be dead.
func TestObfsIsRequired(t *testing.T) {
	srv := newTestServerObfs(t, "pw", "obfs-password")
	client, err := New(serverNode(t, srv, "pw"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if _, err := client.DialContext(ctx, "tcp", "example.com:443"); err == nil {
		t.Fatal("connected to an obfuscated server without obfs")
	}
}

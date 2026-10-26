package transport

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"veil/internal/config"
)

// TestBuildWithCarriesTheStackOverBase proves the base dialer replaces only the
// TCP connection underneath the stack: the node's own address is never dialed,
// and everything Build layers (nothing here — a raw tcp transport) rides the
// connection base returns.
func TestBuildWithCarriesTheStackOverBase(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	var dials int
	base := DialerFunc(func(ctx context.Context) (net.Conn, error) {
		dials++
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	})

	// The node address is unroutable on purpose: any dial of it fails the test.
	n := config.Node{Type: "vless", Server: "203.0.113.9", Port: 443}
	d, err := BuildWith(n, base)
	if err != nil {
		t.Fatalf("BuildWith: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.Dial(ctx)
	if err != nil {
		t.Fatalf("dial over base: %v", err)
	}
	defer conn.Close()

	msg := []byte("ping")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
	if dials != 1 {
		t.Fatalf("base dialed %d times, want 1", dials)
	}
}

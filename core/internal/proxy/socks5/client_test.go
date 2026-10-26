package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"veil/internal/config"
)

// socksServer is a minimal SOCKS5 server: negotiate a method, optionally check
// credentials, accept one CONNECT, then relay bytes to the target. It records
// what the client asked for so a test can assert the protocol was spoken.
type socksServer struct {
	ln       net.Listener
	wantUser string
	wantPass string
	targets  chan string
	users    chan string
}

func startSocks(t *testing.T, user, pass string) *socksServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &socksServer{
		ln: ln, wantUser: user, wantPass: pass,
		targets: make(chan string, 4), users: make(chan string, 4),
	}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *socksServer) addr() string { return s.ln.Addr().String() }

func (s *socksServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *socksServer) handle(conn net.Conn) {
	defer conn.Close()
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	want := byte(methodNoAuth)
	if s.wantUser != "" {
		want = methodUserPass
	}
	offered := false
	for _, m := range methods {
		if m == want {
			offered = true
		}
	}
	if !offered {
		_, _ = conn.Write([]byte{version5, methodNoAcceptable})
		return
	}
	if _, err := conn.Write([]byte{version5, want}); err != nil {
		return
	}
	if want == methodUserPass {
		if !s.authenticate(conn) {
			return
		}
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[1] != cmdConnect {
		_, _ = conn.Write([]byte{version5, 0x07, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	host, err := readHost(conn, req[3])
	if err != nil {
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(conn, pb); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(pb[0])<<8|int(pb[1])))
	s.targets <- target

	upstream, err := net.DialTimeout("tcp", target, 2*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte{version5, 0x05, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	if _, err := conn.Write([]byte{version5, 0x00, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	go func() { _, _ = io.Copy(upstream, conn) }()
	_, _ = io.Copy(conn, upstream)
}

func (s *socksServer) authenticate(conn net.Conn) bool {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return false
	}
	user := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return false
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return false
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return false
	}
	s.users <- string(user)
	if string(user) != s.wantUser || string(pass) != s.wantPass {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return false
	}
	_, _ = conn.Write([]byte{0x01, 0x00})
	return true
}

func readHost(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		b := make([]byte, 4)
		_, err := io.ReadFull(conn, b)
		return net.IP(b).String(), err
	case atypIPv6:
		b := make([]byte, 16)
		_, err := io.ReadFull(conn, b)
		return net.IP(b).String(), err
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return "", err
		}
		b := make([]byte, int(l[0]))
		_, err := io.ReadFull(conn, b)
		return string(b), err
	default:
		return "", fmt.Errorf("bad atyp %d", atyp)
	}
}

// echo starts a TCP echo server and returns its address.
func echo(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func newClient(t *testing.T, srv *socksServer, user, pass string) *Client {
	t.Helper()
	host, portStr, err := net.SplitHostPort(srv.addr())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, _ := strconv.Atoi(portStr)
	c, err := New(config.Node{
		Tag: "s5", Type: "socks5", Server: host, Port: port,
		Username: user, Password: pass,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestDialThroughSocks5 is the core contract: a stream opened through the client
// reaches the target, and the server sees a CONNECT for that target.
func TestDialThroughSocks5(t *testing.T) {
	target := echo(t)
	srv := startSocks(t, "", "")
	c := newClient(t, srv, "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echoed %q, want ping", buf)
	}
	select {
	case got := <-srv.targets:
		if got != target {
			t.Fatalf("server saw target %q, want %q", got, target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the server recorded no CONNECT")
	}
}

// TestDialWithCredentials covers the username/password path a household
// SOCKS5 endpoint usually requires.
func TestDialWithCredentials(t *testing.T) {
	target := echo(t)
	srv := startSocks(t, "nolan", "s3cret")
	c := newClient(t, srv, "nolan", "s3cret")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hi")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := <-srv.users; got != "nolan" {
		t.Fatalf("server saw user %q", got)
	}
}

// TestWrongCredentialsFail: a rejected login must surface as an error, not a
// half-open stream the caller then writes into.
func TestWrongCredentialsFail(t *testing.T) {
	target := echo(t)
	srv := startSocks(t, "nolan", "s3cret")
	c := newClient(t, srv, "nolan", "wrong")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.DialContext(ctx, "tcp", target); err == nil {
		t.Fatal("DialContext succeeded with wrong credentials")
	}
}

// TestUnsupportedNetworkIsRejected keeps UDP from silently looking like TCP.
func TestUnsupportedNetworkIsRejected(t *testing.T) {
	srv := startSocks(t, "", "")
	c := newClient(t, srv, "", "")
	if _, err := c.DialContext(context.Background(), "udp", "127.0.0.1:53"); err == nil {
		t.Fatal("DialContext accepted a udp network")
	}
}

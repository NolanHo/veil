package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	"veil/internal/config"
	"veil/internal/proxy/vless"
)

func main() {
	pub := readFile("/tmp/xbin/pub.txt")
	socks := ""
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "socks://") {
		socks = strings.TrimPrefix(os.Args[1], "socks://")
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if socks != "" {
			return socksDial(ctx, socks, address)
		}
		n := config.Node{Tag: "local", Type: "vless", Server: "127.0.0.1", Port: 11443,
			UUID: "11111111-2222-3333-4444-555555555555", Flow: "xtls-rprx-vision",
			TLS: &config.TLS{Enabled: true, ServerName: "www.icloud.com", Fingerprint: "chrome",
				Reality: &config.Reality{PublicKey: pub}}}
		c, err := vless.New(n)
		if err != nil {
			return nil, err
		}
		return c.DialContext(ctx, "tcp", address)
	}
	// After 3s dump all goroutine stacks to stderr: shows exactly where the
	// TLS handshake is stuck.
	go func() {
		time.Sleep(3 * time.Second)
		pprof.Lookup("goroutine").WriteTo(os.Stderr, 2)
	}()
	targets := []string{"127.0.0.1:8443"}
	if len(os.Args) > 1 {
		targets = os.Args[1:]
	}
	for _, target := range targets {
		host := "localtest"
		path := "/"
		if target == "127.0.0.1:8443" {
			host, path = "localtest", "/big"
		} else if target == "www.gstatic.com:443" {
			host = "www.gstatic.com"
		} else if target == "1.1.1.1:443" {
			host = "one.one.one.one"
		}
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		raw, err := dial(ctx, "tcp", target)
		if err != nil {
			fmt.Printf("[%s] dial: %v\n", target, err)
			cancel()
			continue
		}
		fmt.Printf("[%s] dial done in %s\n", target, time.Since(start))
		tc := tls.Client(raw, &tls.Config{ServerName: host, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
		hstart := time.Now()
		if err := tc.HandshakeContext(ctx); err != nil {
			fmt.Printf("[%s] tls: %v (after %s)\n", target, err, time.Since(hstart))
			raw.Close()
			cancel()
			continue
		}
		fmt.Printf("[%s] tls handshake ok in %s (0x%04x)\n", target, time.Since(hstart), tc.ConnectionState().Version)
		_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
		_, _ = tc.Write([]byte("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"))
		total := 0
		buf := make([]byte, 16384)
		rstart := time.Now()
		for {
			nr, rerr := tc.Read(buf)
			total += nr
			if rerr != nil {
				fmt.Printf("[%s] body done: total=%d err=%v in %s\n", target, total, rerr, time.Since(rstart))
				break
			}
			if total >= 196608 {
				fmt.Printf("[%s] body ok: total=%d in %s\n", target, total, time.Since(rstart))
				break
			}
		}
		raw.Close()
		cancel()
	}
}

// socksDial connects through a SOCKS5 proxy (RFC 1928), CONNECT command only.
func socksDial(ctx context.Context, proxy, address string) (net.Conn, error) {
	d := net.Dialer{}
	c, err := d.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, err
	}
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		c.Close()
		return nil, err
	}
	var r [2]byte
	if _, err := io.ReadFull(c, r[:]); err != nil || r[0] != 0x05 || r[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks: greeting failed %v %v", r, err)
	}
	host, portStr, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portStr)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	var h [10]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks: connect failed %v %v", h[1], err)
	}
	return c, nil
}

func readFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

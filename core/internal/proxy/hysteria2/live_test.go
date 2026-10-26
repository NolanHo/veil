// Package hysteria2_test holds the live check for the hysteria2 outbound.
//
// Everything else in this package runs against a server built from the same
// codec as the client, so the two agree even when the wire format is wrong. That
// is exactly what happened: the missing QPACK field section prefix, the
// uppercase header names and the missing prefix on the response side were all
// invisible locally while every test was green. This test is the only one that
// talks to a real server, so it is the only one that can catch that class.
package hysteria2_test

import (
	"context"
	"crypto/tls"
	"os"
	"testing"
	"time"

	"veil/internal/config"
	"veil/internal/proxy/factory"
	"veil/internal/share"
)

// TestLiveHysteria2 is skipped unless VEIL_LIVE_HY2 names a file holding one
// hysteria2 node in Clash's proxy shape (server, port, password, obfs, pin). The
// file carries credentials, so it lives outside the repository and this test
// only ever sees its path.
//
//	VEIL_LIVE_HY2=/path/to/node.yaml go test ./internal/proxy/hysteria2/ -run TestLiveHysteria2 -v
func TestLiveHysteria2(t *testing.T) {
	path := os.Getenv("VEIL_LIVE_HY2")
	if path == "" {
		t.Skip("set VEIL_LIVE_HY2=<clash yaml with one hysteria2 node> to run against a real server")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	// The node file holds the bare proxy entry, so wrap it the way Clash does.
	nodes, errs := share.ParseClashYAML(append([]byte("proxies:\n"), raw...), "live")
	for _, e := range errs {
		t.Logf("import warning: %v", e)
	}
	var node config.Node
	found := false
	for _, n := range nodes {
		if n.Type == "hysteria2" || n.Type == "hy2" {
			node, found = n, true
			break
		}
	}
	if !found {
		t.Fatalf("no hysteria2 node in %s (%d node(s) parsed)", path, len(nodes))
	}
	t.Logf("node %q -> %s:%d", node.Tag, node.Server, node.Port)

	ob, err := factory.New(node)
	if err != nil {
		t.Fatalf("factory.New: %v", err)
	}
	defer ob.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := ob.DialContext(ctx, "tcp", "www.apple.com:443")
	if err != nil {
		t.Fatalf("DialContext through %s: %v", node.Tag, err)
	}
	defer conn.Close()

	// A TLS handshake through the tunnel proves the QUIC connection, the HTTP/3
	// auth exchange and the TCP stream framing all work against the real server.
	tc := tls.Client(conn, &tls.Config{ServerName: "www.apple.com", MinVersion: tls.VersionTLS12})
	defer tc.Close()
	if err := tc.HandshakeContext(ctx); err != nil {
		t.Fatalf("TLS handshake through the tunnel: %v", err)
	}
	st := tc.ConnectionState()
	t.Logf("TLS OK: version=0x%04x cipher=%s", st.Version, tls.CipherSuiteName(st.CipherSuite))
	if st.Version < tls.VersionTLS12 {
		t.Fatalf("negotiated TLS version 0x%04x", st.Version)
	}
}

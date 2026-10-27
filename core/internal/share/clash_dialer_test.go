package share

import (
	"fmt"
	"strings"
	"testing"
)

const dialerTestUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// dialerProxyDoc is one document with both chain shapes a real profile uses: a
// node reached through another node, and a node reached through a select group
// that the file defines after the proxies.
func dialerProxyDoc(extra string) string {
	return fmt.Sprintf(`
proxies:
  - name: "mdev-hk"
    type: vless
    server: 192.0.2.1
    port: 443
    uuid: %[1]s
    tls: true
  - name: "出口节点"
    type: ss
    server: 203.0.113.12
    port: 3306
    cipher: aes-256-gcm
    password: "secret"
    dialer-proxy: "mdev-hk"
  - name: "日本家宽"
    type: ss
    server: 198.51.100.7
    port: 10001
    cipher: aes-256-gcm
    password: "secret"
    dialer-proxy: "日本家宽入口"
%[2]s
proxy-groups:
  - name: "日本家宽入口"
    type: select
    proxies:
      - mdev-hk
      - DIRECT
  - name: "出口包装"
    type: select
    proxies:
      - 出口节点
`, dialerTestUUID, extra)
}

// A dialer-proxy naming a node or a group is imported as a tag, and the node is
// no longer skipped.
func TestParseClashDialerProxyImportsChain(t *testing.T) {
	c, errs := ParseClashConfig([]byte(dialerProxyDoc("")), "sub")
	if len(errs) != 0 {
		t.Fatalf("errs = %v, want none", errs)
	}
	byTag := make(map[string]string, len(c.Nodes))
	for _, n := range c.Nodes {
		byTag[n.Tag] = n.DialerProxy
	}
	if got := byTag["出口节点"]; got != "mdev-hk" {
		t.Fatalf("出口节点 dialer_proxy = %q, want mdev-hk", got)
	}
	if got := byTag["日本家宽"]; got != "日本家宽入口" {
		t.Fatalf("日本家宽 dialer_proxy = %q, want 日本家宽入口 (a group)", got)
	}
	if got, ok := byTag["mdev-hk"]; !ok || got != "" {
		t.Fatalf("mdev-hk = %q (present %v), want no chain", got, ok)
	}
}

// A name that is not in the document is a broken reference: the node is dropped
// and reported, because importing it would dial the server directly.
func TestParseClashDialerProxyUnknownTag(t *testing.T) {
	doc := `
proxies:
  - name: "orphan"
    type: ss
    server: 198.51.100.7
    port: 8388
    cipher: aes-256-gcm
    password: "secret"
    dialer-proxy: "no-such-proxy"
`
	nodes, errs := ParseClashYAML([]byte(doc), "sub")
	if len(nodes) != 0 {
		t.Fatalf("nodes = %+v, want the node dropped", nodes)
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "dialer-proxy") ||
		!strings.Contains(errs[0].Error(), "no-such-proxy") {
		t.Fatalf("errs = %v, want one dialer-proxy error naming the missing tag", errs)
	}
}

// hysteria2 and wireguard have no TCP connection to hand over, so a chain on
// either is refused instead of dialled directly.
func TestParseClashDialerProxyRejectedForNonTCP(t *testing.T) {
	doc := fmt.Sprintf(`
proxies:
  - name: "mdev-hk"
    type: vless
    server: 192.0.2.1
    port: 443
    uuid: %[1]s
  - name: "hy"
    type: hysteria2
    server: hy.example
    port: 443
    password: "secret"
    dialer-proxy: "mdev-hk"
  - name: "wg"
    type: wireguard
    server: 198.51.100.10
    port: 51820
    ip: 10.9.0.13
    private-key: %[2]s
    public-key: %[3]s
    allowed-ips: 10.9.0.0/24
    dialer-proxy: "mdev-hk"
`, dialerTestUUID, testPrivKey, testPubKey)

	c, errs := ParseClashConfig([]byte(doc), "sub")
	for _, n := range c.Nodes {
		if n.Tag == "hy" || n.Tag == "wg" {
			t.Fatalf("node %q with a chained non-TCP transport was imported", n.Tag)
		}
	}
	if len(errs) != 2 {
		t.Fatalf("errs = %v, want one per rejected node", errs)
	}
	for _, want := range []string{"hysteria2", "wireguard"} {
		found := false
		for _, err := range errs {
			if strings.Contains(err.Error(), "dialer-proxy") && strings.Contains(err.Error(), want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("errs = %v, want a dialer-proxy error naming %s", errs, want)
		}
	}
}

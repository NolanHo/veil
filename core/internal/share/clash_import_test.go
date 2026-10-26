package share

import (
	"fmt"
	"strings"
	"testing"

	"veil/internal/config"
)

// ownerClashYAML is the shape the owner's own Clash profile has: two WireGuard
// peers (homelab and a relay), a hysteria2 node, and the socks5 / TUIC entries
// this build cannot drive. It is the regression fixture for the whole Clash
// import chain.
func ownerClashYAML() string {
	return fmt.Sprintf(`
proxies:
  - name: "homelab-wg"
    type: wireguard
    server: 115.191.57.106
    port: 51820
    ip: 10.173.91.13
    private-key: %s
    public-key: %s
    pre-shared-key: %s
    allowed-ips: ['10.173.91.0/24']
    dns: [10.173.91.1]
    mtu: 1280
    udp: true
  - name: "relay-wg"
    type: wireguard
    server: 115.191.57.106
    port: 51821
    ip: 10.20.1.13
    ipv6: fd00::13
    private-key: %s
    public-key: %s
    allowed-ips: ['10.20.1.0/24', 'fd00::/64']
  - name: "hy2-hk"
    type: hysteria2
    server: hk.example.net
    port: 443
    password: pw
    sni: hk.example.net
    skip-cert-verify: false
    obfs: salamander
    obfs-password: obfspw
  - name: "old-socks"
    type: socks5
    server: 1.2.3.4
    port: 1080
    username: u
    password: p
  - name: "tuic-node"
    type: tuic
    server: t.example.net
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    password: tp
`, testPrivKey, testPubKey, testPSK, testPrivKey, testPubKey)
}

// TestOwnerClashProfileImports is the end-to-end check for the import chain on
// the profile shape the owner actually has: both WireGuard peers must arrive,
// the two entries this build cannot drive must be skipped *and reported*, and
// the nodes in between must be unaffected.
func TestOwnerClashProfileImports(t *testing.T) {
	nodes, errs := ParseClashYAML([]byte(ownerClashYAML()), "clash")

	if len(nodes) != 3 {
		t.Fatalf("nodes = %d (%+v), want the two wireguard peers and the hysteria2 node", len(nodes), nodes)
	}
	eq(t, "tag0", nodes[0].Tag, "homelab-wg")
	eq(t, "type0", nodes[0].Type, "wireguard")
	eq(t, "tag1", nodes[1].Tag, "relay-wg")
	eq(t, "type1", nodes[1].Type, "wireguard")
	eq(t, "tag2", nodes[2].Tag, "hy2-hk")
	eq(t, "type2", nodes[2].Type, "hysteria2")

	// The skipped entries are counted and named, so the user learns why two of
	// their five nodes are missing.
	if len(errs) != 2 {
		t.Fatalf("errs = %v, want exactly the socks5 and tuic skips", errs)
	}
	joined := errs[0].Error() + " | " + errs[1].Error()
	for _, want := range []string{"socks5", "tuic"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("errs = %v, want %q named", errs, want)
		}
	}

	// The hysteria2 node keeps everything the Clash document said.
	hy := nodes[2]
	eq(t, "obfs", hy.Transport.Headers["obfs"], "salamander")
	eq(t, "sni", hy.TLS.ServerName, "hk.example.net")

	cfg := config.Config{Nodes: nodes}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestClashDedupeKeepsDistinctWireGuardPeers is the S6 regression: two peers
// behind the same endpoint but with different keys, addresses and routes are
// different peers, and the de-duplication key has to say so.
func TestClashDedupeKeepsDistinctWireGuardPeers(t *testing.T) {
	doc := fmt.Sprintf(`
proxies:
  - name: "lab"
    type: wireguard
    server: 115.191.57.106
    port: 51820
    ip: 10.173.91.13
    private-key: %s
    public-key: %s
    allowed-ips: ['10.173.91.0/24']
  - name: "lab-2"
    type: wireguard
    server: 115.191.57.106
    port: 51820
    ip: 10.20.1.13
    private-key: %s
    public-key: %s
    allowed-ips: ['10.20.1.0/24']
`, testPrivKey, testPubKey, testPrivKey, testPSK)

	nodes, errs := ParseClashYAML([]byte(doc), "sub")
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes = %d (%+v), want 2: the peers differ in address, key and route", len(nodes), nodes)
	}
	eq(t, "addresses0", strings.Join(nodes[0].Addresses, ","), "10.173.91.13/32")
	eq(t, "addresses1", strings.Join(nodes[1].Addresses, ","), "10.20.1.13/32")
	eq(t, "public_key1", nodes[1].PeerPublicKey, testPSK)
	if nodes[0].Tag == nodes[1].Tag {
		t.Fatalf("both peers got the tag %q", nodes[0].Tag)
	}
}

// TestClashBadNodeDoesNotAbortImport is the S7 regression: one malformed entry
// must cost that entry, not the whole subscription.
func TestClashBadNodeDoesNotAbortImport(t *testing.T) {
	doc := `
proxies:
  - name: "ok-vless"
    type: vless
    server: a.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
  - name: "broken"
    type: vless
    server: b.example.com
    port: 443
    uuid: 22222222-3333-4444-5555-666666666666
    ws-opts: "a string where a mapping belongs"
  - name: "ok-trojan"
    type: trojan
    server: c.example.com
    port: 443
    password: pw
`
	nodes, errs := ParseClashYAML([]byte(doc), "sub")
	if len(nodes) != 2 {
		t.Fatalf("nodes = %d (%+v), want the two well-formed siblings", len(nodes), nodes)
	}
	eq(t, "tag0", nodes[0].Tag, "ok-vless")
	eq(t, "tag1", nodes[1].Tag, "ok-trojan")
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "broken") {
		t.Fatalf("errs = %v, want one entry naming the broken node", errs)
	}
}

// TestClashAllowedIPsRejectsMappingShape is the S8 regression: a mapping where a
// list belongs used to decode to an empty list, i.e. a peer with no route that
// imported "successfully".
func TestClashAllowedIPsRejectsMappingShape(t *testing.T) {
	doc := fmt.Sprintf(`
proxies:
  - name: "mapping-routes"
    type: wireguard
    server: 115.191.57.106
    port: 51820
    ip: 10.173.91.13
    private-key: %s
    public-key: %s
    allowed-ips:
      typo: 10.173.91.0/24
  - name: "mapping-dns"
    type: wireguard
    server: 115.191.57.107
    port: 51820
    ip: 10.173.91.14
    private-key: %s
    public-key: %s
    allowed-ips: ['10.173.91.0/24']
    dns:
      typo: 10.173.91.1
`, testPrivKey, testPubKey, testPrivKey, testPubKey)

	nodes, errs := ParseClashYAML([]byte(doc), "sub")
	if len(nodes) != 0 {
		t.Fatalf("nodes = %+v, want none: a mapping is not a list", nodes)
	}
	if len(errs) != 2 {
		t.Fatalf("errs = %v, want one per malformed node", errs)
	}
	joined := errs[0].Error() + " | " + errs[1].Error()
	for _, want := range []string{"allowed-ips", "dns"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("errs = %v, want %q named", errs, want)
		}
	}
}

// TestClashWireGuardDefaultsAllowedIPs is the S9 regression: Clash gives a
// single-peer WireGuard without allowed-ips the default route by address family.
// Keeping the list empty imports a node that validates and then routes nothing.
func TestClashWireGuardDefaultsAllowedIPs(t *testing.T) {
	v4 := fmt.Sprintf(`
proxies:
  - name: "v4-only"
    type: wireguard
    server: 115.191.57.106
    port: 51820
    ip: 10.173.91.13
    private-key: %s
    public-key: %s
`, testPrivKey, testPubKey)
	nodes, errs := ParseClashYAML([]byte(v4), "sub")
	if len(errs) != 0 || len(nodes) != 1 {
		t.Fatalf("ParseClashYAML = %+v, %v", nodes, errs)
	}
	eq(t, "allowed_ips", strings.Join(nodes[0].AllowedIPs, ","), "0.0.0.0/0")

	dual := strings.Replace(v4, "    ip: 10.173.91.13",
		"    ip: 10.173.91.13\n    ipv6: fd00::13", 1)
	nodes, errs = ParseClashYAML([]byte(dual), "sub")
	if len(errs) != 0 || len(nodes) != 1 {
		t.Fatalf("ParseClashYAML = %+v, %v", nodes, errs)
	}
	eq(t, "allowed_ips", strings.Join(nodes[0].AllowedIPs, ","), "0.0.0.0/0,::/0")

	// An explicit list is never overridden.
	explicit := strings.Replace(v4, "    private-key: "+testPrivKey,
		"    allowed-ips: ['10.173.91.0/24']\n    private-key: "+testPrivKey, 1)
	nodes, errs = ParseClashYAML([]byte(explicit), "sub")
	if len(errs) != 0 || len(nodes) != 1 {
		t.Fatalf("ParseClashYAML = %+v, %v", nodes, errs)
	}
	eq(t, "allowed_ips", strings.Join(nodes[0].AllowedIPs, ","), "10.173.91.0/24")
}

// TestClashWireGuardReservedSkipped is the S11 regression: `reserved` changes the
// handshake wire format (mihomo hands it to the bind), so a node carrying it must
// be skipped with an error rather than imported as a differently-behaving peer.
func TestClashWireGuardReservedSkipped(t *testing.T) {
	doc := fmt.Sprintf(`
proxies:
  - name: "reserved-peer"
    type: wireguard
    server: 115.191.57.106
    port: 51820
    ip: 10.173.91.13
    private-key: %s
    public-key: %s
    allowed-ips: ['10.173.91.0/24']
    reserved: [0, 0, 0]
`, testPrivKey, testPubKey)

	nodes, errs := ParseClashYAML([]byte(doc), "sub")
	if len(nodes) != 0 {
		t.Fatalf("nodes = %+v, want none: reserved is not implemented", nodes)
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "reserved") {
		t.Fatalf("errs = %v, want one about reserved", errs)
	}
}

package share

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"veil/internal/config"
)

// Test keys are generated from bytes rather than pasted, so no scanner mistakes
// the fixture for a real credential.
var (
	testPrivKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	testPubKey  = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	testPSK     = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32))
)

// wgConfText is a wg-quick style peer with every field the importer understands
// plus comments, which real configs are full of.
func wgConfText() string {
	return fmt.Sprintf(`# homelab
[Interface]
PrivateKey = %s
Address = 10.9.0.200/32, fd00::2/128
DNS = 10.9.0.1
MTU = 1420

[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = 10.9.0.0/24, fd00::/64
Endpoint = wg.homelab.example:51820
PersistentKeepalive = 25
`, testPrivKey, testPubKey, testPSK)
}

func TestParseWireGuardConf(t *testing.T) {
	n, err := ParseWireGuardConf(wgConfText(), "homelab.conf")
	if err != nil {
		t.Fatalf("ParseWireGuardConf: %v", err)
	}
	eq(t, "type", n.Type, "wireguard")
	eq(t, "server", n.Server, "wg.homelab.example")
	eqInt(t, "port", n.Port, 51820)
	eq(t, "private_key", n.PrivateKey, testPrivKey)
	eq(t, "public_key", n.PeerPublicKey, testPubKey)
	eq(t, "preshared_key", n.PresharedKey, testPSK)
	eq(t, "mtu", strconv.Itoa(n.MTU), "1420")
	eq(t, "keepalive", strconv.Itoa(n.KeepAlive), "25")
	eq(t, "addresses", strings.Join(n.Addresses, ","), "10.9.0.200/32,fd00::2/128")
	eq(t, "allowed_ips", strings.Join(n.AllowedIPs, ","), "10.9.0.0/24,fd00::/64")
	eq(t, "dns", strings.Join(n.DNS, ","), "10.9.0.1")
	// The tag comes from the imported name, which is what the node list shows.
	eq(t, "tag", n.Tag, "homelab")
	eq(t, "remark", n.Remark, "homelab")

	// An imported node must survive validation and be buildable by the outbound.
	cfg := config.Config{Nodes: []config.Node{n}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestParseWireGuardConfTagFromEndpoint(t *testing.T) {
	// Without an imported name the endpoint host is the only stable identifier a
	// .conf carries.
	n, err := ParseWireGuardConf(wgConfText(), "")
	if err != nil {
		t.Fatalf("ParseWireGuardConf: %v", err)
	}
	eq(t, "tag", n.Tag, "wg.homelab.example")
	eq(t, "remark", n.Remark, "")
}

func TestParseWireGuardConfKeepaliveOff(t *testing.T) {
	conf := strings.Replace(wgConfText(), "PersistentKeepalive = 25", "PersistentKeepalive = off", 1)
	n, err := ParseWireGuardConf(conf, "off")
	if err != nil {
		t.Fatalf("ParseWireGuardConf: %v", err)
	}
	eqInt(t, "keepalive", n.KeepAlive, 0)
}

func TestWireGuardConfRoundTrip(t *testing.T) {
	first, err := ParseWireGuardConf(wgConfText(), "homelab")
	if err != nil {
		t.Fatalf("ParseWireGuardConf: %v", err)
	}
	out, err := WireGuardConf(first)
	if err != nil {
		t.Fatalf("WireGuardConf: %v", err)
	}
	for _, want := range []string{
		"[Interface]",
		"PrivateKey = " + testPrivKey,
		"Address = 10.9.0.200/32, fd00::2/128",
		"DNS = 10.9.0.1",
		"MTU = 1420",
		"[Peer]",
		"PresharedKey = " + testPSK,
		"AllowedIPs = 10.9.0.0/24, fd00::/64",
		"Endpoint = wg.homelab.example:51820",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("exported config misses %q:\n%s", want, out)
		}
	}
	second, err := ParseWireGuardConf(out, "homelab")
	if err != nil {
		t.Fatalf("re-Parse: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("round-trip mismatch\nfirst:  %+v\nsecond: %+v\nexported: %s", first, second, out)
	}
}

func TestParseWireGuardConfErrors(t *testing.T) {
	iface := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.9.0.200/32\n", testPrivKey)
	peer := fmt.Sprintf("[Peer]\nPublicKey = %s\nAllowedIPs = 10.9.0.0/24\n"+
		"Endpoint = wg.example.com:51820\n", testPubKey)

	cases := map[string]string{
		// Things the outbound cannot honour must fail loudly instead of being
		// dropped: a peer that connects with half its settings applied is worse
		// than one that refuses to import.
		"multiple peers":   iface + peer + peer,
		"table":            iface + "Table = off\n" + peer,
		"preup hook":       iface + "PreUp = sysctl -w net.ipv4.ip_forward=1\n" + peer,
		"postdown hook":    iface + "PostDown = rm -f /tmp/x\n" + peer,
		"listen port":      iface + "ListenPort = 51820\n" + peer,
		"amnezia junk":     iface + "Jc = 4\n" + peer,
		"unknown iface":    iface + "Frobnicate = 1\n" + peer,
		"unknown peer key": iface + peer + "Frobnicate = 1\n",
		"missing privkey":  "[Interface]\nAddress = 10.9.0.200/32\n" + peer,
		"missing peer":     iface,
		"missing pubkey":   iface + "[Peer]\nEndpoint = wg.example.com:51820\n",
		"missing endpoint": iface + fmt.Sprintf("[Peer]\nPublicKey = %s\n", testPubKey),
		"bad mtu":          iface + "MTU = huge\n" + peer,
		"bad endpoint":     iface + fmt.Sprintf("[Peer]\nPublicKey = %s\nEndpoint = wg.example.com\n", testPubKey),
		"not key value":    iface + "garbage\n" + peer,
		"unknown section":  iface + "[WireGuard]\n" + peer,
		"key before sect":  "PrivateKey = x\n" + iface + peer,
	}
	for name, conf := range cases {
		if _, err := ParseWireGuardConf(conf, "bad"); err == nil {
			t.Fatalf("%s: ParseWireGuardConf succeeded, want error", name)
		}
	}
}

// clashWireGuardYAML is the shape mihomo/Clash Verge writes for a WireGuard
// peer, including the two spellings of a list value and the owner's `ip:` field
// without a mask. The socks5 entry is what his subscription also contains.
func clashWireGuardYAML() string {
	return fmt.Sprintf(`
proxies:
  - name: "nolan-lab-wg"
    type: wireguard
    server: 198.51.100.10
    port: 51820
    ip: 10.9.0.13
    private-key: %s
    public-key: %s
    allowed-ips: ['10.9.0.0/24', 'fd00::/64']
    dns: [10.9.0.1]
    mtu: 1280
    udp: true
  - name: "gz-relay-wg"
    type: wireguard
    server: gz.example.com
    port: 51821
    ip: 10.20.30.13/24
    private-key: %s
    public-key: %s
    pre-shared-key: %s
    allowed-ips:
      - 10.20.30.0/24
    mtu: 1420
  - name: "old-socks"
    type: tuic
    server: 1.2.3.4
    port: 1080
    username: u
    password: p
`, testPrivKey, testPubKey, testPrivKey, testPubKey, testPSK)
}

func TestParseClashWireGuard(t *testing.T) {
	nodes, errs := ParseClashYAML([]byte(clashWireGuardYAML()), "sub")
	// The socks5 entry is reported so the user knows why one node is missing,
	// but it must not stop the peers from importing.
	if len(nodes) != 2 {
		t.Fatalf("nodes = %d, want 2: %+v (errs %v)", len(nodes), nodes, errs)
	}
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want exactly the unsupported-type skip", errs)
	}
	if !strings.Contains(errs[0].Error(), "tuic") {
		t.Fatalf("errs[0] = %v, want it to name tuic", errs[0])
	}

	first := nodes[0]
	eq(t, "type", first.Type, "wireguard")
	eq(t, "tag", first.Tag, "nolan-lab-wg")
	eq(t, "server", first.Server, "198.51.100.10")
	eqInt(t, "port", first.Port, 51820)
	eq(t, "private_key", first.PrivateKey, testPrivKey)
	eq(t, "public_key", first.PeerPublicKey, testPubKey)
	eq(t, "preshared_key", first.PresharedKey, "")
	// A bare `ip:` is a host address: /32 for v4.
	eq(t, "addresses", strings.Join(first.Addresses, ","), "10.9.0.13/32")
	eq(t, "allowed_ips", strings.Join(first.AllowedIPs, ","), "10.9.0.0/24,fd00::/64")
	eq(t, "dns", strings.Join(first.DNS, ","), "10.9.0.1")
	eq(t, "mtu", strconv.Itoa(first.MTU), "1280")

	second := nodes[1]
	eq(t, "addresses", strings.Join(second.Addresses, ","), "10.20.30.13/24")
	eq(t, "allowed_ips", strings.Join(second.AllowedIPs, ","), "10.20.30.0/24")
	eq(t, "preshared_key", second.PresharedKey, testPSK)
	eq(t, "source", second.Source, "sub")

	// The imported nodes must validate, i.e. be loadable and dialable.
	cfg := config.Config{Nodes: nodes}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestParseClashWireGuardRejectsChainedDialer(t *testing.T) {
	doc := fmt.Sprintf(`
proxies:
  - name: "chained"
    type: wireguard
    server: 198.51.100.10
    port: 51820
    ip: 10.9.0.13
    private-key: %s
    public-key: %s
    allowed-ips: 10.9.0.0/24
    dialer-proxy: "gz-relay-wg"
`, testPrivKey, testPubKey)
	nodes, errs := ParseClashYAML([]byte(doc), "sub")
	if len(nodes) != 0 {
		t.Fatalf("nodes = %+v, want none", nodes)
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "dialer-proxy") {
		t.Fatalf("errs = %v, want a dialer-proxy skip", errs)
	}
}

func TestParseClashWireGuardIncomplete(t *testing.T) {
	// A peer missing its interface address or its keys is malformed for us: it is
	// reported per node, never fatal for the rest of the subscription.
	cases := map[string]string{
		"no ip": `
proxies:
  - name: "broken"
    type: wireguard
    server: 198.51.100.10
    port: 51820
    private-key: ` + testPrivKey + `
    public-key: ` + testPubKey + `
    allowed-ips: ['10.9.0.0/24']
`,
		"no keys": `
proxies:
  - name: "broken"
    type: wireguard
    server: 198.51.100.10
    port: 51820
    ip: 10.9.0.13
    allowed-ips: ['10.9.0.0/24']
`,
	}
	for name, doc := range cases {
		nodes, errs := ParseClashYAML([]byte(doc), "sub")
		if len(nodes) != 0 {
			t.Fatalf("%s: nodes = %+v, want none", name, nodes)
		}
		if len(errs) != 1 {
			t.Fatalf("%s: errs = %v, want one", name, errs)
		}
	}
}

func TestWireGuardImportsAgree(t *testing.T) {
	// Both import paths describe the same peer, so a node read from Clash YAML
	// must survive a trip out through .conf and back unchanged. This is the
	// round-trip for the Clash path: the .conf one is covered above.
	nodes, errs := ParseClashYAML([]byte(clashWireGuardYAML()), "sub")
	if len(nodes) != 2 || len(errs) != 1 {
		t.Fatalf("nodes = %d errs = %v", len(nodes), errs)
	}
	fromClash := nodes[0]
	conf, err := WireGuardConf(fromClash)
	if err != nil {
		t.Fatalf("WireGuardConf: %v", err)
	}
	fromConf, err := ParseWireGuardConf(conf, "nolan-lab-wg")
	if err != nil {
		t.Fatalf("ParseWireGuardConf: %v", err)
	}
	// Source and UDP are subscription bookkeeping, not peer settings.
	fromClash.Source = ""
	fromClash.UDP = nil
	if !reflect.DeepEqual(fromClash, fromConf) {
		t.Fatalf("import paths disagree\nclash: %+v\nconf:  %+v\nconf text:\n%s", fromClash, fromConf, conf)
	}
}

// TestParseTextImportsWireGuardConf is the entry-level test for the paste path:
// a wg-quick .conf pasted into the app must become a node. Parsing it correctly
// but never reaching the parser is the same as not supporting it.
func TestParseTextImportsWireGuardConf(t *testing.T) {
	nodes, errs := ParseText(wgConfText())
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(nodes) != 1 {
		t.Fatalf("nodes = %+v, want the single peer from the .conf", nodes)
	}
	n := nodes[0]
	eq(t, "type", n.Type, "wireguard")
	eq(t, "server", n.Server, "wg.homelab.example")
	eqInt(t, "port", n.Port, 51820)
	eq(t, "private_key", n.PrivateKey, testPrivKey)
	eq(t, "public_key", n.PeerPublicKey, testPubKey)
	eq(t, "preshared_key", n.PresharedKey, testPSK)
	eq(t, "addresses", strings.Join(n.Addresses, ","), "10.9.0.200/32,fd00::2/128")
	eq(t, "allowed_ips", strings.Join(n.AllowedIPs, ","), "10.9.0.0/24,fd00::/64")
	eq(t, "dns", strings.Join(n.DNS, ","), "10.9.0.1")
	eqInt(t, "keepalive", n.KeepAlive, 25)
	// A pasted node has no file name, so the endpoint is what the list shows.
	eq(t, "tag", n.Tag, "wg.homelab.example")

	cfg := config.Config{Nodes: nodes}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// A base64-wrapped body reaches the same parser, like any other text input.
	wrapped := base64.StdEncoding.EncodeToString([]byte(wgConfText()))
	nodes, errs = ParseText(wrapped)
	if len(errs) != 0 || len(nodes) != 1 || nodes[0].Type != "wireguard" {
		t.Fatalf("ParseText(base64 .conf) = %+v, %v", nodes, errs)
	}

	// The subscription path (remote body) reaches the same parser.
	sub, errs := ParseSubscription([]byte(wgConfText()), "homelab-sub")
	if len(errs) != 0 || len(sub) != 1 {
		t.Fatalf("ParseSubscription(.conf) = %+v, %v", sub, errs)
	}
	eq(t, "source", sub[0].Source, "homelab-sub")
	eq(t, "type", sub[0].Type, "wireguard")
}

// TestParseTextImportDetection pins the detection order: the .conf section
// header wins, and nothing that is not a .conf may be parsed as one.
func TestParseTextImportDetection(t *testing.T) {
	// A .conf whose comments carry URLs is still a .conf, not a link list.
	withURL := "# upstream docs: https://www.wireguard.com/quickstart/\n" + wgConfText()
	nodes, errs := ParseText(withURL)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(nodes) != 1 || nodes[0].Type != "wireguard" {
		t.Fatalf("ParseText(.conf with URL comment) = %+v, want one wireguard node", nodes)
	}

	// A link list is untouched by the .conf branch.
	nodes, errs = ParseText("vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443#one")
	if len(errs) != 0 || len(nodes) != 1 || nodes[0].Type != "vless" {
		t.Fatalf("ParseText(link) = %+v, %v", nodes, errs)
	}

	// A Clash document has no [Interface]/[Peer] section and stays YAML.
	nodes, errs = ParseSubscription([]byte(clashWireGuardYAML()), "sub")
	if len(nodes) != 2 {
		t.Fatalf("ParseSubscription(clash) = %d nodes, want 2 (%v)", len(nodes), errs)
	}
	if nodes[0].Type != "wireguard" {
		t.Fatalf("clash import changed shape: %+v", nodes[0])
	}

	// A .conf the outbound cannot honour fails loudly through the same entry.
	if nodes, errs := ParseText(wgConfText() + wgConfText()); len(nodes) != 0 || len(errs) == 0 {
		t.Fatalf("ParseText(two peers) = %+v, %v, want an error and no node", nodes, errs)
	}
}

// TestParseWireGuardConfRepeatedListsAccumulate is the S10 regression: wg-quick
// writes one Address line per address (DNS and AllowedIPs the same way), so a
// repeated key has to add to the list, not replace it.
func TestParseWireGuardConfRepeatedListsAccumulate(t *testing.T) {
	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.9.0.200/32
Address = fd00::2/128
DNS = 10.9.0.1
DNS = 10.9.0.2
MTU = 1420

[Peer]
PublicKey = %s
AllowedIPs = 10.9.0.0/24
AllowedIPs = fd00::/64
Endpoint = wg.homelab.example:51820
`, testPrivKey, testPubKey)

	n, err := ParseWireGuardConf(conf, "multi")
	if err != nil {
		t.Fatalf("ParseWireGuardConf: %v", err)
	}
	eq(t, "addresses", strings.Join(n.Addresses, ","), "10.9.0.200/32,fd00::2/128")
	eq(t, "dns", strings.Join(n.DNS, ","), "10.9.0.1,10.9.0.2")
	eq(t, "allowed_ips", strings.Join(n.AllowedIPs, ","), "10.9.0.0/24,fd00::/64")

	// The round trip must not drop the IPv4 half of either list.
	out, err := WireGuardConf(n)
	if err != nil {
		t.Fatalf("WireGuardConf: %v", err)
	}
	back, err := ParseWireGuardConf(out, "multi")
	if err != nil {
		t.Fatalf("re-Parse: %v\n%s", err, out)
	}
	if !reflect.DeepEqual(n, back) {
		t.Fatalf("round-trip mismatch\nfirst:  %+v\nsecond: %+v\nconf:\n%s", n, back, out)
	}
}

// TestWireGuardConfRejectsInjection is the S12 regression: a value carrying a
// line break would end the directive and inject another one, so export must
// refuse it instead of writing a config that means something else.
func TestWireGuardConfRejectsInjection(t *testing.T) {
	base := config.Node{
		Tag: "wg", Type: "wireguard", Server: "wg.homelab.example", Port: 51820,
		PrivateKey: testPrivKey, PeerPublicKey: testPubKey,
		Addresses:  []string{"10.9.0.200/32"},
		AllowedIPs: []string{"10.9.0.0/24"},
	}
	const injected = "\nPostUp = touch /tmp/wg-export-pwned"
	cases := map[string]func(*config.Node){
		"dns newline":      func(n *config.Node) { n.DNS = []string{"10.9.0.1" + injected} },
		"address newline":  func(n *config.Node) { n.Addresses = []string{"10.9.0.200/32" + injected} },
		"allowed newline":  func(n *config.Node) { n.AllowedIPs = []string{"10.9.0.0/24\r" + injected} },
		"preshared key":    func(n *config.Node) { n.PresharedKey = testPSK + injected },
		"private key":      func(n *config.Node) { n.PrivateKey = testPrivKey + injected },
		"peer public key":  func(n *config.Node) { n.PeerPublicKey = testPubKey + injected },
		"endpoint newline": func(n *config.Node) { n.Server = "wg.homelab.example" + injected },
	}
	for name, mutate := range cases {
		n := base
		mutate(&n)
		out, err := WireGuardConf(n)
		if err == nil {
			t.Fatalf("%s: exported a config with an injected directive:\n%s", name, out)
		}
		// The message must name the writer so the editor can point at it.
		if !strings.Contains(strings.ToLower(err.Error()), "wireguard") {
			t.Fatalf("%s: error %q does not identify the writer", name, err)
		}
	}
}

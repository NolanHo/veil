package share

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"veil/internal/config"
)

// testPin renders a SHA-256 certificate pin both the way mihomo prints it
// (upper-case bytes separated by colons) and bare. It is a digest of a fake
// certificate, not a credential.
func testPin() (bare, coloned string) {
	bare = hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	for i := 0; i < len(bare); i += 2 {
		if i > 0 {
			coloned += ":"
		}
		coloned += bare[i : i+2]
	}
	return bare, strings.ToUpper(coloned)
}

// ownerHysteria2YAML is the shape the owner's Clash Verge profile contains for
// his hysteria2 node: a certificate pin in `fingerprint`, obfs, and a sni.
func ownerHysteria2YAML(pin string) string {
	return fmt.Sprintf(`
proxies:
  - name: "hy2-hk"
    type: hysteria2
    server: hk.example.net
    port: 443
    password: pw
    sni: hk.example.net
    skip-cert-verify: false
    obfs: salamander
    obfs-password: obfspw
    fingerprint: %s
    udp: true
`, pin)
}

func TestParseClashHysteria2CertPin(t *testing.T) {
	_, pin := testPin()
	nodes, errs := ParseClashYAML([]byte(ownerHysteria2YAML(pin)), "sub")
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(nodes) != 1 {
		t.Fatalf("nodes = %+v, want one", nodes)
	}
	n := nodes[0]
	// The digest must arrive whole, colons and all: the outbound decodes it into
	// the SHA-256 it compares against the peer certificate.
	eq(t, "fingerprint", n.TLS.Fingerprint, strings.ToUpper(pin))
	eq(t, "sni", n.TLS.ServerName, "hk.example.net")
	eq(t, "obfs", n.Transport.Headers["obfs"], "salamander")
	eq(t, "obfs-password", n.Transport.Headers["obfs-password"], "obfspw")

	// A pinned node has to survive validation, otherwise the import is useless.
	cfg := config.Config{Nodes: nodes}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestParseClashCertPinBeatsClientFingerprint(t *testing.T) {
	_, pin := testPin()
	doc := strings.Replace(ownerHysteria2YAML(pin), "    udp: true",
		"    client-fingerprint: chrome\n    udp: true", 1)
	nodes, errs := ParseClashYAML([]byte(doc), "sub")
	if len(nodes) != 1 {
		t.Fatalf("nodes = %+v, want one", nodes)
	}
	// The pin authenticates the peer, so a uTLS profile name must not overwrite
	// it; dropping the name is reported instead of being silent.
	eq(t, "fingerprint", nodes[0].TLS.Fingerprint, strings.ToUpper(pin))
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "client-fingerprint") {
		t.Fatalf("errs = %v, want one notice about the dropped client-fingerprint", errs)
	}
}

func TestParseClashClientFingerprintStillWorks(t *testing.T) {
	// Without a pin, client-fingerprint keeps its old meaning, for hysteria2 and
	// for the protocols that only ever had a uTLS name.
	doc := strings.Replace(ownerHysteria2YAML(""), "    udp: true", "    client-fingerprint: firefox\n    udp: true", 1)
	nodes, errs := ParseClashYAML([]byte(doc), "sub")
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	eq(t, "fingerprint", nodes[0].TLS.Fingerprint, "firefox")

	vless := `
proxies:
  - name: "vl"
    type: vless
    server: r.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    tls: true
    servername: r.example.com
    client-fingerprint: chrome
`
	nodes, errs = ParseClashYAML([]byte(vless), "sub")
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	eq(t, "fingerprint", nodes[0].TLS.Fingerprint, "chrome")
}

func TestLinkOmitsCertPin(t *testing.T) {
	bare, pin := testPin()
	if bare == pin || strings.Contains(bare, ":") || !strings.Contains(pin, ":") {
		t.Fatalf("testPin() returned the same spelling twice: bare=%q coloned=%q", bare, pin)
	}

	// A share link has no spelling for a certificate pin. Writing the digest as
	// fp= would make the next import hand it to uTLS as a profile name.
	vless := config.Node{
		Type: "vless", Server: "r.example.com", Port: 443,
		UUID: "11111111-2222-3333-4444-555555555555",
		TLS:  &config.TLS{Enabled: true, ServerName: "r.example.com", Fingerprint: pin},
	}
	link, err := Link(vless)
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	if strings.Contains(link, "fp=") {
		t.Fatalf("link wrote a certificate pin as fp=: %s", link)
	}

	// The uTLS name still round-trips, so nothing was lost for real profiles.
	vless.TLS.Fingerprint = "chrome"
	link, err = Link(vless)
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	if !strings.Contains(link, "fp=chrome") {
		t.Fatalf("link dropped the uTLS profile: %s", link)
	}

	// vmess carries it in base64 JSON, where an empty fp means absent.
	vmess := config.Node{
		Type: "vmess", Server: "v.example.com", Port: 443,
		UUID: "11111111-2222-3333-4444-555555555555",
		TLS:  &config.TLS{Enabled: true, ServerName: "v.example.com", Fingerprint: bare},
	}
	link, err = Link(vmess)
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://"))
	if err != nil {
		t.Fatalf("decode vmess payload: %v", err)
	}
	var doc struct {
		Fp string `json:"fp"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("unmarshal vmess payload: %v", err)
	}
	if doc.Fp != "" {
		t.Fatalf("vmess exported the certificate pin as fp=%q", doc.Fp)
	}
}

// TestHysteria2LinkKeepsCertPin is the S4 regression: a node authenticated by a
// certificate pin must not export as plain "insecure" with no pin, which
// authenticates nothing at all.
func TestHysteria2LinkKeepsCertPin(t *testing.T) {
	bare, coloned := testPin()
	for name, pin := range map[string]string{"bare": bare, "coloned": coloned} {
		n := config.Node{
			Type: "hysteria2", Server: "hk.example.net", Port: 443, Password: "pw",
			TLS: &config.TLS{
				Enabled: true, ServerName: "hk.example.net",
				Insecure: true, Fingerprint: pin,
			},
		}
		link, err := Link(n)
		if err != nil {
			t.Fatalf("%s: Link: %v", name, err)
		}
		back, err := Parse(link)
		if err != nil {
			t.Fatalf("%s: Parse(%s): %v", name, link, err)
		}
		if back.TLS == nil {
			t.Fatalf("%s: TLS lost in %s", name, link)
		}
		eq(t, name+" fingerprint", back.TLS.Fingerprint, pin)
		if !back.TLS.Insecure {
			t.Fatalf("%s: insecure flag lost in %s", name, link)
		}
		eq(t, name+" sni", back.TLS.ServerName, "hk.example.net")

		cfg := config.Config{Nodes: []config.Node{back}}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%s: Validate: %v", name, err)
		}
	}

	// A pin-less node keeps the previous spelling, and a uTLS profile name is
	// still not written as a pin.
	plain := config.Node{
		Type: "hysteria2", Server: "hk.example.net", Port: 443, Password: "pw",
		TLS: &config.TLS{Enabled: true, ServerName: "hk.example.net", Insecure: true},
	}
	link, err := Link(plain)
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	if strings.Contains(link, "pinSHA256") {
		t.Fatalf("pin-less node exported a pin: %s", link)
	}
	if !strings.Contains(link, "insecure=1") {
		t.Fatalf("pin-less node lost insecure: %s", link)
	}

	// A pinSHA256 that is not a digest is a malformed link, not a silent no-op.
	if _, err := Parse("hysteria2://pw@hk.example.net:443?pinSHA256=not-a-digest"); err == nil {
		t.Fatal("Parse accepted a malformed pinSHA256")
	}
}

// A root-level `fingerprint` that is not a digest must never be replaced by a
// uTLS profile name: that turns "pin this certificate" into "verify nothing"
// while the profile still looks configured. Regression for review round 2, B1.
func TestMalformedPinIsNotReplacedByClientFingerprint(t *testing.T) {
	doc := `
proxies:
  - name: "bad-pin"
    type: hysteria2
    server: hk.example.net
    port: 443
    password: pw
    sni: hk.example.net
    skip-cert-verify: true
    fingerprint: "000000000000000000000000000000000000000000000000000000000000000g"
    client-fingerprint: chrome
`
	nodes, errs := ParseClashYAML([]byte(doc), "test")
	if len(nodes) != 0 {
		t.Fatalf("node kept with fingerprint %q; a malformed pin must fail the node", nodes[0].TLS.Fingerprint)
	}
	if len(errs) == 0 {
		t.Fatal("no error reported for a malformed pin")
	}
}

// The exporter and the outbound must agree on what a pin is. The outbound trims
// surrounding whitespace, so a pin pasted with a trailing newline authenticates
// the peer; the share link must not silently drop it. Regression for round 2, B2.
func TestLinkKeepsPinWithSurroundingWhitespace(t *testing.T) {
	pin := "DE:5D:FC:E7:5C:E8:F3:D4:B9:E7:DD:C2:6E:A3:F4:94:9A:9A:29:F5:FB:D1:40:A6:53:0F:55:A4:FA:65:19:A9\n"
	n := config.Node{
		Tag:      "hk",
		Type:     "hysteria2",
		Server:   "hk.example.net",
		Port:     443,
		Password: "pw",
		TLS:      &config.TLS{Enabled: true, ServerName: "hk.example.net", Fingerprint: pin},
	}
	link, err := Link(n)
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	if !strings.Contains(link, "pinSHA256=") {
		t.Fatalf("link %q dropped the certificate pin", link)
	}
	if strings.Contains(link, "insecure=1") && !strings.Contains(link, "pinSHA256=") {
		t.Fatalf("link %q authenticates nothing", link)
	}
}

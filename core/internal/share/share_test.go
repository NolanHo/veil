package share

import (
	"encoding/base64"
	"os"
	"reflect"
	"testing"

	"veil/internal/config"
)

// fixtureA exercises the legacy base64 vless dialect with markdown-mangled SNI.
const fixtureA = "vless://YXV0bzoxMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTVAMjAzLjAuMTEzLjEwOjQ0Mw==?obfs=none&tls=1&peer=www.example.com&xtls=2&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// fixtureB exercises the legacy base64 vmess dialect.
const fixtureB = "vmess://YXV0bzpmMDRkZTE1NC1lYTUwLTQ0OWQtODc3Zi1hNGExZTEwNjM2NWJANDMuMTU0LjE5MS4xMzY6NDQz?remarks=233v2.com_ss2.pivotstudio.cn&obfsParam=ss2.pivotstudio.cn&path=/bestlaser&obfs=websocket&tls=1&peer=ss.pivotlang.tech&allowInsecure=1&alterId=0"

func mustParse(t *testing.T, link string) config.Node {
	t.Helper()
	n, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse(%q) error: %v", link, err)
	}
	return n
}

func eq(t *testing.T, field, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s = %q, want %q", field, got, want)
	}
}

func eqInt(t *testing.T, field string, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("%s = %d, want %d", field, got, want)
	}
}

func TestParseVLESSLegacyFixture(t *testing.T) {
	n := mustParse(t, fixtureA)
	eq(t, "type", n.Type, "vless")
	eq(t, "server", n.Server, "203.0.113.10")
	eqInt(t, "port", n.Port, 443)
	eq(t, "uuid", n.UUID, "11111111-2222-3333-4444-555555555555")
	eq(t, "flow", n.Flow, "xtls-rprx-vision")
	if n.TLS == nil || !n.TLS.Enabled {
		t.Fatalf("TLS not enabled: %+v", n.TLS)
	}
	eq(t, "server_name", n.TLS.ServerName, "www.example.com")
	if n.TLS.Reality == nil {
		t.Fatal("reality not set")
	}
	eq(t, "pbk", n.TLS.Reality.PublicKey, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if n.Transport == nil {
		t.Fatal("transport nil")
	}
	eq(t, "transport", n.Transport.Type, "tcp")
	if n.Remark != "" {
		t.Fatalf("remark = %q, want empty", n.Remark)
	}
	if n.Addr() != "203.0.113.10:443" {
		t.Fatalf("Addr() = %q", n.Addr())
	}
}

func TestParseVMessLegacyFixture(t *testing.T) {
	n := mustParse(t, fixtureB)
	eq(t, "type", n.Type, "vmess")
	eq(t, "server", n.Server, "43.154.191.136")
	eqInt(t, "port", n.Port, 443)
	eq(t, "uuid", n.UUID, "f04de154-ea50-449d-877f-a4a1e106365b")
	eqInt(t, "alter_id", n.AlterID, 0)
	if n.Transport == nil {
		t.Fatal("transport nil")
	}
	eq(t, "transport", n.Transport.Type, "ws")
	eq(t, "path", n.Transport.Path, "/bestlaser")
	eq(t, "host", n.Transport.Host, "ss2.pivotstudio.cn")
	eq(t, "header host", n.Transport.Headers["Host"], "ss2.pivotstudio.cn")
	if n.TLS == nil || !n.TLS.Enabled {
		t.Fatalf("TLS not enabled: %+v", n.TLS)
	}
	eq(t, "sni", n.TLS.ServerName, "ss.pivotlang.tech")
	if !n.TLS.Insecure {
		t.Fatal("insecure should be true")
	}
	eq(t, "remark", n.Remark, "233v2.com_ss2.pivotstudio.cn")
}

func TestNormalizeTag(t *testing.T) {
	cases := map[string]string{
		"www.example.com":    "www.example.com",
		"  a   b  ":          "a b",
		"%E8%8A%82%E7%82%B9": "节点",
		"":                   "",
	}
	for in, want := range cases {
		eq(t, "NormalizeTag("+in+")", NormalizeTag(in), want)
	}
}

func TestParseVLESSModernReality(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@r.example.com:8443" +
		"?type=grpc&security=reality&pbk=PUBKEY123&sid=abcd&spx=%2Fspx&sni=cdn.example.com" +
		"&fp=chrome&flow=xtls-rprx-vision&serviceName=grpcsvc#node%20one"
	n := mustParse(t, link)
	eq(t, "type", n.Type, "vless")
	eq(t, "server", n.Server, "r.example.com")
	eqInt(t, "port", n.Port, 8443)
	eq(t, "uuid", n.UUID, "11111111-2222-3333-4444-555555555555")
	eq(t, "flow", n.Flow, "xtls-rprx-vision")
	if n.TLS == nil || !n.TLS.Enabled {
		t.Fatal("TLS not enabled")
	}
	eq(t, "sni", n.TLS.ServerName, "cdn.example.com")
	eq(t, "fp", n.TLS.Fingerprint, "chrome")
	if n.TLS.Reality == nil {
		t.Fatal("reality nil")
	}
	eq(t, "pbk", n.TLS.Reality.PublicKey, "PUBKEY123")
	eq(t, "sid", n.TLS.Reality.ShortID, "abcd")
	eq(t, "spx", n.TLS.Reality.SpiderX, "/spx")
	if n.Transport == nil {
		t.Fatal("transport nil")
	}
	eq(t, "transport", n.Transport.Type, "grpc")
	eq(t, "service", n.Transport.ServiceName, "grpcsvc")
	eq(t, "remark", n.Remark, "node one")
}

func TestParseVMessJSON(t *testing.T) {
	payload := `{"v":"2","ps":"json node","add":"j.example.com","port":"443",` +
		`"id":"11111111-2222-3333-4444-555555555555","aid":"0","net":"ws","type":"none",` +
		`"host":"cdn.example.com","path":"/ws","tls":"tls","sni":"sni.example.com","fp":"firefox"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(payload))
	n := mustParse(t, link)
	eq(t, "type", n.Type, "vmess")
	eq(t, "server", n.Server, "j.example.com")
	eqInt(t, "port", n.Port, 443)
	eq(t, "uuid", n.UUID, "11111111-2222-3333-4444-555555555555")
	eq(t, "transport", n.Transport.Type, "ws")
	eq(t, "path", n.Transport.Path, "/ws")
	eq(t, "host", n.Transport.Host, "cdn.example.com")
	if n.TLS == nil || !n.TLS.Enabled {
		t.Fatal("TLS not enabled")
	}
	eq(t, "sni", n.TLS.ServerName, "sni.example.com")
	eq(t, "fp", n.TLS.Fingerprint, "firefox")
	eq(t, "remark", n.Remark, "json node")
}

func TestParseTrojan(t *testing.T) {
	n := mustParse(t, "trojan://pa%40ss@t.example.com:443?sni=t.example.com&allowInsecure=1&type=ws&path=%2Ftr&host=cdn.example.com#trojan%20node")
	eq(t, "type", n.Type, "trojan")
	eq(t, "server", n.Server, "t.example.com")
	eqInt(t, "port", n.Port, 443)
	eq(t, "password", n.Password, "pa@ss")
	if n.TLS == nil || !n.TLS.Enabled {
		t.Fatal("TLS should be enabled for trojan")
	}
	eq(t, "sni", n.TLS.ServerName, "t.example.com")
	if !n.TLS.Insecure {
		t.Fatal("insecure should be true")
	}
	eq(t, "transport", n.Transport.Type, "ws")
	eq(t, "path", n.Transport.Path, "/tr")
	eq(t, "host", n.Transport.Host, "cdn.example.com")
	eq(t, "remark", n.Remark, "trojan node")
}

func TestParseSS(t *testing.T) {
	// SIP002: base64(method:password)@host:port
	ui := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:sspass"))
	n := mustParse(t, "ss://"+ui+"@s.example.com:8388#ss1")
	eq(t, "type", n.Type, "ss")
	eq(t, "server", n.Server, "s.example.com")
	eqInt(t, "port", n.Port, 8388)
	eq(t, "method", n.Method, "aes-256-gcm")
	eq(t, "password", n.Password, "sspass")
	eq(t, "remark", n.Remark, "ss1")

	// Legacy: base64(method:password@host:port)
	blob := base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw2@s2.example.com:9000"))
	n = mustParse(t, "ss://"+blob+"#ss2")
	eq(t, "method", n.Method, "chacha20-ietf-poly1305")
	eq(t, "password", n.Password, "pw2")
	eq(t, "server", n.Server, "s2.example.com")
	eqInt(t, "port", n.Port, 9000)
	eq(t, "remark", n.Remark, "ss2")

	// SIP002 with a v2ray-plugin.
	ui = base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw3"))
	n = mustParse(t, "ss://"+ui+"@s3.example.com:443?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dcdn.example.com%3Bpath%3D%2Fss#ss3")
	eq(t, "transport", n.Transport.Type, "ws")
	eq(t, "path", n.Transport.Path, "/ss")
	eq(t, "host", n.Transport.Host, "cdn.example.com")
}

func TestParseHysteria2(t *testing.T) {
	n := mustParse(t, "hy2://hypass@h.example.com:443?sni=h.example.com&insecure=1&obfs=salamander&obfs-password=obfspw#hy2")
	eq(t, "type", n.Type, "hysteria2")
	eq(t, "server", n.Server, "h.example.com")
	eqInt(t, "port", n.Port, 443)
	eq(t, "password", n.Password, "hypass")
	if n.TLS == nil || !n.TLS.Enabled {
		t.Fatal("TLS should be enabled for hysteria2")
	}
	eq(t, "sni", n.TLS.ServerName, "h.example.com")
	if !n.TLS.Insecure {
		t.Fatal("insecure should be true")
	}
	eq(t, "obfs", n.Transport.Headers["obfs"], "salamander")
	eq(t, "obfs-password", n.Transport.Headers["obfs-password"], "obfspw")
	eq(t, "remark", n.Remark, "hy2")

	// hysteria2:// must behave identically to hy2://.
	n2 := mustParse(t, "hysteria2://hypass@h.example.com:443#hy2b")
	eq(t, "server", n2.Server, "h.example.com")
	eq(t, "type", n2.Type, "hysteria2")
}

func TestParseTextAndSubscription(t *testing.T) {
	l1 := "vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?security=tls&sni=a.example.com#alpha"
	l2 := "trojan://pw@2.2.2.2:443#beta"
	text := "# a comment\n\n" + l1 + "\n" + l2 + "\n" + l1 + "\nnot a link\n"

	nodes, errs := ParseText(text)
	eqInt(t, "nodes", len(nodes), 2)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	eq(t, "tag0", nodes[0].Tag, "alpha")
	eq(t, "tag1", nodes[1].Tag, "beta")

	// Every malformed line is reported, good lines still parse.
	_, errs = ParseText(l1 + "\nvless://broken\n")
	if len(errs) != 1 {
		t.Fatalf("want 1 error, got %v", errs)
	}

	// Same link via a base64 subscription body, with a duplicate.
	sub := base64.StdEncoding.EncodeToString([]byte(l1 + "\n" + l2 + "\n" + l1))
	nodes, errs = ParseSubscription([]byte(sub), "mysub")
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	eqInt(t, "nodes", len(nodes), 2)
	eq(t, "source", nodes[0].Source, "mysub")
	eq(t, "source", nodes[1].Source, "mysub")

	// Plain-text subscription also works.
	nodes, errs = ParseSubscription([]byte(l1+"\n"+l2), "plain")
	eqInt(t, "nodes", len(nodes), 2)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	// Distinct nodes sharing a tag get a numeric suffix.
	dup := "vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443#same\n" +
		"vless://11111111-2222-3333-4444-555555555555@3.3.3.3:443#same"
	nodes, _ = ParseText(dup)
	eqInt(t, "nodes", len(nodes), 2)
	eq(t, "tag0", nodes[0].Tag, "same")
	eq(t, "tag1", nodes[1].Tag, "same-2")
}

func TestParseClashYAML(t *testing.T) {
	doc := `
proxies:
  - name: "reality-ws"
    type: vless
    server: r.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    network: ws
    tls: true
    servername: r.example.com
    skip-cert-verify: true
    flow: xtls-rprx-vision
    ws-opts:
      path: /ray
      headers:
        Host: cdn.example.com
    reality-opts:
      public-key: PUBKEY
      short-id: abcd
  - name: "vmess-grpc"
    type: vmess
    server: v.example.com
    port: 8443
    uuid: 22222222-3333-4444-5555-666666666666
    alterId: 0
    cipher: auto
    network: grpc
    tls: true
    sni: v.example.com
    grpc-opts:
      grpc-service-name: svc
  - name: "trojan-1"
    type: trojan
    server: t.example.com
    port: 443
    password: secret
    sni: t.example.com
    skip-cert-verify: true
  - name: "ss-1"
    type: ss
    server: s.example.com
    port: 8388
    cipher: aes-256-gcm
    password: sspass
    udp: true
  - name: "hy2-1"
    type: hysteria2
    server: h.example.com
    port: 443
    password: hypass
    sn: ignored
    obfs: salamander
    obfs-password: obfspw
`
	nodes, errs := ParseClashYAML([]byte(doc), "clashsub")
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	eqInt(t, "nodes", len(nodes), 5)

	v := nodes[0]
	eq(t, "type", v.Type, "vless")
	eq(t, "tag", v.Tag, "reality-ws")
	eq(t, "source", v.Source, "clashsub")
	eq(t, "transport", v.Transport.Type, "ws")
	eq(t, "path", v.Transport.Path, "/ray")
	eq(t, "host", v.Transport.Host, "cdn.example.com")
	eq(t, "flow", v.Flow, "xtls-rprx-vision")
	if v.TLS == nil || !v.TLS.Enabled || v.TLS.Reality == nil {
		t.Fatalf("tls/reality missing: %+v", v.TLS)
	}
	eq(t, "sni", v.TLS.ServerName, "r.example.com")
	if !v.TLS.Insecure {
		t.Fatal("skip-cert-verify not applied")
	}
	eq(t, "pbk", v.TLS.Reality.PublicKey, "PUBKEY")
	eq(t, "sid", v.TLS.Reality.ShortID, "abcd")

	m := nodes[1]
	eq(t, "type", m.Type, "vmess")
	eq(t, "transport", m.Transport.Type, "grpc")
	eq(t, "service", m.Transport.ServiceName, "svc")
	eq(t, "sni", m.TLS.ServerName, "v.example.com")

	tr := nodes[2]
	eq(t, "type", tr.Type, "trojan")
	eq(t, "password", tr.Password, "secret")
	if !tr.TLS.Enabled || !tr.TLS.Insecure {
		t.Fatalf("trojan tls: %+v", tr.TLS)
	}

	ss := nodes[3]
	eq(t, "type", ss.Type, "ss")
	eq(t, "method", ss.Method, "aes-256-gcm")
	eq(t, "password", ss.Password, "sspass")

	hy := nodes[4]
	eq(t, "type", hy.Type, "hysteria2")
	eq(t, "obfs", hy.Transport.Headers["obfs"], "salamander")
	eq(t, "obfs-password", hy.Transport.Headers["obfs-password"], "obfspw")

	// A Clash doc embedded in a base64 subscription is detected too.
	sub := base64.StdEncoding.EncodeToString([]byte(doc))
	nodes, errs = ParseSubscription([]byte(sub), "detected")
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	eqInt(t, "nodes", len(nodes), 5)
}

// TestDedupeKeyCoversTLSIdentity pins which TLS fields decide node identity.
//
// A field that changes how the peer is authenticated or how the handshake is
// spelled makes a different node: merging two of them silently redirects every
// group and rule that names the second spelling to the first node. The
// certificate pin is the sharpest case (see
// TestClashDedupeKeepsDistinctCertPins); insecure, ALPN and the server name
// change the handshake just as much.
func TestDedupeKeyCoversTLSIdentity(t *testing.T) {
	base := config.Node{
		Type:     "hysteria2",
		Server:   "hk.example.net",
		Port:     443,
		Password: "pw",
		TLS:      &config.TLS{Enabled: true, ServerName: "hk.example.net"},
		Remark:   "same",
	}
	cases := []struct {
		field  string
		mutate func(*config.TLS)
	}{
		{"fingerprint", func(tls *config.TLS) { tls.Fingerprint = "AB:CD" }},
		{"insecure", func(tls *config.TLS) { tls.Insecure = true }},
		{"alpn", func(tls *config.TLS) { tls.ALPN = []string{"h3"} }},
		{"servername", func(tls *config.TLS) { tls.ServerName = "other.example.net" }},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			other := base
			tls := *base.TLS
			tc.mutate(&tls)
			other.TLS = &tls
			if got := len(finalize([]config.Node{base, other})); got != 2 {
				t.Fatalf("de-duplication kept %d node(s), want 2: %s changes the peer identity", got, tc.field)
			}
		})
	}

	// The additions must not stop real duplicates from merging.
	if got := len(finalize([]config.Node{base, base})); got != 1 {
		t.Fatalf("two identical nodes produced %d entries, want 1", got)
	}
}

// stripVolatile clears fields that are not part of a link round-trip.
func stripVolatile(n config.Node) config.Node {
	n.Tag = ""
	n.Source = ""
	n.UDP = nil
	return n
}

func TestLinkRoundTrip(t *testing.T) {
	cases := map[string]string{
		"vless-legacy": fixtureA,
		"vmess-legacy": fixtureB,
		"vless-reality": "vless://11111111-2222-3333-4444-555555555555@r.example.com:8443" +
			"?type=grpc&security=reality&pbk=PUBKEY&sid=abcd&spx=%2F&sni=cdn.example.com&fp=chrome&flow=xtls-rprx-vision&serviceName=svc#n1",
		"trojan-ws": "trojan://pw@t.example.com:443?sni=t.example.com&allowInsecure=1&type=ws&path=%2Ftr&host=cdn.example.com#n2",
		"ss":        "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@s.example.com:8388#n3",
		"hysteria2": "hysteria2://pw@h.example.com:443?sni=h.example.com&insecure=1&obfs=salamander&obfs-password=o#n4",
	}
	for name, link := range cases {
		t.Run(name, func(t *testing.T) {
			first := mustParse(t, link)
			out, err := Link(first)
			if err != nil {
				t.Fatalf("Link: %v", err)
			}
			second, err := Parse(out)
			if err != nil {
				t.Fatalf("re-Parse(%q): %v", out, err)
			}
			if !reflect.DeepEqual(stripVolatile(first), stripVolatile(second)) {
				t.Fatalf("round-trip mismatch\nfirst:  %+v\nsecond: %+v\nexported: %s", first, second, out)
			}
		})
	}
}

func TestLinkErrors(t *testing.T) {
	if _, err := Link(config.Node{Type: "vless", Server: "x", Port: 1}); err == nil {
		t.Fatal("want error for vless without uuid")
	}
	if _, err := Link(config.Node{Type: "ss", Server: "x", Port: 1}); err == nil {
		t.Fatal("want error for ss without method/password")
	}
	if _, err := Link(config.Node{Type: "socks", Server: "x", Port: 1}); err == nil {
		t.Fatal("want error for unsupported type")
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		"",
		"   ",
		"http://example.com",
		"vless://",
		"vless://nothost",
		"vless://YQ==@host:443", // uuid invalid
		"vless://11111111-2222-3333-4444-555555555555@host", // no port
		"vless://11111111-2222-3333-4444-555555555555@host:0",
		"vmess://aGVsbG8=", // decodes to "hello"
		"vmess://!!!notbase64!!!",
		"trojan://@host:443",
		"trojan://pw@:443",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("nopassword")) + "@host:8388",
		"ss://garbage",
		"hysteria2://@host:443",
		"hy2://pw@host:99999",
	}
	for _, link := range bad {
		if _, err := Parse(link); err == nil {
			t.Fatalf("Parse(%q) = nil error, want error", link)
		}
	}

	if _, errs := ParseClashYAML([]byte("proxies: [1,2"), ""); len(errs) == 0 {
		t.Fatal("want yaml error")
	}
	if _, errs := ParseSubscription([]byte("!!!not base64!!!"), ""); len(errs) == 0 {
		t.Fatal("want subscription error")
	}
	if _, errs := ParseSubscription(nil, ""); len(errs) == 0 {
		t.Fatal("want empty subscription error")
	}
	if nodes, errs := ParseText(""); nodes != nil || len(errs) != 0 {
		t.Fatalf("ParseText(empty) = %v, %v", nodes, errs)
	}
	// ParseClashYAML must skip unsupported proxy types without an error.
	nodes, errs := ParseClashYAML([]byte("proxies:\n  - {name: d, type: direct, server: '', port: 0}\n"), "")
	if len(nodes) != 0 || len(errs) != 0 {
		t.Fatalf("direct proxy = %v, %v", nodes, errs)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

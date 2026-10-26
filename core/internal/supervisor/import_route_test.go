package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"veil/internal/config"
	"veil/internal/logx"
	"veil/internal/rpc"
)

// routingYAML is a Clash profile with the owner's routing shape (a selector, a
// homelab-oriented group, domain and subnet rules, MATCH) but every group is
// pinned to a built-in outbound instead of a real server: a routing decision
// then shows up as "the stream was carried" (DIRECT) versus "it was refused"
// (REJECT), which is observable through the mixed inbound without a network.
func routingYAML() string {
	return `
proxies:
  - name: "hy2-hk"
    type: hysteria2
    server: 127.0.0.1
    port: 9
    password: placeholder
proxy-groups:
  - name: homelab-wg
    type: select
    proxies: [DIRECT, hy2-hk]
  - name: 选择代理
    type: select
    proxies: [REJECT, hy2-hk]
rules:
  - DOMAIN-SUFFIX,localhost,DIRECT
  - IP-CIDR,127.0.0.1/32,homelab-wg,no-resolve
  - MATCH,选择代理
`
}

// newRuleSupervisor builds a supervisor on the configuration the app ships,
// reduced to what this test needs: rule mode, no DNS (nothing here resolves),
// and the actionless `final` rule that Default carries.
func newRuleSupervisor(t *testing.T) *Supervisor {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := config.Default()
	cfg.Mixed = "127.0.0.1:0"
	cfg.Mode = config.ModeRule
	cfg.Tun.AutoRoute = false
	cfg.DNS.Enable = false
	// The shipped default final has no action; the import must give it one.
	cfg.Rules = []config.Rule{{Type: "final"}}
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	sup, err := New(cfgPath, logx.New(logx.Error, 256))
	if err != nil {
		t.Fatal(err)
	}
	return sup
}

// startEchoOn runs a TCP echo server bound to host and returns its address.
func startEchoOn(t *testing.T, host string) string {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("listen on %s: %v", host, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// socksCarried opens target through the engine's SOCKS5 inbound and reports
// whether the payload came back. The inbound answers success before it dials, so
// a refused or failed route surfaces as an immediate EOF on the first read.
func socksCarried(t *testing.T, addr, target, payload string) bool {
	t.Helper()
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("target %q: %v", target, err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("target %q: %v", target, err)
	}
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(c, greeting); err != nil {
		t.Fatal(err)
	}
	if greeting[0] != 5 || greeting[1] != 0 {
		t.Fatalf("greeting reply %v", greeting)
	}
	// ATYP 3 (domain) keeps a name intact for the rule matcher; ATYP 1 sends the
	// address the client already resolved.
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		req = append(req, 1)
		req = append(req, ip.To4()...)
	} else {
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("connect reply code %d for %s", reply[1], target)
	}
	if _, err := c.Write([]byte(payload)); err != nil {
		return false
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		return false
	}
	return string(buf) == payload
}

// TestImportedClashRoutingReachesTheEngine is the end-to-end check for the
// routing import: a pasted Clash profile must store its groups and rules, and
// the live engine — not just the matcher — must send the homelab subnet to its
// WireGuard group, domestic names direct, and everything else to the group
// MATCH names.
func TestImportedClashRoutingReachesTheEngine(t *testing.T) {
	homelabEcho := startEchoOn(t, "127.0.0.1")
	// A second loopback address, so "no rule matched" is a target a direct dial
	// *would* have reached: refusal then means the MATCH group ran, not that the
	// dial failed.
	unroutedEcho := startEchoOn(t, "127.0.0.2")
	_, port, err := net.SplitHostPort(homelabEcho)
	if err != nil {
		t.Fatal(err)
	}
	domesticTarget := net.JoinHostPort("localhost", port)

	sup := newRuleSupervisor(t)
	res, err := sup.Import(rpc.ImportParams{Text: routingYAML(), Source: "clash"})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if res.Added != 1 || len(res.Errors) != 0 {
		t.Fatalf("ImportResult = %+v, want one node and no errors", res)
	}

	// Stored routing table: the imported rules replace the actionless final and
	// keep their own order (first match wins). Each row carries the import's
	// source, which is what keeps a later subscription refresh away from it.
	wantRules := []config.Rule{
		{Type: "domain-suffix", Value: "localhost", Action: "direct", Source: "clash"},
		{Type: "ip-cidr", Value: "127.0.0.1/32", Action: "homelab-wg", NoResolve: true, Source: "clash"},
		{Type: "final", Action: "选择代理", Source: "clash"},
	}
	if got := sup.Config().Rules; !reflect.DeepEqual(got, wantRules) {
		t.Fatalf("rules =\n%+v\nwant\n%+v", got, wantRules)
	}

	groups := map[string]config.Group{}
	for _, g := range sup.Config().Groups {
		groups[g.Tag] = g
	}
	for tag, want := range map[string][]string{
		"homelab-wg": {"direct", "hy2-hk"},
		"选择代理":       {"reject", "hy2-hk"},
	} {
		if got := groups[tag].Members; !reflect.DeepEqual(got, want) {
			t.Fatalf("group %q members = %v, want %v", tag, got, want)
		}
	}

	// A second import of the same profile must not stack duplicate rules.
	if _, err := sup.Import(rpc.ImportParams{Text: routingYAML(), Source: "clash"}); err != nil {
		t.Fatalf("re-import: %v", err)
	}
	if got := sup.Config().Rules; !reflect.DeepEqual(got, wantRules) {
		t.Fatalf("rules after re-import =\n%+v\nwant\n%+v", got, wantRules)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx, -1); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sup.Stop(context.Background())
	inbound := sup.Status().Inbounds[0].Addr

	// The engine reports a group only once it built it with every member
	// present, so a missing member would take the rule's target away silently.
	now := map[string]string{}
	for _, g := range sup.Groups() {
		now[g.Tag] = g.Now
	}
	if now["homelab-wg"] != "direct" || now["选择代理"] != "reject" {
		t.Fatalf("groups in the running engine = %v, want both imported groups", now)
	}

	// 1. The homelab subnet travels the group (whose member here is DIRECT).
	//    Falling through to MATCH would have refused it.
	if !socksCarried(t, inbound, homelabEcho, "homelab-subnet") {
		t.Fatal("127.0.0.1 was not carried by the IP-CIDR rule's group")
	}
	// 2. A domestic name goes direct because of the domain suffix rule, not
	//    because MATCH happened to allow it (MATCH's group refuses).
	if !socksCarried(t, inbound, domesticTarget, "domestic-name") {
		t.Fatal("localhost was not carried by the DOMAIN-SUFFIX rule")
	}
	// 3. Nothing matches the second loopback address, so it falls to MATCH and
	//    the MATCH group refuses a stream that a direct dial would have carried.
	if socksCarried(t, inbound, unroutedEcho, "unmatched") {
		t.Fatal("an unmatched target was carried instead of going to the MATCH group")
	}

	// 4. Global mode bypasses the rule list and dials the engine's default,
	//    which is the group the imported final names: refusing the same address
	//    that rule mode carried proves the group tag resolved as the default.
	if _, err := sup.Call(ctx, rpc.MethodSetMode, json.RawMessage(`{"mode":"global"}`)); err != nil {
		t.Fatalf("set global mode: %v", err)
	}
	if socksCarried(t, inbound, homelabEcho, "global-default") {
		t.Fatal("global mode did not route through the imported final's group")
	}
}

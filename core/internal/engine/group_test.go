package engine

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"veil/internal/config"
	"veil/internal/logx"
	"veil/internal/outbound"
)

// echoOutbound dials a real TCP echo server and ignores the address it is
// asked for, so a group built by these tests can carry a request end to end
// without a proxy protocol in the way.
type echoOutbound struct {
	tag  string
	addr string
}

func (o echoOutbound) Tag() string  { return o.tag }
func (o echoOutbound) Type() string { return "echo" }
func (o echoOutbound) Close() error { return nil }

func (o echoOutbound) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, o.addr)
}

// startEcho starts a TCP server that echoes every byte back and returns its
// address.
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// echoThrough dials addr through ob, writes msg and returns what came back.
func echoThrough(t *testing.T, ob outbound.Outbound, addr, msg string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := ob.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("%s: dial %s: %v", ob.Tag(), addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("%s: write: %v", ob.Tag(), err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("%s: read: %v", ob.Tag(), err)
	}
	return string(buf)
}

// warnMessages returns the warn-level lines the logger holds.
func warnMessages(log *logx.Logger) []string {
	var out []string
	for _, e := range log.Snapshot(0, 0) {
		if e.Level == logx.Warn.String() {
			out = append(out, e.Msg)
		}
	}
	return out
}

// testConfig is a configuration Reload can build without opening a socket:
// one direct node, the given groups and rules, no listener and no DNS.
func testConfig(groups []config.Group, rules []config.Rule) config.Config {
	cfg := config.Default()
	cfg.Mixed = ""
	cfg.DNS.Enable = false
	cfg.Nodes = []config.Node{}
	cfg.Groups = groups
	cfg.Rules = rules
	return cfg
}

// newReloadingEngine returns an engine that reports itself as running, so Reload
// takes its real build-and-swap path instead of only storing the configuration.
func newReloadingEngine(t *testing.T, cfg config.Config, log *logx.Logger) *Engine {
	t.Helper()
	e, err := New(cfg, log)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	e.mu.Lock()
	e.running = true
	e.ctx = context.Background()
	e.mu.Unlock()
	t.Cleanup(func() {
		e.mu.RLock()
		groups := append([]*Group(nil), e.groups...)
		e.mu.RUnlock()
		for _, g := range groups {
			g.stop()
		}
	})
	return e
}

// TestGroupSkipsMissingMember is acceptance (a): a select group with a member
// that was deleted (or misspelled) is built from the members that do exist, one
// warning names the skipped member and the reason, and a pin on that member
// falls back to the first usable one instead of being cleared.
func TestGroupSkipsMissingMember(t *testing.T) {
	addr := startEcho(t)
	obs := map[string]outbound.Outbound{
		"a": echoOutbound{tag: "a", addr: addr},
		"b": echoOutbound{tag: "b", addr: addr},
	}

	t.Run("select", func(t *testing.T) {
		log := logx.New(logx.Debug, 64)
		grp, err := newGroup(config.Group{
			Tag: "sel", Type: "select", Members: []string{"a", "gone", "b"},
		}, obs, nil, log)
		if err != nil {
			t.Fatalf("newGroup: %v (one missing member must not drop the group)", err)
		}
		if got := len(grp.members); got != 2 {
			t.Fatalf("members = %d, want 2", got)
		}
		warns := warnMessages(log)
		if len(warns) != 1 {
			t.Fatalf("warnings = %q, want exactly one", warns)
		}
		if !strings.Contains(warns[0], `"gone"`) || !strings.Contains(warns[0], "no node or group has this tag") {
			t.Fatalf("warning = %q, want the member tag and the reason", warns[0])
		}
		if got := grp.now().Tag(); got != "a" {
			t.Fatalf("current = %q, want the first available member %q", got, "a")
		}
		if got := echoThrough(t, grp, "echo:1", "hello-select"); got != "hello-select" {
			t.Fatalf("echo through degraded group = %q, want %q", got, "hello-select")
		}
		t.Logf("members=%d current=%q warnings=%q", len(grp.members), grp.now().Tag(), warns)
	})

	t.Run("selected points at the skipped member", func(t *testing.T) {
		log := logx.New(logx.Debug, 64)
		grp, err := newGroup(config.Group{
			Tag: "sel", Type: "select", Members: []string{"a", "gone", "b"}, Selected: "gone",
		}, obs, nil, log)
		if err != nil {
			t.Fatalf("newGroup: %v", err)
		}
		if got := len(grp.members); got != 2 {
			t.Fatalf("members = %d, want 2", got)
		}
		if got := grp.now().Tag(); got != "a" {
			t.Fatalf("current = %q, want the fallback %q", got, "a")
		}
		if grp.cfg.Selected != "gone" {
			t.Fatalf("Selected = %q, want the pin kept so a later reload can restore it", grp.cfg.Selected)
		}
		var fallback string
		for _, w := range warnMessages(log) {
			if strings.Contains(w, "selected member") {
				fallback = w
			}
		}
		if fallback == "" || !strings.Contains(fallback, `"gone"`) || !strings.Contains(fallback, `using "a"`) {
			t.Fatalf("fallback warning = %q, want it to name the pin and the member in use", fallback)
		}
		t.Logf("members=%d current=%q Selected=%q fallback=%q",
			len(grp.members), grp.now().Tag(), grp.cfg.Selected, fallback)
	})
}

// TestGroupSkipsMissingMemberURLTest is acceptance (b): url-test behaves the
// same way.
func TestGroupSkipsMissingMemberURLTest(t *testing.T) {
	addr := startEcho(t)
	obs := map[string]outbound.Outbound{
		"a": echoOutbound{tag: "a", addr: addr},
		"b": echoOutbound{tag: "b", addr: addr},
	}
	log := logx.New(logx.Debug, 64)
	grp, err := newGroup(config.Group{
		Tag: "auto", Type: "url-test", Members: []string{"a", "gone", "b"},
		URL: "http://127.0.0.1:1/generate_204", Interval: 3600,
	}, obs, nil, log)
	if err != nil {
		t.Fatalf("newGroup: %v (one missing member must not drop the group)", err)
	}
	if got := len(grp.members); got != 2 {
		t.Fatalf("members = %d, want 2", got)
	}
	warns := warnMessages(log)
	if len(warns) != 1 || !strings.Contains(warns[0], `"gone"`) {
		t.Fatalf("warnings = %q, want exactly one naming %q", warns, "gone")
	}
	if got := echoThrough(t, grp, "echo:2", "hello-urltest"); got != "hello-urltest" {
		t.Fatalf("echo through degraded url-test group = %q, want %q", got, "hello-urltest")
	}
	t.Logf("members=%d current=%q warnings=%q", len(grp.members), grp.now().Tag(), warns)
	// The first dial armed the probe loop; stop it before the test ends.
	grp.Close()
}

// TestReloadDropsGroupWithoutUsableMembers is acceptance (c): when every member
// is gone the group is not built, the reason reaches lastErr and the log, and a
// rule naming it is still reported as unknown instead of silently taking the
// default outbound.
func TestReloadDropsGroupWithoutUsableMembers(t *testing.T) {
	log := logx.New(logx.Debug, 256)
	cfg := testConfig(
		[]config.Group{{Tag: "dead", Type: "select", Members: []string{"gone", "also-gone"}}},
		[]config.Rule{
			{Type: "domain", Value: "dead.example", Action: "dead"},
			{Type: "final", Action: "direct"},
		},
	)
	e := newReloadingEngine(t, cfg, log)
	if err := e.Reload(cfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if _, built := e.outbounds["dead"]; built {
		t.Fatalf("group %q was built with no usable member", "dead")
	}
	lastErr := e.LastError()
	for _, want := range []string{"group dead", "all members unavailable", `"gone"`, `"also-gone"`} {
		if !strings.Contains(lastErr, want) {
			t.Fatalf("lastErr = %q, want it to mention %q", lastErr, want)
		}
	}
	if warns := strings.Join(warnMessages(log), "\n"); !strings.Contains(warns, "all members unavailable") {
		t.Fatalf("log = %q, want the drop reported there too", warns)
	}
	// The existing discovery path for a rule that names a missing outbound stays.
	ob, _, _, err := e.route(context.Background(), "tcp", "dead.example:443")
	if err != nil {
		t.Fatalf("route: %v", err)
	}
	if ob == nil || ob.Tag() != "direct" {
		t.Fatalf("route outbound = %v, want the default", ob)
	}
	if warns := strings.Join(warnMessages(log), "\n"); !strings.Contains(warns, `wants unknown outbound "dead"`) {
		t.Fatalf("log = %q, want the unknown-outbound warning for the dropped group", warns)
	}
	t.Logf("built=%v lastErr=%q log=%q", e.outbounds["dead"], lastErr, warnMessages(log))
}

// TestReloadParentGroupKeepsWorkingThroughDegradedChild is acceptance (d): a
// parent group whose member is a child group, where the child lost one of its
// members, still builds and still carries the request through the child.
func TestReloadParentGroupKeepsWorkingThroughDegradedChild(t *testing.T) {
	addr := startEcho(t)
	log := logx.New(logx.Debug, 256)
	cfg := testConfig(
		[]config.Group{
			{Tag: "child", Type: "select", Members: []string{"direct", "gone"}},
			{Tag: "parent", Type: "select", Members: []string{"child", "also-gone"}},
		},
		[]config.Rule{
			{Type: "domain", Value: "via-child.example", Action: "child"},
			{Type: "final", Action: "parent"},
		},
	)
	e := newReloadingEngine(t, cfg, log)
	if err := e.Reload(cfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	for _, tag := range []string{"child", "parent"} {
		if _, built := e.outbounds[tag]; !built {
			t.Fatalf("group %q was dropped because one of its members is gone", tag)
		}
	}
	// parent -> child -> direct -> echo server.
	if got := echoThrough(t, e.outbounds["parent"], addr, "via-parent-child"); got != "via-parent-child" {
		t.Fatalf("echo through parent = %q, want %q", got, "via-parent-child")
	}
	// A rule naming the degraded child must land on the child, not on the
	// default outbound: the group exists, only one member of it does not.
	ob, _, _, err := e.route(context.Background(), "tcp", "via-child.example:443")
	if err != nil {
		t.Fatalf("route: %v", err)
	}
	if ob.Tag() != "child" {
		t.Fatalf("route outbound = %q, want the degraded child group", ob.Tag())
	}
	warns := strings.Join(warnMessages(log), "\n")
	for _, want := range []string{`group child skips member "gone"`, `group parent skips member "also-gone"`} {
		if !strings.Contains(warns, want) {
			t.Fatalf("log = %q, want it to contain %q", warns, want)
		}
	}
	if strings.Contains(warns, "wants unknown outbound") {
		t.Fatalf("log = %q, want no unknown-outbound warning while the groups exist", warns)
	}
	// A degraded group keeps working, so it is a warning and not a reload error:
	// lastErr is what the supervisor shows as a failure of the whole reload.
	if last := e.LastError(); last != "" {
		t.Fatalf("lastErr = %q, want a working (if degraded) reload to report no error", last)
	}
	t.Logf("child current=%q parent current=%q route=%q warnings=%q",
		e.outbounds["child"].(*Group).now().Tag(), e.outbounds["parent"].(*Group).now().Tag(), ob.Tag(), warnMessages(log))
}

package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"veil/internal/config"
	"veil/internal/logx"
	"veil/internal/outbound"
	"veil/internal/state"
)

// Group is a policy outbound: select, url-test, fallback or load-balance.
type Group struct {
	cfg     config.Group
	members []outbound.Outbound
	nodes   map[string]config.Node
	log     *logx.Logger

	mu      sync.RWMutex
	current int // index into members
	delays  map[string]probe

	rr atomic.Uint64

	// parent is the engine context the probe loop must die with. The engine
	// records it once (setParent), before the group can be dialed; both that
	// write and start's read happen under lifeMu, because the first connections
	// that arm a group arrive concurrently.
	parent context.Context

	// lifeMu guards the probe-loop lifecycle. It is separate from mu so that
	// stopping a group never queues behind a reader of current/delays.
	lifeMu  sync.Mutex
	armed   bool // a probe loop was launched; it is launched once
	stopped bool // the group is gone for good; no dial re-arms it
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

type probe struct {
	ms   int
	at   time.Time
	fail string
}

const defaultProbeURL = "http://cp.cloudflare.com/generate_204"

// skippedMember is a member the group could not use, with the reason it could
// not: the warning names what to repair, and the error of a group that loses
// every member repeats the same facts.
type skippedMember struct {
	tag    string
	reason string
}

func (s skippedMember) String() string { return fmt.Sprintf("%q (%s)", s.tag, s.reason) }

// unavailableReason explains why tag cannot be used as a member of this group:
// the map either has no such outbound at all, or has one the group does not
// list. A tag the configuration still lists but whose outbound failed to build
// is a different repair than a tag that names nothing at all (a deleted node, a
// misspelling, or a group that failed earlier in the same pass).
func unavailableReason(tag string, obs map[string]outbound.Outbound, nodes map[string]config.Node) string {
	if _, built := obs[tag]; built {
		return "it is not a member of this group"
	}
	if _, known := nodes[tag]; known {
		return "its outbound failed to build"
	}
	return "no node or group has this tag"
}

func newGroup(g config.Group, obs map[string]outbound.Outbound, nodes map[string]config.Node, log *logx.Logger) (*Group, error) {
	if g.Type == "" {
		g.Type = "select"
	}
	grp := &Group{cfg: g, nodes: nodes, log: log, delays: make(map[string]probe)}
	// A member that cannot be built is skipped, not fatal. Dropping the whole
	// group made every rule that named it fall back to the default outbound
	// without saying so: a subnet meant for WireGuard quietly left through the
	// proxy because one unrelated tag in the subscription was stale. Clash skips
	// the member that is gone and keeps the group working; so do we, and the
	// skip is logged with the member and the reason. Only a group with nothing
	// left is refused, and then the error carries the same detail.
	var skipped []string
	for _, tag := range g.Members {
		ob, ok := obs[tag]
		if !ok {
			sk := skippedMember{tag: tag, reason: unavailableReason(tag, obs, nodes)}
			skipped = append(skipped, sk.String())
			if log != nil {
				log.Warnf("group %s skips member %s", g.Tag, sk)
			}
			continue
		}
		grp.members = append(grp.members, ob)
	}
	if len(grp.members) == 0 {
		if len(skipped) == 0 {
			return nil, errors.New("no members")
		}
		return nil, fmt.Errorf("all members unavailable: %s", strings.Join(skipped, ", "))
	}
	// Restore the pinned selection.
	if g.Selected != "" {
		pinned := false
		for i, m := range grp.members {
			if m.Tag() == g.Selected {
				grp.current = i
				pinned = true
				break
			}
		}
		if !pinned {
			// The pin names a member this build had to skip. Route through the
			// first member that does exist, but keep g.cfg.Selected: the pin is
			// the user's choice, and the next reload restores it once the member
			// is importable again instead of leaving the group on the fallback.
			grp.current = 0
			if log != nil {
				log.Warnf("group %s: selected member %s is unavailable, using %q",
					g.Tag, skippedMember{tag: g.Selected, reason: unavailableReason(g.Selected, obs, nodes)}, grp.members[0].Tag())
			}
		}
	}
	return grp, nil
}

// setParent records the context the probe loop derives from. The engine calls it
// once, after newGroup and before the group is published to anything that can
// dial, so the loop lives exactly as long as the engine that owns the group.
func (g *Group) setParent(parent context.Context) {
	g.lifeMu.Lock()
	g.parent = parent
	g.lifeMu.Unlock()
}

// Tag implements outbound.Outbound.
func (g *Group) Tag() string { return g.cfg.Tag }

// Type implements outbound.Outbound.
func (g *Group) Type() string { return "group:" + g.cfg.Type }

// DialsLocally reports whether this group resolves names on this device, so the
// router knows a fake address must be replaced before the dial.
//
// The answer depends on the group type, because the type is what says whether
// `current` is a promise about the member that carries the next connection:
//
//   - select dials exactly the member it reports, so it answers for `current`.
//     That includes the common "selector pinned to DIRECT" profile, which must
//     resolve the fake address locally.
//   - fallback and load-balance walk the member list at dial time, so any of
//     them may carry the connection and one local member is enough to answer
//     true. This is deliberately not "all members": a real address handed to a
//     proxy member still works — the exit node dials an IP — while a fake
//     address handed to a direct member is a dead end, because that dial asks
//     the system resolver and gets the placeholder back. Answering false for a
//     mixed group would keep the remote lookup the proxy member might have done
//     and lose the connection that lands on the direct one; a substitution the
//     proxy did not need costs one lookup, the broken direct dial costs the page.
//   - url-test dials `current` like select, but its own probe loop can move
//     `current` between this answer and the dial that follows it, so it keeps
//     the conservative whole-set answer: true only when every member dials
//     locally. A mixed url-test group therefore still loses the DIRECT member
//     under fake-IP; the alternative is claiming a member it may not dial.
func (g *Group) DialsLocally() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if len(g.members) == 0 {
		return false
	}
	switch g.cfg.Type {
	case "select":
		if g.current < 0 || g.current >= len(g.members) {
			return false
		}
		ld, ok := g.members[g.current].(outbound.LocalDialer)
		return ok && ld.DialsLocally()
	default:
		// Everything but a selector picks per connection: url-test takes the
		// fastest, fallback walks the list, load-balance rotates. Any of them may
		// dial locally, and handing a fake address to a local dial is a dead
		// connection, while handing a real address to a proxy only costs the
		// remote resolution. So one local member is enough to answer yes.
		for _, m := range g.members {
			if ld, ok := m.(outbound.LocalDialer); ok && ld.DialsLocally() {
				return true
			}
		}
		return false
	}
}

// DialContext implements outbound.Outbound.
func (g *Group) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// First use arms the probe loop; the group is about to carry traffic, so
	// keeping its member latencies fresh is now worth the wakeups.
	g.armFrom(ctx)
	switch g.cfg.Type {
	case "fallback":
		var lastErr error
		for _, m := range g.members {
			conn, err := m.DialContext(ctx, network, address)
			if err == nil {
				return conn, nil
			}
			lastErr = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		return nil, fmt.Errorf("all members failed: %w", lastErr)
	case "load-balance":
		n := uint64(len(g.members))
		start := g.rr.Add(1)
		var lastErr error
		for i := uint64(0); i < n; i++ {
			m := g.members[(start+i)%n]
			conn, err := m.DialContext(ctx, network, address)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	default:
		return g.now().DialContext(ctx, network, address)
	}
}

// DialPacket implements outbound.PacketOutbound when the active member does.
func (g *Group) DialPacket(ctx context.Context, address string) (outbound.PacketConn, error) {
	// UDP is the same "the group is carrying traffic" signal as TCP: a url-test
	// group used only for QUIC or DoH never saw DialContext, so its members were
	// never measured. Both paths arm exactly here.
	g.armFrom(ctx)
	ob := g.now()
	p, ok := ob.(outbound.PacketOutbound)
	if !ok {
		return nil, fmt.Errorf("%s: udp not supported", ob.Tag())
	}
	return p.DialPacket(ctx, address)
}

// Close implements outbound.Outbound.
func (g *Group) Close() error {
	g.stop()
	return nil
}

func (g *Group) now() outbound.Outbound {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.members[g.current]
}

func (g *Group) selectTag(tag string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, m := range g.members {
		if m.Tag() == tag {
			g.current = i
			g.cfg.Selected = tag
			return nil
		}
	}
	return fmt.Errorf("%q is not a member of %q", tag, g.cfg.Tag)
}

// internalDialKey marks a connection the engine opens for itself rather than for
// the user: the outbound self-check at start, a member probe, ProbeTag. Such a
// dial must not arm a group's probe loop — AGENTS.md invariant 7 allows periodic
// wakeups only once the tunnel actually carries traffic, and the self-check runs
// on every start, idle or not.
type internalDialKey struct{}

// withInternalDial marks ctx as belonging to an engine-internal dial.
func withInternalDial(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, internalDialKey{}, true)
}

// isInternalDial reports whether ctx belongs to an engine-internal dial.
func isInternalDial(ctx context.Context) bool {
	return ctx != nil && ctx.Value(internalDialKey{}) != nil
}

// probeHTTPInternal is probeHTTP for a probe. The dial it performs is marked as
// engine-internal, so a group it goes through does not start a probe loop of its
// own. Every caller of probeHTTP in this package goes through here; delay.go
// keeps the measurement itself.
func probeHTTPInternal(ctx context.Context, ob outbound.Outbound, url string, timeout time.Duration) (int, error) {
	return probeHTTP(withInternalDial(ctx), ob, url, timeout)
}

// armFrom starts the probe loop for a dial that is about to carry user traffic.
// A probe or a self-check reaches a group through the same DialContext, but it
// is not user traffic and must leave the group dormant.
func (g *Group) armFrom(ctx context.Context) {
	if isInternalDial(ctx) {
		return
	}
	g.start()
}

// start launches the probe loop. Idempotent, and deferred until something
// actually dials through a url-test/fallback group: an imported group that
// nobody uses must not wake the device up every interval.
//
// A stopped group never starts again. An engine Stop or a reload that replaced
// the group cancels the context this loop derives from, so a dial that still
// holds the old group (a connection already routed through it) would otherwise
// create a loop nobody owns any more — it would outlive the engine and tick for
// the rest of the process.
func (g *Group) start() {
	if g.cfg.Type != "url-test" && g.cfg.Type != "fallback" {
		return
	}
	g.lifeMu.Lock()
	defer g.lifeMu.Unlock()
	if g.armed || g.stopped {
		return
	}
	g.armed = true
	parent := g.parent
	if parent == nil {
		parent = context.Background()
	}
	g.launchProbeLoop(parent)
}

// launchProbeLoop starts the ticker goroutine; the caller holds lifeMu.
func (g *Group) launchProbeLoop(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	g.cancel = cancel
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		interval := time.Duration(g.cfg.Interval) * time.Second
		if interval <= 0 {
			interval = 5 * time.Minute
		}
		g.tick(ctx)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				g.tick(ctx)
			}
		}
	}()
}

// stop ends the probe loop and forbids a later one. The stopped flag is
// permanent: reload hands the retired group to connections that are still
// unwinding, and those dials must not resurrect it.
func (g *Group) stop() {
	g.lifeMu.Lock()
	g.stopped = true
	cancel := g.cancel
	g.cancel = nil
	g.lifeMu.Unlock()
	if cancel != nil {
		cancel()
	}
	g.wg.Wait()
}

// tick probes every member and, for url-test, switches to the fastest healthy
// one within the configured tolerance.
func (g *Group) tick(ctx context.Context) {
	url := g.cfg.URL
	if url == "" {
		url = defaultProbeURL
	}
	type res struct {
		tag string
		ms  int
		err error
	}
	ch := make(chan res, len(g.members))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, m := range g.members {
		wg.Add(1)
		go func(m outbound.Outbound) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ms, err := probeHTTPInternal(ctx, m, url, 5*time.Second)
			ch <- res{tag: m.Tag(), ms: ms, err: err}
		}(m)
	}
	wg.Wait()
	close(ch)

	bestTag, bestMS := "", 0
	for r := range ch {
		g.mu.Lock()
		if r.err != nil {
			g.delays[r.tag] = probe{ms: -1, at: time.Now(), fail: r.err.Error()}
		} else {
			g.delays[r.tag] = probe{ms: r.ms, at: time.Now()}
			if bestTag == "" || r.ms < bestMS {
				bestTag, bestMS = r.tag, r.ms
			}
		}
		g.mu.Unlock()
	}
	if g.cfg.Type != "url-test" || bestTag == "" {
		return
	}
	// Only switch when the gain exceeds the tolerance, to avoid flapping.
	g.mu.Lock()
	cur := g.members[g.current]
	if cur.Tag() != bestTag {
		tolerance := g.cfg.Tolerance
		if tolerance <= 0 {
			tolerance = 50
		}
		if p, ok := g.delays[cur.Tag()]; !ok || p.ms < 0 || p.ms > bestMS+tolerance {
			for i, m := range g.members {
				if m.Tag() == bestTag {
					g.current = i
					g.log.Infof("group %s switched to %s (%d ms)", g.cfg.Tag, bestTag, bestMS)
					break
				}
			}
		}
	}
	g.mu.Unlock()
}

func (g *Group) status() state.GroupStatus {
	g.mu.RLock()
	defer g.mu.RUnlock()
	st := state.GroupStatus{
		Tag:  g.cfg.Tag,
		Type: g.cfg.Type,
		Now:  g.members[g.current].Tag(),
	}
	for _, m := range g.members {
		ns := state.NodeStatus{Tag: m.Tag(), Type: m.Type(), DelayMS: -1}
		if n, ok := g.nodes[m.Tag()]; ok {
			ns.Type = n.Type
			ns.Remark = n.Remark
		}
		if p, ok := g.delays[m.Tag()]; ok {
			ns.DelayMS = p.ms
			ns.Alive = p.ms >= 0
			ns.TestedAt = p.at.Unix()
		}
		st.Members = append(st.Members, ns)
	}
	return st
}

// ProbeGroup forces an immediate probe of one group member and returns the
// measured latency.
func (e *Engine) ProbeGroup(groupTag, memberTag string) (int, error) {
	e.mu.RLock()
	g, ok := e.outbounds[groupTag].(*Group)
	e.mu.RUnlock()
	if !ok {
		return -1, fmt.Errorf("group %q not found", groupTag)
	}
	var target outbound.Outbound
	for _, m := range g.members {
		if m.Tag() == memberTag {
			target = m
		}
	}
	if target == nil {
		return -1, fmt.Errorf("%q is not a member of %q", memberTag, groupTag)
	}
	// A member probe is engine-internal: if the member is itself a group, its own
	// probe loop must not be armed by the parent's tick.
	return probeHTTPInternal(e.ctx, target, defaultProbeURL, 5*time.Second)
}

package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
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

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	// startOnce keeps a group from owning two probe loops when it is started
	// both by the engine and, lazily, by the first connection that uses it.
	startOnce sync.Once
	parent    context.Context
}

type probe struct {
	ms   int
	at   time.Time
	fail string
}

const defaultProbeURL = "http://cp.cloudflare.com/generate_204"

func newGroup(g config.Group, obs map[string]outbound.Outbound, nodes map[string]config.Node, log *logx.Logger) (*Group, error) {
	if g.Type == "" {
		g.Type = "select"
	}
	grp := &Group{cfg: g, nodes: nodes, log: log, delays: make(map[string]probe)}
	for _, tag := range g.Members {
		ob, ok := obs[tag]
		if !ok {
			return nil, fmt.Errorf("member %q not found", tag)
		}
		grp.members = append(grp.members, ob)
	}
	if len(grp.members) == 0 {
		return nil, errors.New("no members")
	}
	// Restore the pinned selection.
	if g.Selected != "" {
		for i, m := range grp.members {
			if m.Tag() == g.Selected {
				grp.current = i
			}
		}
	}
	return grp, nil
}

// Tag implements outbound.Outbound.
func (g *Group) Tag() string { return g.cfg.Tag }

// Type implements outbound.Outbound.
func (g *Group) Type() string { return "group:" + g.cfg.Type }

// DialContext implements outbound.Outbound.
// DialsLocally reports whether the member this group would use resolves names
// on this device, so the router knows a fake address must be replaced first.
func (g *Group) DialsLocally() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.current < 0 || g.current >= len(g.members) {
		return false
	}
	if ld, ok := g.members[g.current].(outbound.LocalDialer); ok {
		return ld.DialsLocally()
	}
	return false
}

func (g *Group) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// First use arms the probe loop; the group is about to carry traffic, so
	// keeping its member latencies fresh is now worth the wakeups.
	g.start(g.parent)
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

// start launches the probe loop. Idempotent, and deferred until something
// actually dials through a url-test/fallback group: an imported group that
// nobody uses must not wake the device up every interval.
func (g *Group) start(parent context.Context) {
	if g.cfg.Type != "url-test" && g.cfg.Type != "fallback" {
		return
	}
	if parent == nil {
		parent = context.Background()
	}
	g.startOnce.Do(func() {
		g.parent = parent
		g.launchProbeLoop(parent)
	})
}

func (g *Group) launchProbeLoop(parent context.Context) {
	g.ctx, g.cancel = context.WithCancel(parent)
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		interval := time.Duration(g.cfg.Interval) * time.Second
		if interval <= 0 {
			interval = 5 * time.Minute
		}
		g.tick()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-g.ctx.Done():
				return
			case <-t.C:
				g.tick()
			}
		}
	}()
}

func (g *Group) stop() {
	if g.cancel != nil {
		g.cancel()
		g.wg.Wait()
	}
}

// tick probes every member and, for url-test, switches to the fastest healthy
// one within the configured tolerance.
func (g *Group) tick() {
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
			ms, err := probeHTTP(g.ctx, m, url, 5*time.Second)
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
	return probeHTTP(e.ctx, target, defaultProbeURL, 5*time.Second)
}

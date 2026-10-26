package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"veil/internal/config"
	"veil/internal/dns"
	"veil/internal/inbound"
	"veil/internal/logx"
	"veil/internal/netstack"
	"veil/internal/outbound"
	"veil/internal/proxy/factory"
	"veil/internal/rules"
	"veil/internal/state"
)

// ErrRejected is returned when a routing rule blocks a connection.
var ErrRejected = errors.New("rejected by rule")

// Engine owns the live data path: outbounds, routing, inbounds, tun and stats.
//
// The engine is deliberately unaware of process lifecycle; that belongs to
// internal/supervisor, which starts and stops it and interprets failures.
type Engine struct {
	cfg config.Config
	log *logx.Logger

	stats *Stats

	mu         sync.RWMutex
	running    bool
	startedAt  time.Time
	nodes      map[string]config.Node
	outbounds  map[string]outbound.Outbound
	groups     []*Group
	router     *rules.Engine
	resolver   *dns.Resolver
	mixed      inbound.Server
	tun        *netstack.Stack
	tunFD      int
	tunMTU     int
	needsIP    bool
	defaultOB  outbound.Outbound
	defaultTag string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	lastErrMu    sync.RWMutex
	lastErr      string
	inboundConns map[string]*atomic.Int64

	udpCache    sync.Map
	udpSessions atomic.Int64

	// routeCache memoises the DNS lookups rule matching performs. Zero value is
	// ready to use; see routecache.go for why the engine keeps its own.
	routeCache routeAddrCache
}

// New validates cfg and prepares an engine. It does not open sockets.
func New(cfg config.Config, log *logx.Logger) (*Engine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if log == nil {
		log = logx.New(logx.ParseLevel(cfg.LogLevel), 512)
	}
	e := &Engine{
		cfg:          cfg,
		log:          log,
		stats:        NewStats(),
		nodes:        make(map[string]config.Node, len(cfg.Nodes)),
		outbounds:    make(map[string]outbound.Outbound, len(cfg.Nodes)+len(cfg.Groups)+2),
		inboundConns: make(map[string]*atomic.Int64),
	}
	for _, n := range cfg.Nodes {
		e.nodes[n.Tag] = n
	}
	// Only rules that want an address make the router resolve: a table whose IP
	// rules are all `no-resolve` must never look a name up.
	e.needsIP = rules.NeedsIP(cfg.Rules)
	return e, nil
}

// Config returns the configuration the engine was built from.
func (e *Engine) Config() config.Config { return e.cfg }

// Stats exposes the traffic counters.
func (e *Engine) Stats() *Stats { return e.stats }

// Start brings up outbounds, routing, the mixed inbound and (when tunFD >= 0)
// the tunnel.
func (e *Engine) Start(ctx context.Context, tunFD int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		return errors.New("engine already running")
	}

	e.ctx, e.cancel = context.WithCancel(ctx)
	e.startedAt = time.Now()

	// 1. Outbounds. A broken node must not take the whole engine down: record it
	// and keep going, the supervisor reports the engine as degraded.
	var failed []string
	for _, n := range e.cfg.Nodes {
		ob, err := e.buildOutbound(n)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", n.Tag, err))
			e.log.Errorf("outbound %s (%s) failed to initialise: %v", n.Tag, n.Type, err)
			continue
		}
		e.outbounds[n.Tag] = ob
	}
	e.outbounds["direct"] = factory.Direct{}
	e.outbounds["reject"] = factory.Reject{}
	if len(failed) == len(e.cfg.Nodes) && len(e.cfg.Nodes) > 0 {
		e.setLastErr(strings.Join(failed, "; "))
	}
	for _, g := range e.cfg.Groups {
		grp, err := newGroup(g, e.outbounds, e.nodes, e.log)
		if err != nil {
			failed = append(failed, fmt.Sprintf("group %s: %v", g.Tag, err))
			e.log.Errorf("group %s failed: %v", g.Tag, err)
			continue
		}
		// The probe loop a later dial arms must die with this engine, so the
		// parent is fixed here, before anything can reach the group.
		grp.setParent(e.ctx)
		e.outbounds[g.Tag] = grp
		e.groups = append(e.groups, grp)
	}

	final := ""
	for i := len(e.cfg.Rules) - 1; i >= 0; i-- {
		if e.cfg.Rules[i].Type == "final" {
			final = e.cfg.Rules[i].Action
			break
		}
	}
	e.defaultTag = final
	e.defaultOB = e.resolveTagLocked(final)
	if e.defaultOB == nil {
		// No explicit final: prefer the first select group, then the first node.
		for _, g := range e.groups {
			if g.cfg.Type == "select" {
				e.defaultOB = g
				e.defaultTag = g.cfg.Tag
				break
			}
		}
		if e.defaultOB == nil && len(e.cfg.Nodes) > 0 {
			for _, n := range e.cfg.Nodes {
				if ob := e.outbounds[n.Tag]; ob != nil {
					e.defaultOB, e.defaultTag = ob, n.Tag
					break
				}
			}
		}
		if e.defaultOB == nil {
			e.defaultOB, e.defaultTag = factory.Direct{}, "direct"
		}
	}

	// 2. Router.
	router, err := rules.New(e.cfg.Rules, e.cfg.Mode, e.defaultTag)
	if err != nil {
		e.cancel()
		return fmt.Errorf("rules: %w", err)
	}
	e.router = router

	// 3. DNS.
	if e.cfg.DNS.Enable {
		// Share the engine's pool: a restart must not orphan the addresses
		// applications still hold from before it.
		r, err := dns.NewWithPool(e.cfg.DNS, e.log, e.routeCache.fakePool(nil))
		if err != nil {
			e.log.Errorf("dns disabled: %v", err)
		} else {
			r.SetDial(e.dnsDial)
			e.resolver = r
		}
	}

	// 4. Mixed inbound.
	if e.cfg.Mixed != "" {
		srv, err := inbound.NewMixed(e.cfg.Mixed, e, e.log)
		if err != nil {
			e.cancel()
			return fmt.Errorf("mixed inbound: %w", err)
		}
		e.mixed = srv
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			if err := srv.Serve(); err != nil && !errors.Is(err, net.ErrClosed) {
				e.log.Errorf("mixed inbound stopped: %v", err)
				e.setLastErr(err.Error())
			}
		}()
		e.log.Infof("mixed inbound listening on %s", srv.Addr())
	}

	// 5. Tun.
	e.tunFD = tunFD
	if tunFD >= 0 {
		mtu := e.cfg.Tun.MTU
		if mtu <= 0 {
			mtu = 1400
		}
		st, err := netstack.Start(tunFD, mtu, e, e.log)
		if err != nil {
			e.cancel()
			return fmt.Errorf("tun: %w", err)
		}
		e.tun = st
		e.tunMTU = mtu
		e.log.Infof("tun up (fd %d, mtu %d)", tunFD, mtu)
	}

	// 6. Outbound self-check: prove the selected node can actually reach a
	// domestic and a foreign endpoint, and say so in the log. Without this the
	// user sees "connected" and a broken page with no explanation.
	//
	// The dial is marked engine-internal: it goes through the default outbound,
	// which may be a url-test group, and a self-check is not user traffic — it
	// must not arm that group's probe loop (AGENTS.md invariant 7).
	if e.defaultOB != nil {
		ob := e.defaultOB
		go func() {
			for _, probe := range []struct{ name, url string }{
				{"domestic", "http://www.baidu.com/generate_204"},
				{"foreign", "http://www.gstatic.com/generate_204"},
				{"foreign-tls", "https://www.google.com/generate_204"},
			} {
				ms, perr := probeHTTPInternal(e.ctx, ob, probe.url, 10*time.Second)
				if perr != nil {
					e.log.Warnf("出站自检 %s 失败 (%s): %v", probe.name, ob.Tag(), perr)
				} else {
					e.log.Infof("出站自检 %s 通过 (%s): %dms", probe.name, ob.Tag(), ms)
				}
			}
		}()
	}

	// 7. Group probes (running connections; no periodic wakeups when idle).
	// A probe loop is armed by the first TCP or UDP connection routed through a
	// group, and only by user traffic: the self-check above and the group's own
	// probes are marked internal and leave an unused group asleep. A group the
	// engine no longer owns (stopped, or replaced by a reload) cannot be armed
	// again — see Group.start.

	e.running = true
	return nil
}

// buildOutbound constructs one protocol client.
//
// Socket protection is not wired here: every transport goes through
// transport.TCP/NewDialer, which applies the process-wide protect hook. That
// keeps HarmonyOS fd protection impossible to forget in a new protocol.
func (e *Engine) buildOutbound(n config.Node) (outbound.Outbound, error) {
	return factory.New(n)
}

func (e *Engine) resolveTag(tag string) outbound.Outbound {
	if tag == "" {
		return nil
	}
	// Reload swaps the map under e.mu; a rule matched on the data path reads it
	// here, so the read needs the same lock the write holds.
	e.mu.RLock()
	ob := e.outbounds[tag]
	e.mu.RUnlock()
	return ob
}

// resolveTagLocked is resolveTag for callers that already hold e.mu: the
// RWMutex is not reentrant, so Start (which builds the map under the write
// lock) must not call the locking form.
func (e *Engine) resolveTagLocked(tag string) outbound.Outbound {
	if tag == "" {
		return nil
	}
	return e.outbounds[tag]
}

// Stop tears everything down and waits for handlers to finish.
func (e *Engine) Stop(ctx context.Context) error {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return nil
	}
	e.running = false
	cancel := e.cancel
	mixed := e.mixed
	tun := e.tun
	groups := e.groups
	e.mixed, e.tun = nil, nil
	e.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if mixed != nil {
		_ = mixed.Close()
	}
	if tun != nil {
		_ = tun.Close()
	}
	e.stats.conns.CloseAll()
	for _, g := range groups {
		g.stop()
	}
	for _, ob := range e.outbounds {
		_ = ob.Close()
	}

	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if e.resolver != nil {
		_ = e.resolver.Close()
	}
	e.log.Infof("engine stopped")
	return nil
}

// AttachTun starts the tunnel on an already-created file descriptor.
func (e *Engine) AttachTun(fd, mtu int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.running {
		return errors.New("engine is not running")
	}
	if e.tun != nil {
		return errors.New("tun already attached")
	}
	if mtu <= 0 {
		mtu = e.cfg.Tun.MTU
	}
	if mtu <= 0 {
		mtu = 1400
	}
	st, err := netstack.Start(fd, mtu, e, e.log)
	if err != nil {
		return err
	}
	e.tun = st
	e.tunFD = fd
	e.tunMTU = mtu
	e.log.Infof("tun attached (fd %d, mtu %d)", fd, mtu)
	return nil
}

// DetachTun closes the tunnel but keeps the engine running.
func (e *Engine) DetachTun() error {
	e.mu.Lock()
	tun := e.tun
	e.tun = nil
	e.tunFD = -1
	e.mu.Unlock()
	if tun != nil {
		return tun.Close()
	}
	return nil
}

// Running reports whether Start succeeded and Stop has not run.
func (e *Engine) Running() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running
}

// Status renders the engine-owned part of the UI status.
func (e *Engine) Status() state.Status {
	e.mu.RLock()
	defer e.mu.RUnlock()
	st := state.Status{
		Mode:    e.cfg.Mode,
		Traffic: e.stats.Snapshot(),
		Health:  state.Health{},
	}
	if e.resolver != nil {
		st.DNS = state.DNSStatus{Enabled: true, Listen: e.cfg.DNS.Listen}
	}
	if e.mixed != nil {
		st.Inbounds = append(st.Inbounds, state.InboundStatus{
			Name: "mixed",
			Addr: e.mixed.Addr(),
			Up:   true,
		})
	}
	st.Tun = state.TunStatus{Enabled: e.tun != nil, FD: e.tunFD, MTU: e.tunMTU, Up: e.tun != nil}
	if e.running {
		st.UptimeSec = int64(time.Since(e.startedAt).Seconds())
	}
	return st
}

// Groups renders the policy groups.
func (e *Engine) Groups() []state.GroupStatus {
	e.mu.RLock()
	groups := append([]*Group(nil), e.groups...)
	e.mu.RUnlock()
	out := make([]state.GroupStatus, 0, len(groups))
	for _, g := range groups {
		out = append(out, g.status())
	}
	return out
}

// Select pins a group to a member.
func (e *Engine) Select(groupTag, memberTag string) error {
	e.mu.RLock()
	g, ok := e.outbounds[groupTag].(*Group)
	e.mu.RUnlock()
	if !ok {
		return fmt.Errorf("group %q not found", groupTag)
	}
	return g.selectTag(memberTag)
}

// SetMode switches between rule/global/direct.
func (e *Engine) SetMode(mode string) error {
	switch mode {
	case config.ModeRule, config.ModeGlobal, config.ModeDirect:
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
	e.mu.Lock()
	e.cfg.Mode = mode
	e.mu.Unlock()
	// Rebuild the matcher with the new mode; it is cheap and immutable, which
	// keeps the hot path lock-free.
	router, err := rules.New(e.cfg.Rules, mode, e.defaultTag)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.router = router
	e.mu.Unlock()
	return nil
}

// SetDefault picks the outbound used in global mode and as fallback.
func (e *Engine) SetDefault(tag string) error {
	ob := e.resolveTag(tag)
	if ob == nil {
		return fmt.Errorf("outbound %q not found", tag)
	}
	e.mu.Lock()
	e.defaultOB, e.defaultTag = ob, tag
	e.mu.Unlock()
	return nil
}

// Conns lists live connections.
func (e *Engine) Conns() []state.Conn { return e.stats.conns.List() }

// CloseConn closes one connection by id.
func (e *Engine) CloseConn(id uint64) bool {
	c := e.stats.conns.Get(id)
	if c == nil {
		return false
	}
	_ = c.Close()
	return true
}

// CloseAllConns closes every live connection.
func (e *Engine) CloseAllConns() { e.stats.conns.CloseAll() }

// LastError reports the most recent non-fatal failure.
func (e *Engine) LastError() string {
	e.lastErrMu.RLock()
	defer e.lastErrMu.RUnlock()
	return e.lastErr
}

func (e *Engine) setLastErr(s string) {
	e.lastErrMu.Lock()
	e.lastErr = s
	e.lastErrMu.Unlock()
}

// dnsDial builds the dialer the resolver uses: proxy detours go through the
// matching outbound, everything else is direct.
func (e *Engine) dnsDial(ctx context.Context, network, address string) (net.Conn, error) {
	e.mu.RLock()
	ob := e.defaultOB
	e.mu.RUnlock()
	if ob == nil {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	return ob.DialContext(ctx, network, address)
}

// parseTarget splits host:port and classifies the host.
func parseTarget(target string) (host string, port uint16, ip netip.Addr, err error) {
	h, p, err := net.SplitHostPort(target)
	if err != nil {
		// Some inbound paths hand us a bare host; default to 443.
		h, p = target, "443"
	}
	if ip, err = netip.ParseAddr(h); err != nil {
		host = h
	} else {
		host = ""
	}
	pp, err := net.LookupPort("tcp", p)
	if err != nil || pp < 0 || pp > 65535 {
		if pp2, e2 := parsePort(p); e2 == nil {
			pp = int(pp2)
		} else {
			return "", 0, netip.Addr{}, fmt.Errorf("invalid port %q", p)
		}
	}
	return host, uint16(pp), ip, nil
}

func parsePort(s string) (uint16, error) {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, err
	}
	if n < 0 || n > 65535 {
		return 0, fmt.Errorf("port out of range: %d", n)
	}
	return uint16(n), nil
}

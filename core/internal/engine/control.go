package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"veil/internal/config"
	"veil/internal/dns"
	"veil/internal/outbound"
	"veil/internal/rules"
)

// Reload swaps outbounds, groups, rules and DNS in place, leaving the listener
// and the tun untouched. Live connections keep working: retired outbounds are
// closed only after a grace period.
func (e *Engine) Reload(cfg config.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	e.mu.Lock()
	if !e.running {
		e.cfg = cfg
		e.mu.Unlock()
		return nil
	}
	e.mu.Unlock()

	// Build the replacement set outside the lock.
	obs := make(map[string]outbound.Outbound, len(cfg.Nodes)+len(cfg.Groups)+2)
	obs["direct"] = factoryDirect
	obs["reject"] = factoryReject
	nodes := make(map[string]config.Node, len(cfg.Nodes))
	var buildErrs []string
	for _, n := range cfg.Nodes {
		nodes[n.Tag] = n
		ob, err := e.buildOutbound(n)
		if err != nil {
			buildErrs = append(buildErrs, fmt.Sprintf("%s: %v", n.Tag, err))
			continue
		}
		obs[n.Tag] = ob
	}
	var groups []*Group
	for _, g := range cfg.Groups {
		grp, err := newGroup(g, obs, nodes, e.log)
		if err != nil {
			buildErrs = append(buildErrs, fmt.Sprintf("group %s: %v", g.Tag, err))
			continue
		}
		obs[g.Tag] = grp
		groups = append(groups, grp)
	}

	final := ""
	for i := len(cfg.Rules) - 1; i >= 0; i-- {
		if cfg.Rules[i].Type == "final" {
			final = cfg.Rules[i].Action
			break
		}
	}
	var def outbound.Outbound
	var defTag string
	if final != "" {
		def, defTag = obs[final], final
	}
	if def == nil {
		for _, g := range groups {
			if g.cfg.Type == "select" {
				def, defTag = g, g.cfg.Tag
				break
			}
		}
	}
	if def == nil && len(cfg.Nodes) > 0 {
		for _, n := range cfg.Nodes {
			if ob := obs[n.Tag]; ob != nil {
				def, defTag = ob, n.Tag
				break
			}
		}
	}
	if def == nil {
		def, defTag = factoryDirect, "direct"
	}

	router, err := rules.New(cfg.Rules, cfg.Mode, defTag)
	if err != nil {
		closeAll(obs)
		return fmt.Errorf("rules: %w", err)
	}

	var resolver *dns.Resolver
	if cfg.DNS.Enable {
		r, err := dns.New(cfg.DNS, e.log)
		if err != nil {
			closeAll(obs)
			return fmt.Errorf("dns: %w", err)
		}
		r.SetDial(e.dnsDial)
		resolver = r
	}

	// Swap.
	e.mu.Lock()
	old := e.outbounds
	oldGroups := e.groups
	oldResolver := e.resolver
	oldRouter := e.router
	needsIP := rules.NeedsIP(cfg.Rules)
	e.cfg = cfg
	e.outbounds = obs
	e.nodes = nodes
	e.groups = groups
	e.router = router
	e.resolver = resolver
	e.defaultOB = def
	e.defaultTag = defTag
	e.needsIP = needsIP
	e.mu.Unlock()

	for _, g := range oldGroups {
		g.stop()
	}
	if oldResolver != nil {
		_ = oldResolver.Close()
	}
	_ = oldRouter
	// Give live connections a grace period on the old clients, then close the
	// ones that are no longer referenced.
	// A client rebuilt under the same tag is retired too, not just one whose tag
	// disappeared: the old WireGuard device keeps its peer socket and the old
	// QUIC connection keeps its keepalive, so leaving them alive would have the
	// two fight over the same endpoint and wake the device for nothing.
	retired := make(map[string]outbound.Outbound)
	for tag, ob := range old {
		if cur, keep := obs[tag]; keep && cur != ob {
			retired[tag] = ob
			continue
		}
		if _, keep := obs[tag]; !keep {
			retired[tag] = ob
		}
	}
	if len(retired) > 0 {
		time.AfterFunc(2*time.Minute, func() { closeAll(retired) })
	}
	if len(buildErrs) > 0 {
		e.setLastErr("reload: " + fmt.Sprint(buildErrs))
		e.log.Warnf("reload kept %d broken outbound(s): %v", len(buildErrs), buildErrs)
	}
	return nil
}

func closeAll(m map[string]outbound.Outbound) {
	seen := make(map[outbound.Outbound]bool)
	for _, ob := range m {
		if ob == nil || seen[ob] {
			continue
		}
		seen[ob] = true
		_ = ob.Close()
	}
}

// ProbeInbound verifies the mixed listener really accepts connections. It is
// the health signal the watchdog uses instead of trusting a stale bool.
func (e *Engine) ProbeInbound() error {
	e.mu.RLock()
	srv := e.mixed
	e.mu.RUnlock()
	if srv == nil {
		return nil
	}
	addr := srv.Addr()
	if addr == "" {
		return errors.New("no bound address")
	}
	d := net.Dialer{Timeout: 1500 * time.Millisecond}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	defer conn.Close()
	// Speak SOCKS5 instead of connecting and hanging up: the old probe produced
	// a "sniff first byte: EOF" line every 10s and told us nothing about whether
	// the listener could actually serve a request.
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("listen %s: write greeting: %w", addr, err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("listen %s: no socks reply: %w", addr, err)
	}
	if reply[0] != 0x05 {
		return fmt.Errorf("listen %s: not socks5 (got %#x)", addr, reply[0])
	}
	return nil
}

// TunUp reports whether the tunnel is attached.
func (e *Engine) TunUp() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.tun != nil
}

// OutboundCount reports how many configured outbounds were built successfully.
// A running engine with total > 0 and ok == 0 cannot route anything, and the
// supervisor must say so instead of showing a green switch.
func (e *Engine) OutboundCount() (ok, total int) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	total = len(e.cfg.Nodes)
	for _, n := range e.cfg.Nodes {
		if ob, found := e.outbounds[n.Tag]; found && ob != nil {
			ok++
		}
	}
	return ok, total
}

// ProbeTag measures latency to a node by tag.
func (e *Engine) ProbeTag(tag string) (int, error) {
	e.mu.RLock()
	ob, ok := e.outbounds[tag]
	ctx := e.ctx
	e.mu.RUnlock()
	if !ok {
		return -1, fmt.Errorf("outbound %q not found", tag)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return probeHTTP(ctx, ob, defaultProbeURL, 6*time.Second)
}

// ProbeAll measures every node concurrently, capped at four at a time.
func (e *Engine) ProbeAll() map[string]int {
	e.mu.RLock()
	obs := make(map[string]outbound.Outbound, len(e.outbounds))
	for tag, ob := range e.outbounds {
		if _, isGroup := ob.(*Group); !isGroup {
			obs[tag] = ob
		}
	}
	ctx := e.ctx
	e.mu.RUnlock()
	if ctx == nil {
		ctx = context.Background()
	}
	out := make(map[string]int, len(obs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for tag, ob := range obs {
		wg.Add(1)
		go func(tag string, ob outbound.Outbound) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ms, err := probeHTTP(ctx, ob, defaultProbeURL, 6*time.Second)
			mu.Lock()
			if err != nil {
				out[tag] = -1
			} else {
				out[tag] = ms
			}
			mu.Unlock()
		}(tag, ob)
	}
	wg.Wait()
	return out
}

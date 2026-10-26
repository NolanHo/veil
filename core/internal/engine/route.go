package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"veil/internal/outbound"
	"veil/internal/rules"
)

// route decides which outbound carries a connection and records why.
func (e *Engine) route(ctx context.Context, network, target string) (outbound.Outbound, rules.Action, string, error) {
	host, port, ip, err := parseTarget(target)
	if err != nil {
		return nil, rules.Action{}, target, err
	}
	// A fake address stands for a domain: hand the name to the proxy so the
	// lookup happens at the exit node (remote DNS), never on this device.
	fromFake := false
	if host == "" && ip.IsValid() && e.resolver != nil && e.resolver.IsFake(ip) {
		if name, ok := e.resolver.HostFor(ip); ok {
			host = name
			ip = netip.Addr{}
			target = net.JoinHostPort(name, fmt.Sprint(port))
			fromFake = true
		}
	}

	meta := rules.Meta{Network: network, Host: host, Dst: ip, Port: port}

	// The matcher and the "does any IP rule exist" flag are replaced by SetMode
	// and Reload. Publish them under the lock: the matcher object is immutable,
	// but the pointer itself is not safe to read concurrently with a write.
	e.mu.RLock()
	router, needsIP, resolver := e.router, e.needsIP, e.resolver
	e.mu.RUnlock()

	// IP-based rules (geoip / CIDR) need an address. Resolve once, with a
	// short budget, and keep the domain for the outbound dial so the remote
	// side still sees the hostname.
	// A fake address has no real IP by design: resolving it locally would leak
	// the name and stall for seconds. The proxy resolves it.
	if needsIP && host != "" && resolver != nil && !fromFake {
		rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		addrs, err := resolver.Lookup(rctx, host)
		cancel()
		if err != nil {
			e.log.Debugf("resolve %s for routing failed: %v", host, err)
		} else if len(addrs) > 0 {
			meta.Dst = addrs[0]
		}
	}

	action := router.Match(meta)
	if action.Reject {
		return nil, action, target, outbound.ErrRejected
	}
	ob := e.resolveTag(action.Outbound)
	if ob == nil {
		e.log.Warnf("rule %q wants unknown outbound %q, using default", action.Rule, action.Outbound)
		e.mu.RLock()
		ob = e.defaultOB
		e.mu.RUnlock()
	}
	if ob == nil {
		ob = e.outbounds["direct"]
	}
	if ob == nil {
		return nil, action, target, fmt.Errorf("no outbound available")
	}
	return ob, action, target, nil
}

// resolveTarget resolves a domain to a single address for protocols that need
// an IP (UDP association), falling back to the name itself.
func (e *Engine) resolveTarget(ctx context.Context, host string) (netip.AddrPort, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip, 0), nil
	}
	if e.resolver == nil {
		return netip.AddrPort{}, fmt.Errorf("no resolver for %q", host)
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := e.resolver.Lookup(ctx, host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, fmt.Errorf("no address for %q", host)
	}
	return netip.AddrPortFrom(addrs[0], 0), nil
}

// dialOutbound opens the stream, honouring both the caller's context and a
// hard connect budget.
func dialOutbound(ctx context.Context, ob outbound.Outbound, network, target string) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := ob.DialContext(dctx, network, target)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", ob.Tag(), target, err)
	}
	return conn, nil
}

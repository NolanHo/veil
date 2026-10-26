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
	// The matcher, the resolver and the "does any IP rule exist" flag are
	// replaced by SetMode and Reload. Snapshot them under the lock: the matcher
	// object is immutable, but the pointers are not safe to read concurrently
	// with a write.
	e.mu.RLock()
	router, needsIP, resolver := e.router, e.needsIP, e.resolver
	e.mu.RUnlock()

	// A fake address stands for a domain. Recover the name so domain rules can
	// see it and so the outbound dials by hostname.
	fromFake := false
	if host == "" && ip.IsValid() && resolver != nil && resolver.IsFake(ip) {
		if name, ok := resolver.HostFor(ip); ok {
			host = name
			ip = netip.Addr{}
			target = net.JoinHostPort(name, fmt.Sprint(port))
			fromFake = true
		}
	}

	meta := rules.Meta{Network: network, Host: host, Dst: ip, Port: port}

	// IP-based rules (geoip / CIDR) need an address, and a fake address is not
	// one: it only carries the name the client asked for. Leaving it unresolved
	// made every IP rule dead for fake-IP flows, so domestic sites that a Clash
	// config routes with `GEOIP,CN,DIRECT` fell through to MATCH and went out
	// through the proxy. Resolve the name, hand the address to the matcher, and
	// keep the hostname in `target` — the exit node still performs the
	// authoritative lookup, this one only classifies the connection.
	//
	// Rules marked `no-resolve` are deliberately excluded from "needsIP" and do
	// not accept this address (see rules.Meta.DstFromLookup); resolving for them
	// would be the very leak the flag asks us to avoid.
	if needsIP && host != "" && resolver != nil {
		addrs, err := e.lookupForRoute(ctx, resolver, host)
		if err != nil {
			// No address is a normal outcome: NXDOMAIN, a blocked upstream, or a
			// fake-IP name that does not exist on the wire. IP rules then see an
			// unresolved target and the remaining rules still get their chance.
			e.log.Debugf("resolve %s for routing failed: %v", host, err)
		} else if len(addrs) > 0 {
			meta.Dst = addrs[0]
			meta.DstFromLookup = true
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
	// A fake address only exists inside our own DNS: any outbound that dials
	// locally would hand it to the system resolver, get a fake answer back and
	// connect to nothing (on device that shows up as "connected, this site does
	// not load"). Dial the address the routing lookup produced instead. Proxied
	// outbounds keep the name so the exit node stays the authority for DNS.
	if fromFake && meta.Dst.IsValid() && ob.Tag() == "direct" {
		target = netip.AddrPortFrom(meta.Dst.Unmap(), port).String()
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

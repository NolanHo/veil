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
	// The matcher and the resolver are replaced by SetMode and Reload. Snapshot
	// them under the lock: the matcher object is immutable, but the pointers are
	// not safe to read concurrently with a write.
	e.mu.RLock()
	router, resolver := e.router, e.resolver
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
		} else {
			// Inside the fake range but nobody knows which name it stands for:
			// the mapping died with an old resolver, or the app cached the
			// address across a reload. Dialing it would connect to a
			// benchmarking address and hang until the deadline.
			return nil, rules.Action{}, target, fmt.Errorf(
				"%s is a fake-IP address with no known domain; retry after a DNS lookup", target)
		}
	}

	meta := rules.Meta{Network: network, Host: host, Dst: ip, Port: port}

	// IP-based rules (geoip / CIDR) need an address, and a fake address is not
	// one: it only carries the name the client asked for. Leaving it unresolved
	// made every IP rule dead for fake-IP flows, so domestic sites that a Clash
	// config routes with `GEOIP,CN,DIRECT` fell through to MATCH and went out
	// through the proxy. The matcher gets a lookup callback and performs it when
	// its walk reaches such a rule — not before — and `target` keeps the
	// hostname: the exit node still performs the authoritative lookup, this one
	// only classifies the connection.
	//
	// Lazy on purpose, the way Clash and mihomo behave. Resolving up front as
	// soon as the table contained any IP rule cost every new name a DNS round
	// trip even when a domain rule matched first, and under fake-IP that was the
	// common case.
	//
	// Rules marked `no-resolve` never ask for the lookup and do not accept its
	// answer (see rules.Meta.DstFromLookup); resolving for them would be the
	// very leak the flag asks us to avoid.
	var lookedUp netip.Addr
	var resolve rules.Resolver
	if host != "" && resolver != nil {
		resolve = func() (netip.Addr, error) {
			// One lookup per decision even if the matcher ever asked twice.
			if lookedUp.IsValid() {
				return lookedUp, nil
			}
			addrs, err := e.lookupForRoute(ctx, resolver, host)
			if err != nil {
				// No address is a normal outcome: NXDOMAIN, a blocked upstream, or a
				// fake-IP name that does not exist on the wire. IP rules then see an
				// unresolved target and the remaining rules still get their chance.
				e.log.Debugf("resolve %s for routing failed: %v", host, err)
				return netip.Addr{}, err
			}
			if len(addrs) == 0 {
				return netip.Addr{}, nil
			}
			lookedUp = addrs[0]
			return lookedUp, nil
		}
	}

	action := router.MatchWithResolver(meta, resolve)
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
	dialsLocally := false
	if ld, ok := ob.(outbound.LocalDialer); ok {
		dialsLocally = ld.DialsLocally()
	}
	if fromFake && dialsLocally {
		// The walk may not have needed an address: a domain rule can decide the
		// connection before the table reaches an IP rule, and MODE DIRECT ignores
		// the table altogether. A local dial has no such choice — it cannot dial
		// a name that only exists inside our DNS — so the lookup happens here,
		// once, and only for flows that actually go out directly.
		if !lookedUp.IsValid() && resolve != nil {
			_, _ = resolve()
		}
		if lookedUp.IsValid() {
			target = netip.AddrPortFrom(lookedUp.Unmap(), port).String()
		}
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

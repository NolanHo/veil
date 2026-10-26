// Package factory builds outbound protocol clients from configuration.
package factory

import (
	"context"
	"fmt"
	"net"
	"strings"

	"veil/internal/config"
	"veil/internal/outbound"
	"veil/internal/proxy/hysteria2"
	"veil/internal/proxy/socks5"
	"veil/internal/proxy/ss"
	"veil/internal/proxy/trojan"
	"veil/internal/proxy/vless"
	"veil/internal/proxy/vmess"
	"veil/internal/proxy/wireguard"
	"veil/internal/transport"
)

// Direct is the built-in direct outbound.
type Direct struct{}

// Tag implements outbound.Outbound.
func (Direct) Tag() string { return "direct" }

// Type implements outbound.Outbound.
func (Direct) Type() string { return "direct" }

// DialContext implements outbound.Outbound.
//
// The dialer must be the protect-aware one: a plain net.Dialer sends packets
// back into the tun we own, and the engine then forwards them to itself —
// an endless loop that looks like "VPN connected, nothing loads".
func (Direct) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return transport.NewDialer().DialContext(ctx, network, address)
}

// Close implements outbound.Outbound.
func (Direct) Close() error { return nil }

// DialsLocally implements outbound.LocalDialer: direct resolves the name here.
func (Direct) DialsLocally() bool { return true }

// Reject drops every connection.
type Reject struct{}

// Tag implements outbound.Outbound.
func (Reject) Tag() string { return "reject" }

// Type implements outbound.Outbound.
func (Reject) Type() string { return "reject" }

// DialContext implements outbound.Outbound.
func (Reject) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, outbound.ErrRejected
}

// Close implements outbound.Outbound.
func (Reject) Close() error { return nil }

// New constructs the client for node n.
//
// A node that declares a chain cannot be built alone: its `dialer-proxy` names
// another outbound, which is built (or selected) as part of the whole
// configuration. Such a node is refused here rather than dialled directly —
// a direct dial is exactly the failure a chain exists to prevent. Build is the
// entry point that can honour a chain.
func New(n config.Node) (outbound.Outbound, error) {
	if n.DialerProxy != "" {
		return nil, fmt.Errorf(
			"node %q: dialer-proxy %q needs the whole configuration, not one node", n.Tag, n.DialerProxy)
	}
	return buildOne(n, nil)
}

// buildOne constructs the client for n. base opens every connection to the
// node's server; nil means a direct, protect-aware dial.
//
// Only the TCP-based transports take a base: hysteria2 (QUIC over UDP) and
// WireGuard (its own raw sockets) have no TCP connection to hand over.
func buildOne(n config.Node, base transport.Dialer) (outbound.Outbound, error) {
	switch n.Type {
	case "vless":
		return vless.NewVia(n, base)
	case "vmess":
		return vmess.NewVia(n, base)
	case "trojan":
		return trojan.NewVia(n, base)
	case "ss":
		return ss.NewVia(n, base)
	case "socks5", "socks":
		return socks5.NewVia(n, base)
	case "hysteria2", "hy2":
		return hysteria2.New(n)
	case "wireguard", "wg":
		return wireguard.New(n)
	case "direct":
		return Direct{}, nil
	case "reject":
		return Reject{}, nil
	default:
		return nil, fmt.Errorf("unsupported outbound type %q", n.Type)
	}
}

// Lookup resolves an outbound tag at the moment a connection is made. A chain
// whose target is a group asks it on every dial, which is what makes a selection
// change apply to the next connection without rebuilding anything. It returns
// nil for a tag it does not know.
type Lookup func(tag string) outbound.Outbound

// Build constructs the clients for cfg.Nodes, honouring `dialer-proxy` chains:
//
//	TCP (through the chained outbound) -> TLS/REALITY -> (tcp | ws | grpc)
//
// A node is built after the node its chain names, and the connection to its own
// server is opened by that node's DialContext, so the peer sees the handshake
// arriving from the chain's exit rather than from this device. A chain that
// names a group is resolved through lookup on every dial, because a group picks
// its member per connection.
//
// A node is skipped — reported, never dialled directly — when its chain loops
// back to it, names a tag this configuration does not have, names a node that
// failed to build, or when that node's transport cannot be chained at all:
// hysteria2 is QUIC and WireGuard builds its own sockets, so neither has a TCP
// connection to hand over.
//
// The result holds the nodes that built plus the built-in direct and reject (a
// chain may name them). Each error is "tag: cause" for one skipped node, so a
// broken chain costs that node and not the profile.
//
// lookup may be nil: chains then resolve only the outbounds this call built,
// which is enough when every chain names a node.
func Build(cfg config.Config, lookup Lookup) (map[string]outbound.Outbound, []error) {
	nodes := make(map[string]config.Node, len(cfg.Nodes))
	groups := make(map[string]config.Group, len(cfg.Groups))
	for _, g := range cfg.Groups {
		groups[g.Tag] = g
	}
	for _, n := range cfg.Nodes {
		nodes[n.Tag] = n
	}

	var errs []error
	skip := make(map[string]bool, len(cfg.Nodes))

	// A chain that comes back to the node would hand the connection to the next
	// link forever and never open a socket. Report every node on the loop; the
	// rest of the profile still builds.
	for _, n := range cfg.Nodes {
		if n.DialerProxy == "" {
			continue
		}
		if path := chainCycle(n.Tag, nodes, groups); path != nil {
			skip[n.Tag] = true
			errs = append(errs, fmt.Errorf(
				"%s: dialer-proxy chain loops back to this node: %s", n.Tag, strings.Join(path, " -> ")))
		}
	}

	built := make(map[string]outbound.Outbound, len(nodes)+2)
	built["direct"] = Direct{}
	built["reject"] = Reject{}

	for _, tag := range buildOrder(cfg.Nodes, nodes, groups, skip) {
		n := nodes[tag]
		base, err := chainBase(n, built, nodes, groups, lookup)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", tag, err))
			continue
		}
		ob, err := buildOne(n, base)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", tag, err))
			continue
		}
		built[tag] = ob
	}
	return built, errs
}

// buildOrder lists the node tags so that a chain's target is built first. A node
// whose chain is already known to be unusable is left out: it is reported by the
// caller and must not be dialled at all.
func buildOrder(list []config.Node, nodes map[string]config.Node, groups map[string]config.Group, skip map[string]bool) []string {
	order := make([]string, 0, len(list))
	state := make(map[string]uint8, len(list)) // 0 unseen, 1 in progress, 2 emitted
	var visit func(tag string)
	visit = func(tag string) {
		switch state[tag] {
		case 1, 2:
			return
		}
		state[tag] = 1
		if n, ok := nodes[tag]; ok && n.DialerProxy != "" {
			if _, isGroup := groups[n.DialerProxy]; !isGroup {
				if _, isNode := nodes[n.DialerProxy]; isNode {
					visit(n.DialerProxy)
				}
			}
		}
		state[tag] = 2
		if !skip[tag] {
			order = append(order, tag)
		}
	}
	for _, n := range list {
		visit(n.Tag)
	}
	return order
}

// chainBase returns the dialer that opens n's connection to its own server.
//
// A chain naming a node binds that node's outbound here, at build time: it has
// already been built (see buildOrder), and a reload rebuilds the chained node
// together with its target, so the binding never outlives the client. A chain
// naming a group binds nothing: the group is chosen per connection, so the
// dialer asks lookup each time and follows a selection change.
func chainBase(n config.Node, built map[string]outbound.Outbound, nodes map[string]config.Node, groups map[string]config.Group, lookup Lookup) (transport.Dialer, error) {
	target := n.DialerProxy
	if target == "" {
		return nil, nil
	}
	switch n.Type {
	case "hysteria2", "hy2", "wireguard", "wg":
		return nil, fmt.Errorf(
			"dialer-proxy %q is not supported for %s: its transport is not TCP", target, n.Type)
	}
	addr := n.Addr()
	if _, isGroup := groups[target]; isGroup {
		return transport.DialerFunc(func(ctx context.Context) (net.Conn, error) {
			var ob outbound.Outbound
			if lookup != nil {
				ob = lookup(target)
			}
			if ob == nil {
				return nil, fmt.Errorf("dialer-proxy %q: the group is not built", target)
			}
			// The group's current member carries this connection: the chain exits
			// through whatever the group has selected right now.
			return ob.DialContext(ctx, "tcp", addr)
		}), nil
	}
	if ob, ok := built[target]; ok {
		return transport.DialerFunc(func(ctx context.Context) (net.Conn, error) {
			return ob.DialContext(ctx, "tcp", addr)
		}), nil
	}
	if _, isNode := nodes[target]; isNode {
		return nil, fmt.Errorf("dialer-proxy %q was not built: its own configuration is invalid", target)
	}
	return nil, fmt.Errorf("dialer-proxy %q is not in this configuration", target)
}

// chainRefs returns the tags one outbound's dial passes through: a node's chain
// target, or every member a group could select.
func chainRefs(tag string, nodes map[string]config.Node, groups map[string]config.Group) []string {
	if n, ok := nodes[tag]; ok {
		if n.DialerProxy != "" {
			return []string{n.DialerProxy}
		}
		return nil
	}
	if g, ok := groups[tag]; ok {
		return g.Members
	}
	return nil
}

// chainCycle returns the path along which tag's chain comes back to tag, or nil.
//
// Groups are followed through every member on purpose: a selector can pick any
// of them for any connection, and one connection is all it takes to spin.
func chainCycle(tag string, nodes map[string]config.Node, groups map[string]config.Group) []string {
	var walk func(cur string, path []string, seen map[string]bool) []string
	walk = func(cur string, path []string, seen map[string]bool) []string {
		for _, ref := range chainRefs(cur, nodes, groups) {
			next := append(append([]string(nil), path...), ref)
			if ref == tag {
				return next
			}
			if seen[ref] {
				continue
			}
			seen[ref] = true
			if p := walk(ref, next, seen); p != nil {
				return p
			}
		}
		return nil
	}
	return walk(tag, []string{tag}, map[string]bool{tag: true})
}

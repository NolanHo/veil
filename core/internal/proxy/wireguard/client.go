// Package wireguard implements the WireGuard outbound.
//
// The tunnel terminates in a userspace TCP/IP stack (tun/netstack) instead of an
// OS tun device: inside the HarmonyOS vpnExtension there is exactly one tun and
// it belongs to the extension, so a second one would be both impossible to
// create and unnecessary — flows dialed here are already past the tun.
//
// The one socket this outbound does need is the UDP socket to the peer; it is
// created through transport's protect hook, see bind.go. Names are resolved by
// the host over that same protected path unless the node configures an in-tunnel
// resolver — see tunnelAddr for which and why.
package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"veil/internal/config"
	"veil/internal/outbound"
	"veil/internal/transport"
)

const (
	// defaultMTU matches wg-quick's default. The tunnel MTU is independent of
	// the tun MTU the engine configures, which is smaller so the outer
	// WireGuard packet still fits.
	defaultMTU = 1420

	// dialTimeout bounds a bring-up plus the WireGuard handshake. An empty
	// tunnel would otherwise block a dial until TCP gives up minutes later.
	dialTimeout = 10 * time.Second
)

// errClosed is returned once Close has been called.
var errClosed = errors.New("wireguard: client closed")

// resolverDial opens the connection a DNS query travels over.
//
// A resolver builds its own sockets, so transport.NewDialer's Control hook never
// runs for them; net.Resolver.Dial is the only place to put them back on the
// protected dialer. Variable rather than a literal so a test can aim the resolver
// at a loopback DNS server while keeping the production dial underneath.
var resolverDial = func(ctx context.Context, network, address string) (net.Conn, error) {
	return transport.NewDialer().DialContext(ctx, network, address)
}

// newEndpointResolver returns the resolver used for peer host names. PreferGo
// keeps the Resolver.Dial hook in effect on every platform; the system resolver
// would answer on sockets this process never sees.
func newEndpointResolver() *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: resolverDial}
}

// Client is one WireGuard peer. The device is created on the first dial and
// shared by every stream, like the hysteria2 client's lazily dialed connection.
type Client struct {
	tag string

	endpoint   string // host:port of the peer, as configured
	privKey    string // hex, the spelling the UAPI wants
	peerKey    string
	psk        string
	addresses  []netip.Addr
	dns        []netip.Addr // in-tunnel resolvers; empty = resolve on the host
	allowedIPs []netip.Prefix
	mtu        int
	keepAlive  int

	mu       sync.Mutex
	dial     chan struct{} // one bring-up at a time; a queued dial also watches its ctx
	resolver *net.Resolver
	dev      *device.Device
	stack    *netstack.Net
	closed   bool
	closedCh chan struct{} // closed by Close; wakes a queued dial and stops a bring-up
}

var (
	_ outbound.Outbound       = (*Client)(nil)
	_ outbound.PacketOutbound = (*Client)(nil)
)

// New builds a WireGuard client for n.
func New(n config.Node) (*Client, error) {
	priv, err := decodeKey(n.Tag, "private_key", n.PrivateKey)
	if err != nil {
		return nil, err
	}
	peer, err := decodeKey(n.Tag, "public_key", n.PeerPublicKey)
	if err != nil {
		return nil, err
	}
	var psk string
	if n.PresharedKey != "" {
		if psk, err = decodeKey(n.Tag, "preshared_key", n.PresharedKey); err != nil {
			return nil, err
		}
	}
	addresses, err := parseAddrs(n.Tag, "addresses", n.Addresses)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("wireguard %s: missing addresses", n.Tag)
	}
	dns, err := parseAddrs(n.Tag, "dns", n.DNS)
	if err != nil {
		return nil, err
	}
	allowed, err := parsePrefixes(n.Tag, "allowed_ips", n.AllowedIPs)
	if err != nil {
		return nil, err
	}
	mtu := n.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}
	return &Client{
		tag:        n.Tag,
		endpoint:   n.Addr(),
		privKey:    priv,
		peerKey:    peer,
		psk:        psk,
		addresses:  addresses,
		dns:        dns,
		allowedIPs: allowed,
		mtu:        mtu,
		keepAlive:  n.KeepAlive,
		resolver:   newEndpointResolver(),
		dial:       make(chan struct{}, 1),
		closedCh:   make(chan struct{}),
	}, nil
}

// Tag implements outbound.Outbound.
func (c *Client) Tag() string { return c.tag }

// Type implements outbound.Outbound.
func (c *Client) Type() string { return "wireguard" }

// Close tears the device down; the engine calls it on stop and on reload.
//
// A bring-up publishes its device as soon as the device object exists (see
// start), so this closes either the running device or one that is still being
// configured. Returning while a local device is alive would leak its peer socket
// and leave a stack that nobody owns any more.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.closedCh)
	dev := c.dev
	c.dev, c.stack = nil, nil
	c.mu.Unlock()
	if dev != nil {
		dev.Close()
	}
	return nil
}

// DialContext opens a stream to address through the tunnel.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "", "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("wireguard %s: unsupported network %q", c.tag, network)
	}
	ctx, cancel, err := c.withTimeout(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	ns, err := c.getStack(ctx)
	if err != nil {
		return nil, err
	}
	ap, err := c.tunnelAddr(ctx, ns, address)
	if err != nil {
		return nil, err
	}
	conn, err := ns.DialContextTCPAddrPort(ctx, ap)
	if err != nil {
		return nil, fmt.Errorf("wireguard %s: dial %s: %w", c.tag, ap, err)
	}
	return conn, nil
}

// DialPacket opens a UDP association to address through the tunnel.
//
// The socket is connected to the target: the engine keys one association per
// (outbound, target) pair, and gVisor then filters replies to that peer, which
// is what a WireGuard peer is willing to carry anyway.
func (c *Client) DialPacket(ctx context.Context, address string) (outbound.PacketConn, error) {
	if address == "" {
		return nil, fmt.Errorf("wireguard %s: udp dial needs a target", c.tag)
	}
	ctx, cancel, err := c.withTimeout(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	ns, err := c.getStack(ctx)
	if err != nil {
		return nil, err
	}
	raddr, err := c.tunnelAddr(ctx, ns, address)
	if err != nil {
		return nil, err
	}
	conn, err := ns.DialUDPAddrPort(netip.AddrPort{}, raddr)
	if err != nil {
		return nil, fmt.Errorf("wireguard %s: udp %s: %w", c.tag, raddr, err)
	}
	return packetConn{conn}, nil
}

// getStack returns the running userspace stack, creating it on first use.
func (c *Client) getStack(ctx context.Context) (*netstack.Net, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errClosed
	}
	if c.stack != nil {
		ns := c.stack
		c.mu.Unlock()
		return ns, nil
	}
	c.mu.Unlock()

	// Serialise the bring-up so a burst of dials creates one device, not one per
	// dial. The wait still belongs to the caller: the engine gives every dial its
	// own deadline, and a dial queued behind someone else's handshake has to come
	// back when that deadline expires.
	select {
	case c.dial <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closedCh:
		return nil, errClosed
	}
	defer func() { <-c.dial }()

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errClosed
	}
	if c.stack != nil {
		ns := c.stack
		c.mu.Unlock()
		return ns, nil
	}
	c.mu.Unlock()

	ns, err := c.start(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		// Close ran during the bring-up and already closed the device; this stack
		// belongs to a client that no longer exists.
		return nil, errClosed
	}
	c.stack = ns
	return ns, nil
}

// start creates the userspace stack, applies the peer configuration and brings
// the device up.
//
// The device is published to c.dev before it is configured, so a Close that races
// the first dial has a handle to close instead of seeing nil and returning while
// the local device keeps running. Every failure path drops it again.
func (c *Client) start(ctx context.Context) (*netstack.Net, error) {
	ctx, cancel := c.withClose(ctx)
	defer cancel()

	tun, ns, err := netstack.CreateNetTUN(c.addresses, c.dns, c.mtu)
	if err != nil {
		return nil, fmt.Errorf("wireguard %s: create stack: %w", c.tag, err)
	}
	// Errors only: a wrong key or an unreachable peer is silent otherwise, and
	// that is the failure the user is most likely to hit.
	dev := device.NewDevice(tun, newBind(c.tag), device.NewLogger(device.LogLevelError, "wireguard "+c.tag+": "))
	if err := c.adopt(dev); err != nil {
		dev.Close()
		return nil, err
	}
	conf, err := c.uapiConfig(ctx)
	if err != nil {
		c.discard(dev)
		return nil, err
	}
	if err := dev.IpcSet(conf); err != nil {
		c.discard(dev)
		return nil, fmt.Errorf("wireguard %s: apply config: %w", c.tag, err)
	}
	if err := dev.Up(); err != nil {
		c.discard(dev)
		return nil, fmt.Errorf("wireguard %s: bring up: %w", c.tag, err)
	}
	return ns, nil
}

// adopt registers dev as the client's device; it fails once Close has run.
func (c *Client) adopt(dev *device.Device) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errClosed
	}
	c.dev = dev
	return nil
}

// discard forgets dev and tears it down. device.Close is idempotent, so a
// concurrent Close that already closed it is harmless.
func (c *Client) discard(dev *device.Device) {
	c.mu.Lock()
	if c.dev == dev {
		c.dev = nil
	}
	c.mu.Unlock()
	dev.Close()
}

// withClose derives a context that ends when the client is closed: a bring-up
// abandoned by Close must stop at its next checkpoint instead of opening the peer
// socket for a client that is already down.
func (c *Client) withClose(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-c.closedCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// uapiConfig renders the device/peer section wireguard-go's UAPI expects.
//
// The device keys must come first: everything after public_key belongs to the
// peer, so a private_key written later would be rejected as an unknown peer key.
func (c *Client) uapiConfig(ctx context.Context) (string, error) {
	ep, err := c.endpointAddr(ctx)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", c.privKey)
	fmt.Fprintf(&b, "public_key=%s\n", c.peerKey)
	if c.psk != "" {
		fmt.Fprintf(&b, "preshared_key=%s\n", c.psk)
	}
	fmt.Fprintf(&b, "endpoint=%s\n", ep)
	if c.keepAlive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", c.keepAlive)
	}
	for _, p := range c.allowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", p.Masked())
	}
	return b.String(), nil
}

// endpointAddr resolves the configured peer host:port to the literal ip:port the
// UAPI requires (its endpoint parser does not resolve names).
//
// Names go through c.resolver, whose queries travel over resolverDial and are
// therefore protected: a resolver that opens its own sockets bypasses transport's
// protect hook, and on HarmonyOS those queries are captured by the tun we own
// (invariant 1). There is deliberately no fallback — a name this path cannot
// resolve fails here, because every other resolver is exactly the unprotected
// path this exists to avoid.
func (c *Client) endpointAddr(ctx context.Context) (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(c.endpoint)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("wireguard %s: %w", c.tag, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("wireguard %s: bad port %q", c.tag, portStr)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip.Unmap(), uint16(port)), nil
	}
	ips, err := c.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("wireguard %s: resolve %s: %w", c.tag, host, err)
	}
	var fallback netip.Addr
	for _, ip := range ips {
		ip = ip.Unmap()
		// Prefer IPv4: a homelab peer usually publishes both families but the
		// endpoint is reachable over the v4 address the user configured.
		if ip.Is4() {
			return netip.AddrPortFrom(ip, uint16(port)), nil
		}
		if !fallback.IsValid() {
			fallback = ip
		}
	}
	if !fallback.IsValid() {
		return netip.AddrPort{}, fmt.Errorf("wireguard %s: resolve %s: no address", c.tag, host)
	}
	return netip.AddrPortFrom(fallback, uint16(port)), nil
}

// tunnelAddr resolves a dial target and checks that the peer can carry it.
//
// Where the name is resolved depends on whether the node names a resolver, and
// both halves matter:
//
//   - `dns` set: the name is resolved *inside* the tunnel by the userspace stack.
//     That is the split-horizon case — a homelab name only the peer side knows.
//   - `dns` empty: the name is resolved *outside* through the protected dialer and
//     only the resulting IP enters the tunnel. This is WireGuard's normal model (a
//     peer carries IP packets, not names) and it is the shape of the owner's node.
//     The userspace stack has no resolver in this case: asking it anyway fails
//     every name with "cannot marshal DNS message", which is exactly how the
//     outbound died on device.
func (c *Client) tunnelAddr(ctx context.Context, ns *netstack.Net, address string) (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("wireguard %s: %w", c.tag, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("wireguard %s: bad port %q", c.tag, portStr)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return c.routed(netip.AddrPortFrom(ip.Unmap(), uint16(port)))
	}

	var ips []netip.Addr
	if len(c.dns) > 0 {
		addrs, err := ns.LookupContextHost(ctx, host)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("wireguard %s: resolve %s in tunnel: %w", c.tag, host, err)
		}
		for _, a := range addrs {
			if ip, err := netip.ParseAddr(a); err == nil {
				ips = append(ips, ip)
			}
		}
	} else {
		if ips, err = c.resolver.LookupNetIP(ctx, "ip", host); err != nil {
			// Say what to do about it: this node has no in-tunnel resolver, so the
			// host resolver is the only path, and the remedy for a name only the
			// peer side knows is to configure `dns` on the node.
			return netip.AddrPort{}, fmt.Errorf(
				"wireguard %s: resolve %s outside the tunnel: %w (set this node's dns if only the peer side can resolve it)",
				c.tag, host, err)
		}
	}

	// Pick an address the peer can actually carry: a name may answer with both
	// families while allowed_ips covers only one of them. IPv4 wins among the
	// routable ones, because a homelab peer usually publishes both families but is
	// only reachable over the v4 address.
	var (
		firstErr error
		fallback netip.AddrPort
	)
	for _, ip := range ips {
		ap, err := c.routed(netip.AddrPortFrom(ip.Unmap(), uint16(port)))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if ap.Addr().Is4() {
			return ap, nil
		}
		if !fallback.IsValid() {
			fallback = ap
		}
	}
	if fallback.IsValid() {
		return fallback, nil
	}
	if firstErr != nil {
		return netip.AddrPort{}, firstErr
	}
	return netip.AddrPort{}, fmt.Errorf("wireguard %s: resolve %s: no address", c.tag, host)
}

// routed reports whether the peer's allowed_ips can carry traffic to ap.
//
// A WireGuard peer only carries the prefixes in its allowed_ips and the device
// silently drops everything else, so a dial outside them would hang until its
// deadline with no explanation. Checking here answers the question a homelab peer
// always raises: with allowed_ips = ["10.173.91.0/24"] this outbound cannot be a
// global exit — public destinations fail here with this error, and the fix is to
// widen allowed_ips to 0.0.0.0/0 (a peer that actually offers egress), not to
// retry. An empty allowed_ips can carry nothing at all.
func (c *Client) routed(ap netip.AddrPort) (netip.AddrPort, error) {
	if len(c.allowedIPs) == 0 {
		return netip.AddrPort{}, fmt.Errorf("wireguard %s: peer has no allowed_ips and cannot carry %s", c.tag, ap)
	}
	for _, p := range c.allowedIPs {
		if p.Contains(ap.Addr()) {
			return ap, nil
		}
	}
	return netip.AddrPort{}, fmt.Errorf(
		"wireguard %s: %s is outside the peer's allowed_ips [%s], so the tunnel would drop it; widen allowed_ips if this peer should carry it",
		c.tag, ap, prefixList(c.allowedIPs))
}

// prefixList renders prefixes for an error message.
func prefixList(prefixes []netip.Prefix) string {
	parts := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ", ")
}

// withTimeout gives the dial a deadline when the caller did not.
func (c *Client) withTimeout(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	return ctx, cancel, nil
}

// packetConn adapts gVisor's UDP socket to outbound.PacketConn, which speaks
// netip.AddrPort instead of net.Addr.
type packetConn struct{ *gonet.UDPConn }

var _ outbound.PacketConn = packetConn{}

func (p packetConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	n, addr, err := p.UDPConn.ReadFrom(b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, netip.AddrPort{}, fmt.Errorf("wireguard: unexpected packet source %T", addr)
	}
	return n, udp.AddrPort(), nil
}

func (p packetConn) WriteTo(b []byte, addr netip.AddrPort) (int, error) {
	return p.UDPConn.WriteTo(b, net.UDPAddrFromAddrPort(addr))
}

// decodeKey turns a base64 WireGuard key into the hex form the UAPI takes.
func decodeKey(tag, field, b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", fmt.Errorf("wireguard %s: %s is not base64: %w", tag, field, err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("wireguard %s: %s is %d bytes, want 32", tag, field, len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// parseAddrs accepts the CIDR spelling of wg-quick (10.0.0.2/32) and bare
// addresses, because both appear in hand written configs.
func parseAddrs(tag, field string, list []string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(list))
	for _, s := range list {
		p, err := parseAddrOrPrefix(s)
		if err != nil {
			return nil, fmt.Errorf("wireguard %s: %s: %w", tag, field, err)
		}
		out = append(out, p.Addr())
	}
	return out, nil
}

func parsePrefixes(tag, field string, list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		p, err := parseAddrOrPrefix(s)
		if err != nil {
			return nil, fmt.Errorf("wireguard %s: %s: %w", tag, field, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func parseAddrOrPrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()), nil
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	ip = ip.Unmap()
	return netip.PrefixFrom(ip, ip.BitLen()), nil
}

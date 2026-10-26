// Package ss implements the Shadowsocks client: the classic AEAD methods
// (SIP004/SIP007) and Shadowsocks 2022 (SIP022), over TCP and UDP.
//
// Nothing here resolves the destination: hostnames travel to the server as
// SOCKS5 domain addresses, which is what a proxy client must do to keep DNS out
// of the local network.
package ss

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"veil/internal/config"
	"veil/internal/outbound"
	"veil/internal/transport"
)

// maxDatagram is the largest plaintext UDP payload we are willing to carry.
// Shadowsocks packets are length-prefixed only by the transport, so the real
// limit is the 64 KiB IP datagram minus headers.
const maxDatagram = 65535

// packetOverhead covers salt/nonce, AEAD tags and the maximum SIP022 padding.
const packetOverhead = 1024

const dialTimeout = 10 * time.Second

// Client is one Shadowsocks server.
type Client struct {
	tag    string
	method *Cipher
	key    []byte

	serverAddr string
	dialer     transport.Dialer

	mu      sync.Mutex
	closed  bool
	packets map[*packetConn]struct{}
}

var (
	_ outbound.Outbound       = (*Client)(nil)
	_ outbound.PacketOutbound = (*Client)(nil)
)

// New builds a Shadowsocks client for n. For SIP022 methods n.Password is a
// base64 PSK; for legacy methods it is a passphrase run through EVP_BytesToKey.
func New(n config.Node) (*Client, error) { return NewVia(n, nil) }

// NewVia is New with the TCP connection to the server opened by base instead of
// a direct dial, which is how a chained outbound (mihomo's `dialer-proxy`)
// reaches its server through another proxy. A nil base dials directly, exactly
// like New.
func NewVia(n config.Node, base transport.Dialer) (*Client, error) {
	m, err := CipherByName(n.Method)
	if err != nil {
		return nil, fmt.Errorf("ss %s: %w", n.Tag, err)
	}
	var key []byte
	if m.Is2022 {
		key, err = m.ParseKey(n.Password)
		if err != nil {
			return nil, fmt.Errorf("ss %s: %w", n.Tag, err)
		}
	} else {
		if n.Password == "" {
			return nil, fmt.Errorf("ss %s: empty password", n.Tag)
		}
		key = m.LegacyKey(n.Password)
	}
	dialer, err := transport.BuildWith(n, base)
	if err != nil {
		return nil, fmt.Errorf("ss %s: %w", n.Tag, err)
	}
	return &Client{
		tag:        n.Tag,
		method:     m,
		key:        key,
		serverAddr: n.Addr(),
		dialer:     dialer,
		packets:    make(map[*packetConn]struct{}),
	}, nil
}

// Tag implements outbound.Outbound.
func (c *Client) Tag() string { return c.tag }

// Type implements outbound.Outbound.
func (c *Client) Type() string { return "ss" }

// Close implements outbound.Outbound.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	conns := make([]*packetConn, 0, len(c.packets))
	for pc := range c.packets {
		conns = append(conns, pc)
	}
	c.packets = nil
	c.mu.Unlock()

	for _, pc := range conns {
		_ = pc.Close()
	}
	return nil
}

// DialContext opens a proxied TCP stream to address ("host:port").
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "", "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("ss %s: unsupported network %q", c.tag, network)
	}
	host, port, isDomain, err := parseHostPort(address)
	if err != nil {
		return nil, err
	}

	var addrHeader []byte
	if isDomain {
		addrHeader, err = appendDomainAddr(nil, host, port)
		if err != nil {
			return nil, err
		}
	} else {
		ip, perr := netip.ParseAddr(host)
		if perr != nil {
			return nil, fmt.Errorf("ss %s: bad address %q: %w", c.tag, address, perr)
		}
		addrHeader = appendAddr(nil, netip.AddrPortFrom(ip, port))
	}

	raw, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}

	if c.method.Is2022 {
		sess, err := newSIP022ClientSession(raw, c.method, c.key, addrHeader)
		if err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("ss %s: 2022 handshake: %w", c.tag, err)
		}
		return &tunnelConn{Conn: raw, r: sess, w: sess}, nil
	}

	// Legacy AEAD: the request address is the first chunk on the wire, right
	// after the salt, so the server can connect while we are still reading.
	w := newLegacyWriter(raw, c.key, c.method)
	if _, err := w.Write(addrHeader); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("ss %s: write request: %w", c.tag, err)
	}
	return &tunnelConn{Conn: raw, r: newLegacyReader(raw, c.key, c.method), w: w}, nil
}

// dial opens the transport connection to the server.
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, fmt.Errorf("ss %s: client closed", c.tag)
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dialTimeout)
		defer cancel()
	}
	conn, err := c.dialer.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("ss %s: dial %s: %w", c.tag, c.serverAddr, err)
	}
	return conn, nil
}

// tunnelConn is the net.Conn handed to callers. It hides the salt exchange and
// the chunk framing behind ordinary Read/Write calls.
type tunnelConn struct {
	net.Conn
	r io.Reader
	w io.Writer
}

func (t *tunnelConn) Read(p []byte) (int, error)  { return t.r.Read(p) }
func (t *tunnelConn) Write(p []byte) (int, error) { return t.w.Write(p) }

// DialPacket opens a UDP association. Shadowsocks relays to an arbitrary
// destination per packet, so address is only metadata.
func (c *Client) DialPacket(ctx context.Context, address string) (outbound.PacketConn, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, fmt.Errorf("ss %s: client closed", c.tag)
	}

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dialTimeout)
		defer cancel()
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", c.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("ss %s: dial udp %s: %w", c.tag, c.serverAddr, err)
	}
	pc := &packetConn{
		c:     c,
		conn:  conn,
		rdBuf: make([]byte, maxDatagram+packetOverhead),
	}
	if c.method.Is2022 {
		sess, err := newSIP022PacketSession(c.method, c.key)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		pc.session = sess
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.Close()
		return nil, fmt.Errorf("ss %s: client closed", c.tag)
	}
	c.packets[pc] = struct{}{}
	c.mu.Unlock()
	return pc, nil
}

// packetConn is one UDP association with the server. Reads and writes do not
// block each other: a SOCKS5 server typically runs them in separate goroutines.
type packetConn struct {
	c       *Client
	conn    net.Conn
	session *sip022PacketSession

	rmu   sync.Mutex
	rdBuf []byte

	wmu sync.Mutex

	dlMu     sync.Mutex
	deadline time.Time

	closeOne sync.Once
}

func (p *packetConn) currentDeadline() time.Time {
	p.dlMu.Lock()
	defer p.dlMu.Unlock()
	return p.deadline
}

func (p *packetConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	if err := p.conn.SetReadDeadline(p.currentDeadline()); err != nil {
		return 0, netip.AddrPort{}, err
	}
	n, err := p.conn.Read(p.rdBuf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	packet := p.rdBuf[:n]

	if p.session != nil {
		addr, payload, err := p.session.decode(packet)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		return copy(b, payload), addr, nil
	}

	plain, err := legacyOpenPacket(p.c.method, p.c.key, packet)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	addr, consumed, err := parseAddr(plain)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return copy(b, plain[consumed:]), addr, nil
}

func (p *packetConn) WriteTo(b []byte, addr netip.AddrPort) (int, error) {
	if addrSize(addr) == 0 {
		return 0, fmt.Errorf("ss: invalid destination %s", addr)
	}
	p.wmu.Lock()
	defer p.wmu.Unlock()
	if err := p.conn.SetWriteDeadline(p.currentDeadline()); err != nil {
		return 0, err
	}

	var packet []byte
	var err error
	if p.session != nil {
		packet, err = p.session.encode(addr, b)
	} else {
		plain := appendAddr(make([]byte, 0, addrSize(addr)+len(b)), addr)
		plain = append(plain, b...)
		packet, err = legacySealPacket(p.c.method, p.c.key, plain)
	}
	if err != nil {
		return 0, err
	}
	if _, err := p.conn.Write(packet); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *packetConn) SetDeadline(t time.Time) error {
	p.dlMu.Lock()
	p.deadline = t
	p.dlMu.Unlock()
	if err := p.conn.SetReadDeadline(t); err != nil {
		return err
	}
	return p.conn.SetWriteDeadline(t)
}

func (p *packetConn) Close() error {
	var err error
	p.closeOne.Do(func() {
		err = p.conn.Close()
		p.c.mu.Lock()
		delete(p.c.packets, p)
		p.c.mu.Unlock()
	})
	return err
}

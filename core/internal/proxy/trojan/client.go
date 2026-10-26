package trojan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"veil/internal/config"
	"veil/internal/outbound"
	"veil/internal/transport"
)

// Client is a trojan outbound. It holds no per-connection state: every Dial
// builds a fresh stream from the configured transport dialer, which makes it
// safe for concurrent use.
type Client struct {
	tag      string
	password string
	key      []byte // hex(SHA-224(password)), 56 bytes
	dialer   transport.Dialer
	udp      bool
}

var (
	_ outbound.Outbound       = (*Client)(nil)
	_ outbound.PacketOutbound = (*Client)(nil)
)

// New builds a trojan client for n. Trojan is always TLS: transport.Build
// layers TLS (and any ws/grpc wrapping) on top of plain TCP for us. When the
// node does not name a server name we default it to the server address so the
// certificate is validated against the right host.
func New(n config.Node) (*Client, error) { return NewVia(n, nil) }

// NewVia is New with the TCP connection to the server opened by base instead of
// a direct dial: the TLS (and ws/grpc) stack is carried by that connection,
// which is how a chained outbound (mihomo's `dialer-proxy`) reaches its server
// through another proxy. A nil base dials directly, exactly like New.
func NewVia(n config.Node, base transport.Dialer) (*Client, error) {
	if n.Password == "" {
		return nil, fmt.Errorf("trojan %q: empty password", n.Tag)
	}
	if n.Server == "" || n.Port <= 0 || n.Port > 65535 {
		return nil, fmt.Errorf("trojan %q: invalid server %s:%d", n.Tag, n.Server, n.Port)
	}

	dialer, err := transport.BuildWith(withTLSDefaults(n), base)
	if err != nil {
		return nil, fmt.Errorf("trojan %q: build transport: %w", n.Tag, err)
	}

	return &Client{
		tag:      n.Tag,
		password: n.Password,
		key:      passwordKey(n.Password),
		dialer:   dialer,
		udp:      n.SupportsUDP(),
	}, nil
}

// withTLSDefaults returns a copy of n with TLS forced on and the server name
// defaulted, leaving the caller's node untouched.
func withTLSDefaults(n config.Node) config.Node {
	want := n.Server
	switch {
	case n.TLS == nil:
		n.TLS = &config.TLS{Enabled: true, ServerName: want}
	case !n.TLS.Enabled:
		t := *n.TLS
		t.Enabled = true
		if t.ServerName == "" {
			t.ServerName = want
		}
		n.TLS = &t
	case n.TLS.ServerName == "":
		t := *n.TLS
		t.ServerName = want
		n.TLS = &t
	}
	return n
}

// Tag implements outbound.Outbound.
func (c *Client) Tag() string { return c.tag }

// Type implements outbound.Outbound.
func (c *Client) Type() string { return "trojan" }

// Close implements outbound.Outbound. Connections own their streams, so there
// is nothing to release here.
func (c *Client) Close() error { return nil }

// DialContext opens a trojan TCP stream to address.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "", "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("trojan: unsupported network %q", network)
	}
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host == "" {
		return nil, errors.New("trojan: empty destination")
	}

	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.writeHeader(ctx, conn, commandTCP, host, port); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// DialPacket opens a trojan UDP association. Trojan carries the destination of
// every datagram inside the frame, so the association works for arbitrary
// targets; address is only used as the (informational) header destination.
func (c *Client) DialPacket(ctx context.Context, address string) (outbound.PacketConn, error) {
	if !c.udp {
		return nil, errors.New("trojan: UDP disabled for this node")
	}
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host == "" {
		// No initial target: the header destination is ignored by servers for
		// command 0x03, so an unspecified address is safe.
		host, port = "0.0.0.0", 0
	}

	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.writeHeader(ctx, conn, commandUDP, host, port); err != nil {
		conn.Close()
		return nil, err
	}
	return newPacketConn(conn), nil
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	if c.dialer == nil {
		return nil, errors.New("trojan: no transport dialer")
	}
	conn, err := c.dialer.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("trojan: dial: %w", err)
	}
	return conn, nil
}

func (c *Client) writeHeader(ctx context.Context, conn net.Conn, command byte, host string, port uint16) error {
	hdr, err := buildHeader(make([]byte, 0, headerSZ+16+6), c.key, command, host, port)
	if err != nil {
		return err
	}
	reset, err := applyDeadline(ctx, conn)
	if err != nil {
		return err
	}
	defer reset()
	if _, err := conn.Write(hdr); err != nil {
		return fmt.Errorf("trojan: write request header: %w", err)
	}
	return nil
}

// applyDeadline mirrors ctx's deadline onto conn and returns a func that clears
// it. A server that never answers (or a saturated socket) must not wedge the
// dial past the caller's budget.
func applyDeadline(ctx context.Context, conn net.Conn) (func(), error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return func() {}, nil
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	return func() { _ = conn.SetDeadline(time.Time{}) }, nil
}

// Package socks5 implements a SOCKS5 outbound: the client's byte stream is
// relayed to a SOCKS5 server that performs the connection on its behalf.
//
// It exists because a Clash profile can name a household or ISP-provided
// SOCKS5 endpoint as an exit, and that endpoint is not one of the proxy
// protocols otherwise supported here.
package socks5

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"veil/internal/config"
	"veil/internal/outbound"
	"veil/internal/transport"
)

const (
	version5 = 0x05

	methodNoAuth       = 0x00
	methodUserPass     = 0x02
	methodNoAcceptable = 0xff

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// Client is a SOCKS5 outbound. It keeps no per-connection state beyond the
// dialer, so it is safe for concurrent use.
type Client struct {
	tag    string
	server string
	user   string
	pass   string
	dialer transport.Dialer
	udp    bool
}

var (
	_ outbound.Outbound       = (*Client)(nil)
	_ outbound.PacketOutbound = (*Client)(nil)
)

// NewVia builds a SOCKS5 client whose own connection to the server is opened by
// base. A nil base keeps the protect-aware dial, so this is New with a chain.
func NewVia(n config.Node, base transport.Dialer) (*Client, error) {
	if n.Server == "" || n.Port <= 0 || n.Port > 65535 {
		return nil, fmt.Errorf("socks5 %q: invalid server %s:%d", n.Tag, n.Server, n.Port)
	}
	user, pass := credentials(n)
	if (user == "") != (pass == "") {
		return nil, fmt.Errorf("socks5 %q: username and password must be given together", n.Tag)
	}
	var dialer transport.Dialer
	var err error
	if base != nil {
		dialer, err = transport.BuildWith(n, base)
	} else {
		dialer, err = transport.Build(n)
	}
	if err != nil {
		return nil, fmt.Errorf("socks5 %q: build transport: %w", n.Tag, err)
	}
	return &Client{
		tag:    n.Tag,
		server: net.JoinHostPort(n.Server, strconv.Itoa(n.Port)),
		user:   user,
		pass:   pass,
		dialer: dialer,
		udp:    n.SupportsUDP(),
	}, nil
}

// credentials reads the pair the configuration carries. Clash spells a SOCKS5
// login as username/password; an empty pair means the server takes none.
func credentials(n config.Node) (string, string) {
	return n.Username, n.Password
}

// New builds a SOCKS5 client for n.
func New(n config.Node) (*Client, error) { return NewVia(n, nil) }

// Tag implements outbound.Outbound.
func (c *Client) Tag() string { return c.tag }

// Type implements outbound.Outbound.
func (c *Client) Type() string { return "socks5" }

// Close implements outbound.Outbound.
func (c *Client) Close() error { return nil }

// DialContext opens a SOCKS5 stream to address through the server.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("socks5 %q: unsupported network %q", c.tag, network)
	}
	raw, err := c.dialer.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("socks5 %q: dial server: %w", c.tag, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}
	if err := c.handshake(raw); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err := c.connect(raw, address); err != nil {
		_ = raw.Close()
		return nil, err
	}
	// The deadline belonged to the handshake, not to the relayed stream.
	_ = raw.SetDeadline(time.Time{})
	return raw, nil
}

// handshake negotiates the authentication method and, when the server asks for
// one, sends the username and password (RFC 1929).
func (c *Client) handshake(conn net.Conn) error {
	methods := []byte{methodNoAuth}
	if c.user != "" {
		methods = []byte{methodUserPass}
	}
	req := make([]byte, 0, 2+len(methods))
	req = append(req, version5, byte(len(methods)))
	req = append(req, methods...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 %q: greet: %w", c.tag, err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("socks5 %q: read method: %w", c.tag, err)
	}
	if reply[0] != version5 {
		return fmt.Errorf("socks5 %q: server speaks version %d", c.tag, reply[0])
	}
	if reply[1] == methodNoAcceptable {
		return fmt.Errorf("socks5 %q: no acceptable authentication method", c.tag)
	}
	if reply[1] != methodNoAuth {
		if c.user == "" {
			return fmt.Errorf("socks5 %q: server wants authentication but no credentials are configured", c.tag)
		}
		return c.authenticate(conn)
	}
	return nil
}

func (c *Client) authenticate(conn net.Conn) error {
	if len(c.user) > 255 || len(c.pass) > 255 {
		return fmt.Errorf("socks5 %q: credentials longer than 255 bytes", c.tag)
	}
	msg := make([]byte, 0, 3+len(c.user)+len(c.pass))
	msg = append(msg, 0x01, byte(len(c.user)))
	msg = append(msg, c.user...)
	msg = append(msg, byte(len(c.pass)))
	msg = append(msg, c.pass...)
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("socks5 %q: send credentials: %w", c.tag, err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("socks5 %q: read auth reply: %w", c.tag, err)
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("socks5 %q: authentication rejected (status %d)", c.tag, reply[1])
	}
	return nil
}

// connect asks the server for a stream to address and consumes its reply.
func (c *Client) connect(conn net.Conn, address string) error {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("socks5 %q: bad target %q: %w", c.tag, address, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("socks5 %q: bad port %q", c.tag, portStr)
	}
	req := []byte{version5, cmdConnect, 0x00}
	req, err = appendHost(req, host)
	if err != nil {
		return fmt.Errorf("socks5 %q: %w", c.tag, err)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 %q: send connect: %w", c.tag, err)
	}
	return readReply(conn, c.tag)
}

// appendHost encodes host as an address the protocol understands: an IPv4 or
// IPv6 literal when it parses as one, the raw name otherwise.
func appendHost(dst []byte, host string) ([]byte, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			b := ip.As4()
			dst = append(dst, atypIPv4)
			return append(dst, b[:]...), nil
		}
		b := ip.As16()
		dst = append(dst, atypIPv6)
		return append(dst, b[:]...), nil
	}
	if len(host) == 0 || len(host) > 255 {
		return nil, fmt.Errorf("host %q cannot be encoded", host)
	}
	dst = append(dst, atypDomain, byte(len(host)))
	return append(dst, host...), nil
}

// readReply consumes a SOCKS5 reply and turns its status into an error.
func readReply(conn net.Conn, tag string) error {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("socks5 %q: read reply: %w", tag, err)
	}
	if head[0] != version5 {
		return fmt.Errorf("socks5 %q: reply version %d", tag, head[0])
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5 %q: connect failed: %s", tag, statusText(head[1]))
	}
	switch head[3] {
	case atypIPv4:
		_, err := io.ReadFull(conn, make([]byte, 4+2))
		return err
	case atypIPv6:
		_, err := io.ReadFull(conn, make([]byte, 16+2))
		return err
	case atypDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return err
		}
		_, err := io.ReadFull(conn, make([]byte, int(length[0])+2))
		return err
	default:
		return fmt.Errorf("socks5 %q: reply has unknown address type %d", tag, head[3])
	}
}

func statusText(code byte) string {
	switch code {
	case 0x01:
		return "general failure"
	case 0x02:
		return "connection not allowed"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("status %d", code)
	}
}

// DialPacket reports that UDP is not relayed yet. A SOCKS5 UDP association
// needs its own datagram relay (the reply carries the address the server
// expects traffic at), and a half-implemented one would silently drop packets;
// TCP through the same node keeps working.
func (c *Client) DialPacket(ctx context.Context, address string) (outbound.PacketConn, error) {
	if !c.udp {
		return nil, fmt.Errorf("socks5 %q: UDP is disabled for this node", c.tag)
	}
	return nil, fmt.Errorf("socks5 %q: UDP relay is not implemented; this node carries TCP only", c.tag)
}

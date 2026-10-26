// Package vless implements the VLESS client protocol, including the
// XTLS-Vision flow (xtls-rprx-vision) and UDP relaying.
package vless

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"time"
	"unsafe"

	utls "github.com/refraction-networking/utls"

	"veil/internal/config"
	"veil/internal/outbound"
	"veil/internal/transport"
)

// errVisionUDP: UDP needs MUX when flow is xtls-rprx-vision (see DialPacket).
var errVisionUDP = errors.New("vless: udp over xtls-rprx-vision needs mux (not implemented)")

// Client is one VLESS upstream. It is safe for concurrent use: every Dial*
// builds fresh per-connection state.
type Client struct {
	tag    string
	addr   string
	dialer transport.Dialer
	uuid   [16]byte
	flow   string
}

// New builds a VLESS client from a configuration node.
func New(n config.Node) (*Client, error) { return NewVia(n, nil) }

// NewVia is New with the TCP connection to the server opened by base instead of
// a direct dial: the transport stack is carried by that connection, which is how
// a chained outbound (mihomo's `dialer-proxy`) reaches its server through
// another proxy. A nil base dials directly, exactly like New.
func NewVia(n config.Node, base transport.Dialer) (*Client, error) {
	if t := strings.TrimSpace(n.Type); t != "" && !strings.EqualFold(t, "vless") {
		return nil, fmt.Errorf("vless: node %q has type %q", n.Tag, n.Type)
	}
	uuid, err := parseUUID(n.UUID)
	if err != nil {
		return nil, err
	}
	flow, err := normalizeFlow(n.Flow)
	if err != nil {
		return nil, err
	}
	dialer, err := transport.BuildWith(n, base)
	if err != nil {
		return nil, fmt.Errorf("vless: node %q: %w", n.Tag, err)
	}
	return &Client{
		tag:    n.Tag,
		addr:   n.Addr(),
		dialer: dialer,
		uuid:   uuid,
		flow:   flow,
	}, nil
}

// normalizeFlow validates the flow name. "xtls-rprx-vision-udp443" is accepted
// because share links use it; the "-udp443" suffix only changes what the client
// is allowed to send over the flow, and we simply honour the flow itself.
func normalizeFlow(f string) (string, error) {
	f = strings.TrimSpace(f)
	switch f {
	case "":
		return "", nil
	case FlowVision, FlowVision + "-udp443":
		return FlowVision, nil
	default:
		return "", fmt.Errorf("vless: unsupported flow %q", f)
	}
}

// Tag implements outbound.Outbound.
func (c *Client) Tag() string { return c.tag }

// Type implements outbound.Outbound.
func (c *Client) Type() string { return "vless" }

// Close implements outbound.Outbound. The transport layer keeps no shared
// resources between dials, so there is nothing to release.
func (c *Client) Close() error { return nil }

// DialContext opens a VLESS TCP stream to address.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6", "":
	default:
		return nil, fmt.Errorf("vless: unsupported network %q", network)
	}
	ip, domain, port, err := destination(address)
	if err != nil {
		return nil, fmt.Errorf("vless dial %s via %s: %w", address, c.tag, err)
	}
	conn, err := c.open(ctx, ip, domain, port, commandTCP)
	if err != nil {
		return nil, fmt.Errorf("vless dial %s via %s: %w", address, c.tag, err)
	}
	return conn, nil
}

// DialPacket opens a UDP association.
func (c *Client) DialPacket(ctx context.Context, address string) (outbound.PacketConn, error) {
	if c.flow == FlowVision {
		// Vision carries UDP on a MUX stream (v1.mux.cool:666) with XUDP frames.
		ap, perr := netip.ParseAddrPort(address)
		if perr != nil {
			return nil, fmt.Errorf("vless: udp target must be ip:port: %w", perr)
		}
		stream, serr := c.open(ctx, netip.Addr{}, muxTarget, 666, commandMux)
		if serr != nil {
			return nil, serr
		}
		return newXUDP(stream, ap), nil
	}
	if c.flow == FlowVision && false {
		// Xray rewrites UDP to MUX (v1.mux.cool:666) when flow is
		// xtls-rprx-vision (proxy/vless/outbound/outbound.go). Sending command=2
		// with a vision flow is rejected by the server, which used to cost every
		// DNS query a 5s timeout. Until MUX/XUDP is implemented, say so instead
		// of hanging: the resolver then goes direct.
		return nil, errVisionUDP
	}
	var (
		ip     netip.Addr
		domain string
		port   uint16
	)
	if address != "" {
		var err error
		ip, domain, port, err = destination(address)
		if err != nil {
			return nil, fmt.Errorf("vless udp %s via %s: %w", address, c.tag, err)
		}
	} else {
		// VLESS carries a destination in the request header even for UDP; every
		// datagram repeats it, so a placeholder is harmless.
		ip = netip.AddrFrom4([4]byte{})
	}
	conn, err := c.open(ctx, ip, domain, port, commandUDP)
	if err != nil {
		return nil, fmt.Errorf("vless udp %s via %s: %w", address, c.tag, err)
	}
	return &packetConn{conn: conn}, nil
}

// open runs the transport dial, sends the request header, reads the response
// header and returns the stream (wrapped with the Vision framing when the flow
// is configured).
func (c *Client) open(ctx context.Context, ip netip.Addr, domain string, port uint16, command byte) (net.Conn, error) {
	raw, err := c.dialer.Dial(ctx)
	if err != nil {
		return nil, err
	}
	// Interrupt the header exchange if the context is cancelled: a proxy that
	// accepts TCP but never answers must not pin the caller.
	stop := context.AfterFunc(ctx, func() { _ = raw.SetDeadline(time.Now()) })
	defer stop()

	header, err := requestHeader{
		User:    c.uuid,
		Flow:    c.flow,
		Command: command,
		Address: ip,
		Domain:  domain,
		Port:    port,
	}.encode()
	if err != nil {
		raw.Close()
		return nil, err
	}
	if c.flow == FlowVision {
		// Vision needs a streaming start: Xray's inbound writes the response
		// header into a buffered writer and only flushes it together with the
		// first downlink data (bufferWriter.SetFlushNext()). Waiting for the
		// header before sending anything deadlocks both sides. So: send the
		// request header, return immediately, and consume the 2-byte response
		// header lazily on the first Read.
		if _, err := raw.Write(header); err != nil {
			raw.Close()
			return nil, fmt.Errorf("write request header: %w", err)
		}
		if err := raw.SetDeadline(time.Time{}); err != nil {
			raw.Close()
			return nil, err
		}
		st := newVisionState(c.uuid[:])
		st.padding = true
		w := newVisionWriter(raw, st)
		vc := &visionConn{Conn: raw, raw: raw, uuid: c.uuid, writer: w, state: st}
		vc.tcp = unwrapTransport(raw)
		vc.tlsIn, vc.tlsRaw = accessTLSBuffers(raw)
		return vc, nil
	}

	if _, err := raw.Write(header); err != nil {
		raw.Close()
		return nil, fmt.Errorf("write request header: %w", err)
	}
	if _, err := readResponseHeader(raw); err != nil {
		raw.Close()
		return nil, err
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		raw.Close()
		return nil, err
	}
	return raw, nil
}

// visionConn replaces Read/Write with the Vision framing while keeping the
// underlying connection's Close, addresses and deadline methods.
//
// The vision state and readers are created lazily: the response header must be
// consumed from the *raw* connection before any buffered vision reader exists,
// and it only arrives after the first uplink bytes are flushed.
type visionConn struct {
	net.Conn
	raw    net.Conn
	tcp    net.Conn // transport-unwrapped conn for post-Direct raw reads
	uuid   [16]byte
	state  *visionState
	once   sync.Once
	err    error
	reader io.Reader
	writer *visionWriter
	tlsIn  *bytes.Reader // transport TLS pending decrypted bytes
	tlsRaw *bytes.Buffer // transport TLS pending undecrypted bytes
}

// unwrapTransport returns the TCP conn under the transport crypto layer (for
// REALITY that is the uTLS conn), mirroring Xray's UnwrapRawConn. After a
// Vision Direct frame both peers bypass the transport crypto and exchange raw
// TCP bytes; reading those through the TLS layer fails record authentication.
func unwrapTransport(conn net.Conn) net.Conn {
	if uc, ok := conn.(*utls.UConn); ok {
		if raw := uc.NetConn(); raw != nil {
			return raw
		}
	}
	return conn
}

// accessTLSBuffers returns the transport TLS layer's pending buffers: decrypted
// application data not yet returned (input) and bytes read from the socket but
// not yet decrypted (rawInput). Vision needs them when the peer switches to
// Direct: the TLS layer may hold buffered bytes past the Direct frame, which
// must be delivered before reading the raw conn. Mirrors Xray's AccessTLSBuffers.
func accessTLSBuffers(conn net.Conn) (*bytes.Reader, *bytes.Buffer) {
	if conn == nil {
		return nil, nil
	}
	v := reflect.ValueOf(conn)
	if v.Kind() != reflect.Pointer {
		return nil, nil
	}
	e := v.Elem()
	if e.Kind() != reflect.Struct {
		return nil, nil
	}
	in := e.FieldByName("input")
	if !in.IsValid() || in.Type() != reflect.TypeOf(bytes.Reader{}) {
		return nil, nil
	}
	rawIn := e.FieldByName("rawInput")
	if !rawIn.IsValid() || rawIn.Type() != reflect.TypeOf(bytes.Buffer{}) {
		return nil, nil
	}
	// FieldByName on an embedded *Conn (utls.UConn) returns promoted fields;
	// NewAt recovers an addressable view of the unexported field.
	inPtr, ok1 := reflect.NewAt(in.Type(), unsafe.Pointer(in.UnsafeAddr())).Elem().Addr().Interface().(*bytes.Reader)
	rawPtr, ok2 := reflect.NewAt(rawIn.Type(), unsafe.Pointer(rawIn.UnsafeAddr())).Elem().Addr().Interface().(*bytes.Buffer)
	if !ok1 || !ok2 {
		return nil, nil
	}
	return inPtr, rawPtr
}

func (c *visionConn) init() {
	c.once.Do(func() {
		if _, err := readResponseHeader(c.raw); err != nil {
			if vdbgOn() {
				vdbg("init: response header: %v", err)
			}
			c.err = err
			return
		}
		if vdbgOn() {
			vdbg("init: response header ok, vision reader active")
		}
		c.reader = newVisionReader(c.raw, c.tcp, c.tlsIn, c.tlsRaw, c.state, c.writer)
	})
}

func (c *visionConn) Read(p []byte) (int, error) {
	c.init()
	if c.err != nil {
		return 0, c.err
	}
	return c.reader.Read(p)
}

func (c *visionConn) Write(p []byte) (int, error) {
	// Always framed: the server's vision reader starts at the first payload
	// byte, so an unframed first write corrupts the stream (uplink counted,
	// downlink forever empty).
	if vdbgOn() {
		vdbg("write: n=%d head=% x", len(p), byten(p, len(p), 16))
	}
	n, err := c.writer.Write(p)
	if vdbgOn() {
		vdbg("write: wrote=%d err=%v", n, err)
	}
	return n, err
}

// compile-time interface checks.
var (
	_ outbound.Outbound       = (*Client)(nil)
	_ outbound.PacketOutbound = (*Client)(nil)
	_ net.Conn                = (*visionConn)(nil)
	_                         = errors.Is
)

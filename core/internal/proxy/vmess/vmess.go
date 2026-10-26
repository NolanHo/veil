// Package vmess implements the VMess client protocol with AEAD headers.
//
// Two layers matter for compatibility:
//
//   - the request header, which is AES-ECB(auth id) + AEAD-sealed length +
//     connection nonce + AEAD-sealed body, all keyed through the VMess KDF
//     chain (see kdf.go);
//   - the body, a stream of AEAD chunks whose nonce is the session IV with a
//     16-bit chunk counter patched into its first two bytes (see chunk.go).
//
// Only alterId=0 (AEAD) is implemented: the legacy AES-CFB scheme is deprecated
// and no modern server requires it.
package vmess

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/cpu"

	"veil/internal/config"
	"veil/internal/outbound"
	"veil/internal/transport"
)

// Client is a VMess outbound. It carries no per-connection state, so a single
// value serves concurrent dials.
type Client struct {
	tag      string
	id       [uuidLen]byte
	key      [16]byte // cmdKey
	security byte
	dialer   transport.Dialer
	udp      bool
}

var (
	_ outbound.Outbound       = (*Client)(nil)
	_ outbound.PacketOutbound = (*Client)(nil)
)

// New builds a VMess client for n.
func New(n config.Node) (*Client, error) { return NewVia(n, nil) }

// NewVia is New with the TCP connection to the server opened by base instead of
// a direct dial: the transport stack is carried by that connection, which is how
// a chained outbound (mihomo's `dialer-proxy`) reaches its server through
// another proxy. A nil base dials directly, exactly like New.
func NewVia(n config.Node, base transport.Dialer) (*Client, error) {
	if n.UUID == "" {
		return nil, fmt.Errorf("vmess %q: missing uuid", n.Tag)
	}
	if n.Server == "" || n.Port <= 0 || n.Port > 65535 {
		return nil, fmt.Errorf("vmess %q: invalid server %s:%d", n.Tag, n.Server, n.Port)
	}
	if n.AlterID != 0 {
		return nil, fmt.Errorf("vmess %q: alterId %d is not supported (AEAD only)", n.Tag, n.AlterID)
	}

	id, err := parseUUID(n.UUID)
	if err != nil {
		return nil, fmt.Errorf("vmess %q: %w", n.Tag, err)
	}
	security, err := resolveSecurity(n.Method)
	if err != nil {
		return nil, fmt.Errorf("vmess %q: %w", n.Tag, err)
	}

	dialer, err := transport.BuildWith(n, base)
	if err != nil {
		return nil, fmt.Errorf("vmess %q: build transport: %w", n.Tag, err)
	}

	return &Client{
		tag:      n.Tag,
		id:       id,
		key:      cmdKey(id),
		security: security,
		dialer:   dialer,
		udp:      n.SupportsUDP(),
	}, nil
}

// Tag implements outbound.Outbound.
func (c *Client) Tag() string { return c.tag }

// Type implements outbound.Outbound.
func (c *Client) Type() string { return "vmess" }

// Close implements outbound.Outbound. Sessions own their connections.
func (c *Client) Close() error { return nil }

// DialContext opens a VMess TCP stream to address.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "", "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("vmess: unsupported network %q", network)
	}
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host == "" {
		return nil, errors.New("vmess: empty destination")
	}

	sess, err := newSession(c.security)
	if err != nil {
		return nil, err
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.handshake(ctx, conn, sess, cmdTCP, host, port); err != nil {
		conn.Close()
		return nil, err
	}
	return newConn(conn, sess), nil
}

// DialPacket opens a VMess UDP association. VMess datagrams carry their own
// destination, so address only seeds the request header.
func (c *Client) DialPacket(ctx context.Context, address string) (outbound.PacketConn, error) {
	if !c.udp {
		return nil, errors.New("vmess: UDP disabled for this node")
	}
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host == "" {
		host, port = "0.0.0.0", 0
	}

	sess, err := newSession(c.security)
	if err != nil {
		return nil, err
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.handshake(ctx, conn, sess, cmdUDP, host, port); err != nil {
		conn.Close()
		return nil, err
	}
	return &packetConn{
		conn:   conn,
		writer: newChunkWriter(conn, sess.requestCipher),
		reader: &responseReader{
			r:          conn,
			cipher:     sess.responseCipher,
			key:        sess.responseKey,
			iv:         sess.responseIV,
			wantHeader: sess.responseHeaderByte,
		},
	}, nil
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	if c.dialer == nil {
		return nil, errors.New("vmess: no transport dialer")
	}
	conn, err := c.dialer.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("vmess: dial: %w", err)
	}
	return conn, nil
}

// handshake writes the sealed request header.
func (c *Client) handshake(ctx context.Context, conn net.Conn, sess *session, command byte, host string, port uint16) error {
	hdr := &requestHeader{
		bodyIV:         sess.bodyIV,
		bodyKey:        sess.bodyKey,
		responseHeader: sess.responseHeaderByte,
		option:         optionChunkStream,
		security:       c.security,
		command:        command,
		host:           host,
		port:           port,
	}
	// Padding length lives in the high nibble of the security byte; the
	// reference implementation randomises 0..15 to blur the header size.
	var pad [1]byte
	if err := randomBytes(pad[:]); err != nil {
		return err
	}
	hdr.paddingLen = int(pad[0] >> 4)

	plain, err := hdr.marshal(rndReader{})
	if err != nil {
		return err
	}
	sealed, err := sealRequestHeader(c.key, plain, rndReader{}, time.Now().Unix())
	if err != nil {
		return err
	}

	reset, err := applyDeadline(ctx, conn)
	if err != nil {
		return err
	}
	defer reset()
	if _, err := conn.Write(sealed); err != nil {
		return fmt.Errorf("vmess: write request header: %w", err)
	}
	return nil
}

// session holds the per-connection key material. Every dial gets a fresh one:
// reusing keys would repeat AEAD nonces.
type session struct {
	bodyKey [16]byte
	bodyIV  [16]byte

	responseKey        [16]byte
	responseIV         [16]byte
	responseHeaderByte byte

	requestCipher  *chunkCipher
	responseCipher *chunkCipher
}

func newSession(security byte) (*session, error) {
	var material [33]byte // IV || key || response header byte
	if err := randomBytes(material[:]); err != nil {
		return nil, err
	}
	s := &session{}
	copy(s.bodyIV[:], material[:16])
	copy(s.bodyKey[:], material[16:32])
	s.responseHeaderByte = material[32]

	// The response direction is keyed from the request material so the server
	// can derive it without extra negotiation.
	bodyKey := sha256.Sum256(s.bodyKey[:])
	copy(s.responseKey[:], bodyKey[:16])
	bodyIV := sha256.Sum256(s.bodyIV[:])
	copy(s.responseIV[:], bodyIV[:16])

	var err error
	if s.requestCipher, err = newChunkCipher(s.bodyKey, s.bodyIV, security); err != nil {
		return nil, err
	}
	if s.responseCipher, err = newChunkCipher(s.responseKey, s.responseIV, security); err != nil {
		return nil, err
	}
	return s, nil
}

// resolveSecurity maps a node's method to the wire security byte. "auto"
// resolves once, at construction, to a concrete scheme: VMess AEAD servers
// reject AUTO in the header.
func resolveSecurity(method string) (byte, error) {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "", "auto":
		if hasAESGCMHardware() {
			return securityAES128GCM, nil
		}
		return securityChaCha20Poly1305, nil
	case "aes-128-gcm", "aes128-gcm", "aes128gcm", "aes-gcm":
		return securityAES128GCM, nil
	case "chacha20-poly1305", "chacha20-ietf-poly1305", "chacha20poly1305":
		return securityChaCha20Poly1305, nil
	case "none", "zero":
		return securityNone, nil
	default:
		return 0, fmt.Errorf("unsupported vmess security %q", method)
	}
}

// hasAESGCMHardware mirrors the reference client: pick AES-128-GCM when the CPU
// can do it quickly, otherwise ChaCha20-Poly1305.
func hasAESGCMHardware() bool {
	if cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ && cpu.X86.HasSSE41 && cpu.X86.HasSSSE3 {
		return true
	}
	// Go's GCM assembly is also fast enough on Apple silicon even without PMULL
	// detection, matching the reference behaviour.
	if (cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) || (runtime.GOOS == "darwin" && runtime.GOARCH == "arm64") {
		return true
	}
	return false
}

// rndReader adapts crypto/rand to the io.Reader the header code expects.
type rndReader struct{}

func (rndReader) Read(p []byte) (int, error) {
	if err := randomBytes(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// splitHostPort is a lenient net.SplitHostPort: a bare host yields port 0.
func splitHostPort(address string) (string, uint16, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", 0, nil
	}
	if h, p, err := net.SplitHostPort(address); err == nil {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return "", 0, fmt.Errorf("vmess: invalid port in %q", address)
		}
		return strings.Trim(h, "[]"), uint16(n), nil
	}
	trimmed := strings.Trim(address, "[]")
	if _, err := netip.ParseAddr(trimmed); err == nil {
		return trimmed, 0, nil
	}
	if strings.Contains(address, ":") {
		return "", 0, fmt.Errorf("vmess: invalid address %q", address)
	}
	return address, 0, nil
}

// applyDeadline mirrors ctx's deadline onto conn and returns a func that clears
// it once the handshake is done.
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

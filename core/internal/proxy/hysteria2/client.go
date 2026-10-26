package hysteria2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"

	"veil/internal/config"
	"veil/internal/outbound"
	"veil/internal/transport"
)

const (
	// dialTimeout bounds a fresh QUIC handshake plus authentication.
	dialTimeout = 10 * time.Second

	defaultIdleTimeout = 30 * time.Second
	keepAlivePeriod    = 10 * time.Second
)

// errClosed is returned once Close has been called.
var errClosed = errors.New("hysteria2: client closed")

// diagWire is the switch for the QUIC socket diagnostics: the datagram counters
// and the wire details a failed dial reports. It exists because a device-session
// handshake failure is otherwise indistinguishable between "nothing was sent"
// (socket captured by the tun, no route), "sent, nothing came back" (server or
// middlebox dropped us) and "something answered that is not the server".
//
// It is off by default and must stay that way: counting costs two atomics per
// sent datagram and an atomic plus a mutex per received one, and wrapping the
// socket hides ReadMsgUDP/WriteMsgUDP from quic-go, which then falls back to its
// basic datagram path. VEIL_DIAG_HY2=1 turns it on for a debugging session.
var diagWire = os.Getenv("VEIL_DIAG_HY2") == "1"

// dialRefusedError means the server answered but refused the target. It is a
// per-request failure, not a connection failure, so the QUIC connection is kept.
type dialRefusedError struct{ msg string }

func (e *dialRefusedError) Error() string {
	return "hysteria2: server refused connection: " + e.msg
}

// Client is one Hysteria2 server. It owns a single lazily established QUIC
// connection shared by all streams and datagram sessions.
type Client struct {
	tag        string
	serverAddr string
	password   string

	tlsConfig  *tls.Config
	quicConfig *quic.Config

	// obfs is the salamander obfuscator the node asks for, nil when the server
	// sends plain QUIC.
	obfs *salamander

	mu      sync.Mutex
	dialMu  sync.Mutex // serialises handshakes so only one runs at a time
	conn    *quic.Conn
	tr      *quic.Transport
	pktConn net.PacketConn
	h3      *h3State
	closed  bool

	// udpDisabled is set when the server's auth response says it does not
	// relay UDP.
	udpDisabled bool

	sessions map[*packetConn]struct{}
}

var (
	_ outbound.Outbound       = (*Client)(nil)
	_ outbound.PacketOutbound = (*Client)(nil)
)

// New builds a Hysteria2 client for n.
//
// Salamander obfuscation is supported: share/hysteria2.go and the Clash importer
// keep "obfs"/"obfs-password" in Transport.Headers (config.Node has no dedicated
// obfs field), and both must match the server exactly or the QUIC handshake
// never completes.
func New(n config.Node) (*Client, error) {
	if n.Password == "" {
		return nil, fmt.Errorf("hysteria2 %s: missing password", n.Tag)
	}
	tlsConfig, err := buildTLSConfig(n)
	if err != nil {
		return nil, err
	}
	obfs, err := obfsFromNode(n)
	if err != nil {
		return nil, fmt.Errorf("hysteria2 %s: %w", n.Tag, err)
	}
	return &Client{
		tag:        n.Tag,
		serverAddr: n.Addr(),
		password:   n.Password,
		tlsConfig:  tlsConfig,
		obfs:       obfs,
		quicConfig: buildQUICConfig(),
		sessions:   make(map[*packetConn]struct{}),
	}, nil
}

func buildTLSConfig(n config.Node) (*tls.Config, error) {
	// Hysteria2 mandates QUIC + TLS 1.3 with ALPN "h3"; the certificate is
	// usually self-signed, hence the insecure flag.
	cfg := &tls.Config{
		ServerName: n.Server,
		NextProtos: []string{alpnH3},
		MinVersion: tls.VersionTLS13,
	}
	if n.TLS != nil {
		if n.TLS.ServerName != "" {
			cfg.ServerName = n.TLS.ServerName
		}
		cfg.InsecureSkipVerify = n.TLS.Insecure
		// ALPN must still offer h3 first; extra protocols are kept after it.
		cfg.NextProtos = []string{alpnH3}
		for _, p := range n.TLS.ALPN {
			if p != "" && p != alpnH3 {
				cfg.NextProtos = append(cfg.NextProtos, p)
			}
		}
		pin, err := certPin(n.TLS.Fingerprint)
		if err != nil {
			return nil, fmt.Errorf("hysteria2 %s: %w", n.Tag, err)
		}
		if pin != nil {
			// A pinned digest replaces the CA chain, so chain verification has
			// to step aside for it: with skip-cert-verify=false a self-signed
			// server would otherwise be rejected before the pin is looked at.
			cfg.InsecureSkipVerify = true
			cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return errors.New("hysteria2: server presented no certificate")
				}
				got := sha256.Sum256(rawCerts[0])
				if !bytes.Equal(got[:], pin) {
					return fmt.Errorf("hysteria2: certificate fingerprint mismatch: got %x want %x", got, pin)
				}
				return nil
			}
		}
	}
	return cfg, nil
}

// utlsFingerprintNames lists the tls.fingerprint values that name a uTLS
// profile instead of pinning a certificate: exactly the spellings
// transport.fingerprintIDs accepts (internal/transport/tls.go). Keep the two
// lists in sync — that resolver is unexported and transport must not grow an
// export just for this package, so the canonical names come from transport's
// constants and the remaining utls spellings are written out here.
//
// This is a whitelist, not a shape test. "Contains a non-hex character" is no
// evidence that the user meant a profile name; guessing that is what let a
// one-character typo in a digest drop the certificate constraint entirely.
var utlsFingerprintNames = []string{
	transport.FingerprintChrome, "hellochrome",
	transport.FingerprintFirefox, "hellofirefox",
	transport.FingerprintSafari, "hellosafari",
	transport.FingerprintIOS, "helloios",
	transport.FingerprintAndroid, "helloandroid",
	transport.FingerprintEdge, "helloedge",
	transport.FingerprintRandomized, "random", "hellorandomized",
}

// isUTLSFingerprint reports whether name (already trimmed and lower-cased) is a
// uTLS profile name transport would resolve.
func isUTLSFingerprint(name string) bool {
	for _, n := range utlsFingerprintNames {
		if name == n {
			return true
		}
	}
	return false
}

// certPin decodes the SHA-256 digest of the server certificate carried in
// tls.fingerprint, which Hysteria2 nodes use instead of a CA chain (colons are
// accepted as separators, matching openssl and Clash output; hex is
// case-insensitive).
//
// tls.fingerprint is also where other protocols keep the uTLS fingerprint name
// ("chrome", "firefox", ...), so a *known* profile name still means "no pin":
// this package uses crypto/tls, cannot apply the profile, and keeps the CA
// behaviour it had before.
//
// Everything else must decode as a digest. A value that is neither a known
// profile name nor a SHA-256 pin is an error, because reporting "no pin" for a
// mistyped digest silently removes the only authentication constraint the node
// has and lets the client talk to any self-signed peer.
func certPin(fingerprint string) ([]byte, error) {
	name := strings.ToLower(strings.TrimSpace(fingerprint))
	if name == "" {
		return nil, nil
	}
	if isUTLSFingerprint(name) {
		return nil, nil
	}
	bare := strings.NewReplacer(":", "", " ", "").Replace(name)
	for _, c := range bare {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, fmt.Errorf("tls.fingerprint %q: not a SHA-256 certificate pin and not a known uTLS fingerprint (%s)",
				fingerprint, strings.Join(utlsFingerprintNames, ", "))
		}
	}
	pin, err := hex.DecodeString(bare)
	if err != nil {
		// Hex digits only, so the user meant a pin and mistyped its length.
		return nil, fmt.Errorf("tls.fingerprint %q: %w", fingerprint, err)
	}
	if len(pin) != sha256.Size {
		return nil, fmt.Errorf("tls.fingerprint %q: want a %d-byte SHA-256 digest, got %d bytes",
			fingerprint, sha256.Size, len(pin))
	}
	return pin, nil
}

func buildQUICConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:                 defaultIdleTimeout,
		KeepAlivePeriod:                keepAlivePeriod,
		EnableDatagrams:                true,
		InitialStreamReceiveWindow:     4 << 20,
		MaxStreamReceiveWindow:         8 << 20,
		InitialConnectionReceiveWindow: 8 << 20,
		MaxConnectionReceiveWindow:     16 << 20,
	}
}

// obfsFromNode returns the obfuscator the node asks for, or nil for plain QUIC.
// The settings are carried in Transport.Headers ("obfs", "obfs-password") by the
// share and Clash importers; anything but salamander would silently mismatch the
// server, so an unknown type is an error rather than a no-op.
func obfsFromNode(n config.Node) (*salamander, error) {
	if n.Transport == nil {
		return nil, nil
	}
	kind := strings.ToLower(strings.TrimSpace(n.Transport.Headers["obfs"]))
	switch kind {
	case "", "none":
		return nil, nil
	case "salamander":
	default:
		return nil, fmt.Errorf("unsupported obfs %q", n.Transport.Headers["obfs"])
	}
	return newSalamander(n.Transport.Headers["obfs-password"])
}

// Tag implements outbound.Outbound.
func (c *Client) Tag() string { return c.tag }

// Type implements outbound.Outbound.
func (c *Client) Type() string { return "hysteria2" }

// Close tears down the QUIC connection and every datagram session.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	sessions := make([]*packetConn, 0, len(c.sessions))
	for s := range c.sessions {
		sessions = append(sessions, s)
	}
	c.sessions = nil
	conn, tr, pkt := c.conn, c.tr, c.pktConn
	c.conn, c.tr, c.pktConn = nil, nil, nil
	c.mu.Unlock()

	for _, s := range sessions {
		_ = s.Close()
	}
	if conn != nil {
		_ = conn.CloseWithError(0, "")
	}
	if tr != nil {
		_ = tr.Close()
	}
	if pkt != nil {
		_ = pkt.Close()
	}
	return nil
}

// invalidate drops conn if it is still the connection we are using, so the next
// call dials a fresh one.
func (c *Client) invalidate(conn *quic.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != conn {
		return
	}
	c.dropLocked()
}

func (c *Client) dropLocked() {
	conn, tr, pkt := c.conn, c.tr, c.pktConn
	c.conn, c.tr, c.pktConn = nil, nil, nil
	if conn != nil {
		_ = conn.CloseWithError(0, "")
	}
	if tr != nil {
		_ = tr.Close()
	}
	if pkt != nil {
		_ = pkt.Close()
	}
}

// getConn returns the shared QUIC connection, dialing and authenticating it on
// first use or after a failure.
func (c *Client) getConn(ctx context.Context) (*quic.Conn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errClosed
	}
	if c.conn != nil {
		select {
		case <-c.conn.Context().Done():
			c.dropLocked()
		default:
			conn := c.conn
			c.mu.Unlock()
			return conn, nil
		}
	}
	c.mu.Unlock()

	// Dial without holding the lock would race with other dialers; hold a
	// dedicated mutex so exactly one handshake happens at a time.
	c.dialMu.Lock()
	defer c.dialMu.Unlock()

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errClosed
	}
	if c.conn != nil {
		select {
		case <-c.conn.Context().Done():
			c.dropLocked()
		default:
			conn := c.conn
			c.mu.Unlock()
			return conn, nil
		}
	}
	c.mu.Unlock()

	conn, tr, pkt, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.CloseWithError(0, "")
		_ = tr.Close()
		_ = pkt.Close()
		return nil, errClosed
	}
	c.conn, c.tr, c.pktConn = conn, tr, pkt
	c.mu.Unlock()
	return conn, nil
}

func (c *Client) dial(ctx context.Context) (*quic.Conn, *quic.Transport, net.PacketConn, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dialTimeout)
		defer cancel()
	}
	serverAddr, err := c.resolveServer(ctx, dnsResolver)
	if err != nil {
		return nil, nil, nil, err
	}
	pkt, err := listenPacket(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("hysteria2 %s: %w", c.tag, err)
	}
	// Obfuscation sits above the protected socket: every datagram QUIC puts on
	// the wire is wrapped, and the fd was already handed to the protector. The
	// diagnostics switch adds the packet counters on top; see wrapDiag.
	pkt, outer, raw := c.wrapDiag(pkt)

	tr := &quic.Transport{Conn: pkt}
	// quic-go wants an address for the transport; listen on the unspecified
	// address of the same family as the server.
	conn, err := tr.Dial(ctx, serverAddr, c.tlsConfig, c.quicConfig)
	if err != nil {
		var local net.Addr
		if diagWire {
			local = pkt.LocalAddr()
		}
		_ = tr.Close()
		_ = pkt.Close()
		return nil, nil, nil, c.dialError(serverAddr, local, outer, raw, err)
	}
	if err := c.authenticate(ctx, conn); err != nil {
		_ = conn.CloseWithError(0, "")
		_ = tr.Close()
		_ = pkt.Close()
		return nil, nil, nil, err
	}
	return conn, tr, pkt, nil
}

// wrapDiag turns the freshly opened socket into the one quic-go dials on.
//
// The obfs layer always applies — it is what the server speaks. The counting
// shims exist only when diagWire is on, and then the raw counter sits under the
// obfs layer: comparing it with the outer counter tells "the server answered
// with obfuscated bytes we decoded into garbage" apart from "the server answered
// in plaintext". With the switch off the socket comes back as it went in: no
// wrapper, no allocation, no lock on the packet path.
func (c *Client) wrapDiag(pkt net.PacketConn) (conn net.PacketConn, outer, raw *countingConn) {
	if !diagWire {
		if c.obfs != nil {
			pkt = newSalamanderConn(pkt, c.obfs)
		}
		return pkt, nil, nil
	}
	if c.obfs != nil {
		// Without obfs the two counters would tally exactly the same datagrams,
		// so the raw one is only worth its wrapper when something sits between.
		raw = &countingConn{PacketConn: pkt}
		pkt = newSalamanderConn(raw, c.obfs)
	}
	outer = &countingConn{PacketConn: pkt}
	return outer, outer, raw
}

// dialError reports a failed QUIC dial.
//
// The counters and the first datagram's source and leading bytes are diagnostics,
// not error detail: they are attached only when diagWire is on, so an ordinary
// log line never carries raw network bytes.
func (c *Client) dialError(serverAddr, local net.Addr, outer, raw *countingConn, err error) error {
	if !diagWire || outer == nil {
		return fmt.Errorf("hysteria2 %s: quic dial %s: %w", c.tag, serverAddr, err)
	}
	localDesc := "unknown"
	if local != nil {
		localDesc = local.String()
	}
	return fmt.Errorf("hysteria2 %s: quic dial %s: %w (local %s, wire %s, raw %s)",
		c.tag, serverAddr, err, localDesc, outer, rawOrUncounted(raw))
}

// rawOrUncounted renders the under-obfs counter, which only exists when the node
// asks for obfs.
func rawOrUncounted(raw *countingConn) string {
	if raw == nil {
		return "not counted (no obfs)"
	}
	return raw.String()
}

// countingConn tallies datagrams so a failed QUIC dial can report whether the
// socket put anything on the wire at all. It is a diagnostics shim: dial wraps a
// socket with it only when diagWire is on.
type countingConn struct {
	net.PacketConn
	sentPkts, sentBytes, recvPkts, recvBytes atomic.Int64

	// First datagram that came back: its source and leading bytes are what tells
	// a QUIC version negotiation apart from a Retry, an ICMP-driven error or a
	// middlebox talking to us.
	recvMu    sync.Mutex
	firstFrom string
	firstRecv []byte
}

func (c *countingConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if n > 0 {
		c.sentPkts.Add(1)
		c.sentBytes.Add(int64(n))
	}
	return n, err
}

func (c *countingConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if n > 0 {
		c.recvPkts.Add(1)
		c.recvBytes.Add(int64(n))
		c.recvMu.Lock()
		if c.firstFrom == "" {
			c.firstFrom = addr.String()
			head := n
			if head > 24 {
				head = 24
			}
			c.firstRecv = append([]byte(nil), p[:head]...)
		}
		c.recvMu.Unlock()
	}
	return n, addr, err
}

// SyscallConn forwards to the socket underneath every wrapper. quic-go and the
// protect test both reach for the raw descriptor through it; hiding it behind a
// counting shim silently disables socket options (buffer sizing, PMTU).
func (c *countingConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.PacketConn.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, fmt.Errorf("hysteria2: %T exposes no syscall handle", c.PacketConn)
}

// SetReadBuffer / SetWriteBuffer keep quic-go's socket tuning working through
// the counter.
func (c *countingConn) SetReadBuffer(n int) error {
	if u, ok := c.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return u.SetReadBuffer(n)
	}
	return nil
}

func (c *countingConn) SetWriteBuffer(n int) error {
	if u, ok := c.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return u.SetWriteBuffer(n)
	}
	return nil
}

func (c *countingConn) String() string {
	c.recvMu.Lock()
	from, head := c.firstFrom, append([]byte(nil), c.firstRecv...)
	c.recvMu.Unlock()
	s := fmt.Sprintf("sent %d pkts/%d B, recv %d pkts/%d B",
		c.sentPkts.Load(), c.sentBytes.Load(), c.recvPkts.Load(), c.recvBytes.Load())
	if from != "" {
		s += fmt.Sprintf(", first from %s head %x", from, head)
	}
	return s
}

// listenPacket opens the UDP socket the QUIC transport rides on. The Control
// hook runs transport.ProtectFD while the socket is still unbound, so on
// HarmonyOS the descriptor reaches VpnConnection.protect before the first
// datagram: an unprotected socket would be captured by our own tun and the
// tunnel would eat its own packets (AGENTS.md invariant 1). transport only
// offers UDP protection as a standalone helper, so the ListenConfig lives here
// instead of using net.ListenUDP.
func listenPacket(ctx context.Context) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var perr error
		if err := c.Control(func(fd uintptr) {
			perr = transport.ProtectFD(fd)
		}); err != nil {
			return err
		}
		return perr
	}}
	return lc.ListenPacket(ctx, "udp", ":0")
}

// dnsResolver turns a node's server name into an address. Dialing through
// transport is the point: net.DefaultResolver uses an unpatched net.Dialer, so
// the nameserver socket never reaches VpnConnection.protect and the query is
// captured by our own tun exactly like an unprotected QUIC socket would be
// (AGENTS.md invariant 1). PreferGo keeps the Go resolver in charge where cgo
// is available, because the cgo resolver ignores Dial and would go back to an
// unprotected socket; the OHOS build is CGO_ENABLED=0 and already netgo.
var dnsResolver = &net.Resolver{PreferGo: true, Dial: protectedDial}

// protectedDial is the resolver's Dial hook: a protect-aware socket to the
// nameserver the system resolver configuration points at.
func protectedDial(ctx context.Context, network, address string) (net.Conn, error) {
	return transport.NewDialer().DialContext(ctx, network, address)
}

// resolveServer turns the node's server into the UDP address quic-go dials. r is
// dnsResolver outside tests; it is a parameter so a test can aim the lookup at
// a local nameserver while the production dial hook stays in the path.
func (c *Client) resolveServer(ctx context.Context, r *net.Resolver) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(c.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("hysteria2 %s: %w", c.tag, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("hysteria2 %s: bad port %q", c.tag, portStr)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip.Unmap(), uint16(port))), nil
	}
	ips, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("hysteria2 %s: resolve %s: %w", c.tag, host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("hysteria2 %s: no address for %s", c.tag, host)
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ips[0].Unmap(), uint16(port))), nil
}

// authenticate performs the HTTP/3 auth exchange on the freshly dialed
// connection. The request is a plain POST to https://hysteria/auth; the server
// answers 233 when the credential is accepted.
func (c *Client) authenticate(ctx context.Context, conn *quic.Conn) error {
	h3, err := openH3Streams(ctx, conn)
	if err != nil {
		return fmt.Errorf("hysteria2 %s: open h3 streams: %w", c.tag, err)
	}
	fields, err := h3Request(ctx, conn, authHost, authPath, []headerField{
		{headerAuth, c.password},
		// A receive rate of 0 means "unknown"; the server then reports the
		// bandwidth it measures, which we ignore.
		{headerCCRX, "0"},
		{headerPadding, randomPadding(authPaddingMin, authPaddingMax)},
	})
	if err != nil {
		return fmt.Errorf("hysteria2 %s: auth request: %w", c.tag, err)
	}
	status, err := statusOf(fields)
	if err != nil {
		return fmt.Errorf("hysteria2 %s: %w", c.tag, err)
	}
	if status != statusAuth {
		return fmt.Errorf("hysteria2 %s: authentication failed (status %d)", c.tag, status)
	}
	// The server tells us whether it relays UDP; absence means yes.
	if v := headerValue(fields, headerUDPEnabled); v != "" {
		if enabled, perr := strconv.ParseBool(v); perr == nil && !enabled {
			c.udpDisabled = true
		}
	}
	// The HTTP/3 control and QPACK streams must stay open for the lifetime of
	// the connection, so the client owns them.
	c.h3 = h3
	return nil
}

// DialContext opens a proxied TCP stream to address ("host:port").
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "", "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("hysteria2 %s: unsupported network %q", c.tag, network)
	}
	addr, err := normalizeAddr(address)
	if err != nil {
		return nil, err
	}
	stream, conn, err := c.openStream(ctx, addr)
	if err != nil {
		return nil, err
	}
	tc := &tcpConn{stream: stream, conn: conn}
	// Opening the stream and waiting for the server's answer can take a while;
	// do not hand out a connection whose caller already gave up.
	if err := ctx.Err(); err != nil {
		_ = tc.Close()
		return nil, err
	}
	return tc, nil
}

func (c *Client) openStream(ctx context.Context, addr string) (*quic.Stream, *quic.Conn, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := c.getConn(ctx)
		if err != nil {
			return nil, nil, err
		}
		stream, err := conn.OpenStreamSync(ctx)
		if err == nil {
			if err = writeTCPRequest(stream, addr); err == nil {
				err = readTCPResponse(stream)
			}
			if err == nil {
				return stream, conn, nil
			}
			stream.CancelRead(0)
			stream.CancelWrite(0)
		}
		var refused *dialRefusedError
		if errors.As(err, &refused) {
			// The connection is healthy; the request itself was rejected.
			return nil, conn, err
		}
		lastErr = err
		c.invalidate(conn)
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
	}
	return nil, nil, fmt.Errorf("hysteria2 %s: open stream: %w", c.tag, lastErr)
}

// tcpConn adapts a QUIC stream to net.Conn.
type tcpConn struct {
	stream *quic.Stream
	conn   *quic.Conn
}

func (t *tcpConn) Read(p []byte) (int, error)  { return t.stream.Read(p) }
func (t *tcpConn) Write(p []byte) (int, error) { return t.stream.Write(p) }
func (t *tcpConn) Close() error {
	t.stream.CancelRead(0)
	return t.stream.Close()
}

func (t *tcpConn) LocalAddr() net.Addr  { return t.conn.LocalAddr() }
func (t *tcpConn) RemoteAddr() net.Addr { return t.conn.RemoteAddr() }

func (t *tcpConn) SetDeadline(deadline time.Time) error {
	return t.stream.SetDeadline(deadline)
}

func (t *tcpConn) SetReadDeadline(deadline time.Time) error {
	return t.stream.SetReadDeadline(deadline)
}

func (t *tcpConn) SetWriteDeadline(deadline time.Time) error {
	return t.stream.SetWriteDeadline(deadline)
}

// DialPacket opens a UDP session. address is the initial target; Hysteria2
// carries the destination in every datagram, so it is only advisory.
func (c *Client) DialPacket(ctx context.Context, address string) (outbound.PacketConn, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	session := uint32(0)
	for session == 0 {
		b := make([]byte, 4)
		if _, err := randRead(b); err != nil {
			return nil, err
		}
		session = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	}
	pc := &packetConn{
		c:         c,
		conn:      conn,
		sessionID: session,
		frags:     make(map[uint16]*fragState),
		closed:    make(chan struct{}),
		buf:       make([]byte, maxUDPSize),
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errClosed
	}
	c.sessions[pc] = struct{}{}
	c.mu.Unlock()
	return pc, nil
}

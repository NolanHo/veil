package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"

	"veil/internal/transport"
)

// bind is the UDP socket WireGuard talks to its peer through.
//
// conn.NewDefaultBind cannot be used: it creates its sockets with net.ListenUDP,
// which on HarmonyOS is captured by the tun we own, so the encrypted packets
// would be forwarded back into the tunnel we are trying to build. Here the
// socket goes through a net.ListenConfig Control hook, i.e. the same
// transport.ProtectFD hook every other socket in the core uses.
//
// Batching is not implemented (the peer count is one and the traffic profile is
// a homelab link), so one packet is read and written per syscall.
type bind struct {
	tag string

	mu sync.Mutex
	pc *net.UDPConn
}

var _ conn.Bind = (*bind)(nil)

func newBind(tag string) *bind { return &bind{tag: tag} }

// Open implements conn.Bind. A port of zero lets the kernel pick one; the
// returned port is what the peer receives replies from.
func (b *bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pc != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	pc, err := listenUDP(port)
	if err != nil {
		return nil, 0, fmt.Errorf("wireguard %s: %w", b.tag, err)
	}
	b.pc = pc
	actual := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	return []conn.ReceiveFunc{b.receive}, actual, nil
}

// Close implements conn.Bind. Every ReceiveFunc returns net.ErrClosed after it.
func (b *bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pc == nil {
		return nil
	}
	pc := b.pc
	b.pc = nil
	return pc.Close()
}

// SetMark implements conn.Bind. SO_MARK does not exist on HarmonyOS; packets are
// kept out of the tun by protect() instead.
func (b *bind) SetMark(uint32) error { return nil }

// BatchSize implements conn.Bind.
func (b *bind) BatchSize() int { return 1 }

// Send implements conn.Bind.
func (b *bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(*endpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	if len(bufs) != 1 || len(bufs[0]) == 0 {
		return nil
	}
	b.mu.Lock()
	pc := b.pc
	b.mu.Unlock()
	if pc == nil {
		return net.ErrClosed
	}
	_, err := pc.WriteToUDPAddrPort(bufs[0], e.addr)
	return err
}

// ParseEndpoint implements conn.Bind. WireGuard endpoints are literal ip:port;
// config.Node.Server is resolved before the device is configured.
func (b *bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, fmt.Errorf("wireguard %s: bad endpoint %q: %w", b.tag, s, err)
	}
	return &endpoint{addr: ap}, nil
}

// receive is the single ReceiveFunc of this bind.
func (b *bind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	b.mu.Lock()
	pc := b.pc
	b.mu.Unlock()
	if pc == nil {
		return 0, net.ErrClosed
	}
	n, addr, err := pc.ReadFromUDPAddrPort(packets[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	// A fresh endpoint per packet: the device hands it to its encryption queue,
	// which reads it after this goroutine has moved on.
	eps[0] = &endpoint{addr: addr}
	return 1, nil
}

// endpoint is a peer address. Only the destination half is meaningful: the core
// has exactly one peer and no socket-source caching to do.
type endpoint struct {
	addr netip.AddrPort
}

var _ conn.Endpoint = (*endpoint)(nil)

func (e *endpoint) ClearSrc()           {}
func (e *endpoint) SrcToString() string { return "" }
func (e *endpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *endpoint) DstToString() string { return e.addr.String() }
func (e *endpoint) DstIP() netip.Addr   { return e.addr.Addr() }

func (e *endpoint) DstToBytes() []byte {
	b, _ := e.addr.MarshalBinary()
	return b
}

// listenUDP opens the peer socket with the protect hook installed.
func listenUDP(port uint16) (*net.UDPConn, error) {
	// ListenConfig.Control runs after the descriptor exists and before it is
	// bound, which is exactly where VpnConnection.protect(fd) has to land.
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var perr error
			if err := c.Control(func(fd uintptr) { perr = transport.ProtectFD(fd) }); err != nil {
				return err
			}
			return perr
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", ":"+strconv.Itoa(int(port)))
	if err != nil {
		return nil, fmt.Errorf("open peer socket: %w", err)
	}
	udp, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("open peer socket: unexpected type %T", pc)
	}
	// Belt and braces: protect once more on the bound descriptor. protect() is
	// idempotent and this catches a platform where the control hook is skipped.
	rc, err := udp.SyscallConn()
	if err != nil {
		_ = udp.Close()
		return nil, fmt.Errorf("open peer socket: %w", err)
	}
	var perr error
	if err := rc.Control(func(fd uintptr) { perr = transport.ProtectFD(fd) }); err != nil {
		_ = udp.Close()
		return nil, fmt.Errorf("open peer socket: %w", err)
	}
	if perr != nil {
		_ = udp.Close()
		return nil, fmt.Errorf("protect peer socket: %w", perr)
	}
	return udp, nil
}

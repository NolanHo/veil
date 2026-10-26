package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"veil/internal/outbound"
	"veil/internal/transport"
)

// bufPool recycles 32 KiB relay buffers; a long-lived proxy must not allocate a
// fresh buffer for every megabyte it moves.
var bufPool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}

// idleTimeout bounds how long a half-dead connection can occupy a slot.
const idleTimeout = 10 * time.Minute

// HandleTCP implements inbound.Handler and the netstack TCP forwarder.
func (e *Engine) HandleTCP(ctx context.Context, client net.Conn, target, source string) error {
	ob, action, target, err := e.route(ctx, "tcp", target)
	if err != nil {
		_ = client.Close()
		return err
	}
	upstream, err := dialOutbound(ctx, ob, "tcp", target)
	if err != nil {
		// Warn level on purpose: this is the line that tells us (and the user)
		// which hop broke — the in-app log viewer shows it without a debugger.
		e.log.Warnf("tcp %s via %s failed: %v", target, ob.Tag(), err)
		_ = client.Close()
		return err
	}
	e.log.Debugf("tcp %s via %s (%s)", target, ob.Tag(), action.Rule)

	tracked := e.stats.conns.Add(&Conn{
		Network:  "tcp",
		Source:   source,
		Dest:     target,
		Outbound: ob.Tag(),
		Rule:     action.Rule,
		Chain:    ob.Type(),
		closer:   upstream,
	})
	if tracked == nil {
		e.log.Warnf("connection limit reached, dropping %s -> %s", source, target)
		_ = upstream.Close()
		_ = client.Close()
		return errors.New("connection limit reached")
	}
	e.stats.active.Add(1)
	e.stats.totalConn.Add(1)
	defer func() {
		e.stats.active.Add(-1)
		e.stats.conns.Remove(tracked.ID)
		_ = tracked.Close()
		_ = client.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pipe(upstream, client, &tracked.up, e.stats.AddUp)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		pipe(client, upstream, &tracked.down, e.stats.AddDown)
		if cw, ok := client.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
	return nil
}

// pipe copies src to dst, counting bytes and refreshing the read deadline so a
// silently dead peer cannot pin resources forever.
func pipe(dst, src net.Conn, counter *atomic.Int64, global func(int64)) {
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := *bp
	for {
		_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := src.Read(buf)
		if n > 0 {
			if counter != nil {
				counter.Add(int64(n))
			}
			if global != nil {
				global(int64(n))
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// udpSession is a cached UDP association for one outbound + destination.
type udpSession struct {
	pc   outbound.PacketConn
	ob   string
	mu   sync.Mutex
	last time.Time
}

// udpKey identifies a UDP association.
type udpKey struct {
	ob     string
	target string
}

// HandleUDP implements inbound.Handler: one datagram in, one datagram out.
func (e *Engine) HandleUDP(ctx context.Context, payload []byte, target, source string) ([]byte, error) {
	// DNS hijack: anything aimed at :53 is answered locally through the
	// resolver (which can itself detour over a proxy).
	e.mu.RLock()
	resolver := e.resolver
	e.mu.RUnlock()
	if resolver != nil {
		if _, port, err := net.SplitHostPort(target); err == nil && port == "53" {
			rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			return resolver.Exchange(rctx, payload)
		}
	}

	ob, _, routed, err := e.route(ctx, "udp", target)
	if err != nil {
		return nil, err
	}
	target = routed
	po, ok := ob.(outbound.PacketOutbound)
	if !ok {
		// e.g. VLESS with xtls-rprx-vision: Xray requires UDP to ride on MUX,
		// which we have not implemented. This used to fall back to a direct
		// association "so QUIC does not stall", which quietly sent the traffic
		// out of the local interface — from the wrong address, outside the
		// chain, and for a rule that said "this subnet goes through the
		// tunnel". Failing lets the application fall back to TCP.
		return nil, fmt.Errorf("udp via %s is not supported by this outbound", ob.Tag())
	}

	key := udpKey{ob: ob.Tag(), target: target}
	s := e.getUDPSession(ctx, po, key)
	if s == nil {
		return nil, errors.New("cannot open udp association")
	}

	ap, err := e.udpAddr(target)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = time.Now()

	if _, err := s.pc.WriteTo(payload, ap); err != nil {
		e.dropUDPSession(key, s)
		return nil, err
	}
	_ = s.pc.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64*1024)
	n, _, err := s.pc.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (e *Engine) getUDPSession(ctx context.Context, po outbound.PacketOutbound, key udpKey) *udpSession {
	if v, ok := e.udpCache.Load(key); ok {
		return v.(*udpSession)
	}
	// VLESS/XUDP takes ip:port only. Resolve the domain once here: QUIC-heavy
	// apps emit hundreds of datagrams per second, and failing (plus logging)
	// on each of them starves the ArkTS main thread (THREAD_BLOCK_3S).
	target := key.target
	if ap, aerr := e.udpAddr(target); aerr == nil {
		target = ap.String()
	}
	pc, err := po.DialPacket(ctx, target)
	if err != nil {
		e.log.Debugf("udp dial %s via %s: %v", target, key.ob, err)
		return nil
	}
	s := &udpSession{pc: pc, ob: key.ob, last: time.Now()}
	actual, loaded := e.udpCache.LoadOrStore(key, s)
	if loaded {
		_ = pc.Close()
		return actual.(*udpSession)
	}
	e.udpSessions.Add(1)
	// No per-session timer: idle associations are swept lazily when a new one is
	// created, so an idle engine has zero wakeups.
	e.sweepIdleUDP()
	return s
}

func (e *Engine) dropUDPSession(key udpKey, s *udpSession) {
	if e.udpCache.CompareAndDelete(key, s) {
		e.udpSessions.Add(-1)
		_ = s.pc.Close()
	}
}

// sweepIdleUDP closes associations that have been idle for over a minute.
// Called on UDP session creation; safe to run concurrently.
func (e *Engine) sweepIdleUDP() {
	now := time.Now()
	e.udpCache.Range(func(k, v any) bool {
		s, ok := v.(*udpSession)
		if !ok {
			return true
		}
		s.mu.Lock()
		idle := now.Sub(s.last) > 60*time.Second
		s.mu.Unlock()
		if idle {
			e.dropUDPSession(k.(udpKey), s)
		}
		return true
	})
}

// directUDP sends one datagram outside the tunnel.
func (e *Engine) directUDP(ctx context.Context, payload []byte, target string) ([]byte, error) {
	ap, err := e.udpAddr(target)
	if err != nil {
		return nil, err
	}
	conn, err := transport.NewDialer().DialContext(ctx, "udp", net.JoinHostPort(ap.Addr().String(), fmt.Sprint(ap.Port())))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	buf := make([]byte, 64*1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// udpAddr converts a target to an address, resolving a domain if needed.
func (e *Engine) udpAddr(target string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(target); err == nil {
		return ap, nil
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ap, err := e.resolveTarget(context.Background(), host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	p, err := net.LookupPort("udp", port)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ap.Addr(), uint16(p)), nil
}

// ActiveUDPSessions reports the number of cached UDP associations.
func (e *Engine) ActiveUDPSessions() int64 { return e.udpSessions.Load() }

package hysteria2

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// diagSwitch flips the diagnostics switch for one test and restores it.
func diagSwitch(t *testing.T, on bool) {
	t.Helper()
	prev := diagWire
	diagWire = on
	t.Cleanup(func() { diagWire = prev })
}

// countingStub is a datagram socket that reports how often it was used, so a
// test can tell a pass-through from a layer on top.
type countingStub struct {
	mu     sync.Mutex
	reads  int
	writes int
}

var _ net.PacketConn = (*countingStub)(nil)

func (s *countingStub) ReadFrom(p []byte) (int, net.Addr, error) {
	s.mu.Lock()
	s.reads++
	s.mu.Unlock()
	return copy(p, "quic"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, nil
}

func (s *countingStub) WriteTo(p []byte, _ net.Addr) (int, error) {
	s.mu.Lock()
	s.writes++
	s.mu.Unlock()
	return len(p), nil
}

func (s *countingStub) Close() error                     { return nil }
func (s *countingStub) LocalAddr() net.Addr              { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }
func (s *countingStub) SetDeadline(time.Time) error      { return nil }
func (s *countingStub) SetReadDeadline(time.Time) error  { return nil }
func (s *countingStub) SetWriteDeadline(time.Time) error { return nil }

func (s *countingStub) counts() (reads, writes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads, s.writes
}

// TestDiagnosticsOffKeepsTheSocketUnwrapped is the zero-overhead regression.
//
// The counters were once unconditional: every dial lay a counting shim over the
// socket (two of them without obfs), which put two atomics on every sent packet
// and a mutex on every received one. With the switch off the conn quic-go dials
// on has to be the socket that was opened: same value, no wrapper, no counters.
func TestDiagnosticsOffKeepsTheSocketUnwrapped(t *testing.T) {
	diagSwitch(t, false)
	stub := &countingStub{}
	c := &Client{tag: "diag"}

	conn, outer, raw := c.wrapDiag(stub)
	if conn != net.PacketConn(stub) {
		t.Fatalf("wrapDiag with diagnostics off returned %T, want the socket itself", conn)
	}
	if outer != nil || raw != nil {
		t.Fatalf("wrapDiag with diagnostics off allocated counters: outer = %v, raw = %v", outer, raw)
	}
	if _, ok := conn.(*countingConn); ok {
		t.Fatal("wrapDiag with diagnostics off wrapped the socket in a countingConn")
	}

	// Nothing sits between the caller and the socket either.
	if _, err := conn.WriteTo([]byte("ping"), stub.LocalAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if _, _, err := conn.ReadFrom(make([]byte, 8)); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if reads, writes := stub.counts(); reads != 1 || writes != 1 {
		t.Fatalf("the socket saw %d reads / %d writes, want one of each", reads, writes)
	}

	// Obfs is a feature, not a diagnostic: it still wraps, but no counter does.
	obfs, err := newSalamander("obfs-test")
	if err != nil {
		t.Fatalf("newSalamander: %v", err)
	}
	c.obfs = obfs
	conn, outer, raw = c.wrapDiag(&countingStub{})
	if _, ok := conn.(*countingConn); ok {
		t.Fatalf("wrapDiag with obfs and diagnostics off returned a countingConn")
	}
	if _, ok := conn.(*salamanderConn); !ok {
		t.Fatalf("wrapDiag with obfs returned %T, want the obfs wrapper", conn)
	}
	if outer != nil || raw != nil {
		t.Fatalf("wrapDiag with obfs and diagnostics off allocated counters: outer = %v, raw = %v", outer, raw)
	}
}

// TestDiagnosticsOnCountsDatagrams is the other half: the switch still does what
// it was written for, so the diagnostics stay usable on device.
func TestDiagnosticsOnCountsDatagrams(t *testing.T) {
	diagSwitch(t, true)
	c := &Client{tag: "diag"}

	conn, outer, raw := c.wrapDiag(&countingStub{})
	if outer == nil || conn != net.PacketConn(outer) {
		t.Fatalf("wrapDiag with diagnostics on returned %T and outer %v", conn, outer)
	}
	if raw != nil {
		t.Fatalf("wrapDiag without obfs allocated the under-obfs counter %v", raw)
	}
	if _, _, err := conn.ReadFrom(make([]byte, 8)); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if got := outer.recvPkts.Load(); got != 1 {
		t.Fatalf("received packets counted %d, want 1", got)
	}
	if summary := outer.String(); !strings.Contains(summary, "first from 127.0.0.1:9 head 71756963") {
		t.Fatalf("summary %q does not carry the first datagram's source and head", summary)
	}

	// With obfs the raw counter sits underneath, so the two tallies can differ.
	obfs, err := newSalamander("obfs-test")
	if err != nil {
		t.Fatalf("newSalamander: %v", err)
	}
	c.obfs = obfs
	base := &countingStub{}
	conn, outer, raw = c.wrapDiag(base)
	if outer == nil || raw == nil {
		t.Fatalf("wrapDiag with obfs and diagnostics on: outer = %v, raw = %v", outer, raw)
	}
	if outer == raw {
		t.Fatal("wrapDiag put the outer and the under-obfs counter on the same socket")
	}
	if raw.PacketConn != net.PacketConn(base) {
		t.Fatalf("the under-obfs counter wraps %T, want the raw socket", raw.PacketConn)
	}
	// The outer counter sits on the obfs layer, which keeps the udpLikeConn
	// forwarding the raw counter provides (socket buffers, PMTU), so either
	// obfs wrapper is correct here.
	switch outer.PacketConn.(type) {
	case *salamanderConn, *salamanderUDPConn:
	default:
		t.Fatalf("the outer counter wraps %T, want the obfs layer", outer.PacketConn)
	}
	if conn != net.PacketConn(outer) {
		t.Fatalf("wrapDiag returned %T, want the outer counter", conn)
	}
}

// TestFailedDialOmitsWireBytesUnlessDiagnosticsOn checks where the diagnostics
// end up: with the switch off a failed dial's error is the network failure and
// nothing else, while turning the switch on re-attaches the counters and the
// first datagram's source and header bytes.
func TestFailedDialOmitsWireBytesUnlessDiagnosticsOn(t *testing.T) {
	newClient := func() *Client {
		return &Client{
			tag:        "diag",
			serverAddr: "127.0.0.1:1",
			tlsConfig: &tls.Config{
				ServerName: "diag.test",
				NextProtos: []string{alpnH3},
				MinVersion: tls.VersionTLS13,
			},
			quicConfig: buildQUICConfig(),
		}
	}
	failDial := func(t *testing.T) error {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		_, _, _, err := newClient().dial(ctx)
		if err == nil {
			t.Fatal("dialing a loopback port with nothing behind it succeeded")
		}
		return err
	}

	t.Run("off", func(t *testing.T) {
		diagSwitch(t, false)
		err := failDial(t)
		if !strings.Contains(err.Error(), "quic dial") {
			t.Fatalf("error %q does not name the failed QUIC dial", err)
		}
		for _, unwanted := range []string{"wire ", "first from", "head ", "(local "} {
			if strings.Contains(err.Error(), unwanted) {
				t.Fatalf("error %q carries the wire diagnostics %q with diagnostics off", err, unwanted)
			}
		}
	})

	t.Run("on", func(t *testing.T) {
		diagSwitch(t, true)
		err := failDial(t)
		if !strings.Contains(err.Error(), "wire sent ") {
			t.Fatalf("error %q does not carry the wire counters with diagnostics on", err)
		}
	})
}

// TestDialErrorDropsWireBytes pins the split precisely: the same counters are
// rendered into the error only when the switch is on.
func TestDialErrorDropsWireBytes(t *testing.T) {
	stub := &countingStub{}
	outer := &countingConn{PacketConn: stub}
	if _, _, err := outer.ReadFrom(make([]byte, 8)); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	c := &Client{tag: "diag"}
	addr := stub.LocalAddr()
	boom := errors.New("boom")

	diagSwitch(t, false)
	quiet := c.dialError(addr, addr, outer, nil, boom)
	if !strings.Contains(quiet.Error(), "boom") {
		t.Fatalf("error %q lost the underlying failure", quiet)
	}
	for _, unwanted := range []string{"71756963", "first from", "wire "} {
		if strings.Contains(quiet.Error(), unwanted) {
			t.Fatalf("error %q carries %q with diagnostics off", quiet, unwanted)
		}
	}

	diagSwitch(t, true)
	loud := c.dialError(addr, addr, outer, nil, boom)
	if !strings.Contains(loud.Error(), "first from 127.0.0.1:9 head 71756963") {
		t.Fatalf("error %q does not carry the first datagram with diagnostics on", loud)
	}
}

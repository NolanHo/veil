// Package outbound defines the contract every proxy protocol implements.
package outbound

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// Outbound is a single upstream proxy. Implementations are safe for concurrent
// use and hold no per-connection state outside of Dial* calls.
type Outbound interface {
	// Tag is the unique name from the configuration.
	Tag() string
	// Type is the protocol name (vless, vmess, ...).
	Type() string
	// DialContext opens a stream to address ("host:port"). It returns a net.Conn
	// whose Close releases all underlying resources.
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	Close() error
}

// PacketConn is a UDP association. ReadFrom may return packets from different
// remote addresses; WriteTo targets an arbitrary address (SOCKS5 semantics).
type PacketConn interface {
	ReadFrom(p []byte) (n int, addr netip.AddrPort, err error)
	WriteTo(p []byte, addr netip.AddrPort) (int, error)
	Close() error
	SetDeadline(t time.Time) error
}

// LocalDialer is implemented by outbounds that resolve the destination address
// on this device (the built-in direct), as opposed to proxies that hand the
// name to the exit node. The router uses it to avoid handing a fake address
// from the local DNS to a dial that would resolve it again.
//
// A policy group implements it too, and conservatively: it answers true only
// when every member it could use dials locally, because the member that ends up
// dialing is chosen at dial time and the router must not substitute an address
// into a flow that a proxy carries. See engine.Group.DialsLocally.
type LocalDialer interface {
	DialsLocally() bool
}

// PacketOutbound is implemented by protocols able to relay UDP.
type PacketOutbound interface {
	// DialPacket opens a UDP association. address is the initial target and may
	// be empty when the protocol supports arbitrary destinations per packet.
	DialPacket(ctx context.Context, address string) (PacketConn, error)
}

// PacketOutboundFor resolves whether o supports UDP for the given target.
func PacketOutboundFor(o Outbound) (PacketOutbound, bool) {
	p, ok := o.(PacketOutbound)
	return p, ok
}

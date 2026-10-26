// Package dns provides resolve-cache, UDP/TCP/DoT/DoH upstreams and an
// in-tunnel DNS server for the tun device.
package dns

import (
	"context"
	"net"
	"net/netip"

	"veil/internal/config"
	"veil/internal/logx"
)

// DialFunc opens a stream. The engine supplies one that honours routing so DNS
// can be sent through a proxy.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Resolver resolves names with a TTL cache.
type Resolver struct {
	cfg    config.DNSConfig
	log    *logx.Logger
	dial   DialFunc
	fake   *fakeIPPool
	fakeOn bool
}

// New builds a resolver. dial is used for DoH/DoT and for UDP detours; it may
// be nil until SetDial is called.
func New(cfg config.DNSConfig, log *logx.Logger) (*Resolver, error) {
	return &Resolver{cfg: cfg, log: log, fake: newFakeIPPool(), fakeOn: true}, nil
}

// HostFor maps a fake address back to the domain it stands for.
func (r *Resolver) HostFor(ip netip.Addr) (string, bool) {
	if r == nil || r.fake == nil {
		return "", false
	}
	return r.fake.hostFor(ip)
}

// AdoptFakeIPs carries the previous resolver's domain mappings over. A reload
// rebuilds the resolver; the device keeps talking to the addresses the old pool
// handed out, so the new one has to know them too.
func (r *Resolver) AdoptFakeIPs(old *Resolver) {
	if r == nil || old == nil || r.fake == nil {
		return
	}
	r.fake.adopt(old.fake)
}

// FakeFor returns the synthetic address this resolver uses for host,
// allocating one if needed. It is the inverse of HostFor.
func (r *Resolver) FakeFor(host string) netip.Addr {
	if r == nil || r.fake == nil || !r.fakeOn {
		return netip.Addr{}
	}
	return r.fake.ipFor(host)
}

// DisableFakeIP turns off synthetic answers (used by tests that exercise the
// upstream path directly).
func (r *Resolver) DisableFakeIP() { r.fakeOn = false }

// IsFake reports whether ip is a synthetic address handed out by this resolver.
func (r *Resolver) IsFake(ip netip.Addr) bool {
	return r != nil && r.fakeOn && isFakeAddr(ip)
}

// SetDial injects the routing-aware dialer.
func (r *Resolver) SetDial(d DialFunc) { r.dial = d }

// Lookup resolves host to addresses (A and AAAA), using the cache.
func (r *Resolver) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookup(ctx, host)
}

// Close releases idle connections.
func (r *Resolver) Close() error { return nil }

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
	fake   *FakePool
	fakeOn bool
	gen    uint64
}

// New builds a resolver with a fake-IP pool of its own. dial is used for DoH/DoT
// and for UDP detours; it may be nil until SetDial is called.
func New(cfg config.DNSConfig, log *logx.Logger) (*Resolver, error) {
	return NewWithPool(cfg, log, nil)
}

// NewWithPool builds a resolver that allocates fake addresses from pool. A
// reload hands in the pool the engine already owns instead of letting the new
// resolver allocate its own: two pools — even one seeded from the other's
// mappings — could hand the same address to two different domains. A nil pool
// means "give me a private one".
func NewWithPool(cfg config.DNSConfig, log *logx.Logger, pool *FakePool) (*Resolver, error) {
	if pool == nil {
		pool = NewFakePool()
	}
	return &Resolver{cfg: cfg, log: log, fake: pool, fakeOn: true}, nil
}

// HostFor maps a fake address back to the domain it stands for.
func (r *Resolver) HostFor(ip netip.Addr) (string, bool) {
	if r == nil || r.fake == nil {
		return "", false
	}
	return r.fake.hostFor(ip)
}

// Pool returns the fake-IP pool this resolver allocates from, so a reload can
// keep using the same one.
func (r *Resolver) Pool() *FakePool {
	if r == nil {
		return nil
	}
	return r.fake
}

// AdoptFakeIPs makes r share old's pool. It adopts the pool object itself, not a
// copy of its mappings: the device keeps talking to the addresses the old pool
// handed out, and a resolver that kept allocating from a copy could reissue one
// of them for another domain.
func (r *Resolver) AdoptFakeIPs(old *Resolver) {
	if r == nil || old == nil || old.fake == nil {
		return
	}
	r.fake = old.fake
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

// SetGeneration stamps the resolver with the configuration generation it was
// built for. The engine sets it before the resolver is published, so nothing
// reads or writes it concurrently: the routing cache keys its answers by it, and
// a lookup performed for an older generation must not be remembered as part of
// the newer one.
func (r *Resolver) SetGeneration(gen uint64) {
	if r != nil {
		r.gen = gen
	}
}

// Generation reports the configuration generation this resolver belongs to. A
// resolver built outside a reload reports 0.
func (r *Resolver) Generation() uint64 {
	if r == nil {
		return 0
	}
	return r.gen
}

// SetDial injects the routing-aware dialer.
func (r *Resolver) SetDial(d DialFunc) { r.dial = d }

// Lookup resolves host to addresses (A and AAAA), using the cache.
func (r *Resolver) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookup(ctx, host)
}

// Close releases idle connections.
func (r *Resolver) Close() error { return nil }

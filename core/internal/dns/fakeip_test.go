package dns

import (
	"net/netip"
	"testing"

	"veil/internal/config"
)

// newPoolResolver builds a resolver that allocates from pool, the way the engine
// builds one on every reload.
func newPoolResolver(t *testing.T, pool *FakePool) *Resolver {
	t.Helper()
	r, err := NewWithPool(config.DNSConfig{Enable: true}, nil, pool)
	if err != nil {
		t.Fatalf("NewWithPool: %v", err)
	}
	return r
}

// TestReloadKeepsOneAllocator pins the reason the pool outlives the resolver: a
// reload swaps the resolver, but the outgoing one can still be answering (a
// connection snapshotted it) while the incoming one starts allocating. Two pools
// — even one holding a copy of the other's mappings — would let the incoming one
// reissue an address the outgoing one had just given to a different name, and the
// client dialling that address would land on the wrong domain.
func TestReloadKeepsOneAllocator(t *testing.T) {
	pool := NewFakePool()
	oldRes := newPoolResolver(t, pool)

	early := oldRes.FakeFor("early.test")
	if !early.IsValid() {
		t.Fatal("no fake address for early.test")
	}

	// The reload builds the replacement from the same pool.
	newRes := newPoolResolver(t, pool)

	// The outgoing resolver is still answering for flows that snapshotted it.
	late := oldRes.FakeFor("late.test")
	next := newRes.FakeFor("other.test")
	if !late.IsValid() || !next.IsValid() {
		t.Fatalf("allocation failed: late=%v next=%v", late, next)
	}
	if next == late {
		t.Fatalf("the new resolver reissued %v, already handed to late.test", late)
	}
	if next == early {
		t.Fatalf("the new resolver reissued %v, already handed to early.test", early)
	}

	// Both resolvers answer with every mapping, in both directions: one pool, one
	// name per address, no matter which resolver asks.
	for _, r := range []*Resolver{oldRes, newRes} {
		for _, want := range []struct {
			ip   string
			host string
		}{
			{early.String(), "early.test"},
			{late.String(), "late.test"},
			{next.String(), "other.test"},
		} {
			host, ok := r.HostFor(netip.MustParseAddr(want.ip))
			if !ok || host != want.host {
				t.Fatalf("HostFor(%s) = %q,%v, want %q", want.ip, host, ok, want.host)
			}
		}
	}
}

// TestAdoptFakeIPsSharesPool keeps the older entry point honest: adopting a
// resolver's fake IPs adopts the pool object, not a snapshot of it.
func TestAdoptFakeIPsSharesPool(t *testing.T) {
	oldRes, err := New(config.DNSConfig{Enable: true}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	newRes, err := New(config.DNSConfig{Enable: true}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	newRes.AdoptFakeIPs(oldRes)
	if newRes.Pool() != oldRes.Pool() {
		t.Fatal("AdoptFakeIPs copied the pool instead of sharing it")
	}

	early := oldRes.FakeFor("early.test")
	late := oldRes.FakeFor("late.test") // allocated after the adoption
	next := newRes.FakeFor("other.test")
	if next == early || next == late {
		t.Fatalf("shared pool reissued an address: early=%v late=%v next=%v", early, late, next)
	}
	if host, ok := newRes.HostFor(late); !ok || host != "late.test" {
		t.Fatalf("HostFor(%v) = %q,%v, want late.test", late, host, ok)
	}
}

package dns

import (
	"net/netip"
	"sync"
)

// FakePool hands out synthetic addresses for domains and maps them back.
//
// Why: DNS must be answered at the *proxy* end. A client-side resolver (even
// DoH) either gets poisoned answers or leaks which sites you visit. With
// fake-IP the tunnel answers every A query with 198.18.x.x, and the engine
// turns that address back into the domain, so the proxy resolves the name and
// the local network never sees a real lookup.
//
// One pool per engine, not one per resolver. A reload builds a new resolver but
// keeps this object (see Engine.Reload and NewWithPool), which is what makes the
// mapping consistent across a reload: there is only ever one allocator, so the
// address the outgoing resolver just handed to one name can never be handed to a
// different name by the incoming one. Copying the mappings into a fresh pool
// would not give that guarantee — the copy is a snapshot, and an address
// allocated from the old pool after the snapshot would be reissued by the new
// one for another domain, silently routing the older connection to the wrong
// host.
type FakePool struct {
	mu     sync.RWMutex
	byIP   map[netip.Addr]string
	byHost map[string]netip.Addr
	next   uint32
}

// NewFakePool returns an empty pool.
func NewFakePool() *FakePool {
	return &FakePool{
		byIP:   make(map[netip.Addr]string, 1024),
		byHost: make(map[string]netip.Addr, 1024),
		next:   1,
	}
}

// ipFor returns the fake address for host, allocating one if needed.
func (p *FakePool) ipFor(host string) netip.Addr {
	if host == "" {
		return netip.Addr{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if ip, ok := p.byHost[host]; ok {
		return ip
	}
	// 198.18.0.0/15 is the benchmarking range: never routable, so a leaked
	// packet goes nowhere instead of hitting a real host.
	for tries := 0; tries < 1<<20; tries++ {
		n := p.next
		p.next++
		ip := netip.AddrFrom4([4]byte{198, 18, byte(n >> 8), byte(n)})
		if _, taken := p.byIP[ip]; taken {
			continue
		}
		p.byIP[ip] = host
		p.byHost[host] = ip
		return ip
	}
	return netip.Addr{}
}

// hostFor resolves a fake address back to its domain.
func (p *FakePool) hostFor(ip netip.Addr) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	h, ok := p.byIP[ip]
	return h, ok
}

// isFake reports whether ip belongs to the pool range.
func isFakeAddr(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	b := ip.As4()
	return b[0] == 198 && (b[1] == 18 || b[1] == 19)
}

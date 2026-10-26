package dns

import (
	"net/netip"
	"sync"
)

// fakeIPPool hands out synthetic addresses for domains and maps them back.
//
// Why: DNS must be answered at the *proxy* end. A client-side resolver (even
// DoH) either gets poisoned answers or leaks which sites you visit. With
// fake-IP the tunnel answers every A query with 198.18.x.x, and the engine
// turns that address back into the domain, so the proxy resolves the name and
// the local network never sees a real lookup.
type fakeIPPool struct {
	mu     sync.RWMutex
	byIP   map[netip.Addr]string
	byHost map[string]netip.Addr
	next   uint32
}

func newFakeIPPool() *fakeIPPool {
	return &fakeIPPool{
		byIP:   make(map[netip.Addr]string, 1024),
		byHost: make(map[string]netip.Addr, 1024),
		next:   1,
	}
}

// ipFor returns the fake address for host, allocating one if needed.
func (p *fakeIPPool) ipFor(host string) netip.Addr {
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

// adopt copies every mapping from old. A resolver reload builds a fresh pool,
// and the applications on the device keep using the addresses the old pool
// handed out — without this, those connections arrive as bare 198.18.x.x
// destinations whose domain nobody knows any more.
func (p *fakeIPPool) adopt(old *fakeIPPool) {
	if old == nil {
		return
	}
	old.mu.RLock()
	byIP := make(map[netip.Addr]string, len(old.byIP))
	byHost := make(map[string]netip.Addr, len(old.byHost))
	for k, v := range old.byIP {
		byIP[k] = v
	}
	for k, v := range old.byHost {
		byHost[k] = v
	}
	next := old.next
	old.mu.RUnlock()

	p.mu.Lock()
	for k, v := range byIP {
		p.byIP[k] = v
	}
	for k, v := range byHost {
		p.byHost[k] = v
	}
	if next > p.next {
		p.next = next
	}
	p.mu.Unlock()
}

// hostFor resolves a fake address back to its domain.
func (p *fakeIPPool) hostFor(ip netip.Addr) (string, bool) {
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

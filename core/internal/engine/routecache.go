package engine

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"veil/internal/dns"
)

// Why the router looks names up at all, and why it caches them here:
//
// A rule such as `GEOIP,CN,DIRECT` or `IP-CIDR,10.0.0.0/8,DIRECT` can only be
// answered with an address. When the client speaks in names — and under fake-IP
// it always does, because the address it dialled is a 198.18.x.x placeholder —
// the router has to obtain one itself. That lookup sits on the connection hot
// path, so it gets a short budget, it never runs while e.mu is held, and its
// answers are memoised briefly: one page load opens dozens of connections to the
// same few names, and a DNS round trip per connection would turn a routing
// decision into visible latency.
//
// Only a lookup a rule actually asked for lands here: matching is lazy (see
// rules.MatchWithResolver), so a name a domain rule classified never reaches
// this table at all.
//
// The resolver has a cache of its own, but it is gated on the user's
// `dns.cache` setting; rule evaluation must not become slow just because that
// knob is off, so the engine keeps its own short-lived table.
const (
	// routeResolveTimeout bounds how long a routing decision may wait for DNS.
	// It is the same 3 s the data path already used for this lookup: long enough
	// for a DoH round trip through a slow proxy hop, short enough not to stall a
	// connection noticeably when the upstream is dead.
	routeResolveTimeout = 3 * time.Second
	// routeCacheTTL is how long a successful answer is reused. A rule decision
	// only has to be roughly right; a minute bounds staleness while removing the
	// lookup from nearly every connection.
	routeCacheTTL = 60 * time.Second
	// routeCacheNegTTL remembers a failure, so a dead or blocked upstream costs
	// one timeout instead of one per connection.
	routeCacheNegTTL = 10 * time.Second
	// routeCacheMax bounds the table: a browser profile with thousands of
	// distinct hosts must not grow it without end.
	routeCacheMax = 1024
)

// routeAddrEntry is a cached lookup result, positive or negative.
type routeAddrEntry struct {
	addrs   []netip.Addr
	err     error
	expires time.Time
}

// routeFlight is one lookup in progress that concurrent callers wait on. A page
// load opens dozens of connections to the same handful of names at once; without
// this, a cold cache would still send a query per connection.
type routeFlight struct {
	done  chan struct{}
	addrs []netip.Addr
	err   error
}

// routeAddrCache is a zero-value-usable memo for routing lookups. It owns both
// the answers and the in-flight bookkeeping, so "one lookup per name per window"
// holds regardless of how the resolver is configured. There is no timer: entries
// expire when read and are swept when inserted, so an idle engine keeps its
// zero-wakeup property (AGENTS.md invariant 7).
type routeAddrCache struct {
	mu      sync.Mutex
	entries map[string]routeAddrEntry
	flight  map[string]*routeFlight
}

func (c *routeAddrCache) get(host string, now time.Time) (routeAddrEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ent, ok := c.entries[host]
	if !ok {
		return routeAddrEntry{}, false
	}
	if !now.Before(ent.expires) {
		delete(c.entries, host)
		return routeAddrEntry{}, false
	}
	return ent, true
}

func (c *routeAddrCache) put(host string, ent routeAddrEntry, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]routeAddrEntry, 64)
	}
	if len(c.entries) >= routeCacheMax {
		for k, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= routeCacheMax {
			// Everything is still fresh: drop the table instead of growing past
			// the bound. Losing warm entries is cheaper than unbounded memory.
			clear(c.entries)
		}
	}
	c.entries[host] = ent
}

// begin returns the lookup currently in flight for host, plus whether the caller
// is the one that has to perform it.
func (c *routeAddrCache) begin(host string) (*routeFlight, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if f, ok := c.flight[host]; ok {
		return f, false
	}
	if c.flight == nil {
		c.flight = make(map[string]*routeFlight, 8)
	}
	f := &routeFlight{done: make(chan struct{})}
	c.flight[host] = f
	return f, true
}

// finish publishes a result: the entry first (so a caller arriving after the
// flight is gone finds the cache), then the waiters, then the flight is retired.
// close(done) is the happens-before edge the waiters rely on, so the fields
// above need no lock of their own. store is false for a caller that went away
// before its answer arrived — those waiters still get the result, but a
// cancelled dial must not poison the table.
func (c *routeAddrCache) finish(host string, f *routeFlight, ent routeAddrEntry, now time.Time, store bool) {
	if store {
		c.put(host, ent, now)
	}
	f.addrs, f.err = ent.addrs, ent.err
	close(f.done)
	c.mu.Lock()
	delete(c.flight, host)
	c.mu.Unlock()
}

// lookupForRoute resolves host for rule matching. The resolver is passed in
// because a reload can swap it; callers must not hold e.mu here, the resolver
// does its own I/O. The only caller is the callback route hands to the matcher,
// which invokes it at most once per decision and only when a rule needs an
// address.
func (e *Engine) lookupForRoute(ctx context.Context, resolver *dns.Resolver, host string) ([]netip.Addr, error) {
	now := time.Now()
	if ent, ok := e.routeCache.get(host, now); ok {
		return ent.addrs, ent.err
	}
	f, leader := e.routeCache.begin(host)
	if !leader {
		select {
		case <-f.done:
			return f.addrs, f.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	lctx, cancel := context.WithTimeout(ctx, routeResolveTimeout)
	addrs, err := resolver.Lookup(lctx, host)
	cancel()
	ttl := routeCacheTTL
	if err != nil || len(addrs) == 0 {
		ttl = routeCacheNegTTL
	}
	ent := routeAddrEntry{addrs: addrs, err: err, expires: now.Add(ttl)}
	e.routeCache.finish(host, f, ent, now, ctx.Err() == nil)
	return addrs, err
}

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
//
// Two properties make this table correct across a reload, and both are why the
// type also owns DNS state that is not strictly a cache:
//
//   - Every entry and every flight is keyed by the resolver generation it was
//     produced for (see advance). A reload advances the generation, so an answer
//     the outgoing resolver gave is never read by a decision made under the
//     incoming configuration, and a lookup that was already in flight when the
//     reload happened cannot put its answer into the new generation's namespace.
//   - The cache read and the flight registration are one decision under one lock
//     (see reserve). Done as two steps, a caller that had already missed the
//     cache could register a second flight after another caller's flight had
//     finished, and the same name would go upstream twice.
//
// The fake-IP pool lives here too: like the generation it has to outlive a
// reload, and it is engine-owned DNS state — one allocator for every resolver the
// engine builds, so an address handed out before a reload keeps meaning the same
// domain afterwards.
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

// routeKey namespaces a lookup by the resolver generation that produced it.
type routeKey struct {
	gen  uint64
	host string
}

// routeAddrCache is a zero-value-usable memo for routing lookups. It owns both
// the answers and the in-flight bookkeeping, so "one lookup per name per window"
// holds regardless of how the resolver is configured. There is no timer: entries
// expire when read and are swept when inserted, so an idle engine keeps its
// zero-wakeup property (AGENTS.md invariant 7).
type routeAddrCache struct {
	mu      sync.Mutex
	gen     uint64
	pool    *dns.FakePool
	entries map[routeKey]routeAddrEntry
	flight  map[routeKey]*routeFlight
}

// advance moves the table to a new resolver generation and drops what the
// previous ones left behind. The engine calls it once per reload, before the new
// resolver is published, so no decision can be made from answers that belong to
// the configuration being replaced.
func (c *routeAddrCache) advance() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	for k := range c.entries {
		if k.gen != c.gen {
			delete(c.entries, k)
		}
	}
	return c.gen
}

// fakePool returns the one fake-IP pool every resolver this engine builds
// allocates from, creating it on first use. seed is the resolver that is live at
// the time — the first reload continues with the pool that resolver already
// handed addresses out of, so the addresses clients hold keep their names; later
// calls return that same object, which is what keeps a single allocator.
func (c *routeAddrCache) fakePool(seed *dns.Resolver) *dns.FakePool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pool == nil {
		c.pool = seed.Pool()
		if c.pool == nil {
			c.pool = dns.NewFakePool()
		}
	}
	return c.pool
}

// entryLocked returns the fresh entry for key, dropping it when it has expired.
func (c *routeAddrCache) entryLocked(key routeKey, now time.Time) (routeAddrEntry, bool) {
	ent, ok := c.entries[key]
	if !ok {
		return routeAddrEntry{}, false
	}
	if !now.Before(ent.expires) {
		delete(c.entries, key)
		return routeAddrEntry{}, false
	}
	return ent, true
}

// get reads the current generation's entry for host. The routing path goes
// through reserve instead, because "cached or in flight" has to be one decision;
// this is the plain read of the table.
func (c *routeAddrCache) get(host string, now time.Time) (routeAddrEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.entryLocked(routeKey{gen: c.gen, host: host}, now)
}

// reserve is the whole decision for one lookup: answer from the cache, join the
// flight already running for this generation and host, or become the leader that
// has to go upstream. All three outcomes are decided while holding one lock, so
// two callers can never both conclude that a lookup is needed.
func (c *routeAddrCache) reserve(gen uint64, host string, now time.Time) (ent routeAddrEntry, hit bool, f *routeFlight, leader bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := routeKey{gen: gen, host: host}
	if ent, ok := c.entryLocked(key, now); ok {
		return ent, true, nil, false
	}
	if running, ok := c.flight[key]; ok {
		return routeAddrEntry{}, false, running, false
	}
	if c.flight == nil {
		c.flight = make(map[routeKey]*routeFlight, 8)
	}
	f = &routeFlight{done: make(chan struct{})}
	c.flight[key] = f
	return routeAddrEntry{}, false, f, true
}

// put remembers an answer in the namespace of the generation that produced it.
// The generation is part of the key, so an answer that a flight started before
// the reload finally produces lands in the generation it was asked for: the
// newer generation cannot read it, and the next advance sweeps it away. Writing
// it there is deliberately not an error — a cancelled or superseded lookup must
// still release its waiters with the answer it got.
func (c *routeAddrCache) put(gen uint64, host string, ent routeAddrEntry, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[routeKey]routeAddrEntry, 64)
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
	c.entries[routeKey{gen: gen, host: host}] = ent
}

// finish publishes a result: the entry first (so a caller arriving after the
// flight is gone finds the cache), then the waiters, then the flight is retired.
// close(done) is the happens-before edge the waiters rely on, so the fields
// above need no lock of their own. store is false for a caller that went away
// before its answer arrived — those waiters still get the result, but a cancelled
// dial must not poison the table.
func (c *routeAddrCache) finish(gen uint64, host string, f *routeFlight, ent routeAddrEntry, now time.Time, store bool) {
	if store {
		c.put(gen, host, ent, now)
	}
	f.addrs, f.err = ent.addrs, ent.err
	close(f.done)
	key := routeKey{gen: gen, host: host}
	c.mu.Lock()
	if c.flight[key] == f {
		delete(c.flight, key)
	}
	c.mu.Unlock()
}

// lookupForRoute resolves host for rule matching. The resolver is passed in
// because a reload can swap it; callers must not hold e.mu here, the resolver
// does its own I/O. The only caller is the callback route hands to the matcher,
// which invokes it at most once per decision and only when a rule needs an
// address.
func (e *Engine) lookupForRoute(ctx context.Context, resolver *dns.Resolver, host string) ([]netip.Addr, error) {
	now := time.Now()
	// The generation travels with the resolver. A decision that still holds the
	// outgoing resolver (route snapshots it under e.mu) therefore reads and
	// writes under that older generation: its answer can neither be served to
	// the new configuration nor stored as part of it.
	gen := resolver.Generation()
	ent, hit, f, leader := e.routeCache.reserve(gen, host, now)
	if hit {
		return ent.addrs, ent.err
	}
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
	ent = routeAddrEntry{addrs: addrs, err: err, expires: now.Add(ttl)}
	e.routeCache.finish(gen, host, f, ent, now, ctx.Err() == nil)
	return addrs, err
}

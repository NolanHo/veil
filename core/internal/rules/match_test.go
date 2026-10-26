package rules

import (
	"errors"
	"net/netip"
	"testing"

	"veil/internal/config"
)

// cnRoute is an address inside the generated geoip:cn snapshot, so `GEOIP,CN`
// has something to match on both sides of the lookup.
const cnRoute = "223.5.5.5"

// lookupCounter is a Resolver that answers with a fixed address (or error) and
// counts calls. Counting is the whole point: laziness is observable only as the
// number of lookups a match performed.
type lookupCounter struct {
	calls int
	addr  string
	err   error
}

func (c *lookupCounter) resolve() (netip.Addr, error) {
	c.calls++
	if c.err != nil {
		return netip.Addr{}, c.err
	}
	return addr(c.addr), nil
}

// newMatcher compiles rs against a fallback tag shared by the tests.
func newMatcher(t *testing.T, rs []config.Rule) *Engine {
	t.Helper()
	e, err := New(rs, config.ModeRule, "fallback")
	if err != nil {
		t.Fatalf("New(%v): %v", rs, err)
	}
	return e
}

// TestMatchLazyDomainRuleCostsNoLookup is the regression this change exists for:
// a table that classifies the connection by domain must not resolve the name
// just because it also contains an IP rule. Clash and mihomo resolve only when
// the walk reaches an IP rule, and so must we.
func TestMatchLazyDomainRuleCostsNoLookup(t *testing.T) {
	e := newMatcher(t, []config.Rule{
		{Type: "domain-suffix", Value: "corp.example", Action: "direct"},
		{Type: "geoip", Value: "cn", Action: "proxy"},
		{Type: "final", Action: "proxy"},
	})
	lc := &lookupCounter{addr: cnRoute}

	got := e.MatchWithResolver(Meta{Network: "tcp", Host: "git.corp.example", Port: 443}, lc.resolve)
	if got.Rule != "domain-suffix:corp.example" || got.Outbound != "direct" {
		t.Fatalf("action = %+v, want direct/domain-suffix:corp.example", got)
	}
	if lc.calls != 0 {
		t.Fatalf("lookups = %d, want 0: the domain rule decided the connection", lc.calls)
	}
}

// TestMatchLazyIPRuleResolvesWhenReached is the other half of the same coin: a
// preceding domain rule that misses must not stop GEOIP from working, and the
// lookup happens exactly once, at the IP rule.
func TestMatchLazyIPRuleResolvesWhenReached(t *testing.T) {
	e := newMatcher(t, []config.Rule{
		{Type: "domain-suffix", Value: "corp.example", Action: "reject"},
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "final", Action: "proxy"},
	})
	lc := &lookupCounter{addr: cnRoute}

	got := e.MatchWithResolver(Meta{Network: "tcp", Host: "www.example.com", Port: 443}, lc.resolve)
	if got.Rule != "geoip:cn" || got.Outbound != "direct" {
		t.Fatalf("action = %+v, want direct/geoip:cn", got)
	}
	if lc.calls != 1 {
		t.Fatalf("lookups = %d, want 1", lc.calls)
	}
}

// TestMatchLazyNoResolveNeitherResolvesNorMatches pins `no-resolve` on both
// sides: the flagged rule never makes the matcher resolve, and it never accepts
// the address another rule's lookup produced.
func TestMatchLazyNoResolveNeitherResolvesNorMatches(t *testing.T) {
	t.Run("alone it resolves nothing", func(t *testing.T) {
		e := newMatcher(t, []config.Rule{
			{Type: "ip-cidr", Value: cnRoute + "/32", Action: "reject", NoResolve: true},
			{Type: "geoip", Value: "private", Action: "reject", NoResolve: true},
			{Type: "final", Action: "proxy"},
		})
		lc := &lookupCounter{addr: cnRoute}
		got := e.MatchWithResolver(Meta{Host: "www.example.com"}, lc.resolve)
		if got.Rule != "final" || got.Outbound != "proxy" {
			t.Fatalf("action = %+v, want proxy/final", got)
		}
		if lc.calls != 0 {
			t.Fatalf("lookups = %d, want 0: no-resolve must not resolve", lc.calls)
		}
	})

	t.Run("looked-up address does not feed it", func(t *testing.T) {
		// A plain rule wants an address and gets one that matches neither it nor
		// the no-resolve rule that follows; the flagged rule must not fire on the
		// address the lookup produced.
		e := newMatcher(t, []config.Rule{
			{Type: "geoip", Value: "cn", Action: "direct"},
			{Type: "ip-cidr", Value: "8.8.8.8/32", Action: "reject", NoResolve: true},
			{Type: "final", Action: "proxy"},
		})
		lc := &lookupCounter{addr: "8.8.8.8"}
		got := e.MatchWithResolver(Meta{Host: "www.example.com"}, lc.resolve)
		if got.Rule != "final" || got.Outbound != "proxy" {
			t.Fatalf("action = %+v, want proxy/final: no-resolve was fed the lookup", got)
		}
		if lc.calls != 1 {
			t.Fatalf("lookups = %d, want 1", lc.calls)
		}
	})
}

// TestMatchLazyResolveFailureContinues: a failed lookup is not fatal. The IP
// rules see no address, evaluation moves on, and a later rule can still decide
// the connection — with one lookup, not one per IP rule.
func TestMatchLazyResolveFailureContinues(t *testing.T) {
	e := newMatcher(t, []config.Rule{
		{Type: "ip-cidr", Value: "10.0.0.0/8", Action: "reject"},
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "domain-suffix", Value: "example.com", Action: "proxy"},
		{Type: "final", Action: "direct"},
	})
	lc := &lookupCounter{err: errors.New("no such host")}

	got := e.MatchWithResolver(Meta{Host: "www.example.com"}, lc.resolve)
	if got.Rule != "domain-suffix:example.com" || got.Outbound != "proxy" {
		t.Fatalf("action = %+v, want proxy/domain-suffix:example.com", got)
	}
	if lc.calls != 1 {
		t.Fatalf("lookups = %d, want 1: a failure must not be retried within one match", lc.calls)
	}
}

// TestMatchLazyResolvedAddressFeedsLaterRules: the address belongs to the walk,
// not to the rule that triggered it. A CIDR that misses must let the next IP
// rule match on the same address without a second lookup.
func TestMatchLazyResolvedAddressFeedsLaterRules(t *testing.T) {
	e := newMatcher(t, []config.Rule{
		{Type: "ip-cidr", Value: "10.0.0.0/8", Action: "reject"},
		{Type: "ip-cidr", Value: cnRoute + "/32", Action: "direct"},
		{Type: "final", Action: "proxy"},
	})
	lc := &lookupCounter{addr: cnRoute}

	got := e.MatchWithResolver(Meta{Host: "www.example.com"}, lc.resolve)
	if got.Rule != "ip-cidr:"+cnRoute+"/32" || got.Outbound != "direct" {
		t.Fatalf("action = %+v, want direct/ip-cidr:%s/32", got, cnRoute)
	}
	if lc.calls != 1 {
		t.Fatalf("lookups = %d, want 1", lc.calls)
	}
}

// TestMatchLazyOneLookupPerMatch bounds the cost: however many IP rules the walk
// crosses, it resolves at most once.
func TestMatchLazyOneLookupPerMatch(t *testing.T) {
	e := newMatcher(t, []config.Rule{
		{Type: "ip-cidr", Value: "10.0.0.0/8", Action: "reject"},
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "ip-cidr6", Value: "2001:db8::/32", Action: "reject"},
		{Type: "final", Action: "proxy"},
	})
	lc := &lookupCounter{addr: "8.8.8.8"}

	got := e.MatchWithResolver(Meta{Host: "www.example.com"}, lc.resolve)
	if got.Rule != "final" {
		t.Fatalf("action = %+v, want final", got)
	}
	if lc.calls != 1 {
		t.Fatalf("lookups = %d, want 1: one lookup per match", lc.calls)
	}
}

// TestMatchLazyClientAddressIsNotResolved: an address the client sent literally
// is already the answer; no rule may turn it into a lookup.
func TestMatchLazyClientAddressIsNotResolved(t *testing.T) {
	e := newMatcher(t, []config.Rule{
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "final", Action: "proxy"},
	})
	lc := &lookupCounter{addr: "8.8.8.8"}

	got := e.MatchWithResolver(Meta{Dst: addr(cnRoute), Port: 443}, lc.resolve)
	if got.Rule != "geoip:cn" {
		t.Fatalf("action = %+v, want geoip:cn", got)
	}
	if lc.calls != 0 {
		t.Fatalf("lookups = %d, want 0: the destination arrived as an address", lc.calls)
	}
}

// TestMatchLazyGlobalAndDirectModes: the modes that ignore the rule table must
// ignore the resolver too.
func TestMatchLazyGlobalAndDirectModes(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{
		{config.ModeGlobal, "fallback"},
		{config.ModeDirect, "direct"},
	} {
		e, err := New([]config.Rule{
			{Type: "geoip", Value: "cn", Action: "direct"},
		}, tc.mode, "fallback")
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		lc := &lookupCounter{addr: cnRoute}
		got := e.MatchWithResolver(Meta{Host: "www.example.com"}, lc.resolve)
		if got.Outbound != tc.want {
			t.Fatalf("%s: outbound = %q, want %q", tc.mode, got.Outbound, tc.want)
		}
		if lc.calls != 0 {
			t.Fatalf("%s: lookups = %d, want 0", tc.mode, lc.calls)
		}
	}
}

// TestMatchWithoutResolver: MatchWithResolver must stay usable without a
// resolver (and Match, which is just that call with nil), where IP rules simply
// cannot match.
func TestMatchWithoutResolver(t *testing.T) {
	e := newMatcher(t, []config.Rule{
		{Type: "geoip", Value: "cn", Action: "direct"},
		{Type: "final", Action: "proxy"},
	})
	if got := e.MatchWithResolver(Meta{Host: "www.example.com"}, nil); got.Rule != "final" {
		t.Fatalf("nil resolver: action = %+v, want final", got)
	}
	if got := e.Match(Meta{Host: "www.example.com"}); got.Rule != "final" {
		t.Fatalf("Match: action = %+v, want final", got)
	}
}

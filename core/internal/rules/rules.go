// Package rules implements Veil's routing rule matcher.
package rules

import (
	"net/netip"
	"strings"

	"veil/internal/config"
)

// Meta is the per-connection information available to the matcher.
type Meta struct {
	Network string // tcp | udp
	Host    string // requested domain, empty when the client sent an IP
	Dst     netip.Addr
	Port    uint16
	Process string

	// DstFromLookup marks Dst as filled by the router's own DNS lookup rather
	// than read from the client's packet. Rules carrying `no-resolve` must not
	// match such an address; see compiled.dstUsable.
	DstFromLookup bool
}

// Action is the routing decision.
type Action struct {
	Outbound string // node or group tag; "direct" / "reject" are built-ins
	Reject   bool
	Rule     string // matched rule, for display; empty when the default applied
}

// Resolver answers one routing lookup for the connection being matched. A
// caller hands it to MatchWithResolver and it is called at most once per
// Match, and only when the walk actually needs an address. It must honour its
// own deadline: the matcher adds none.
type Resolver func() (netip.Addr, error)

// Engine matches Meta values against an ordered rule list.
type Engine struct {
	rules []compiled
	mode  string
	final string
}

// New compiles rs. mode is config.ModeRule/Global/Direct; final is the fallback
// outbound tag.
func New(rs []config.Rule, mode, final string) (*Engine, error) {
	e := &Engine{mode: mode, final: final}
	compiledRules, err := compile(rs)
	if err != nil {
		return nil, err
	}
	e.rules = compiledRules
	return e, nil
}

// Match returns the first matching action. It never blocks and never performs
// DNS lookups: a caller that wants IP rules to see a resolved address fills
// Meta.Dst itself and flags it with DstFromLookup, or uses MatchWithResolver.
func (e *Engine) Match(m Meta) Action { return e.MatchWithResolver(m, nil) }

// MatchWithResolver is Match with a lazy address source.
//
// Evaluation walks the rules in order and behaves exactly like Match until an
// IP rule (ip-cidr, ip-cidr6, geoip) is reached while Meta.Dst holds no usable
// address. Only then — and at most once — is resolve called; the address it
// returns is treated as looked up (Meta.DstFromLookup) for the rest of the
// walk. A failure leaves the destination unresolved: that rule cannot match,
// nothing panics, and evaluation continues with the next rule. A rule carrying
// `no-resolve` never triggers a lookup and never matches the address one
// produced; that is the flag's whole point.
//
// Laziness is the reason this exists. Clash and mihomo resolve for an IP rule
// only when the walk reaches it, so a table like
//
//	DOMAIN-SUFFIX,corp.example,DIRECT
//	GEOIP,CN,DIRECT
//
// classifies domestic corporate hosts without a DNS round trip. Resolving up
// front whenever the table happened to contain an IP rule charged every
// connection for it.
func (e *Engine) MatchWithResolver(m Meta, resolve Resolver) Action {
	switch e.mode {
	case config.ModeGlobal:
		return Action{Outbound: e.final, Rule: "global"}
	case config.ModeDirect:
		return Action{Outbound: "direct", Rule: "direct"}
	}
	// attempted guards "one lookup per match": a second IP rule after a failed
	// lookup must not retry, or a dead upstream would cost the 3 s budget once
	// per IP rule instead of once per connection.
	attempted := false
	for i := range e.rules {
		c := &e.rules[i]
		if !attempted && c.needsAddr(m) {
			attempted = true
			if resolve != nil {
				if addr, err := resolve(); err == nil && addr.IsValid() {
					m.Dst, m.DstFromLookup = addr, true
				}
			}
		}
		if c.match(m) {
			return c.action
		}
	}
	return Action{Outbound: e.final}
}

// NeedsIP reports whether any rule in rs can only be evaluated with a
// destination address. Rules marked `no-resolve` do not count: they must never
// be the reason a domain gets looked up.
//
// It is a property of the table, not a decision the data path takes: matching
// resolves lazily (see MatchWithResolver), so a table that contains an IP rule
// no longer implies a lookup per connection.
func NeedsIP(rs []config.Rule) bool {
	for _, r := range rs {
		if r.NoResolve {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(r.Type)) {
		case "ip-cidr", "ip-cidr6", "geoip":
			return true
		}
	}
	return false
}

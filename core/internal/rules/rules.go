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
// Meta.Dst itself (engine.route does) and flags it with DstFromLookup.
func (e *Engine) Match(m Meta) Action {
	switch e.mode {
	case config.ModeGlobal:
		return Action{Outbound: e.final, Rule: "global"}
	case config.ModeDirect:
		return Action{Outbound: "direct", Rule: "direct"}
	}
	for i := range e.rules {
		if e.rules[i].match(m) {
			return e.rules[i].action
		}
	}
	return Action{Outbound: e.final}
}

// NeedsIP reports whether any rule in rs can only be evaluated with a
// destination address. Rules marked `no-resolve` do not count: they must never
// be the reason a domain gets looked up.
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

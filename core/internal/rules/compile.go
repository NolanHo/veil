package rules

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"veil/internal/config"
)

// kind enumerates the compiled rule behaviours. Using an enum instead of a
// string keeps the hot path (match) free of map lookups and interface calls.
type kind int

const (
	kindDomain kind = iota
	kindDomainSuffix
	kindDomainKeyword
	kindDomainRegex
	kindIPCIDR
	kindGeoIPPrivate
	kindGeoIPCN
	kindPort
	kindNetwork
	kindProcess
	kindFinal
)

// compiled is one parsed rule. Fields are only populated for the kinds that
// need them; match must therefore branch on kind first.
type compiled struct {
	action Action
	kind   kind

	domain  string // lowercase, no trailing dot (domain / domain-suffix)
	keyword string // lowercase (domain-keyword)
	regex   *regexp.Regexp
	prefix  netip.Prefix
	portLo  uint16
	portHi  uint16
	network string // lowercase tcp / udp
	process string // basename, lowercase

	// noResolve carries Clash's `no-resolve` flag on IP rules. It says "judge
	// this rule on the address the client sent; do not turn the name into an
	// address for it". Only the IP kinds (ip-cidr, ip-cidr6, geoip) read it.
	noResolve bool
}

// compile parses rs into matchable form. Rule order is preserved: the matcher
// relies on it for "first match wins".
func compile(rs []config.Rule) ([]compiled, error) {
	out := make([]compiled, 0, len(rs))
	for i, r := range rs {
		typ := strings.ToLower(strings.TrimSpace(r.Type))
		val := strings.TrimSpace(r.Value)
		actName := strings.TrimSpace(r.Action)

		c := compiled{
			action: Action{
				Outbound: actName,
				Reject:   strings.EqualFold(actName, "reject"),
			},
			noResolve: r.NoResolve,
		}

		switch typ {
		case "domain":
			c.kind = kindDomain
			c.domain = normalizeDomain(val)
			c.action.Rule = "domain:" + val

		case "domain-suffix":
			c.kind = kindDomainSuffix
			// Accept both ".example.com" and "example.com".
			c.domain = normalizeDomain(strings.TrimPrefix(val, "."))
			if c.domain == "" {
				return nil, fmt.Errorf("rule %d: empty domain-suffix", i)
			}
			c.action.Rule = "domain-suffix:" + val

		case "domain-keyword":
			c.kind = kindDomainKeyword
			c.keyword = strings.ToLower(val)
			if c.keyword == "" {
				return nil, fmt.Errorf("rule %d: empty domain-keyword", i)
			}
			c.action.Rule = "domain-keyword:" + val

		case "domain-regex":
			c.kind = kindDomainRegex
			re, err := regexp.Compile(val)
			if err != nil {
				return nil, fmt.Errorf("rule %d: domain-regex %q: %w", i, val, err)
			}
			c.regex = re
			c.action.Rule = "domain-regex:" + val

		case "ip-cidr", "ip-cidr6":
			c.kind = kindIPCIDR
			p, err := parsePrefix(val)
			if err != nil {
				return nil, fmt.Errorf("rule %d: %s %q: %w", i, typ, val, err)
			}
			c.prefix = p
			c.action.Rule = typ + ":" + p.String()

		case "geoip":
			switch strings.ToLower(val) {
			case "private":
				c.kind = kindGeoIPPrivate
			case "cn":
				c.kind = kindGeoIPCN
			default:
				return nil, fmt.Errorf("rule %d: geoip %q: unknown value", i, val)
			}
			c.action.Rule = "geoip:" + strings.ToLower(val)

		case "port":
			c.kind = kindPort
			lo, hi, err := parsePortRange(val)
			if err != nil {
				return nil, fmt.Errorf("rule %d: port %q: %w", i, val, err)
			}
			c.portLo, c.portHi = lo, hi
			c.action.Rule = "port:" + val

		case "network":
			c.kind = kindNetwork
			c.network = strings.ToLower(val)
			if c.network != "tcp" && c.network != "udp" {
				return nil, fmt.Errorf("rule %d: network %q: want tcp or udp", i, val)
			}
			c.action.Rule = "network:" + c.network

		case "process":
			c.kind = kindProcess
			c.process = strings.ToLower(filepath.Base(val))
			if c.process == "" || c.process == "." {
				return nil, fmt.Errorf("rule %d: empty process name", i)
			}
			c.action.Rule = "process:" + val

		case "final":
			c.kind = kindFinal
			c.action.Rule = "final"

		default:
			return nil, fmt.Errorf("rule %d: unknown rule type %q", i, r.Type)
		}

		out = append(out, c)
	}
	return out, nil
}

// match reports whether m satisfies c. Domain-ish rules are skipped when the
// client sent a bare IP (Host empty), IP rules when no usable address is
// available, so a rule never fires on a prerequisite it cannot evaluate.
func (c compiled) match(m Meta) bool {
	switch c.kind {
	case kindFinal:
		return true

	case kindDomain, kindDomainSuffix, kindDomainKeyword, kindDomainRegex:
		if m.Host == "" {
			return false
		}
		host := normalizeDomain(m.Host)
		switch c.kind {
		case kindDomain:
			return host == c.domain
		case kindDomainSuffix:
			// True suffix only: "example.com" and "a.example.com" match,
			// "evilexample.com" does not.
			return host == c.domain || strings.HasSuffix(host, "."+c.domain)
		case kindDomainKeyword:
			return strings.Contains(host, c.keyword)
		case kindDomainRegex:
			return c.regex.MatchString(host)
		}
		return false

	case kindIPCIDR:
		if !c.dstUsable(m) {
			return false
		}
		return c.prefix.Contains(m.Dst)

	case kindGeoIPPrivate:
		if !c.dstUsable(m) {
			return false
		}
		return isPrivateAddr(m.Dst)

	case kindGeoIPCN:
		if !c.dstUsable(m) {
			return false
		}
		a := m.Dst.Unmap()
		a = a.WithZone("")
		for _, p := range cnPrefixes {
			if p.Contains(a) {
				return true
			}
		}
		return false

	case kindPort:
		return m.Port >= c.portLo && m.Port <= c.portHi

	case kindNetwork:
		return strings.EqualFold(m.Network, c.network)

	case kindProcess:
		// Nothing fills Meta.Process yet: HarmonyOS hands the tun packets over
		// without the owning uid, so a process rule can only ever miss. It stays
		// compiled (a config must import), but the match below is unreachable in
		// production until the netstack/inbound path learns the app identity.
		if m.Process == "" {
			return false
		}
		// Compare basenames: rules may be written as "/usr/bin/curl".
		return strings.ToLower(filepath.Base(m.Process)) == c.process
	}
	return false
}

// dstUsable reports whether an IP rule may look at m.Dst.
//
// A rule marked no-resolve exists to say "decide on the address the client sent,
// do not resolve the name for me". The engine resolves a name exactly once, for
// the rules that do want an address (see engine.route), and flags the result in
// Meta.DstFromLookup; without this check that single lookup would silently feed
// every no-resolve rule in the table and undo the user's choice.
func (c compiled) dstUsable(m Meta) bool {
	if !m.Dst.IsValid() {
		return false
	}
	return !c.noResolve || !m.DstFromLookup
}

// normalizeDomain lowercases and strips the trailing dot (FQDN form), which is
// how clients may encode a root-anchored name.
func normalizeDomain(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	return strings.ToLower(s)
}

// parsePrefix accepts a CIDR or a bare address (treated as a host prefix).
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		// Mask host bits so Contains behaves predictably.
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// parsePortRange parses "443" or "1000-2000".
func parsePortRange(s string) (lo, hi uint16, err error) {
	if s == "" {
		return 0, 0, fmt.Errorf("empty port")
	}
	a, b, hasRange := strings.Cut(s, "-")
	lo64, err := strconv.ParseUint(strings.TrimSpace(a), 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("bad port: %w", err)
	}
	if !hasRange {
		return uint16(lo64), uint16(lo64), nil
	}
	hi64, err := strconv.ParseUint(strings.TrimSpace(b), 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("bad port range end: %w", err)
	}
	if hi64 < lo64 {
		return 0, 0, fmt.Errorf("inverted range")
	}
	return uint16(lo64), uint16(hi64), nil
}

// cgnat is RFC 6598 shared address space, which netip does not treat as private.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// isPrivateAddr reports whether a is non-public: RFC1918, loopback,
// link-local, CGNAT or IPv6 ULA.
func isPrivateAddr(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	if !a.IsValid() {
		return false
	}
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsUnspecified() || cgnat.Contains(a)
}

// cnPrefixes is the mainland-China IPv4 allocation list used by geoip:cn. It
// comes from the generated APNIC snapshot in geoip_cn_data.go: a hand-curated
// table missed whole CDN blocks, and a domestic site on an unlisted range went
// through the proxy — the most visible way this client differed from Clash.
var cnPrefixes []netip.Prefix

func init() {
	fields := strings.Split(cnPrefixData, ",")
	cnPrefixes = make([]netip.Prefix, 0, len(fields)+len(cnPrefixesCurated))
	for _, f := range fields {
		if p, err := netip.ParsePrefix(strings.TrimSpace(f)); err == nil {
			cnPrefixes = append(cnPrefixes, p)
		}
	}
	// Union with the curated table: it knows a few ranges the delegation file
	// attributes to another country code (114DNS, for one), and a missing range
	// means domestic traffic leaves through the proxy.
	cnPrefixes = append(cnPrefixes, cnPrefixesCurated...)
}

// mustPrefixes parses literal prefixes at package init. A malformed literal is
// a programming error, so panicking is intentional (and caught by tests).
func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			panic("rules: bad cn prefix literal " + s + ": " + err.Error())
		}
		out = append(out, p.Masked())
	}
	return out
}

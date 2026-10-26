package dns

import "strings"

// fakeIPBypassSuffixes lists the suffixes the tunnel never answers with a
// synthetic address. mDNS, the router and a corporate suffix list resolve these
// names inside the local network, so the exit node has no way to look them up:
// a fake address handed to a public DoH server comes back NXDOMAIN, and with
// route's "fake address + local dial" rule the connection fails outright.
//
// This is the minimal form of mihomo's `fake-ip-filter`, which is where the
// profile format this app imports takes the idea from.
var fakeIPBypassSuffixes = []string{"local", "lan", "internal", "home.arpa", "localhost"}

// bypassFakeIP reports whether host must be resolved by the configured upstream
// servers instead of being answered from the fake-IP pool.
//
// A fake address is a promise that the name is resolvable at the exit node, and
// that promise is false for names only the local network knows: a NAS, a
// printer, a router, anything under a home or corporate search suffix. Answering
// those with 198.18.x sent them to a public resolver that cannot resolve them.
//
// Single-label names (no dot) are the local suffix list's business — the client
// appends its own search domain, and mDNS answers `.local` — so they bypass too.
// Everything else keeps the fake answer, which is the whole point of the pool.
//
// A configured list (config.DNSConfig.FakeIPFilter) extends the built-in one;
// entries are suffixes, and a leading "+." or "*." is accepted because the
// profile format writes both spellings.
func bypassFakeIP(host string, configured []string) bool {
	name := normalizeHost(host)
	if name == "" {
		return false
	}
	if !strings.Contains(name, ".") {
		return true
	}
	for _, suffix := range fakeIPBypassSuffixes {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	for _, suffix := range configured {
		s := normalizeConfiguredSuffix(suffix)
		if s == "" {
			continue
		}
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

// normalizeConfiguredSuffix strips the wildcard spelling a profile may use.
func normalizeConfiguredSuffix(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "+.")
	s = strings.TrimPrefix(s, "*.")
	return strings.TrimSuffix(s, ".")
}

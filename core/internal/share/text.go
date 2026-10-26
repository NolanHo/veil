package share

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"veil/internal/config"
)

// ParseText parses a plain-text node list: one share link per line. Blank
// lines, comments ('#', '//') and stray markdown are ignored. When no line
// carries a scheme the whole text is treated as a base64 subscription body.
//
// A wg-quick .conf is accepted too: its [Interface]/[Peer] header is the only
// unambiguous marker in the input, so it is checked first (see isWireGuardConf)
// and wins over the link and base64 branches. Without this branch the parser
// would be dead code — the app has no other way to accept a pasted .conf.
//
// Parsing never aborts on a bad line: failures are collected in the second
// return value so one broken link cannot discard a whole subscription.
func ParseText(text string) ([]config.Node, []error) {
	text = strings.TrimPrefix(text, "\ufeff")
	if isWireGuardConf(text) {
		return wireGuardConfNode(text, "")
	}
	var nodes []config.Node
	var errs []error

	lines := strings.Split(text, "\n")
	seenLink := false
	for _, line := range lines {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if !strings.Contains(line, "://") {
			continue
		}
		seenLink = true
		n, err := Parse(line)
		if err != nil {
			errs = append(errs, fmt.Errorf("line %q: %w", truncate(line, 48), err))
			continue
		}
		nodes = append(nodes, n)
	}

	if !seenLink {
		// Possibly a base64-encoded subscription dumped as text. The decoded body
		// is a link list or, like any pasted text, a wg-quick .conf.
		if decoded := b64Text(text); decoded != "" && (strings.Contains(decoded, "://") || isWireGuardConf(decoded)) {
			return ParseText(decoded)
		}
		if strings.TrimSpace(text) == "" {
			return nil, nil
		}
		errs = append(errs, fmt.Errorf("share: no share link found in text"))
		return nil, errs
	}
	return finalize(nodes), errs
}

// ParseSubscription parses a subscription body, which may be plain text, a
// base64 blob of share links, or a Clash YAML document. source is recorded on
// every node so the UI can group nodes by subscription.
func ParseSubscription(body []byte, source string) ([]config.Node, []error) {
	text := strings.TrimPrefix(string(body), "\ufeff")
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil, []error{fmt.Errorf("share: empty subscription body")}
	}

	var nodes []config.Node
	var errs []error

	switch {
	case isWireGuardConf(trimmed):
		// Same precedence as ParseText: a .conf body names exactly one peer and
		// carries no share link, so its section header decides before the
		// link/YAML/base64 branches get a guess at the text.
		nodes, errs = wireGuardConfNode(trimmed, "")
	case strings.Contains(trimmed, "://"):
		nodes, errs = ParseText(trimmed)
	case looksLikeClash(trimmed):
		nodes, errs = ParseClashYAML([]byte(trimmed), source)
	default:
		decoded := b64Text(trimmed)
		if decoded == "" {
			return nil, []error{fmt.Errorf("share: subscription is neither plain text, base64 nor YAML")}
		}
		decoded = strings.TrimPrefix(decoded, "\ufeff")
		if looksLikeClash(decoded) {
			nodes, errs = ParseClashYAML([]byte(decoded), source)
		} else {
			nodes, errs = ParseText(decoded)
		}
	}

	for i := range nodes {
		if source != "" {
			nodes[i].Source = source
		}
	}
	return nodes, errs
}

// looksLikeClash reports whether s starts a Clash config with a proxies list.
func looksLikeClash(s string) bool {
	head := s
	if len(head) > 4096 {
		head = head[:4096]
	}
	return strings.Contains(head, "proxies:") || strings.HasPrefix(strings.TrimSpace(head), "proxy-groups:")
}

// finalizeResult is the product of de-duplication: the surviving nodes plus the
// name bookkeeping de-duplication owes its callers.
type finalizeResult struct {
	nodes []config.Node
	// aliases maps every input display name to the tag of the node it resolved
	// to. Two entries that differ only in name (not in identity) become one node,
	// so both spellings must keep resolving to that node: the Clash importer
	// addresses outbounds by name, and a group or rule that used the dropped
	// spelling would otherwise be discarded as a dangling reference.
	//
	// When distinct nodes share a name, the first one owns the alias; the
	// duplicates still import under a suffixed tag (that is how a subscription
	// with repeated display names behaves). The Clash importer rejects that case
	// before de-duplication instead, because Clash names must be unique.
	aliases map[string]string
}

// finalize de-duplicates nodes and makes every tag unique. Nodes are compared
// on identity (see dedupeKey); the first occurrence wins. Repeated tags get a
// "-2", "-3", ... suffix.
func finalize(nodes []config.Node) []config.Node {
	return finalizeWithAliases(nodes).nodes
}

// finalizeWithAliases is finalize plus the identity→tag bookkeeping the Clash
// importer needs: an entry merged by de-duplication must leave its name behind,
// pointing at the node that survived.
func finalizeWithAliases(nodes []config.Node) finalizeResult {
	res := finalizeResult{
		nodes:   make([]config.Node, 0, len(nodes)),
		aliases: make(map[string]string, len(nodes)),
	}
	kept := make(map[string]string, len(nodes)) // identity -> surviving tag
	tags := make(map[string]bool, len(nodes))

	for _, n := range nodes {
		key := dedupeKey(n)
		name := NormalizeTag(n.Remark)
		if tag, dup := kept[key]; dup {
			if name != "" {
				if _, ok := res.aliases[name]; !ok {
					res.aliases[name] = tag
				}
			}
			continue
		}

		base := name
		if base == "" {
			base = fmt.Sprintf("%s-%s-%d", n.Type, n.Server, n.Port)
		}
		tag := base
		for i := 2; tags[tag]; i++ {
			tag = base + "-" + strconv.Itoa(i)
		}
		tags[tag] = true
		if name != "" {
			if _, ok := res.aliases[name]; !ok {
				res.aliases[name] = tag
			}
		}
		kept[key] = tag
		n.Tag = tag
		res.nodes = append(res.nodes, n)
	}
	return res
}

// dedupeKey builds the identity string used for duplicate detection.
func dedupeKey(n config.Node) string {
	cred := n.UUID + "|" + n.Password + "|" + n.Method
	var tr string
	if n.Transport != nil {
		tr = n.Transport.Type + "|" + n.Transport.Path + "|" + n.Transport.Host + "|" + n.Transport.ServiceName
		if len(n.Transport.Headers) > 0 {
			keys := make([]string, 0, len(n.Transport.Headers))
			for k := range n.Transport.Headers {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				tr += "|" + k + "=" + n.Transport.Headers[k]
			}
		}
	}
	var tlsPart string
	if n.TLS != nil {
		tlsPart = strconv.FormatBool(n.TLS.Enabled) + "|" + n.TLS.ServerName
		if n.TLS.Reality != nil {
			tlsPart += "|" + n.TLS.Reality.PublicKey + "|" + n.TLS.Reality.ShortID
		}
	}
	return strings.ToLower(n.Type) + "|" + strings.ToLower(n.Server) + "|" +
		strconv.Itoa(n.Port) + "|" + cred + "|" + tr + "|" + tlsPart + "|" + wgIdentity(n)
}

// wgIdentity is the WireGuard half of the identity: two peers behind the same
// endpoint with different keys, interface addresses, routes or keepalive are
// different peers, and a key that ignored them would drop one silently.
func wgIdentity(n config.Node) string {
	if !strings.EqualFold(n.Type, "wireguard") {
		return ""
	}
	return n.PrivateKey + "|" + n.PeerPublicKey + "|" + n.PresharedKey + "|" +
		strings.Join(n.Addresses, ",") + "|" + strings.Join(n.AllowedIPs, ",") + "|" +
		strings.Join(n.DNS, ",") + "|" + strconv.Itoa(n.MTU) + "|" + strconv.Itoa(n.KeepAlive)
}

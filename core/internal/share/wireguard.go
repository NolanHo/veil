package share

import (
	"bufio"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode"

	"veil/internal/config"
)

// isWireGuardConf reports whether text is a wg-quick .conf: a line that is
// exactly an [Interface] or [Peer] section header.
//
// That header is the format's only unambiguous marker — a share link and a Clash
// document never contain one — so it is what the import paths test before they
// try anything else. Comment lines are not trimmed further, so a commented out
// header ("# [Peer]") does not count.
func isWireGuardConf(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		switch strings.ToLower(strings.TrimSpace(strings.TrimSuffix(line, "\r"))) {
		case "[interface]", "[peer]":
			return true
		}
	}
	return false
}

// wireGuardConfNode parses a .conf body for the text importers. A .conf describes
// exactly one peer, so there is nothing here to de-duplicate or re-tag:
// ParseWireGuardConf already derived the tag from the given name or the endpoint.
func wireGuardConfNode(text, name string) ([]config.Node, []error) {
	n, err := ParseWireGuardConf(text, name)
	if err != nil {
		return nil, []error{err}
	}
	return []config.Node{n}, nil
}

// ParseWireGuardConf parses a wg-quick style .conf into a node.
//
// name is what the user called the file (or the peer) when importing; it becomes
// the node's tag and remark because a .conf carries no name of its own. Without
// it the tag falls back to the endpoint host.
//
// Anything the userspace outbound cannot honour is rejected instead of silently
// dropped: a peer whose firewall rules or obfuscation parameters were ignored
// would connect and then behave inexplicably.
func ParseWireGuardConf(text, name string) (config.Node, error) {
	n := config.Node{Type: "wireguard"}

	const (
		sectionNone = iota
		sectionInterface
		sectionPeer
	)
	section := sectionNone
	peers := 0

	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch strings.ToLower(line) {
			case "[interface]":
				section = sectionInterface
			case "[peer]":
				peers++
				if peers > 1 {
					return config.Node{}, fmt.Errorf("share: wireguard: multiple [Peer] sections are not supported")
				}
				section = sectionPeer
			default:
				return config.Node{}, fmt.Errorf("share: wireguard: unsupported section %q", line)
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return config.Node{}, fmt.Errorf("share: wireguard: %q is not a key = value line", line)
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		var err error
		switch section {
		case sectionInterface:
			err = applyInterfaceKey(&n, key, value)
		case sectionPeer:
			err = applyPeerKey(&n, key, value)
		default:
			err = fmt.Errorf("%q appears before [Interface]", key)
		}
		if err != nil {
			return config.Node{}, fmt.Errorf("share: wireguard: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return config.Node{}, fmt.Errorf("share: wireguard: %w", err)
	}

	if n.PrivateKey == "" {
		return config.Node{}, fmt.Errorf("share: wireguard: missing PrivateKey")
	}
	if peers == 0 {
		return config.Node{}, fmt.Errorf("share: wireguard: missing [Peer] section")
	}
	if n.PeerPublicKey == "" {
		return config.Node{}, fmt.Errorf("share: wireguard: missing PublicKey")
	}
	if n.Server == "" || n.Port == 0 {
		return config.Node{}, fmt.Errorf("share: wireguard: missing Endpoint")
	}

	if name = strings.TrimSuffix(strings.TrimSpace(name), ".conf"); name != "" {
		n.Remark = NormalizeTag(name)
		n.Tag = n.Remark
	}
	if n.Tag == "" {
		// A .conf has no name field, so the endpoint is the only stable
		// identifier left to show in the node list.
		n.Tag = NormalizeTag(n.Server)
	}
	return n, nil
}

// applyInterfaceKey fills the [Interface] half of n.
func applyInterfaceKey(n *config.Node, key, value string) error {
	switch strings.ToLower(key) {
	case "privatekey":
		n.PrivateKey = value
	// wg-quick writes one Address (and one DNS) line per value, so a repeated
	// key adds to the list; assigning here would keep only the last line and drop
	// the IPv4 address of a dual-stack interface.
	case "address":
		n.Addresses = append(n.Addresses, splitList(value)...)
	case "dns":
		n.DNS = append(n.DNS, splitList(value)...)
	case "mtu":
		mtu, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("bad MTU %q", value)
		}
		n.MTU = mtu
	case "listenport", "table", "fwmark", "saveconfig", "preup", "postup", "predown", "postdown",
		"jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4":
		return fmt.Errorf("%s is not supported by the outbound", key)
	default:
		return fmt.Errorf("unknown [Interface] key %q", key)
	}
	return nil
}

// applyPeerKey fills the [Peer] half of n.
func applyPeerKey(n *config.Node, key, value string) error {
	switch strings.ToLower(key) {
	case "publickey":
		n.PeerPublicKey = value
	case "presharedkey":
		n.PresharedKey = value
	// Repeated AllowedIPs lines are legal wg syntax and accumulate, like Address.
	case "allowedips":
		n.AllowedIPs = append(n.AllowedIPs, splitList(value)...)
	case "endpoint":
		server, port, err := splitEndpoint(value)
		if err != nil {
			return err
		}
		n.Server, n.Port = server, port
	case "persistentkeepalive":
		// wg-quick allows "off" for a disabled keepalive.
		if strings.EqualFold(value, "off") {
			n.KeepAlive = 0
			return nil
		}
		ka, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("bad PersistentKeepalive %q", value)
		}
		n.KeepAlive = ka
	default:
		return fmt.Errorf("unknown [Peer] key %q", key)
	}
	return nil
}

// WireGuardConf renders n as a wg-quick .conf, the inverse of
// ParseWireGuardConf. The node editor uses it to show a peer in the form the
// user's other machines understand.
func WireGuardConf(n config.Node) (string, error) {
	if n.Type != "wireguard" && n.Type != "wg" {
		return "", fmt.Errorf("share: wireguard: cannot export node type %q", n.Type)
	}
	if n.PrivateKey == "" || n.PeerPublicKey == "" || n.Server == "" || n.Port == 0 {
		return "", fmt.Errorf("share: wireguard: incomplete node %q", n.Tag)
	}
	// Every value that reaches a "Key = value" line is checked first: one line
	// break inside a value ends the directive and injects another one, so a node
	// carrying "10.9.0.1\nPostUp = ..." must be refused, not written out as a
	// config that does something the user never asked for.
	for _, f := range []struct {
		field  string
		values []string
	}{
		{"PrivateKey", []string{n.PrivateKey}},
		{"Address", n.Addresses},
		{"DNS", n.DNS},
		{"PublicKey", []string{n.PeerPublicKey}},
		{"PresharedKey", []string{n.PresharedKey}},
		{"AllowedIPs", n.AllowedIPs},
		{"Endpoint", []string{n.Server}},
	} {
		for _, v := range f.values {
			if err := checkConfValue(f.field, v); err != nil {
				return "", err
			}
		}
	}
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", n.PrivateKey)
	if len(n.Addresses) > 0 {
		fmt.Fprintf(&b, "Address = %s\n", strings.Join(n.Addresses, ", "))
	}
	if len(n.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(n.DNS, ", "))
	}
	if n.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", n.MTU)
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", n.PeerPublicKey)
	if n.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", n.PresharedKey)
	}
	if len(n.AllowedIPs) > 0 {
		fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(n.AllowedIPs, ", "))
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", n.Addr())
	if n.KeepAlive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", n.KeepAlive)
	}
	return b.String(), nil
}

// checkConfValue rejects a value the line-oriented .conf cannot carry: control
// characters (the newline that ends a directive, a CR, a NUL) or anything that
// would not survive the pair of trim steps the parser applies.
func checkConfValue(field, value string) error {
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("share: wireguard: %s contains the control character %q and cannot be written to a .conf", field, r)
		}
	}
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("share: wireguard: %s has surrounding whitespace", field)
	}
	return nil
}

// normalizeWGAddrs gives a bare address its full-length mask, which is how
// mihomo's `ip:` field is meant (10.9.0.13 == 10.9.0.13/32). A value that
// still does not parse is passed through so the outbound reports it in its own
// words.
func normalizeWGAddrs(list []string) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			out = append(out, s)
			continue
		}
		if ip, err := netip.ParseAddr(s); err == nil {
			out = append(out, netip.PrefixFrom(ip, ip.BitLen()).String())
			continue
		}
		out = append(out, s)
	}
	return out
}

// defaultAllowedIPs is Clash's rule for a single-peer WireGuard with no
// allowed-ips of its own: one default route per address family the interface has
// an address in (mihomo adapter/outbound/wireguard.go). It is applied by the
// Clash mapping only — a .conf without AllowedIPs means "no route", which is what
// wg-quick does too.
func defaultAllowedIPs(addresses []string) []string {
	var v4, v6 bool
	for _, a := range addresses {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			continue
		}
		if p.Addr().Is4() {
			v4 = true
		} else {
			v6 = true
		}
	}
	out := make([]string, 0, 2)
	if v4 {
		out = append(out, "0.0.0.0/0")
	}
	if v6 {
		out = append(out, "::/0")
	}
	return out
}

// splitList splits a comma separated wg-quick list value.
func splitList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitEndpoint splits "host:port", including the bracketed IPv6 spelling.
func splitEndpoint(value string) (string, int, error) {
	i := strings.LastIndexByte(value, ':')
	if i <= 0 {
		return "", 0, fmt.Errorf("bad Endpoint %q", value)
	}
	host := strings.TrimSuffix(strings.TrimPrefix(value[:i], "["), "]")
	port, err := strconv.Atoi(value[i+1:])
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("bad Endpoint %q", value)
	}
	if host == "" {
		return "", 0, fmt.Errorf("bad Endpoint %q", value)
	}
	return host, port, nil
}

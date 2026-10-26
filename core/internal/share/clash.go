package share

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"veil/internal/config"
)

// clashDocument is the subset of a Clash config we care about.
//
// Proxies, proxy-groups and rules stay raw yaml.Nodes: decoding a whole list is
// one all-or-nothing step, so a single malformed entry would drop every
// sibling. The entries are decoded one at a time in ParseClashConfig instead.
type clashDocument struct {
	Proxies []yaml.Node `yaml:"proxies"`
	// The two routing sections stay raw nodes so "the key is absent" and "the
	// key is written with no entries" remain different facts: a bare `rules:`
	// (null) or `rules: []` is a user clearing the table, while no `rules:` key
	// at all says nothing about it. See ClashConfig.RulesProvided.
	ProxyGroups yaml.Node `yaml:"proxy-groups"`
	Rules       yaml.Node `yaml:"rules"`
	// ProxyProviders stays a raw node as well: its keys are the names a group's
	// `use:` list refers to, and the entries are decoded one at a time (see
	// parseClashProviders) so one broken definition does not cost the others.
	ProxyProviders yaml.Node `yaml:"proxy-providers"`
}

type clashProxy struct {
	Name              string `yaml:"name"`
	Type              string `yaml:"type"`
	Server            string `yaml:"server"`
	Port              any    `yaml:"port"`
	UUID              string `yaml:"uuid"`
	Username          string `yaml:"username"`
	Password          string `yaml:"password"`
	Cipher            string `yaml:"cipher"`
	AlterID           any    `yaml:"alterId"`
	Network           string `yaml:"network"`
	TLS               bool   `yaml:"tls"`
	ServerName        string `yaml:"servername"`
	SNI               string `yaml:"sni"`
	SkipCertVerify    bool   `yaml:"skip-cert-verify"`
	ClientFingerprint string `yaml:"client-fingerprint"`
	// Fingerprint is mihomo's certificate pin for hysteria2 (hex SHA-256). It
	// shares tls.fingerprint with the uTLS profile name above; the two are told
	// apart by shape (see certPinShape).
	Fingerprint  string            `yaml:"fingerprint"`
	Flow         string            `yaml:"flow"`
	Obfs         string            `yaml:"obfs"`
	ObfsPassword string            `yaml:"obfs-password"`
	ALPN         []string          `yaml:"alpn"`
	UDP          *bool             `yaml:"udp"`
	WSOpts       *clashWSOpts      `yaml:"ws-opts"`
	GRPCOpts     *clashGRPCOpts    `yaml:"grpc-opts"`
	RealityOpts  *clashRealityOpts `yaml:"reality-opts"`

	// WireGuard (mihomo spelling: `ip` is the interface address, `ipv6` its v6
	// counterpart, `pre-shared-key` the optional PSK).
	IP           string `yaml:"ip"`
	IPv6         string `yaml:"ipv6"`
	PrivateKey   string `yaml:"private-key"`
	PublicKey    string `yaml:"public-key"`
	PreSharedKey string `yaml:"pre-shared-key"`
	// The two list-valued keys stay raw so a wrong shape is an error instead of
	// an empty list, and so the message can name the key it rejected.
	AllowedIPs  yaml.Node `yaml:"allowed-ips"`
	DNS         yaml.Node `yaml:"dns"`
	MTU         any       `yaml:"mtu"`
	KeepAlive   any       `yaml:"persistent-keepalive"`
	DialerProxy string    `yaml:"dialer-proxy"`
	// Reserved is the mihomo wireguard option that prepends bytes to every
	// handshake packet. Raw so "present at all" is visible (see node()).
	Reserved yaml.Node `yaml:"reserved"`
	// AmneziaWG is mihomo's amnezia-wg-option block, which rewrites the handshake
	// with junk packets. Raw for the same reason as Reserved: presence alone
	// makes the peer behave differently, so it must be visible.
	AmneziaWG yaml.Node `yaml:"amnezia-wg-option"`

	// warnings collects what was dropped from an otherwise usable node; the
	// caller reports them and keeps the node, unlike errors which skip it.
	warnings []error
}

// listValue reads a YAML value that Clash spells either as a sequence or as a
// comma separated scalar. field names the key in the error message; a mapping is
// rejected instead of quietly becoming an empty list.
func listValue(field string, node *yaml.Node) ([]string, error) {
	switch node.Kind {
	case 0: // key absent
		return nil, nil
	case yaml.ScalarNode:
		return splitList(node.Value), nil
	case yaml.SequenceNode:
		out := make([]string, 0, len(node.Content))
		for _, item := range node.Content {
			if item.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("%s: list items must be strings", field)
			}
			out = append(out, item.Value)
		}
		return out, nil
	case yaml.AliasNode:
		return listValue(field, node.Alias)
	default:
		return nil, fmt.Errorf("%s: expected a list or a comma separated string, got a %s", field, yamlKindName(node.Kind))
	}
}

// yamlKindName names a node kind for an error message.
func yamlKindName(kind yaml.Kind) string {
	switch kind {
	case yaml.DocumentNode:
		return "document"
	case yaml.SequenceNode:
		return "list"
	case yaml.MappingNode:
		return "mapping"
	case yaml.ScalarNode:
		return "scalar"
	case yaml.AliasNode:
		return "alias"
	default:
		return "value"
	}
}

type clashWSOpts struct {
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
}

type clashGRPCOpts struct {
	ServiceName string `yaml:"grpc-service-name"`
}

type clashRealityOpts struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id"`
}

// asInt converts a YAML scalar (int or quoted string) to int.
func asInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case string:
		if i, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
			return i
		}
	}
	return 0
}

// ParseClashYAML parses the `proxies:` list of a Clash/Clash.Meta config.
//
// Entries we cannot drive are never fatal: `direct`/`reject` style pseudo
// proxies are skipped silently, and a real proxy this build does not support
// (socks5, tuic, ...) is skipped with an error so the user learns why one node
// of their subscription is missing while the rest still import.
//
// This is the nodes-only door, kept for callers that cannot consume groups and
// rules (subscription fetch). The returned errors describe the whole document,
// including the proxy-groups/rules entries this function does not return; use
// ParseClashConfig when the routing half is wanted too.
func ParseClashYAML(doc []byte, source string) ([]config.Node, []error) {
	c, errs := ParseClashConfig(doc, source)
	return c.Nodes, errs
}

// parseClashProxies decodes the `proxies:` entries one at a time into nodes. It
// also returns the name map de-duplication produced: every proxy name that
// resolved to a surviving node, including the spellings that were merged away.
func parseClashProxies(d *clashDocument, source string, errs *[]error) ([]config.Node, map[string]string) {
	var nodes []config.Node
	// Clash names are one namespace: two different proxies cannot share a name,
	// or every group member and rule action that spells it silently picks one of
	// them while the other becomes unreachable. Clash itself rejects such a
	// profile; here the later entry is skipped and reported.
	owner := make(map[string]string, len(d.Proxies)) // display name -> identity
	for i := range d.Proxies {
		// One entry at a time: a malformed node costs that node, not the
		// subscription. A document-level syntax error is still fatal above.
		var p clashProxy
		if err := d.Proxies[i].Decode(&p); err != nil {
			*errs = append(*errs, fmt.Errorf("share: clash proxy %d (%q): %w", i, p.Name, err))
			continue
		}
		n, err := p.node()
		if err != nil {
			*errs = append(*errs, fmt.Errorf("share: clash proxy %d (%q): %w", i, p.Name, err))
			continue
		}
		// A warning describes a setting dropped from a node that still imports.
		for _, w := range p.warnings {
			*errs = append(*errs, fmt.Errorf("share: clash proxy %d (%q): %w", i, p.Name, w))
		}
		if n.Type == "" {
			continue // unsupported type
		}
		n.Remark = NormalizeTag(p.Name)
		// DIRECT/REJECT are built-in outbounds here, and every group member or
		// rule action that spells those names means the built-in. A node keeping
		// the name could never be addressed, and for "direct"/"reject" its tag
		// would also collide with the built-in tag in the stored configuration.
		if builtin, reserved := clashBuiltinTag(n.Remark); reserved {
			*errs = append(*errs, fmt.Errorf(
				"share: clash proxy %d (%q): name collides with the built-in %q outbound", i, p.Name, builtin))
			continue
		}
		if n.Remark != "" {
			key := dedupeKey(n)
			if prev, taken := owner[n.Remark]; taken && prev != key {
				*errs = append(*errs, fmt.Errorf(
					"share: clash proxy %d (%q): name is used by more than one node; kept the first", i, p.Name))
				continue
			}
			if _, taken := owner[n.Remark]; !taken {
				owner[n.Remark] = key
			}
		}
		n.Source = source
		nodes = append(nodes, n)
	}
	res := finalizeWithAliases(nodes)
	return res.nodes, res.aliases
}

// node converts one Clash proxy entry into a config.Node. A zero Type means
// "pseudo proxy, skip silently"; an error means the entry is malformed or
// unsupported, and the caller records it and moves on.
func (p *clashProxy) node() (config.Node, error) {
	typ := strings.ToLower(strings.TrimSpace(p.Type))
	server := strings.TrimSpace(p.Server)
	port := asInt(p.Port)

	// A chained dialer-proxy means "reach this peer through another outbound".
	// The field is imported as written; resolving the name to a tag and refusing
	// the types whose socket layer cannot be chained happens once the whole
	// document is known (see resolveDialerProxies and the type switch below).
	n := config.Node{
		Server:      server,
		Port:        port,
		AlterID:     asInt(p.AlterID),
		Flow:        strings.TrimSpace(p.Flow),
		Password:    p.Password,
		Method:      p.Cipher,
		UDP:         p.UDP,
		DialerProxy: strings.TrimSpace(p.DialerProxy),
	}

	switch typ {
	case "vless", "vmess":
		n.Type = typ
		n.UUID = strings.TrimSpace(p.UUID)
		if n.Type == "vless" {
			n.AlterID = 0
		}
	case "trojan":
		n.Type = "trojan"
	case "ss", "shadowsocks":
		n.Type = "ss"
		n.Method = p.Cipher
	case "socks5", "socks":
		// A household or ISP-provided SOCKS5 exit. Clash spells the login as
		// username/password; both empty means the server takes none.
		n.Type = "socks5"
		n.Username = strings.TrimSpace(p.Username)
		n.Password = p.Password
	case "hysteria2", "hy2":
		n.Type = "hysteria2"
	case "wireguard", "wg":
		n.Type = "wireguard"
		n.PrivateKey = strings.TrimSpace(p.PrivateKey)
		n.PeerPublicKey = strings.TrimSpace(p.PublicKey)
		n.PresharedKey = strings.TrimSpace(p.PreSharedKey)
		// `reserved` prepends bytes to every handshake packet (mihomo hands it to
		// the bind). Our bind does not, so the peer would behave differently from
		// the config it came from; skip it like a chained dialer-proxy instead.
		// An empty list means "no reserved bytes", which is what we do.
		if p.Reserved.Kind != 0 && !(p.Reserved.Kind == yaml.SequenceNode && len(p.Reserved.Content) == 0) {
			return config.Node{}, fmt.Errorf("reserved is not supported by this build")
		}
		// amnezia-wg-option is the same class of problem: it rewrites the
		// handshake (junk packets, custom header types), so a peer that needs it
		// would never come up and a peer that does not would be told parameters
		// this build never sends.
		if p.AmneziaWG.Kind != 0 {
			return config.Node{}, fmt.Errorf("amnezia-wg-option is not supported by this build")
		}
		allowed, err := listValue("allowed-ips", &p.AllowedIPs)
		if err != nil {
			return config.Node{}, err
		}
		dns, err := listValue("dns", &p.DNS)
		if err != nil {
			return config.Node{}, err
		}
		// mihomo keeps the interface addressing in `ip` (and optionally `ipv6`),
		// spelled without a mask.
		n.Addresses = normalizeWGAddrs([]string{p.IP, p.IPv6})
		n.AllowedIPs = normalizeWGAddrs(allowed)
		if len(n.AllowedIPs) == 0 {
			// Clash gives a single-peer WireGuard without allowed-ips the default
			// route for each address family the interface has an address in
			// (mihomo adapter/outbound/wireguard.go). Keeping the empty list
			// imports a peer that validates and then routes nothing.
			n.AllowedIPs = defaultAllowedIPs(n.Addresses)
		}
		n.DNS = dns
		n.MTU = asInt(p.MTU)
		n.KeepAlive = asInt(p.KeepAlive)
	case "", "direct", "reject", "dns", "selector", "urltest":
		return config.Node{}, nil
	default:
		// A real proxy we cannot drive: skipping it silently would leave the user
		// wondering why one node of the subscription is missing.
		return config.Node{}, fmt.Errorf("unsupported proxy type %q", p.Type)
	}

	// A chain hands the TCP connection to the node's server to another outbound.
	// hysteria2 speaks QUIC over its own UDP socket and WireGuard builds raw
	// sockets in its userspace stack, so neither has a TCP connection to hand
	// over; importing them anyway would dial the peer directly — from this
	// device, with our address as the source — which is the failure the chain
	// exists to prevent. Skip the node and say so.
	if n.DialerProxy != "" {
		switch n.Type {
		case "hysteria2", "wireguard":
			return config.Node{}, fmt.Errorf(
				"dialer-proxy %q is not supported for %s: its transport is not TCP", n.DialerProxy, n.Type)
		}
	}

	if server == "" || port <= 0 || port > 65535 {
		return config.Node{}, fmt.Errorf("invalid address %q:%d", server, port)
	}
	switch n.Type {
	case "vless", "vmess":
		if err := validateUUID(n.UUID); err != nil {
			return config.Node{}, err
		}
	case "trojan", "hysteria2":
		if n.Password == "" {
			return config.Node{}, fmt.Errorf("missing password")
		}
	case "ss":
		if n.Method == "" || n.Password == "" {
			return config.Node{}, fmt.Errorf("missing cipher/password")
		}
	case "wireguard":
		if n.PrivateKey == "" || n.PeerPublicKey == "" {
			return config.Node{}, fmt.Errorf("missing wireguard private-key/public-key")
		}
		if len(n.Addresses) == 0 {
			return config.Node{}, fmt.Errorf("missing wireguard ip")
		}
	}

	// Transport.
	switch normalizeNetwork(p.Network) {
	case "ws":
		tr := ensureTransport(&n, "ws")
		tr.Type = "ws"
		if p.WSOpts != nil {
			tr.Path = p.WSOpts.Path
			for k, v := range p.WSOpts.Headers {
				if tr.Headers == nil {
					tr.Headers = map[string]string{}
				}
				tr.Headers[k] = v
				if strings.EqualFold(k, "host") {
					tr.Host = v
				}
			}
		}
	case "grpc":
		tr := ensureTransport(&n, "grpc")
		tr.Type = "grpc"
		if p.GRPCOpts != nil {
			tr.ServiceName = p.GRPCOpts.ServiceName
		}
	case "h2":
		tr := ensureTransport(&n, "h2")
		tr.Type = "h2"
		if p.WSOpts != nil {
			tr.Path = p.WSOpts.Path
		}
	}

	// TLS / REALITY.
	tlsOn := p.TLS || p.RealityOpts != nil || n.Type == "hysteria2" || n.Type == "trojan"
	if tlsOn {
		t := ensureTLS(&n)
		t.Enabled = true
		t.ServerName = strings.TrimSpace(p.SNI)
		if t.ServerName == "" {
			t.ServerName = strings.TrimSpace(p.ServerName)
		}
		if t.ServerName == "" && (n.Type == "hysteria2" || n.Type == "trojan") {
			t.ServerName = server
		}
		t.Insecure = p.SkipCertVerify
		// Only hysteria2 consumes a certificate pin; for the other protocols the
		// same key would be read as a uTLS name and break the dial.
		if pin := strings.TrimSpace(p.Fingerprint); pin != "" && n.Type == "hysteria2" {
			t.Fingerprint = pin
		}
		if ua := strings.TrimSpace(p.ClientFingerprint); ua != "" {
			if t.Fingerprint != "" {
				// A root-level fingerprint is the user's authentication
				// constraint. A pin must win over the uTLS name, and a value that
				// is *not* a pin must be an error: replacing a typo'd pin with a
				// profile name silently switches the node to "no certificate
				// verification", which is the worst possible outcome.
				if !certPinShape(t.Fingerprint) {
					return config.Node{}, fmt.Errorf(
						"fingerprint %q is not a SHA-256 certificate pin (64 hex digits); refusing to use client-fingerprint %q instead",
						t.Fingerprint, ua)
				}
				p.warnings = append(p.warnings, fmt.Errorf(
					"client-fingerprint %q dropped: fingerprint %q pins the certificate instead", ua, t.Fingerprint))
			} else {
				t.Fingerprint = ua
			}
		}
		if len(p.ALPN) > 0 {
			t.ALPN = append(t.ALPN, p.ALPN...)
		}
		if p.RealityOpts != nil {
			t.Reality = &config.Reality{
				PublicKey: strings.TrimSpace(p.RealityOpts.PublicKey),
				ShortID:   strings.TrimSpace(p.RealityOpts.ShortID),
			}
			if t.Fingerprint == "" {
				t.Fingerprint = "chrome"
			}
		}
	}

	// Hysteria2 obfs travels in transport headers (see hysteria2.go).
	if p.Obfs != "" && !strings.EqualFold(p.Obfs, "none") {
		if n.Transport == nil {
			n.Transport = &config.Transport{}
		}
		if n.Transport.Headers == nil {
			n.Transport.Headers = map[string]string{}
		}
		n.Transport.Headers["obfs"] = p.Obfs
		if p.ObfsPassword != "" {
			n.Transport.Headers["obfs-password"] = p.ObfsPassword
		}
	}
	return n, nil
}

// resolveDialerProxies turns each node's dialer-proxy name into the tag it became
// and drops the node when that name is not part of this document.
//
// dialer-proxy names an outbound the same way a group member does, so it goes
// through the same namespace: tag normalisation may rewrite it, de-duplication
// may have merged it away, and the target may be a group, not only a `proxies:`
// entry. A name that resolves to nothing is not a setting worth keeping — the
// node would dial its server directly, from this device, which is exactly what
// the chain exists to prevent — so the node is dropped and the error names both
// ends, like a group member that names nothing.
//
// The namespace is only complete once the proxy-groups are parsed, so this runs
// after parseClashGroups rather than inside clashProxy.node().
func resolveDialerProxies(nodes []config.Node, ns *clashNamespace, errs *[]error) []config.Node {
	out := make([]config.Node, 0, len(nodes))
	for _, n := range nodes {
		if n.DialerProxy == "" {
			out = append(out, n)
			continue
		}
		name := NormalizeTag(n.DialerProxy)
		if tag, ok := ns.names[name]; ok {
			n.DialerProxy = tag
			out = append(out, n)
			continue
		}
		if builtin, reserved := clashBuiltinTag(name); reserved {
			n.DialerProxy = builtin
			out = append(out, n)
			continue
		}
		*errs = append(*errs, fmt.Errorf(
			"share: node %q: dialer-proxy %q is not in this configuration", n.Tag, n.DialerProxy))
	}
	return out
}

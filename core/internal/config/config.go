// Package config defines Veil's on-disk configuration model.
//
// The model is deliberately a plain data structure: parsing, validation and
// migration live here; runtime behaviour lives in internal/engine.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Mode selects the routing policy.
const (
	ModeRule   = "rule"
	ModeGlobal = "global"
	ModeDirect = "direct"
)

// Node is one upstream proxy endpoint.
type Node struct {
	Tag       string     `json:"tag"`
	Type      string     `json:"type"` // vless | vmess | trojan | ss | hysteria2 | wireguard | socks | http | direct
	Server    string     `json:"server"`
	Port      int        `json:"port"`
	UUID      string     `json:"uuid,omitempty"`
	Password  string     `json:"password,omitempty"`
	Method    string     `json:"method,omitempty"` // shadowsocks cipher
	Flow      string     `json:"flow,omitempty"`   // xtls-rprx-vision
	AlterID   int        `json:"alter_id,omitempty"`
	UDP       *bool      `json:"udp,omitempty"`
	TLS       *TLS       `json:"tls,omitempty"`
	Transport *Transport `json:"transport,omitempty"`
	Remark    string     `json:"remark,omitempty"` // display name from the share link
	Source    string     `json:"source,omitempty"` // subscription name, empty for manual

	// WireGuard. The endpoint lives in Server/Port like every other node; the
	// keys are base64 as written by `wg genkey`, and the address sets are CIDR
	// lists because that is what a wg-quick .conf and the userspace stack use.
	PrivateKey    string   `json:"private_key,omitempty"`
	PeerPublicKey string   `json:"public_key,omitempty"`
	PresharedKey  string   `json:"preshared_key,omitempty"`
	Addresses     []string `json:"addresses,omitempty"`
	AllowedIPs    []string `json:"allowed_ips,omitempty"`
	MTU           int      `json:"mtu,omitempty"`       // 0 selects the WireGuard default (1420)
	KeepAlive     int      `json:"keepalive,omitempty"` // PersistentKeepalive, seconds
	DNS           []string `json:"dns,omitempty"`       // resolvers for the userspace stack
}

// Addr returns "host:port".
func (n Node) Addr() string { return net.JoinHostPort(n.Server, fmt.Sprint(n.Port)) }

// SupportsUDP reports whether UDP relaying is enabled for this node.
func (n Node) SupportsUDP() bool { return n.UDP == nil || *n.UDP }

// TLS holds transport security settings.
type TLS struct {
	Enabled    bool     `json:"enabled"`
	ServerName string   `json:"server_name,omitempty"`
	Insecure   bool     `json:"insecure,omitempty"`
	ALPN       []string `json:"alpn,omitempty"`
	// Fingerprint is overloaded by shape, because Clash/mihomo put both meanings
	// in this one key and users paste either:
	//   - a hex SHA-256 digest (colons optional) pins the peer certificate, which
	//     is how a Hysteria2 deployment with a self-signed cert is authenticated;
	//   - a profile name ("chrome", "firefox", "randomized") selects a uTLS
	//     ClientHello, which is what REALITY and the TLS-minor protocols need.
	// A separate field would collide with this one's JSON tag (Go drops duplicate
	// tags silently), so the shape decides; protocol packages that consume it
	// must ask before treating a value as a name.
	Fingerprint string   `json:"fingerprint,omitempty"`
	Reality     *Reality `json:"reality,omitempty"`
}

// Reality holds REALITY parameters (Xray-compatible).
type Reality struct {
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id,omitempty"`
	SpiderX   string `json:"spider_x,omitempty"`
}

// Transport holds the stream layer settings.
type Transport struct {
	Type        string            `json:"type"` // tcp | ws | grpc | h2
	Path        string            `json:"path,omitempty"`
	Host        string            `json:"host,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	EarlyData   int               `json:"early_data,omitempty"`
	ServiceName string            `json:"service_name,omitempty"`
}

// The generated selector. It is the only group this app creates on its own, and
// the only one that takes new nodes as they are imported (see Group.Auto).
const (
	AutoGroupTag      = "proxy"
	AutoGroupProbeURL = "http://cp.cloudflare.com/generate_204"
)

// Group is a user-visible collection of nodes with a selection policy.
type Group struct {
	Tag       string   `json:"tag"`
	Type      string   `json:"type"` // select | url-test | fallback | load-balance
	Members   []string `json:"members"`
	URL       string   `json:"url,omitempty"`      // latency probe URL
	Interval  int      `json:"interval,omitempty"` // seconds
	Tolerance int      `json:"tolerance,omitempty"`
	// Selected is the user's choice, meaningful for select groups.
	Selected string `json:"selected,omitempty"`
	// Auto marks a group this app generated rather than one the user or an
	// imported profile defined. Only an auto group picks up nodes from a later
	// import: a curated group's member list is itself the routing decision, so
	// growing it behind the user's back would move where fallback/url-test send
	// traffic. The field is omitted when false, so configurations written before
	// it existed read as curated (see markLegacyAutoGroup for the one exception).
	Auto bool `json:"auto,omitempty"`
	// Source names the document this group came from: a subscription's name, or
	// the source a pasted profile was imported under. A refresh replaces the
	// groups of its own source only, and a group with no source was built by hand
	// and is never touched.
	Source string `json:"source,omitempty"`
	// Providers names the proxy providers an imported Clash group collects
	// through its `use:` list. Those members are not in the document at all —
	// they live behind a URL or a file — so they are added to Members after
	// parsing, by the expansion in internal/supervisor. A group may therefore
	// have providers and no inline members; that is not an empty group (see
	// Validate).
	Providers []string `json:"providers,omitempty"`
}

// ProxyProvider is one `proxy-providers:` entry of an imported Clash/mihomo
// profile: a node list that lives outside the profile and that groups collect by
// name through `use:` (Group.Providers).
//
// Only what decides *which* nodes the provider contributes is modelled here. The
// fetch and the expansion into a group's members belong to internal/supervisor;
// this type carries enough for that to run and to be repeated on a refresh: a
// URL for the http kind, a path for the file kind, and the name filters the
// profile applied to the provider's node list.
type ProxyProvider struct {
	// Name is the provider's key in the document, which is the spelling a
	// group's `use:` entry refers to.
	Name string `json:"name"`
	// Type is "http" (fetch URL) or "file" (read Path). Any other provider type
	// is dropped at parse time with an error, because nothing here could read it.
	Type string `json:"type"`
	URL  string `json:"url,omitempty"`
	Path string `json:"path,omitempty"`
	// Interval is how often the provider should be refreshed, in seconds as the
	// document states it; 0 leaves the cadence to the app.
	Interval int `json:"interval,omitempty"`
	// Filter and ExcludeFilter are the profile's regexes over the provider's node
	// names: `filter` keeps what matches, `exclude-filter` drops what matches.
	// They are applied when the provider's nodes are expanded into members.
	Filter        string `json:"filter,omitempty"`
	ExcludeFilter string `json:"exclude_filter,omitempty"`
}

// Rule is one routing rule. Rules are evaluated top to bottom; the first match
// wins, and Action names a node, a group, or one of the built-ins
// "direct"/"reject".
type Rule struct {
	Type      string `json:"type"` // domain | domain-suffix | domain-keyword | domain-regex | ip-cidr | ip-cidr6 | geoip | port | network | process | final
	Value     string `json:"value"`
	Action    string `json:"action"`
	NoResolve bool   `json:"no_resolve,omitempty"`
	// Source names the document this rule came from, exactly like Node.Source
	// and Group.Source: a subscription's name, or the source a pasted profile
	// was imported under. A refresh replaces the rules of its own source only;
	// a rule with no source was written by hand (that is also how every rule in
	// a configuration written before the field existed reads) and is never
	// removed by a subscription refresh.
	Source string `json:"source,omitempty"`
}

// DNSConfig configures name resolution for both the app and the tunnel.
type DNSConfig struct {
	Enable  bool        `json:"enable"`
	Listen  string      `json:"listen,omitempty"` // address of the in-tunnel DNS server, e.g. 172.19.0.2:53
	Servers []DNSServer `json:"servers"`
	Final   string      `json:"final,omitempty"` // server tag used when no rule matches
	Cache   bool        `json:"cache"`
}

// DNSServer is one upstream resolver.
type DNSServer struct {
	Tag     string   `json:"tag"`
	Addr    string   `json:"addr"`             // ip:port, https://..., tls://...
	Detour  string   `json:"detour,omitempty"` // outbound tag, empty = direct
	Domains []string `json:"domains,omitempty"`
}

// TunConfig configures the VPN tun device.
type TunConfig struct {
	MTU        int      `json:"mtu"`
	IPv4       string   `json:"ipv4"`
	IPv6       string   `json:"ipv6,omitempty"`
	DNS        string   `json:"dns"`
	AutoRoute  bool     `json:"auto_route"`
	BypassLAN  bool     `json:"bypass_lan"`
	Routes     []string `json:"routes,omitempty"`
	BypassApps []string `json:"bypass_apps,omitempty"`
	AllowApps  []string `json:"allow_apps,omitempty"`
}

// Subscription is a remote node list.
type Subscription struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Interval int    `json:"interval,omitempty"` // seconds; 0 disables auto update
	Updated  int64  `json:"updated,omitempty"`  // unix seconds of last successful fetch
}

// Config is the whole application configuration.
type Config struct {
	Version       int            `json:"version"`
	LogLevel      string         `json:"log_level"`
	Mode          string         `json:"mode"`
	Mixed         string         `json:"mixed"` // socks5+http listen address
	API           string         `json:"api,omitempty"`
	Tun           TunConfig      `json:"tun"`
	DNS           DNSConfig      `json:"dns"`
	Nodes         []Node         `json:"nodes"`
	Groups        []Group        `json:"groups"`
	Rules         []Rule         `json:"rules"`
	Subscriptions []Subscription `json:"subscriptions"`
	// Providers are the proxy providers the imported profiles defined, by name
	// (Group.Providers refers to them). Their nodes are stored like any other
	// node, with Node.Source set to the provider's name, which is what lets a
	// refresh replace exactly what one provider contributed.
	Providers []ProxyProvider `json:"providers,omitempty"`
}

// Default returns a sane out-of-the-box configuration: a mixed inbound and a
// rule set that keeps LAN/local traffic direct and sends everything else
// through the selected node.
func Default() Config {
	return Config{
		Version:  1,
		LogLevel: "info",
		Mode:     ModeRule,
		Mixed:    "127.0.0.1:7890",
		Tun: TunConfig{
			// 1280 keeps TLS handshakes (1.5-4 KB) inside the tunnel: with a
			// 1400 MTU, small cleartext requests passed while every HTTPS
			// handshake stalled — the classic MSS/MTU symptom.
			MTU:       1280,
			IPv4:      "172.19.0.1",
			DNS:       "172.19.0.2",
			AutoRoute: true,
			BypassLAN: true,
		},
		DNS: DNSConfig{
			Enable: true,
			Listen: "172.19.0.2:53",
			Cache:  true,
			Servers: []DNSServer{
				// Encrypted DNS, so answers cannot be poisoned. These endpoints
				// are reachable from a mainland network (1.1.1.1/dns.google are
				// not), which is why the Cloudflare DoH版本 timed out.
				{Tag: "remote", Addr: "https://doh.pub/dns-query"},
				{Tag: "backup", Addr: "https://dns.alidns.com/dns-query"},
			},
			Final: "remote",
		},
		Rules: []Rule{
			{Type: "geoip", Value: "private", Action: "direct"},
			{Type: "domain-suffix", Value: "local", Action: "direct"},
			{Type: "final", Action: ""},
		},
	}
}

// Validate reports the first structural problem in c.
//
// It also normalises nil slices to empty ones: the JSON encoding of a nil slice
// is `null`, and the ArkTS UI iterates these arrays directly (a null array is a
// hard TypeError that takes the whole app down).
func (c *Config) Validate() error {
	if c.Version == 0 {
		c.Version = 1
	}
	if c.Nodes == nil {
		c.Nodes = []Node{}
	}
	if c.Groups == nil {
		c.Groups = []Group{}
	}
	if c.Rules == nil {
		c.Rules = []Rule{}
	}
	if c.Subscriptions == nil {
		c.Subscriptions = []Subscription{}
	}
	if c.Tun.MTU == 0 {
		c.Tun.MTU = 1280
	}
	if c.Tun.MTU > 1280 {
		// Existing configs kept 1400, where small cleartext requests passed but
		// every TLS handshake stalled. Clamp it.
		c.Tun.MTU = 1280
	}
	if c.DNS.Servers == nil {
		c.DNS.Servers = []DNSServer{}
	}
	if c.Providers == nil {
		c.Providers = []ProxyProvider{}
	}
	for i := range c.Groups {
		if c.Groups[i].Members == nil {
			c.Groups[i].Members = []string{}
		}
	}
	switch c.Mode {
	case "", ModeRule, ModeGlobal, ModeDirect:
	default:
		return fmt.Errorf("unknown mode %q", c.Mode)
	}
	if c.Mode == "" {
		c.Mode = ModeRule
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	tags := make(map[string]bool, len(c.Nodes)+2)
	tags["direct"] = true
	tags["reject"] = true
	for i := range c.Nodes {
		n := &c.Nodes[i]
		if n.Tag == "" {
			n.Tag = fmt.Sprintf("%s-%d", n.Type, i+1)
		}
		if tags[n.Tag] {
			return fmt.Errorf("duplicate outbound tag %q", n.Tag)
		}
		tags[n.Tag] = true
		if n.Type == "" {
			return fmt.Errorf("node %q: missing type", n.Tag)
		}
		if n.Type != "direct" {
			if n.Server == "" || n.Port <= 0 || n.Port > 65535 {
				return fmt.Errorf("node %q: invalid server %s:%d", n.Tag, n.Server, n.Port)
			}
		}
		switch n.Type {
		case "vless", "vmess":
			if n.UUID == "" {
				return fmt.Errorf("node %q: missing uuid", n.Tag)
			}
		case "trojan", "hysteria2":
			if n.Password == "" {
				return fmt.Errorf("node %q: missing password", n.Tag)
			}
			// tls.fingerprint is not validated here on purpose: it is either a
			// certificate pin or a uTLS profile name (see TLS.Fingerprint), and
			// only the protocol that dials knows which shapes it can honour, so
			// it reports the problem with the detail the user needs.
		case "ss":
			if n.Method == "" || n.Password == "" {
				return fmt.Errorf("node %q: missing ss method/password", n.Tag)
			}
		case "wireguard", "wg":
			if n.PrivateKey == "" || n.PeerPublicKey == "" {
				return fmt.Errorf("node %q: missing wireguard private_key/public_key", n.Tag)
			}
			// The userspace stack has no interface address to send from without
			// this, and every dial then fails with an opaque gVisor error; catch
			// it while the UI can still explain it.
			if len(n.Addresses) == 0 {
				return fmt.Errorf("node %q: wireguard requires addresses", n.Tag)
			}
		}
		if n.Transport != nil && n.Transport.Type != "" && n.Transport.Type != "tcp" && n.Transport.Type != "ws" && n.Transport.Type != "grpc" && n.Transport.Type != "h2" {
			return fmt.Errorf("node %q: unsupported transport %q", n.Tag, n.Transport.Type)
		}
	}
	for i := range c.Groups {
		g := &c.Groups[i]
		if g.Tag == "" {
			return fmt.Errorf("group %d: missing tag", i)
		}
		if tags[g.Tag] {
			return fmt.Errorf("duplicate outbound tag %q", g.Tag)
		}
		tags[g.Tag] = true
		// A group with Providers is not empty even when Members is: its members
		// are the nodes of those providers, which only the expansion can produce.
		// Requiring Members here would make every imported profile that collects
		// an airport subscription through `use:` unstorable.
		if len(g.Members) == 0 && len(g.Providers) == 0 {
			return fmt.Errorf("group %q: no members", g.Tag)
		}
	}
	for i, r := range c.Rules {
		if r.Type == "" {
			return fmt.Errorf("rule %d: missing type", i)
		}
		if r.Type != "final" && r.Value == "" {
			return fmt.Errorf("rule %d: missing value", i)
		}
		if r.Action != "" && !tags[r.Action] {
			return fmt.Errorf("rule %d: unknown action %q", i, r.Action)
		}
	}
	return nil
}

// Load reads JSON from path. A missing file yields Default().
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	migrateDNS(&c)
	MarkGeneratedGroups(&c)
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Save writes c atomically to path.
func Save(path string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// migrateDNS repairs the pre-1.0 default that sent every query to 1.1.1.1
// without a proxy detour: on a mainland network that resolver never answers, so
// DNS (and therefore every app) looked broken even when the tunnel worked.
func migrateDNS(c *Config) {
	hasDoH := false
	for _, srv := range c.DNS.Servers {
		if strings.HasPrefix(srv.Addr, "https://") {
			hasDoH = true
		}
	}
	if !hasDoH {
		// Old defaults resolved everything through a mainland UDP resolver, which
		// poisons foreign names. Replace with encrypted DNS that is reachable
		// from here.
		c.DNS.Servers = []DNSServer{
			{Tag: "remote", Addr: "https://doh.pub/dns-query"},
			{Tag: "backup", Addr: "https://dns.alidns.com/dns-query"},
		}
		c.DNS.Final = "remote"
		return
	}
	// An earlier default used Cloudflare, which a mainland egress cannot reach.
	for i := range c.DNS.Servers {
		if strings.Contains(c.DNS.Servers[i].Addr, "1.1.1.1") {
			c.DNS.Servers[i].Addr = "https://doh.pub/dns-query"
			c.DNS.Servers[i].Detour = ""
		}
	}
	if c.DNS.Final != "remote" {
		return
	}
	for _, srv := range c.DNS.Servers {
		if srv.Detour != "" {
			return
		}
	}
	for i := range c.DNS.Servers {
		if c.DNS.Servers[i].Tag == "remote" {
			c.DNS.Servers[i].Addr = "119.29.29.29:53"
		}
	}
	if len(c.DNS.Servers) == 0 {
		c.DNS.Servers = []DNSServer{{Tag: "local", Addr: "223.5.5.5:53"}}
	}
	c.DNS.Final = c.DNS.Servers[0].Tag
}

// MarkGeneratedGroups restores Group.Auto on the selector this app generates
// when the marker is missing.
//
// Two producers lose the marker: a configuration file written before the field
// existed, and an RPC client that round-trips a configuration through a model
// without it (an upgrade would then silently freeze the group — it reads as
// user-curated, so the next imported subscription adds nodes the selector never
// shows, the same trap S19 closes for curated groups, from the other side).
//
// The match is deliberately exact (tag, type, probe URL, no pin, and a member
// list that is precisely every node in order), because marking a group the user
// curates would re-open the bug this field exists to close.
func MarkGeneratedGroups(c *Config) {
	for i := range c.Groups {
		g := &c.Groups[i]
		if g.Auto || g.Tag != AutoGroupTag || g.Type != "select" || g.URL != AutoGroupProbeURL ||
			g.Selected != "" || g.Interval != 0 || g.Tolerance != 0 {
			continue
		}
		if len(g.Members) != len(c.Nodes) || len(g.Members) == 0 {
			continue
		}
		same := true
		for j := range c.Nodes {
			if g.Members[j] != c.Nodes[j].Tag {
				same = false
				break
			}
		}
		if same {
			g.Auto = true
		}
	}
}

// StripNodeName removes the "name" suffix conventions some subscriptions use.
func StripNodeName(s string) string { return strings.TrimSpace(s) }

package share

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"veil/internal/config"
)

// ClashConfig is what a Clash/mihomo document contributes to a Veil
// configuration: the nodes, the proxy groups that collect them, and the routing
// rules that address them.
//
// The three travel together because groups and rules name nodes by their Clash
// `name`, and only the parser knows which tag a name became (tags are
// normalised and de-duplicated, see finalize). Parsing them apart would leave
// the caller guessing at that mapping.
type ClashConfig struct {
	Nodes  []config.Node
	Groups []config.Group
	Rules  []config.Rule
}

// ParseClashConfig parses the routing half (`proxy-groups:` and `rules:`) of a
// Clash/mihomo document alongside its `proxies:`.
//
// Nothing here is fatal: an entry this build cannot honour (an unsupported
// proxy, a group whose members all vanished, a RULE-SET that depends on a file
// we do not ship) is skipped and reported, so the rest of the profile still
// imports. A document-level YAML syntax error is the one exception.
func ParseClashConfig(doc []byte, source string) (ClashConfig, []error) {
	var d clashDocument
	if err := yaml.Unmarshal(doc, &d); err != nil {
		return ClashConfig{}, []error{fmt.Errorf("share: clash yaml: %w", err)}
	}
	var errs []error
	nodes := parseClashProxies(&d, source, &errs)

	// Clash names address nodes and groups alike; map every name to the tag it
	// ended up with so members and rule actions resolve to the same outbound.
	names := make(map[string]string, len(nodes))
	for _, n := range nodes {
		if _, ok := names[n.Remark]; !ok {
			names[n.Remark] = n.Tag
		}
	}
	groups := parseClashGroups(d.ProxyGroups, names, &errs)
	for _, g := range groups {
		if _, ok := names[g.Tag]; !ok {
			names[g.Tag] = g.Tag
		}
	}
	rules := parseClashRules(d.Rules, names, &errs)

	return ClashConfig{Nodes: nodes, Groups: groups, Rules: rules}, errs
}

// clashGroup is one `proxy-groups:` entry.
type clashGroup struct {
	Name    string    `yaml:"name"`
	Type    string    `yaml:"type"`
	Proxies yaml.Node `yaml:"proxies"`
	URL     string    `yaml:"url"`
	// Interval and tolerance are seconds/milliseconds written either bare or
	// quoted, so they stay raw and go through asInt.
	Interval  any `yaml:"interval"`
	Tolerance any `yaml:"tolerance"`
}

// groupPlan is one group whose members are still Clash names.
type groupPlan struct {
	cfg   config.Group
	names []string
}

const (
	groupTodo = iota
	groupBusy
	groupDone
	groupDropped
)

// parseClashGroups turns the `proxy-groups:` entries into config.Group values.
//
// Groups are ordered so that a group is placed after every group it lists: the
// engine builds groups in order and drops one whose member outbound does not
// exist yet, and real profiles routinely define the selector before the
// url-test group it points at.
func parseClashGroups(entries []yaml.Node, names map[string]string, errs *[]error) []config.Group {
	plans := make([]*groupPlan, 0, len(entries))
	index := make(map[string]int, len(entries)) // group tag -> plan index
	for i := range entries {
		var g clashGroup
		if err := entries[i].Decode(&g); err != nil {
			*errs = append(*errs, fmt.Errorf("share: clash group %d (%q): %w", i, g.Name, err))
			continue
		}
		typ, err := clashGroupType(g.Type)
		if err != nil {
			*errs = append(*errs, fmt.Errorf("share: clash group %q: %w", g.Name, err))
			continue
		}
		tag := NormalizeTag(g.Name)
		if tag == "" {
			*errs = append(*errs, fmt.Errorf("share: clash group %d: missing name", i))
			continue
		}
		members, err := listValue("proxies", &g.Proxies)
		if err != nil {
			*errs = append(*errs, fmt.Errorf("share: clash group %q: %w", tag, err))
			continue
		}
		if len(members) == 0 {
			*errs = append(*errs, fmt.Errorf("share: clash group %q: no members", tag))
			continue
		}
		if _, dup := index[tag]; dup {
			*errs = append(*errs, fmt.Errorf("share: clash group %q: duplicate group name", tag))
			continue
		}
		index[tag] = len(plans)
		plans = append(plans, &groupPlan{
			cfg: config.Group{
				Tag:       tag,
				Type:      typ,
				URL:       strings.TrimSpace(g.URL),
				Interval:  asInt(g.Interval),
				Tolerance: asInt(g.Tolerance),
			},
			names: members,
		})
	}

	state := make([]int, len(plans))
	out := make([]config.Group, 0, len(plans))
	var visit func(i int) bool
	visit = func(i int) bool {
		switch state[i] {
		case groupDone:
			return true
		case groupBusy, groupDropped:
			return false
		}
		state[i] = groupBusy
		plan := plans[i]
		members := make([]string, 0, len(plan.names))
		seen := make(map[string]bool, len(plan.names))
		for _, name := range plan.names {
			tag, isGroup, ok := clashMember(NormalizeTag(name), names, index)
			if !ok {
				*errs = append(*errs, fmt.Errorf(
					"share: clash group %q: member %q is not in this configuration", plan.cfg.Tag, name))
				continue
			}
			if isGroup {
				if state[index[tag]] == groupBusy {
					// A cycle cannot be built by a single-pass engine: the member
					// would have to exist before the group that defines it. Drop
					// the back edge and keep the rest of the group working.
					*errs = append(*errs, fmt.Errorf(
						"share: clash group %q: member %q closes a member cycle and was dropped", plan.cfg.Tag, name))
					continue
				}
				if !visit(index[tag]) {
					*errs = append(*errs, fmt.Errorf(
						"share: clash group %q: member group %q was dropped", plan.cfg.Tag, name))
					continue
				}
			}
			if seen[tag] {
				continue
			}
			seen[tag] = true
			members = append(members, tag)
		}
		if len(members) == 0 {
			state[i] = groupDropped
			*errs = append(*errs, fmt.Errorf("share: clash group %q: no usable members", plan.cfg.Tag))
			return false
		}
		plan.cfg.Members = members
		state[i] = groupDone
		out = append(out, plan.cfg)
		return true
	}
	for i := range plans {
		visit(i)
	}
	return out
}

// clashGroupType maps a Clash group type to the policy the engine implements.
func clashGroupType(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "select":
		return "select", nil
	case "url-test":
		return "url-test", nil
	case "fallback":
		return "fallback", nil
	case "load-balance":
		return "load-balance", nil
	case "":
		return "", fmt.Errorf("missing type")
	default:
		// relay, and anything a newer mihomo adds, would need engine support;
		// silently importing it as select would route traffic somewhere the
		// profile never intended.
		return "", fmt.Errorf("unsupported group type %q", s)
	}
}

// clashMember resolves one group member name to an outbound tag. DIRECT and
// REJECT are built-in outbounds in this build, and profiles put them in
// selectors all the time ("手动切换: [auto, DIRECT]").
func clashMember(key string, names map[string]string, groups map[string]int) (tag string, isGroup, ok bool) {
	switch {
	case strings.EqualFold(key, "DIRECT"):
		return "direct", false, true
	case strings.EqualFold(key, "REJECT"), strings.EqualFold(key, "REJECT-DROP"):
		return "reject", false, true
	}
	// Groups first: names also carries group tags once parsing is done, and a
	// member that is a group must be reported as one so it is ordered in.
	if _, found := groups[key]; found {
		return key, true, true
	}
	if tag, found := names[key]; found {
		return tag, false, true
	}
	return "", false, false
}

// clashRuleTypes maps a Clash rule headline to the config.Rule type.
var clashRuleTypes = map[string]string{
	"DOMAIN":         "domain",
	"DOMAIN-SUFFIX":  "domain-suffix",
	"DOMAIN-KEYWORD": "domain-keyword",
	"DOMAIN-REGEX":   "domain-regex",
	"IP-CIDR":        "ip-cidr",
	"IP-CIDR6":       "ip-cidr6",
	"GEOIP":          "geoip",
	"DST-PORT":       "port",
	"NETWORK":        "network",
	"PROCESS-NAME":   "process",
}

// parseClashRules turns `rules:` lines into config.Rule values, in order.
//
// Rule order is the whole semantics ("first match wins"), so nothing is
// reordered here: a rule we cannot express is skipped, never moved. MATCH ends
// the list; anything written after it is unreachable in Clash too.
func parseClashRules(entries []yaml.Node, names map[string]string, errs *[]error) []config.Rule {
	out := make([]config.Rule, 0, len(entries))
	matched := false
	for i := range entries {
		entry := &entries[i]
		if entry.Kind != yaml.ScalarNode {
			*errs = append(*errs, fmt.Errorf("share: clash rule %d: expected a string, got a %s",
				i, yamlKindName(entry.Kind)))
			continue
		}
		raw := strings.TrimSpace(entry.Value)
		if raw == "" {
			continue
		}
		if matched {
			*errs = append(*errs, fmt.Errorf("share: clash rule %d (%q): unreachable after MATCH",
				i, truncate(raw, 48)))
			continue
		}
		fields := strings.Split(raw, ",")
		for j := range fields {
			fields[j] = strings.TrimSpace(fields[j])
		}
		head := strings.ToUpper(fields[0])

		if head == "MATCH" || head == "FINAL" {
			if len(fields) < 2 || fields[1] == "" {
				*errs = append(*errs, fmt.Errorf("share: clash rule %d (%q): missing action", i, raw))
				continue
			}
			action, ok := clashRuleAction(fields[1], names)
			if !ok {
				*errs = append(*errs, fmt.Errorf("share: clash rule %d (%q): %w", i, raw, errUnknownAction(fields[1])))
				continue
			}
			out = append(out, config.Rule{Type: "final", Action: action})
			matched = true
			continue
		}

		typ, known := clashRuleTypes[head]
		if !known {
			*errs = append(*errs, fmt.Errorf("share: clash rule %d (%q): %w", i, truncate(raw, 48), errUnsupportedRule(head)))
			continue
		}
		if len(fields) < 3 || fields[1] == "" || fields[2] == "" {
			*errs = append(*errs, fmt.Errorf("share: clash rule %d (%q): wants TYPE,VALUE,ACTION", i, raw))
			continue
		}
		value, err := clashRuleValue(typ, fields[1])
		if err != nil {
			*errs = append(*errs, fmt.Errorf("share: clash rule %d (%q): %w", i, truncate(raw, 48), err))
			continue
		}
		action, ok := clashRuleAction(fields[2], names)
		if !ok {
			*errs = append(*errs, fmt.Errorf("share: clash rule %d (%q): %w", i, truncate(raw, 48), errUnknownAction(fields[2])))
			continue
		}
		rule := config.Rule{Type: typ, Value: value, Action: action}
		for _, f := range fields[3:] {
			if strings.EqualFold(f, "no-resolve") {
				rule.NoResolve = true
			}
		}
		out = append(out, rule)
	}
	return out
}

// clashRuleAction maps a rule target to the tag the engine knows: a built-in,
// or the tag an imported node/group ended up with.
func clashRuleAction(name string, names map[string]string) (string, bool) {
	switch {
	case strings.EqualFold(name, "DIRECT"):
		return "direct", true
	case strings.EqualFold(name, "REJECT"), strings.EqualFold(name, "REJECT-DROP"):
		return "reject", true
	}
	tag, ok := names[NormalizeTag(name)]
	return tag, ok
}

func errUnknownAction(name string) error {
	return fmt.Errorf("action %q is not a node or group in this configuration", name)
}

// errUnsupportedRule names the reason a rule headline was skipped. A rule set
// lives outside the profile (a URL or a file shipped by Clash), so honouring it
// would silently drop the traffic shaping the user expects from it.
func errUnsupportedRule(head string) error {
	switch head {
	case "RULE-SET", "GEOSITE", "GEOIP-URL", "DOMAIN-SET", "IP-ASN", "SUB-RULE", "AND", "OR", "NOT", "SCRIPT":
		return fmt.Errorf("%s depends on an external rule set that this build does not ship", head)
	default:
		return fmt.Errorf("unsupported rule type %q", head)
	}
}

// clashRuleValue normalises a rule value and rejects the ones the matcher
// cannot compile: an unparsable value here would make every rule after it
// unloadable, because the engine compiles the whole list in one pass.
func clashRuleValue(typ, value string) (string, error) {
	switch typ {
	case "ip-cidr", "ip-cidr6":
		if !validPrefix(value) {
			return "", fmt.Errorf("%s %q is not a valid address or CIDR", typ, value)
		}
		return value, nil
	case "domain-regex":
		if _, err := regexp.Compile(value); err != nil {
			return "", fmt.Errorf("domain-regex %q: %w", value, err)
		}
		return value, nil
	case "geoip":
		v := strings.ToLower(value)
		switch v {
		case "cn", "private":
			return v, nil
		default:
			return "", fmt.Errorf("geoip %q: this build only knows the built-in cn and private sets", value)
		}
	case "network":
		v := strings.ToLower(value)
		if v != "tcp" && v != "udp" {
			return "", fmt.Errorf("network %q: want tcp or udp", value)
		}
		return v, nil
	case "port":
		if !validPortRange(value) {
			return "", fmt.Errorf("port %q is not a port or port range", value)
		}
		return value, nil
	default:
		// domain / domain-suffix / domain-keyword / process.
		return value, nil
	}
}

// validPrefix mirrors what the matcher accepts: a CIDR or a bare address.
func validPrefix(s string) bool {
	if strings.Contains(s, "/") {
		_, err := netip.ParsePrefix(s)
		return err == nil
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// validPortRange accepts "443" and "1000-2000".
func validPortRange(s string) bool {
	lo, hi, hasRange := strings.Cut(s, "-")
	if _, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16); err != nil {
		return false
	}
	if !hasRange {
		return true
	}
	_, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
	return err == nil
}

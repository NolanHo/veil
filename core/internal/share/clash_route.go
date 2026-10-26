package share

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"veil/internal/config"
	"veil/internal/rules"
)

// ClashConfig is what a Clash/mihomo document contributes to a Veil
// configuration: the nodes, the proxy groups that collect them, and the routing
// rules that address them.
//
// The three travel together because groups and rules name nodes by their Clash
// `name`, and only the parser knows which tag a name became (tags are
// normalised and de-duplicated, see finalizeWithAliases). Parsing them apart
// would leave the caller guessing at that mapping.
type ClashConfig struct {
	Nodes  []config.Node
	Groups []config.Group
	Rules  []config.Rule

	// Providers are the document's `proxy-providers:` entries. They are part of
	// this result because the groups reference them by name: a group whose
	// members come from a provider keeps that reference (Group.Providers) and is
	// expanded later, so the definition has to travel with the groups that need
	// it.
	Providers []config.ProxyProvider

	// RulesProvided reports whether the document had a `rules:` key at all.
	// It is true for an explicit empty list — and for a bare `rules:` with no
	// value under it — and false when the key is absent. Those are different
	// statements, and an empty Rules slice alone cannot tell them apart. A
	// consumer that merges the table should therefore read:
	//   RulesProvided == false  -> the document is silent; keep the stored rules
	//   RulesProvided == true   -> the document owns the table; replace it
	//                              (an empty Rules here means "clear it")
	// When the section's value has the wrong shape, the decode error is reported
	// instead and Rules stays empty while the bit remains true. The same
	// reasoning applies to GroupsProvided and Groups.
	RulesProvided bool

	// GroupsProvided reports whether the document had a `proxy-groups:` key at
	// all; an explicit empty list means "no groups", an absent key means "the
	// document says nothing about groups".
	GroupsProvided bool
}

// clashNamespace is the name space of one imported document: every display name
// that resolved to an outbound (nodes first, then the groups that survived),
// plus the tags already taken by nodes.
type clashNamespace struct {
	names map[string]string // display name -> outbound tag
	tags  map[string]bool   // tags already used by an imported node
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
	nodes, aliases := parseClashProxies(&d, source, &errs)

	// Clash names address nodes and groups alike; the namespace maps every name
	// to the tag it ended up with so members and rule actions resolve to the same
	// outbound. aliases already carries every proxy name, including the spellings
	// de-duplication merged away.
	ns := &clashNamespace{names: aliases, tags: make(map[string]bool, len(nodes))}
	for _, n := range nodes {
		ns.tags[n.Tag] = true
	}

	// A section whose value has the wrong shape does not take the document down:
	// the rest of the profile still imports, and the presence bit still says the
	// document tried to state that section.
	providers := parseClashProviders(&d.ProxyProviders, &errs)

	groupEntries, groupsProvided, err := clashSection(&d.ProxyGroups)
	if err != nil {
		errs = append(errs, fmt.Errorf("share: clash proxy-groups: %w", err))
	}
	groups := parseClashGroups(groupEntries, ns, &errs)

	// dialer-proxy names an outbound, and groups join the namespace only above;
	// see resolveDialerProxies (clash.go).
	nodes = resolveDialerProxies(nodes, ns, &errs)

	ruleEntries, rulesProvided, err := clashSection(&d.Rules)
	if err != nil {
		errs = append(errs, fmt.Errorf("share: clash rules: %w", err))
	}
	rules := parseClashRules(ruleEntries, ns.names, &errs)

	return ClashConfig{
		Nodes:          nodes,
		Groups:         groups,
		Rules:          rules,
		Providers:      providers,
		RulesProvided:  rulesProvided,
		GroupsProvided: groupsProvided,
	}, errs
}

// clashSection decodes one optional routing section. present reports whether the
// key was written at all: a bare `rules:` (a YAML null) is present with no
// entries, exactly like `rules: []`; only a missing key is absent.
func clashSection(n *yaml.Node) (entries []yaml.Node, present bool, err error) {
	if n.Kind == 0 {
		return nil, false, nil
	}
	if err := n.Decode(&entries); err != nil {
		return nil, true, err
	}
	return entries, true, nil
}

// normalizeNameFilter makes a group's filter usable by this build.
//
// mihomo compiles these with a regex engine that supports lookahead, and a very
// common profile idiom is `^((?!Traffic).)*$` — "everything whose name does not
// mention Traffic" — used to keep the airport's quota and expiry pseudo-nodes
// out of a selector. Go's RE2 cannot express that, and silently keeping every
// node would put "剩余流量：100 GB" into a fallback group, where it would be the
// first thing dialed.
//
// So the exclusion form is translated into the equivalent exclude-filter, and
// anything else that does not compile is reported instead of ignored: a filter
// the user wrote and this build cannot honour must be visible.
func normalizeNameFilter(filter, exclude string) (string, string, error) {
	filter = strings.TrimSpace(filter)
	exclude = strings.TrimSpace(exclude)
	if filter == "" {
		return "", exclude, nil
	}
	if _, err := regexp.Compile(filter); err == nil {
		return filter, exclude, nil
	}
	if inner, ok := lookaheadExclusion(filter); ok {
		if exclude == "" {
			return "", inner, nil
		}
		return "", "(?:" + exclude + ")|(?:" + inner + ")", nil
	}
	return "", exclude, fmt.Errorf(
		"filter %q is not a pattern this build can compile (lookahead is unsupported)", filter)
}

// lookaheadExclusion unwraps the `^((?!X).)*$` idiom into X.
func lookaheadExclusion(pattern string) (string, bool) {
	trimmed := strings.TrimSpace(pattern)
	const head = "^((?!"
	const tail = ").)*$"
	if !strings.HasPrefix(trimmed, head) || !strings.HasSuffix(trimmed, tail) {
		return "", false
	}
	inner := trimmed[len(head) : len(trimmed)-len(tail)]
	if inner == "" {
		return "", false
	}
	return inner, true
}

// clashProvider is one `proxy-providers:` entry.
type clashProvider struct {
	Type          string `yaml:"type"`
	URL           string `yaml:"url"`
	Path          string `yaml:"path"`
	Interval      any    `yaml:"interval"`
	Filter        string `yaml:"filter"`
	ExcludeFilter string `yaml:"exclude-filter"`
}

// parseClashProviders reads the top-level `proxy-providers:` mapping into the
// definitions a group's `use:` list needs.
//
// Only the keys that decide *which* nodes a provider can contribute are read.
// `override`, `health-check` and `proxy` are ignored on purpose and are not an
// error: override rewrites fields of the fetched nodes, health-check drives
// mihomo's own probing, and proxy names the outbound mihomo fetches through —
// none of them changes the set of nodes a profile expects in its groups, and
// nearly every real profile carries a health-check block, so reporting them
// would fill the import report with noise about fields that cost nothing.
//
// A provider whose type this build cannot read is skipped and reported: keeping
// it would leave the groups that use it empty with no explanation.
func parseClashProviders(n *yaml.Node, errs *[]error) []config.ProxyProvider {
	if n.Kind == 0 {
		return nil
	}
	// A bare `proxy-providers:` is an explicitly empty mapping, not an error.
	if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		return nil
	}
	if n.Kind != yaml.MappingNode {
		*errs = append(*errs, fmt.Errorf(
			"share: clash proxy-providers: expected a mapping, got a %s", yamlKindName(n.Kind)))
		return nil
	}
	out := make([]config.ProxyProvider, 0, len(n.Content)/2)
	// Provider names are one namespace, like proxy and group names: two
	// definitions under one name would make `use:` pick one of them silently.
	seen := make(map[string]bool, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, value := n.Content[i], n.Content[i+1]
		name := NormalizeTag(key.Value)
		if name == "" {
			*errs = append(*errs, fmt.Errorf("share: clash proxy-provider %d: missing name", i/2))
			continue
		}
		var p clashProvider
		if err := value.Decode(&p); err != nil {
			*errs = append(*errs, fmt.Errorf("share: clash proxy-provider %q: %w", name, err))
			continue
		}
		typ := strings.ToLower(strings.TrimSpace(p.Type))
		switch typ {
		case "http", "file":
		case "":
			*errs = append(*errs, fmt.Errorf("share: clash proxy-provider %q: missing type", name))
			continue
		default:
			*errs = append(*errs, fmt.Errorf(
				"share: clash proxy-provider %q: unsupported provider type %q", name, p.Type))
			continue
		}
		if seen[name] {
			*errs = append(*errs, fmt.Errorf(
				"share: clash proxy-provider %q: name is used by more than one definition; kept the first", name))
			continue
		}
		seen[name] = true
		out = append(out, config.ProxyProvider{
			Name:          name,
			Type:          typ,
			URL:           strings.TrimSpace(p.URL),
			Path:          strings.TrimSpace(p.Path),
			Interval:      asInt(p.Interval),
			Filter:        strings.TrimSpace(p.Filter),
			ExcludeFilter: strings.TrimSpace(p.ExcludeFilter),
		})
	}
	return out
}

// clashGroup is one `proxy-groups:` entry.
type clashGroup struct {
	Name    string    `yaml:"name"`
	Type    string    `yaml:"type"`
	Proxies yaml.Node `yaml:"proxies"`
	// Use lists proxy-provider names. It is not an outbound reference: the
	// members behind a provider are only known once it has been fetched, so the
	// list is kept as written and expanded later.
	Use yaml.Node `yaml:"use"`
	URL string    `yaml:"url"`
	// Interval and tolerance are seconds/milliseconds written either bare or
	// quoted, so they stay raw and go through asInt.
	Interval      any    `yaml:"interval"`
	Tolerance     any    `yaml:"tolerance"`
	Filter        string `yaml:"filter"`
	ExcludeFilter string `yaml:"exclude-filter"`
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

// normalizeProviderNames puts the `use:` entries into the spelling provider
// names are kept in, and drops repeats: the same provider twice would expand to
// the same nodes twice. Nil means the group names no provider at all, so an
// empty result stays nil and is omitted from the stored group.
func normalizeProviderNames(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := make([]string, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		key := NormalizeTag(name)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseClashGroups turns the `proxy-groups:` entries into config.Group values.
//
// Groups are ordered so that a group is placed after every group it lists: the
// engine builds groups in order and drops one whose member outbound does not
// exist yet, and real profiles routinely define the selector before the
// url-test group it points at.
//
// A group shares the outbound tag namespace with nodes and the DIRECT/REJECT
// built-ins. A name that collides with either is skipped and reported: keeping
// it would produce a tag that overwrites (or is shadowed by) the other outbound,
// so references would silently land on the wrong destination.
//
// A group that collects its members from proxy providers (`use:`) is returned
// with those references in Providers and an empty Members list: the members only
// exist after the provider has been fetched, which is the supervisor's job.
func parseClashGroups(entries []yaml.Node, ns *clashNamespace, errs *[]error) []config.Group {
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
		use, err := listValue("use", &g.Use)
		if err != nil {
			*errs = append(*errs, fmt.Errorf("share: clash group %q: %w", tag, err))
			continue
		}
		// A group that names neither inline members nor a provider is genuinely
		// empty; a group that names only a provider is not, and it must survive:
		// routing rules address it by name, so dropping it here deletes the
		// outbound every one of those rules sends traffic to.
		if len(members) == 0 && len(use) == 0 {
			*errs = append(*errs, fmt.Errorf("share: clash group %q: no members", tag))
			continue
		}
		providers := normalizeProviderNames(use)
		if _, dup := index[tag]; dup {
			*errs = append(*errs, fmt.Errorf("share: clash group %q: duplicate group name", tag))
			continue
		}
		if builtin, reserved := clashBuiltinTag(tag); reserved {
			*errs = append(*errs, fmt.Errorf(
				"share: clash group %q: name collides with the built-in %q outbound", tag, builtin))
			continue
		}
		if nodeTag, taken := ns.names[tag]; taken {
			*errs = append(*errs, fmt.Errorf(
				"share: clash group %q: name collides with the imported node %q", tag, nodeTag))
			continue
		}
		if ns.tags[tag] {
			*errs = append(*errs, fmt.Errorf(
				"share: clash group %q: tag is already used by an imported node", tag))
			continue
		}
		nameFilter, excludeFilter, ferr := normalizeNameFilter(g.Filter, g.ExcludeFilter)
		if ferr != nil {
			*errs = append(*errs, fmt.Errorf("share: clash group %q: %w", tag, ferr))
		}
		index[tag] = len(plans)
		plans = append(plans, &groupPlan{
			cfg: config.Group{
				Tag:       tag,
				Type:      typ,
				URL:       strings.TrimSpace(g.URL),
				Interval:  asInt(g.Interval),
				Tolerance: asInt(g.Tolerance),
				Providers: providers,
				// mihomo writes these on the group and applies them to the
				// provider's nodes only; they never filter an inline member.
				Filter:        nameFilter,
				ExcludeFilter: excludeFilter,
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
			tag, isGroup, ok := clashMember(NormalizeTag(name), ns.names, index)
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
		if len(members) == 0 && len(plan.cfg.Providers) == 0 {
			state[i] = groupDropped
			*errs = append(*errs, fmt.Errorf("share: clash group %q: no usable members", plan.cfg.Tag))
			return false
		}
		// A group whose only members come from providers is left with an empty
		// member list on purpose: the expansion (internal/supervisor) fills it
		// from the providers named in Providers. The group is still an
		// addressable outbound, so rules naming it keep working, and groups that
		// list it are still ordered after it.
		plan.cfg.Members = members
		// The group is now an addressable outbound: a rule action naming it
		// resolves to its tag, and a later group listing it is ordered after it.
		ns.names[plan.cfg.Tag] = plan.cfg.Tag
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

// clashBuiltinTag reports the engine outbound a policy name means. DIRECT and
// REJECT(-DROP) are built-in outbounds here, not nodes, and every group member
// or rule action that spells them means the built-in.
//
// This is also the reserved-name test for the import: a node or group with such
// a name could never be addressed (the spelling always means the built-in), and
// a "direct"/"reject" tag would additionally collide with the built-in tag in
// the stored configuration, which validation rejects as a duplicate outbound.
func clashBuiltinTag(name string) (string, bool) {
	switch {
	case strings.EqualFold(name, "DIRECT"):
		return "direct", true
	case strings.EqualFold(name, "REJECT"), strings.EqualFold(name, "REJECT-DROP"):
		return "reject", true
	}
	return "", false
}

// clashMember resolves one group member name to an outbound tag. DIRECT and
// REJECT are built-in outbounds in this build, and profiles put them in
// selectors all the time ("手动切换: [auto, DIRECT]").
func clashMember(key string, names map[string]string, groups map[string]int) (tag string, isGroup, ok bool) {
	if tag, builtin := clashBuiltinTag(key); builtin {
		return tag, false, true
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
			rule := config.Rule{Type: "final", Action: action}
			if err := clashRuleCompiles(rule); err != nil {
				*errs = append(*errs, fmt.Errorf("share: clash rule %d (%q) does not compile: %w", i, raw, err))
				continue
			}
			out = append(out, rule)
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
		if err := clashRuleCompiles(rule); err != nil {
			*errs = append(*errs, fmt.Errorf("share: clash rule %d (%q) does not compile: %w", i, truncate(raw, 48), err))
			continue
		}
		out = append(out, rule)
	}
	return out
}

// clashRuleCompiles asks the matcher itself whether one rule loads. The value
// checks above cover the shapes this importer knows, but the engine compiles the
// whole list in one pass: a rule that only fails there — an inverted port range,
// a domain suffix that normalises to nothing, a process name that is just a path
// separator — would import cleanly and then take the entire tunnel down at
// start, with nothing in the UI to point at the rule.
//
// It runs the real compiler one rule at a time rather than restating its checks
// here, so the two cannot drift apart.
func clashRuleCompiles(r config.Rule) error {
	_, err := rules.New([]config.Rule{r}, config.ModeRule, r.Action)
	return err
}

// clashRuleAction maps a rule target to the tag the engine knows: a built-in,
// or the tag an imported node/group ended up with.
func clashRuleAction(name string, names map[string]string) (string, bool) {
	key := NormalizeTag(name)
	if tag, builtin := clashBuiltinTag(key); builtin {
		return tag, true
	}
	tag, ok := names[key]
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
		v := strings.ToLower(strings.TrimSpace(value))
		switch v {
		case "cn", "private":
			return v, nil
		case "lan":
			// mihomo ships a "LAN" country code meaning RFC1918 space; a
			// profile that relies on it to keep the local network direct would
			// otherwise send it through the proxy.
			return "private", nil
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

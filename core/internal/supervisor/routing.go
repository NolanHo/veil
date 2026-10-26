package supervisor

import (
	"fmt"
	"strings"

	"veil/internal/config"
	"veil/internal/share"
)

// routingTable is one document's contribution to the routing half of the
// configuration: the groups that collect nodes and the rules that address them.
//
// The presence bits carry the difference between "this document says the table
// is empty" and "this document did not mention the table". They come from the
// parser, which is the only layer that sees the document itself: a stated
// section is the document's complete statement of intent and replaces what is
// stored, an unstated one leaves the stored table alone.
type routingTable struct {
	Groups []config.Group
	Rules  []config.Rule

	GroupsProvided bool
	RulesProvided  bool
}

// clashRouting adapts the Clash parser's result to a merge request.
//
// A section that failed to parse comes back as "provided but empty" with an
// error. Treating that as "the document states an empty table" would wipe the
// user's routing because of a typo, so a section that errored is downgraded to
// "not stated" and the stored table survives.
func clashRouting(c share.ClashConfig, errs []error) routingTable {
	broken := func(keywords ...string) bool {
		for _, err := range errs {
			if err == nil {
				continue
			}
			for _, k := range keywords {
				if strings.Contains(err.Error(), k) {
					return true
				}
			}
		}
		return false
	}
	t := routingTable{
		Groups:         c.Groups,
		Rules:          c.Rules,
		GroupsProvided: c.GroupsProvided,
		RulesProvided:  c.RulesProvided,
	}
	if t.GroupsProvided && len(c.Groups) == 0 && broken("clash group", "clash proxy-groups") {
		t.GroupsProvided = false
	}
	if t.RulesProvided && len(c.Rules) == 0 && broken("clash rule", "clash rules") {
		t.RulesProvided = false
	}
	return t
}

// mergeRouting folds one document's routing table into the live configuration.
func (s *Supervisor) mergeRouting(t routingTable) (groupCount, ruleCount int, warnings []string) {
	if !t.GroupsProvided && !t.RulesProvided {
		return 0, 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return mergeRoutingTable(&s.cfg, t)
}

// mergeRoutingTable folds t into cfg and reports how many groups and rules the
// document contributed.
//
// A group or rule the document defines replaces the one already there, and
// everything else is kept: the routing table of a pasted profile is the user's
// intent for the tags it names, not necessarily the whole of what they have
// stored (a second subscription, groups they built in the UI). A *stated but
// empty* section is different — it says the profile has no groups/rules at all,
// and the corresponding table is cleared.
//
// Groups are re-ordered across the whole merged set, not just across the
// document's own groups: the engine builds groups in one pass and drops a group
// whose member does not exist yet, so a merged set can be broken by an order
// that was valid in each half separately.
func mergeRoutingTable(cfg *config.Config, t routingTable) (groupCount, ruleCount int, warnings []string) {
	if t.GroupsProvided {
		if len(t.Groups) > 0 {
			incoming := make(map[string]bool, len(t.Groups))
			for _, g := range t.Groups {
				incoming[g.Tag] = true
			}
			kept := make([]config.Group, 0, len(cfg.Groups)+len(t.Groups))
			for _, g := range cfg.Groups {
				if !incoming[g.Tag] {
					kept = append(kept, g)
				}
			}
			var orderWarnings []string
			cfg.Groups, orderWarnings = orderGroups(append(kept, t.Groups...))
			warnings = append(warnings, orderWarnings...)
			groupCount = len(t.Groups)
		} else {
			// `proxy-groups: []`: the profile states that it defines no groups.
			// The generated selector stays, so the imported nodes remain
			// reachable and a later node import still has somewhere to put them.
			cfg.Groups = autoGroups(cfg.Groups)
			warnings = append(warnings, "the document states an empty proxy-groups list; only generated groups were kept")
		}
	}
	if t.RulesProvided {
		if len(t.Rules) > 0 {
			// A Clash profile's rule list is an ordered, complete table and first
			// match wins. Merging imported rules *behind* the stock ones silently
			// shadows them — the stock "geoip private → direct" beats an imported
			// "ip-cidr 10.x → wireguard", which is exactly what a split tunnel
			// needs to work. So the import replaces the table; the stock rules are
			// starter content, not user intent.
			rules := append([]config.Rule(nil), t.Rules...)
			if !hasFinalRule(rules) {
				// Without a final rule unmatched traffic has no destination at all.
				rules = append(rules, config.Rule{Type: "final"})
			}
			cfg.Rules = rules
			ruleCount = len(t.Rules)
		} else {
			// `rules: []`: the profile states that no rule should match, so
			// traffic follows the engine's default outbound. Nothing is appended
			// here — a final rule would contradict the empty list.
			cfg.Rules = []config.Rule{}
			warnings = append(warnings, "the document states an empty rules list; the rule table is now empty")
		}
	}
	return groupCount, ruleCount, warnings
}

func hasFinalRule(rules []config.Rule) bool {
	for _, r := range rules {
		if r.Type == "final" {
			return true
		}
	}
	return false
}

// autoGroups keeps the generated groups only.
func autoGroups(groups []config.Group) []config.Group {
	out := make([]config.Group, 0, len(groups))
	for _, g := range groups {
		if g.Auto {
			out = append(out, g)
		}
	}
	return out
}

// orderGroups places every group after the groups it lists as members.
//
// The engine builds outbounds in stored order and a group whose member is not
// built yet is dropped whole, so the order is load-bearing. Parsing a single
// document already yields such an order (share.parseClashGroups walks the same
// dependencies); merging that document into a stored set breaks it again, which
// is why the merge re-runs the ordering over the result.
//
// A member cycle cannot be satisfied by any order. Both groups are kept — the
// supervisor does not delete the user's routing — and the cycle is reported, so
// the consequence (the engine skips the group built first) is visible instead of
// mysterious.
func orderGroups(groups []config.Group) ([]config.Group, []string) {
	pos := make(map[string]int, len(groups))
	for i := range groups {
		pos[groups[i].Tag] = i
	}
	const (
		unvisited = iota
		visiting
		ordered
	)
	state := make([]int, len(groups))
	out := make([]config.Group, 0, len(groups))
	var warnings []string
	var visit func(i int)
	visit = func(i int) {
		if state[i] != unvisited {
			return
		}
		state[i] = visiting
		for _, member := range groups[i].Members {
			j, isGroup := pos[member]
			if !isGroup {
				continue
			}
			if state[j] == visiting {
				warnings = append(warnings, fmt.Sprintf(
					"groups %q and %q list each other; the engine builds groups in order and will skip the first one",
					groups[i].Tag, groups[j].Tag))
				continue
			}
			visit(j)
		}
		state[i] = ordered
		out = append(out, groups[i])
	}
	for i := range groups {
		visit(i)
	}
	return out, warnings
}

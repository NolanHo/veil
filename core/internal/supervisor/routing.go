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

// routingOrigin says where one document's routing rows come from and how much of
// the stored table they own.
type routingOrigin struct {
	// Source is the label stamped on every group and rule the document brings:
	// the subscription's name when one is refreshed, or the source a pasted
	// profile is imported under (the same label its nodes get). A later refresh
	// finds its own rows by this label; a row without one belongs to the user.
	Source string

	// OwnsTable makes the document's rule list replace the whole table instead of
	// only the rows that carry Source. A pasted Clash profile states a complete,
	// ordered rule table, so it owns the table; a subscription only owns its own
	// slice of it.
	OwnsTable bool
}

// mergeRoutingTable folds t into cfg and reports how many groups and rules the
// document contributed.
//
// A row the document defines replaces the one already there, and everything else
// is kept: the routing table of a document is its intent for the tags it names,
// not necessarily the whole of what the user has stored (a second subscription,
// groups they built in the UI). What "everything else" is, though, depends on
// who the document speaks for (routingOrigin): a pasted profile states a
// complete rule table, so OwnsTable clears what was there, while a subscription
// only replaces the rows stamped with its own name and leaves the user's rules
// and every other source alone. A *stated but empty* section says the document
// has no groups/rules at all, and clears that same scope, never more.
//
// Groups are re-ordered across the whole merged set, not just across the
// document's own groups: the engine builds groups in one pass and drops a group
// whose member does not exist yet, so a merged set can be broken by an order
// that was valid in each half separately.
func mergeRoutingTable(cfg *config.Config, t routingTable, origin routingOrigin) (groupCount, ruleCount int, warnings []string) {
	if t.GroupsProvided {
		if len(t.Groups) > 0 {
			incoming := make([]config.Group, 0, len(t.Groups))
			defined := make(map[string]bool, len(t.Groups))
			for _, g := range t.Groups {
				g.Source = origin.Source
				incoming = append(incoming, g)
				defined[g.Tag] = true
			}
			kept := make([]config.Group, 0, len(cfg.Groups)+len(incoming))
			for _, g := range cfg.Groups {
				// A refresh drops the groups this source brought last time: a group
				// the document no longer defines is gone from the document.
				if !origin.OwnsTable && fromSource(g.Source, origin.Source) {
					continue
				}
				if defined[g.Tag] {
					if g.Source != origin.Source {
						// A tag is an outbound's identity, so only one group can hold
						// it, and the document's rules already name its version. The
						// group that loses is the user's own, so say it.
						from := g.Source
						if from == "" {
							from = "a hand-built group"
						}
						warnings = append(warnings, fmt.Sprintf(
							"group %q replaces the group of the same name from %s", g.Tag, from))
					}
					continue
				}
				kept = append(kept, g)
			}
			var orderWarnings []string
			cfg.Groups, orderWarnings = orderGroups(append(kept, incoming...))
			warnings = append(warnings, orderWarnings...)
			groupCount = len(incoming)
		} else if origin.OwnsTable {
			// `proxy-groups: []`: the profile states that it defines no groups.
			// The generated selector stays, so the imported nodes remain
			// reachable and a later node import still has somewhere to put them.
			cfg.Groups = autoGroups(cfg.Groups)
			warnings = append(warnings, "the document states an empty proxy-groups list; only generated groups were kept")
		} else {
			// A subscription that stops stating groups stops contributing them;
			// the groups other sources and the user built are not its to clear.
			kept := make([]config.Group, 0, len(cfg.Groups))
			for _, g := range cfg.Groups {
				if !fromSource(g.Source, origin.Source) {
					kept = append(kept, g)
				}
			}
			cfg.Groups = kept
			warnings = append(warnings, "the document states an empty proxy-groups list; the subscription's groups were removed")
		}
	}
	if t.RulesProvided {
		if origin.OwnsTable {
			if len(t.Rules) > 0 {
				// A Clash profile's rule list is an ordered, complete table and first
				// match wins. Merging imported rules *behind* the stock ones silently
				// shadows them — the stock "geoip private → direct" beats an imported
				// "ip-cidr 10.x → wireguard", which is exactly what a split tunnel
				// needs to work. So the import replaces the table; the stock rules are
				// starter content, not user intent.
				rules := make([]config.Rule, 0, len(t.Rules)+1)
				for _, r := range t.Rules {
					r.Source = origin.Source
					rules = append(rules, r)
				}
				if !hasFinalRule(rules) {
					// Without a final rule unmatched traffic has no destination at all.
					// The appended one carries no source: it is this app's fallback, not
					// something the document said.
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
		} else {
			var ruleWarnings []string
			ruleCount, ruleWarnings = mergeSourceRules(cfg, origin.Source, t)
			warnings = append(warnings, ruleWarnings...)
		}
	}
	return groupCount, ruleCount, warnings
}

// mergeSourceRules replaces one source's slice of the rule table and leaves every
// other row exactly where it is.
//
// Rule order is the semantics ("first match wins"), so both placements are
// load-bearing:
//
//   - The document's rules take the span its old rules occupied, so a refresh
//     never moves a subscription's block across the rules the user wrote. A
//     source that has no rules yet is inserted just above the table's catch-all:
//     below it, none of them could ever match.
//   - A final rule is a catch-all and therefore cannot be inserted between stored
//     rules either. It takes the stored final's place when that one carries no
//     action (the app writes such a placeholder when nobody picked a target), and
//     otherwise the stored final wins with a warning, because swapping it would
//     silently change where the user's unmatched traffic goes.
func mergeSourceRules(cfg *config.Config, source string, t routingTable) (ruleCount int, warnings []string) {
	body := make([]config.Rule, 0, len(t.Rules))
	var docFinal *config.Rule
	for _, r := range t.Rules {
		r.Source = source
		if r.Type == "final" {
			if docFinal == nil {
				final := r
				docFinal = &final
			}
			continue
		}
		body = append(body, r)
	}

	kept := make([]config.Rule, 0, len(cfg.Rules))
	at := -1
	for _, r := range cfg.Rules {
		if fromSource(r.Source, source) {
			if at < 0 {
				at = len(kept)
			}
			continue
		}
		kept = append(kept, r)
	}
	if at < 0 {
		at = finalIndex(kept)
	}
	out := make([]config.Rule, 0, len(kept)+len(body)+1)
	out = append(out, kept[:at]...)
	out = append(out, body...)
	out = append(out, kept[at:]...)
	ruleCount = len(body)

	if docFinal != nil {
		if i := finalIndex(out); i < len(out) {
			if out[i].Action == "" {
				out[i] = *docFinal
				ruleCount++
			} else {
				warnings = append(warnings, fmt.Sprintf(
					"the document's MATCH rule was skipped: the rule table already falls through to %q", out[i].Action))
			}
		} else {
			out = append(out, *docFinal)
			ruleCount++
		}
	}
	if len(t.Rules) == 0 {
		warnings = append(warnings, "the document states an empty rules list; the subscription's rules were removed")
	}
	cfg.Rules = out
	return ruleCount, warnings
}

// fromSource reports whether a stored row belongs to source. Nothing belongs to
// the empty source: those rows were written by hand.
func fromSource(row, source string) bool { return source != "" && row == source }

// finalIndex is the position of the first catch-all rule, or len(rules) when the
// table has none.
func finalIndex(rules []config.Rule) int {
	for i, r := range rules {
		if r.Type == "final" {
			return i
		}
	}
	return len(rules)
}

func hasFinalRule(rules []config.Rule) bool { return finalIndex(rules) < len(rules) }

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

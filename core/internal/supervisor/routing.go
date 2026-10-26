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
	// Providers are the document's `proxy-providers:` entries. They travel with
	// the groups because a group's `use:` list names them: the members behind a
	// provider are only known once it has been fetched, and that happens after
	// the document has been merged (see importRows and applyProvider).
	Providers []config.ProxyProvider

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
		Providers:      c.Providers,
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

// resolveIncomingTags gives every row of one document a tag no other source
// holds, and reports the renames as warnings.
//
// A tag is an outbound's identity: the engine's rule actions, the UI's group
// list and the stored configuration all address a group or a node by it, and
// Validate refuses two outbounds with one name. A document therefore cannot
// reuse a tag another source already owns — a subscription whose node is also
// pasted by hand used to make every refresh fail with `duplicate outbound tag`,
// and two subscriptions defining `shared` made the second take the first's group
// over, so deleting the second took the first's rules with it.
//
// The name a document gets is derived from its own tag and its source
// ("x (subA)"), never from an arrival counter, so refreshing the same document
// lands on the same tag. Rows the document keeps for itself are claimed before a
// name is generated, so a generated name never takes a tag the document's own
// rows refer to. Duplicate tags *within* one source keep the existing
// replace-by-tag behaviour: those rows are one source correcting itself.
//
// A document without a source speaks for the user: its tags are the user's, and
// a stored row of the same name is the row being replaced, so nothing is renamed.
func resolveIncomingTags(cfg *config.Config, nodes []config.Node, tables []*routingTable, origin routingOrigin) []string {
	if origin.Source == "" {
		return nil
	}
	foreign := make(map[string]bool, len(cfg.Nodes)+len(cfg.Groups)+4)
	// The built-ins are outbound names too, and Validate reserves them.
	foreign["direct"] = true
	foreign["reject"] = true
	for _, n := range cfg.Nodes {
		if n.Tag != "" && !fromSource(n.Source, origin.Source) {
			foreign[n.Tag] = true
		}
	}
	for _, g := range cfg.Groups {
		if g.Tag != "" && !fromSource(g.Source, origin.Source) {
			foreign[g.Tag] = true
		}
	}
	claimed := make(map[string]bool, len(nodes)+len(cfg.Groups))
	for _, n := range nodes {
		if n.Tag != "" && !foreign[n.Tag] {
			claimed[n.Tag] = true
		}
	}
	for _, t := range tables {
		for _, g := range t.Groups {
			if g.Tag != "" && !foreign[g.Tag] {
				claimed[g.Tag] = true
			}
		}
	}
	taken := func(tag string) bool { return foreign[tag] || claimed[tag] }

	var warnings []string
	renames := make(map[string]string)
	rename := func(kind, tag string) string {
		if tag == "" || !foreign[tag] {
			return tag
		}
		next := disambiguatedTag(tag, origin.Source, taken)
		claimed[next] = true
		renames[tag] = next
		warnings = append(warnings, fmt.Sprintf(
			"%s %q is already used by another source; stored as %q", kind, tag, next))
		return next
	}

	for i := range nodes {
		nodes[i].Tag = rename("node", nodes[i].Tag)
	}
	for _, t := range tables {
		for gi := range t.Groups {
			t.Groups[gi].Tag = rename("group", t.Groups[gi].Tag)
		}
	}
	// A document addresses its own rows by tag, so a rename has to follow the
	// document: its group members and rule actions must point at its own rows,
	// not at the other source's row that kept the name.
	for _, t := range tables {
		for gi := range t.Groups {
			for mi, member := range t.Groups[gi].Members {
				if to, ok := renames[member]; ok {
					t.Groups[gi].Members[mi] = to
				}
			}
		}
		for ri := range t.Rules {
			if to, ok := renames[t.Rules[ri].Action]; ok {
				t.Rules[ri].Action = to
			}
		}
	}
	return warnings
}

// disambiguatedTag builds the name a row takes when its document tag is already
// held by another source: `tag (source)`, or `tag (source)-2` when even that is
// spoken for. Deterministic in its inputs, which is what makes a refresh stable.
func disambiguatedTag(tag, source string, taken func(string) bool) string {
	base := fmt.Sprintf("%s (%s)", tag, source)
	if !taken(base) {
		return base
	}
	for i := 2; ; i++ {
		if candidate := fmt.Sprintf("%s-%d", base, i); !taken(candidate) {
			return candidate
		}
	}
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
//
// The caller renames rows that collide with another source before merging (see
// resolveIncomingTags), so a tag reaching this function belongs to exactly one
// source: the same tag here means the same group is being redefined.
func mergeRoutingTable(cfg *config.Config, t routingTable, origin routingOrigin) (groupCount, ruleCount int, warnings []string) {
	if t.GroupsProvided {
		if len(t.Groups) > 0 {
			// The tag is the group's identity, not the document's: the user's pin
			// (Selected) and the app's auto marker belong to the group, so a
			// document that redefines a tag inherits them. Without this a refresh
			// — and the refresh on start makes that a daily event — silently
			// moved the user's own choice back to the provider's first member.
			previous := make(map[string]config.Group, len(cfg.Groups))
			for _, g := range cfg.Groups {
				previous[g.Tag] = g
			}
			incoming := make([]config.Group, 0, len(t.Groups))
			defined := make(map[string]bool, len(t.Groups))
			for _, g := range t.Groups {
				g.Source = origin.Source
				if old, ok := previous[g.Tag]; ok {
					g.Auto = g.Auto || old.Auto
					switch {
					case old.Selected == "":
					case contains(g.Members, old.Selected):
						g.Selected = old.Selected
					case len(g.Providers) > 0:
						// The provider's nodes are not expanded yet, so an empty
						// member list proves nothing: keep the pin and let the
						// post-expansion pass clear it if the node really is gone.
						g.Selected = old.Selected
					default:
						// A pin can only survive while its member does. Clearing it
						// changes where traffic exits, so it is reported.
						warnings = append(warnings, fmt.Sprintf(
							"group %q: the selected member %q is no longer a member; the selection was cleared",
							g.Tag, old.Selected))
					}
				}
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

// clearDanglingSelections drops a pin whose member is no longer in the group and
// reports it.
//
// The inheritance in mergeRoutingTable only sees the member list the document
// states; the membership rebuild that follows a refresh can still remove a
// member (the document lists a node it stopped defining). A pin that names
// nothing would let the group fall back to another member without saying so, and
// that is a change of where traffic exits.
func clearDanglingSelections(cfg *config.Config) []string {
	var warnings []string
	for gi := range cfg.Groups {
		g := &cfg.Groups[gi]
		if g.Selected == "" || contains(g.Members, g.Selected) {
			continue
		}
		warnings = append(warnings, fmt.Sprintf(
			"group %q: the selected member %q is no longer a member; the selection was cleared", g.Tag, g.Selected))
		g.Selected = ""
	}
	return warnings
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

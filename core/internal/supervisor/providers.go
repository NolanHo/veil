package supervisor

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"veil/internal/config"
)

// Proxy providers.
//
// A Clash profile may keep its node list outside the document: `proxy-providers:`
// says where the list lives (a URL, or a file on the machine that wrote the
// profile), and a group collects it by name through `use:`. Importing such a
// profile therefore stores the definitions and the group's reference to them
// (config.ProxyProvider, config.Group.Providers) but not a single node, and every
// rule that names that group has nothing to send traffic to until the provider is
// fetched and its nodes are expanded into the group's members.
//
// The nodes are stored like any other node, with Source set to the provider's
// name. That one field is the whole ownership model: a refresh replaces exactly
// the nodes whose Source is its own name, and the membership expansion rebuilds
// the provider half of every group from the same field. It also means a provider
// and a subscription with the same name would fight over the same rows — provider
// names and subscription names share one label space here.

// providerKind reports whether this build can fetch a provider, and why not when
// it cannot.
func providerKind(p config.ProxyProvider) (ok bool, reason string) {
	switch typ := strings.ToLower(strings.TrimSpace(p.Type)); typ {
	case "http":
		return true, ""
	case "file":
		// A file provider names a path on the device that wrote the profile.
		// There is no such file here — the profile arrived as text — so the
		// group that uses it cannot be filled, and saying so is all this build
		// can honestly do.
		return false, "type file: no local file to read"
	case "":
		return false, "missing type"
	default:
		return false, fmt.Sprintf("unsupported type %q", typ)
	}
}

// providerFilter compiles the profile's name filters.
//
// A nil filter keeps everything. An uncompilable regexp is an error rather than
// a no-op: the filter decides which of the provider's nodes the user wanted, so
// ignoring it would put nodes in a group the profile excluded.
func providerFilter(p config.ProxyProvider) (keep func(config.Node) bool, err error) {
	var want, drop *regexp.Regexp
	if s := strings.TrimSpace(p.Filter); s != "" {
		re, cerr := regexp.Compile(s)
		if cerr != nil {
			return nil, fmt.Errorf("filter %q: %w", s, cerr)
		}
		want = re
	}
	if s := strings.TrimSpace(p.ExcludeFilter); s != "" {
		re, cerr := regexp.Compile(s)
		if cerr != nil {
			return nil, fmt.Errorf("exclude-filter %q: %w", s, cerr)
		}
		drop = re
	}
	if want == nil && drop == nil {
		return nil, nil
	}
	return func(n config.Node) bool {
		if want != nil && !want.MatchString(n.Tag) {
			return false
		}
		return drop == nil || !drop.MatchString(n.Tag)
	}, nil
}

// providerNodes fetches one provider and returns the nodes it contributes, in the
// provider's own document order, with Source already set to its name.
func (s *Supervisor) providerNodes(ctx context.Context, p config.ProxyProvider) (nodes []config.Node, warnings []string, err error) {
	if ok, why := providerKind(p); !ok {
		return nil, nil, fmt.Errorf("%s", why)
	}
	if p.Name == "" {
		return nil, nil, fmt.Errorf("missing name")
	}
	if p.URL == "" {
		return nil, nil, fmt.Errorf("missing url")
	}
	filter, err := providerFilter(p)
	if err != nil {
		return nil, nil, err
	}
	// The same fetch a subscription goes through: the same protected egress, the
	// same timeout and body cap, and both the Clash document and the link-list
	// door (providers serve either).
	body, err := s.fetchSubscription(ctx, p.URL, p.Name)
	if err != nil {
		return nil, nil, err
	}
	if len(body.Nodes) == 0 {
		return nil, nil, fmt.Errorf("the provider listed no node")
	}
	out := make([]config.Node, 0, len(body.Nodes))
	for _, n := range body.Nodes {
		// A provider serves a node list; whatever groups or rules the same body
		// states belong to whoever serves it, not to the profile that uses the
		// provider, so only the nodes travel from here.
		n.Source = p.Name
		if filter != nil && !filter(n) {
			continue
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		warnings = append(warnings, fmt.Sprintf(
			"filter %q / exclude-filter %q matched none of the provider's %d node(s)",
			p.Filter, p.ExcludeFilter, len(body.Nodes)))
	}
	return out, warnings, nil
}

// findProvider returns the stored definition of one provider, or nil.
func findProvider(cfg *config.Config, name string) *config.ProxyProvider {
	for i := range cfg.Providers {
		if cfg.Providers[i].Name == name {
			return &cfg.Providers[i]
		}
	}
	return nil
}

// providerNodeCount reports how many stored nodes belong to one provider.
func providerNodeCount(cfg *config.Config, name string) int {
	n := 0
	for _, node := range cfg.Nodes {
		if fromSource(node.Source, name) {
			n++
		}
	}
	return n
}

// mergeProviders folds one document's provider definitions into cfg by name, and
// reports the names whose definition this document introduced or changed.
//
// Replace-by-name is the whole rule, and it is what makes a reimport of an edited
// profile take effect: a provider defined again with another URL or another
// filter owns that name now. A provider the document still lists unchanged keeps
// its stored definition and its nodes.
//
// Providers carry no Source, so a document that stops mentioning one is not a
// statement that it is unwanted: another imported profile may well share it, and
// deleting it would take that profile's group members with it. Removing a
// provider is the UI's decision (see reconcileProviders).
func mergeProviders(cfg *config.Config, providers []config.ProxyProvider) (changed, warnings []string) {
	for _, p := range providers {
		if p.Name == "" {
			continue
		}
		// A name is one owner: a provider that shares it with a subscription
		// would have its nodes deleted by a subscription refresh, and deleting
		// the provider would delete the subscription's nodes.
		if err := providerNameFree(cfg, p.Name); err != nil {
			warnings = append(warnings, fmt.Sprintf("provider %q: %v", p.Name, err))
			continue
		}
		at := -1
		for i := range cfg.Providers {
			if cfg.Providers[i].Name == p.Name {
				at = i
				break
			}
		}
		if at < 0 {
			cfg.Providers = append(cfg.Providers, p)
			changed = append(changed, p.Name)
			continue
		}
		if cfg.Providers[at] == p {
			continue
		}
		cfg.Providers[at] = p
		changed = append(changed, p.Name)
	}
	return changed, warnings
}

// groupKeeps applies a group's filter/exclude-filter to a provider node name.
// An invalid pattern keeps every node: the import already reported the regex
// elsewhere, and silently emptying a group is worse than showing its nodes.
func groupKeeps(g *config.Group, tag string) bool {
	if s := strings.TrimSpace(g.Filter); s != "" {
		re, err := regexp.Compile(s)
		if err == nil && !re.MatchString(tag) {
			return false
		}
	}
	if s := strings.TrimSpace(g.ExcludeFilter); s != "" {
		re, err := regexp.Compile(s)
		if err == nil && re.MatchString(tag) {
			return false
		}
	}
	return true
}

// expandProviderGroups recomputes the provider half of every group's membership:
// the inline members first, then each provider's nodes in the provider's own
// order.
//
// The provider half is rebuilt rather than appended to, which is what makes a
// refresh replace its own nodes: a tag the provider no longer serves drops out of
// the group and one it serves now moves in, with no history left behind. What
// stays inline is every member no configured provider owns — built-ins, other
// groups, nodes the user wrote by hand — in its original relative order, so an
// imported `[DIRECT, <airport>]` selector keeps DIRECT first.
//
// A group that names a provider this configuration does not define is kept and
// reported: its other members still route, and dropping the group would take
// every rule that addresses its tag with it. Only an explicit provider removal
// dismantles the group (see reconcileProviders).
func expandProviderGroups(cfg *config.Config) (warnings []string) {
	for gi := range cfg.Groups {
		g := &cfg.Groups[gi]
		if len(g.Providers) == 0 {
			continue
		}
		owned := make(map[string]bool, len(g.Providers))
		for _, name := range g.Providers {
			owned[name] = true
		}
		members := make([]string, 0, len(g.Members)+len(cfg.Nodes))
		seen := make(map[string]bool, len(g.Members)+len(cfg.Nodes))
		for _, m := range g.Members {
			// nodeSource is empty for a member that is not a stored node
			// (direct, reject, another group), and those are never a provider's.
			if owned[nodeSource(cfg.Nodes, m)] {
				continue
			}
			if seen[m] {
				continue
			}
			seen[m] = true
			members = append(members, m)
		}
		for _, name := range g.Providers {
			if findProvider(cfg, name) == nil {
				warnings = append(warnings, fmt.Sprintf(
					"group %q: provider %q is not defined in this configuration; its nodes are missing",
					g.Tag, name))
				continue
			}
			for i := range cfg.Nodes {
				n := &cfg.Nodes[i]
				if n.Source != name || seen[n.Tag] {
					continue
				}
				// A profile splits one airport into country selectors with a
				// regex on the group; it filters the provider's nodes only.
				if !groupKeeps(g, n.Tag) {
					continue
				}
				seen[n.Tag] = true
				members = append(members, n.Tag)
			}
		}
		g.Members = members
	}
	return warnings
}

// reconcileProviders drops what a provider contributed after the provider itself
// is gone from the incoming configuration.
//
// A provider's nodes are not the user's: nobody typed them, they arrived from a
// URL, and with the provider deleted nothing would ever refresh or replace them.
// They go, together with the group membership and rules that only existed to
// reach them — a group left with neither members nor providers is gone too,
// because no later refresh could ever fill it again. Groups that still have
// members or another provider keep working.
func reconcileProviders(prev, next *config.Config, warn func(string)) (removed []string) {
	for _, old := range prev.Providers {
		if findProvider(next, old.Name) != nil {
			continue
		}
		removed = append(removed, old.Name)
		nodes := make([]config.Node, 0, len(next.Nodes))
		for _, n := range next.Nodes {
			if n.Source != old.Name {
				nodes = append(nodes, n)
			}
		}
		next.Nodes = nodes
	}
	if len(removed) == 0 {
		return nil
	}
	// A node that dialed *through* a provider node just lost its hop. Leaving
	// the reference would save a config the engine then cannot build, and the
	// rules pointing at that node would quietly fall through to the default
	// outbound; clearing it keeps the node usable and says so.
	for i := range next.Nodes {
		if next.Nodes[i].DialerProxy == "" {
			continue
		}
		for _, name := range removed {
			if findNode(prev, next.Nodes[i].DialerProxy) != nil &&
				findNode(next, next.Nodes[i].DialerProxy) == nil {
				warn(fmt.Sprintf(
					"node %q dialed through %q, which belonged to the removed provider %q: it dials directly now",
					next.Nodes[i].Tag, next.Nodes[i].DialerProxy, name))
				next.Nodes[i].DialerProxy = ""
				break
			}
		}
	}
	gone := make(map[string]bool, len(removed))
	for _, name := range removed {
		gone[name] = true
		warn(fmt.Sprintf("provider %q was removed: its nodes are gone", name))
	}
	for gi := range next.Groups {
		g := &next.Groups[gi]
		kept := make([]string, 0, len(g.Providers))
		for _, name := range g.Providers {
			if !gone[name] {
				kept = append(kept, name)
			}
		}
		g.Providers = kept
	}
	dropEmptyGroups(next)
	pruneRouting(next)
	return removed
}

// findNode returns the node with this tag, or nil.
func findNode(cfg *config.Config, tag string) *config.Node {
	for i := range cfg.Nodes {
		if cfg.Nodes[i].Tag == tag {
			return &cfg.Nodes[i]
		}
	}
	return nil
}

// dropEmptyGroups removes groups that can never carry traffic: no members and no
// provider left to fill them. Validate refuses to store such a group, and it is
// the only state in which a group is removed for being empty — a group with a
// provider keeps its wiring even while the provider has no nodes.
func dropEmptyGroups(cfg *config.Config) {
	groups := make([]config.Group, 0, len(cfg.Groups))
	for _, g := range cfg.Groups {
		if len(g.Members) == 0 && len(g.Providers) == 0 {
			continue
		}
		groups = append(groups, g)
	}
	cfg.Groups = groups
}

// providerFetch is when, and from which address, one provider was last fetched in
// this run.
type providerFetch struct {
	url string
	at  time.Time
}

// noteProviderFetch records a successful fetch. Only a fetch that ended in the
// configuration being updated counts: a failure must be retried on the next
// opportunity rather than be remembered as "current".
func (s *Supervisor) noteProviderFetch(name, url string) {
	s.mu.Lock()
	if s.providerFetched == nil {
		s.providerFetched = make(map[string]providerFetch)
	}
	s.providerFetched[name] = providerFetch{url: url, at: time.Now()}
	s.mu.Unlock()
}

// providerDue reports whether a provider's interval has elapsed since this run
// last fetched it.
//
// A provider this run has never fetched is due, and so is one whose address has
// changed: starting the tunnel is exactly when a profile is expected to be
// current (the same reasoning refreshDueSubscriptions applies to subscriptions).
// The record lives in memory, so an app restart counts as "due once" rather than
// persisting a timestamp the configuration has no field for.
func (s *Supervisor) providerDue(p config.ProxyProvider, now time.Time) bool {
	s.mu.Lock()
	last, ok := s.providerFetched[p.Name]
	s.mu.Unlock()
	if !ok || last.url != p.URL {
		return true
	}
	return !now.Before(last.at.Add(time.Duration(p.Interval) * time.Second))
}

// stillProvided reports whether the configuration still holds this provider at
// the address a fetch was made from.
//
// The fetch runs outside the configuration lock (a provider URL can take the full
// timeout), so by the time the body arrives the provider may have been deleted or
// pointed somewhere else. The body speaks for the address it came from; applying
// it to a different one would install nodes the user just asked to be rid of.
func stillProvided(cfg *config.Config, fetched config.ProxyProvider) error {
	p := findProvider(cfg, fetched.Name)
	if p == nil {
		return fmt.Errorf("provider %q was removed while it was being fetched", fetched.Name)
	}
	// The whole definition, not just the URL: a filter that changed mid-fetch
	// would otherwise apply the new rules to the old response, and the stale
	// result would be recorded as this interval's answer.
	if *p != fetched {
		return fmt.Errorf("provider %q changed while it was being fetched; fetch it again", fetched.Name)
	}
	return nil
}

// applyProvider refetches one provider and replaces what it contributed.
//
// It is the only writer of a provider's nodes, and it runs in three steps: read
// the definition, fetch (outside the configuration lock), then commit the nodes
// and the membership they feed in one transaction. A failure anywhere leaves the
// stored configuration untouched, so an airport that is down costs no members.
//
// The returned warnings are the ones a caller has somewhere to show them: a tag
// renamed because another source holds it, a filter that kept nothing. They are
// logged here as well, because the callers that run in the background have
// nowhere else to put them.
// providerNameFree reports whether name can own nodes: a provider and a
// subscription share one Source label, so two owners under one name would delete
// and replace each other's nodes. Subscriptions win — they are the older
// concept and the user named them first.
func providerNameFree(cfg *config.Config, name string) error {
	for _, sub := range cfg.Subscriptions {
		if sub.Name == name {
			return fmt.Errorf(
				"a subscription is already called %q; provider and subscription names share one namespace", name)
		}
	}
	return nil
}

func (s *Supervisor) applyProvider(ctx context.Context, name string) (warnings []string, err error) {
	s.mu.Lock()
	stored := s.cfg.Providers
	var p config.ProxyProvider
	found := false
	for _, cand := range stored {
		if cand.Name == name {
			p, found = cand, true
			break
		}
	}
	s.mu.Unlock()
	if !found {
		return nil, fmt.Errorf("provider %q is not defined", name)
	}
	nodes, fetchWarnings, err := s.providerNodes(ctx, p)
	if err != nil {
		for _, w := range fetchWarnings {
			s.log.Warnf("provider %s: %s", name, w)
		}
		return nil, err
	}
	warnings = append(warnings, fetchWarnings...)
	err = s.commitConfig(func(cfg *config.Config) error {
		if err := stillProvided(cfg, p); err != nil {
			return err
		}
		// A tag is one outbound: a provider node whose name another source
		// already holds is renamed by the same rule an import uses, so the two
		// sources cannot take each other's tag.
		for _, w := range resolveIncomingTags(cfg, nodes, nil, routingOrigin{Source: name}) {
			warnings = append(warnings, w)
		}
		kept := make([]config.Node, 0, len(cfg.Nodes)+len(nodes))
		for _, n := range cfg.Nodes {
			if !fromSource(n.Source, name) {
				kept = append(kept, n)
			}
		}
		cfg.Nodes = append(kept, nodes...)
		// The generated selector takes every node, provider ones included; a
		// curated group takes nothing on its own (see growAutoGroups).
		ensureAutoGroup(cfg)
		growAutoGroups(cfg, nodes)
		for _, w := range expandProviderGroups(cfg) {
			warnings = append(warnings, w)
		}
		pruneRouting(cfg)
		for _, w := range clearDanglingSelections(cfg) {
			warnings = append(warnings, w)
		}
		return nil
	})
	for _, w := range warnings {
		s.log.Warnf("provider %s: %s", name, w)
	}
	if err != nil {
		return warnings, err
	}
	s.noteProviderFetch(name, p.URL)
	return warnings, nil
}

// dueProviders lists the providers whose interval has elapsed, in stored order.
func (s *Supervisor) dueProviders(now time.Time) []string {
	s.mu.Lock()
	stored := append([]config.ProxyProvider(nil), s.cfg.Providers...)
	s.mu.Unlock()
	var due []string
	for _, p := range stored {
		if p.Interval <= 0 {
			continue
		}
		if ok, _ := providerKind(p); !ok {
			continue
		}
		if s.providerDue(p, now) {
			due = append(due, p.Name)
		}
	}
	return due
}

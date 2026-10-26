package supervisor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	"veil/internal/config"
	"veil/internal/rpc"
	"veil/internal/share"
	"veil/internal/state"
	"veil/internal/transport"
	"veil/internal/version"
)

// Call dispatches one RPC method.
func (s *Supervisor) Call(ctx context.Context, method string, params json.RawMessage) (any, error) {
	switch method {
	case rpc.MethodStart:
		var p rpc.StartParams
		_ = decode(params, &p)
		return s.Status(), s.Start(ctx, p.TunFD)
	case rpc.MethodStop:
		return s.Status(), s.Stop(ctx)
	case rpc.MethodStatus:
		return s.Status(), nil
	case rpc.MethodVersion:
		return rpc.VersionResult{Version: version.Version, Commit: version.Commit}, nil
	case rpc.MethodNodes:
		return s.nodeStatuses(), nil
	case rpc.MethodGroups:
		return s.Groups(), nil
	case rpc.MethodImport:
		var p rpc.ImportParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return s.Import(p)
	case rpc.MethodSelect:
		var p rpc.SelectParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return s.Select(p)
	case rpc.MethodDelay:
		var p rpc.DelayParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return s.Delay(ctx, p)
	case rpc.MethodDelete:
		var p rpc.DeleteParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return struct{}{}, s.Delete(p.Tag)
	case rpc.MethodSetMode:
		var p rpc.ModeParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		// The mode is part of the stored configuration, so it leaves through the
		// same door as every other write. Editing s.cfg and saving on the side
		// put two writers on config.json at once (config.Save's fixed ".tmp"
		// name then fails with "no such file or directory") and let memory and
		// disk disagree. The engine's router is rebuilt by the reload inside
		// commitConfig, which already applies cfg.Mode.
		if err := s.commitConfig(func(cfg *config.Config) error {
			cfg.Mode = p.Mode
			return nil
		}); err != nil {
			return nil, err
		}
		return s.Status(), nil
	case rpc.MethodSubAdd:
		var p rpc.SubParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return s.addSubscription(p)
	case rpc.MethodSubUpdate:
		var p rpc.SubUpdateParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return s.updateSubscription(ctx, p.Name)
	case rpc.MethodSubDelete:
		var p rpc.SubUpdateParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return struct{}{}, s.deleteSubscription(p.Name)
	case rpc.MethodConns:
		return s.Conns(), nil
	case rpc.MethodCloseConn:
		var p rpc.ConnParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		s.mu.Lock()
		eng := s.eng
		s.mu.Unlock()
		if eng == nil {
			return struct{}{}, nil
		}
		eng.CloseConn(p.ID)
		return struct{}{}, nil
	case rpc.MethodCloseAll:
		s.mu.Lock()
		eng := s.eng
		s.mu.Unlock()
		if eng != nil {
			eng.CloseAllConns()
		}
		return struct{}{}, nil
	case rpc.MethodLogs:
		var p rpc.LogsParams
		_ = decode(params, &p)
		if p.Limit <= 0 {
			p.Limit = 200
		}
		entries := s.log.Snapshot(p.AfterID, p.Limit)
		out := rpc.LogsResult{Lines: make([]rpc.LogLine, 0, len(entries))}
		for _, e := range entries {
			out.Lines = append(out.Lines, rpc.LogLine{ID: e.ID, Time: e.Time, Level: e.Level, Msg: e.Msg})
			if e.ID > out.Last {
				out.Last = e.ID
			}
		}
		return out, nil
	case rpc.MethodConfig:
		return s.Config(), nil
	case rpc.MethodSetConfig:
		var p rpc.SetConfigParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		var cfg config.Config
		if err := json.Unmarshal(p.Config, &cfg); err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
		return s.SetConfig(cfg)
	case rpc.MethodSetTunFD:
		var p rpc.TunParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		s.mu.Lock()
		eng := s.eng
		s.mu.Unlock()
		if eng == nil {
			return nil, errNotRunning
		}
		if err := eng.AttachTun(p.FD, p.MTU); err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.tunFD = p.FD
		s.mu.Unlock()
		s.setPhase(state.PhaseRunning, "")
		return s.Status(), nil
	case rpc.MethodClearTun:
		s.mu.Lock()
		eng := s.eng
		s.mu.Unlock()
		if eng != nil {
			_ = eng.DetachTun()
		}
		s.setPhase(state.PhaseDegraded, "tun detached")
		return s.Status(), nil
	case rpc.MethodResetStats:
		s.mu.Lock()
		eng := s.eng
		s.mu.Unlock()
		if eng != nil {
			eng.Stats().Reset()
		}
		return struct{}{}, nil
	default:
		return nil, fmt.Errorf("unknown method %q", method)
	}
}

var errNotRunning = fmt.Errorf("core is not running")

func decode(raw json.RawMessage, v any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return json.Unmarshal(raw, v)
}

// Conns returns live connections.
func (s *Supervisor) Conns() []state.Conn {
	s.mu.Lock()
	eng := s.eng
	s.mu.Unlock()
	if eng == nil {
		return []state.Conn{}
	}
	return eng.Conns()
}

// Groups returns policy groups.
func (s *Supervisor) Groups() []state.GroupStatus {
	s.mu.Lock()
	eng := s.eng
	cfg := s.cfg
	s.mu.Unlock()
	if eng != nil {
		if g := eng.Groups(); len(g) > 0 {
			return g
		}
	}
	// Engine stopped: report the configured nodes with unknown latency so the UI
	// can still browse and edit them.
	out := make([]state.GroupStatus, 0, len(cfg.Nodes)+len(cfg.Groups))
	if len(cfg.Groups) > 0 {
		for _, g := range cfg.Groups {
			// Nothing pinned yet: report what the engine would use, so a stopped
			// client shows the node it is about to dial instead of a blank.
			now := g.Selected
			if now == "" && len(g.Members) > 0 {
				now = g.Members[0]
			}
			gs := state.GroupStatus{Tag: g.Tag, Type: g.Type, Now: now}
			for _, m := range g.Members {
				gs.Members = append(gs.Members, state.NodeStatus{Tag: m, Type: nodeType(cfg, m), DelayMS: -1})
			}
			out = append(out, gs)
		}
		return out
	}
	gs := state.GroupStatus{Tag: "proxy", Type: "select"}
	for _, n := range cfg.Nodes {
		gs.Members = append(gs.Members, state.NodeStatus{Tag: n.Tag, Type: n.Type, Remark: n.Remark, DelayMS: -1})
	}
	return append(out, gs)
}

func nodeType(cfg config.Config, tag string) string {
	for _, n := range cfg.Nodes {
		if n.Tag == tag {
			return n.Type
		}
	}
	return ""
}

// nodeStatuses flattens groups into nodes.
func (s *Supervisor) nodeStatuses() []state.NodeStatus {
	out := []state.NodeStatus{}
	seen := map[string]bool{}
	for _, g := range s.Groups() {
		for _, n := range g.Members {
			if !seen[n.Tag] {
				seen[n.Tag] = true
				out = append(out, n)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Tag < out[j].Tag })
	return out
}

// Select pins a group member.
func (s *Supervisor) Select(p rpc.SelectParams) (any, error) {
	s.mu.Lock()
	eng := s.eng
	s.mu.Unlock()
	if eng != nil {
		if err := eng.Select(p.Group, p.Tag); err != nil {
			return nil, err
		}
	}
	if err := s.commitConfig(func(cfg *config.Config) error {
		for i := range cfg.Groups {
			if cfg.Groups[i].Tag == p.Group {
				cfg.Groups[i].Selected = p.Tag
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return s.Groups(), nil
}

// Delay probes one node.
func (s *Supervisor) Delay(ctx context.Context, p rpc.DelayParams) (rpc.DelayResult, error) {
	s.mu.Lock()
	eng := s.eng
	s.mu.Unlock()
	if eng == nil {
		return rpc.DelayResult{Tag: p.Tag, Delay: -1}, errNotRunning
	}
	done := make(chan struct{})
	var ms int
	var err error
	go func() {
		ms, err = eng.ProbeTag(p.Tag)
		close(done)
	}()
	timeout := 10 * time.Second
	if p.Timeout > 0 {
		timeout = time.Duration(p.Timeout) * time.Millisecond
	}
	select {
	case <-done:
	case <-time.After(timeout):
		return rpc.DelayResult{Tag: p.Tag, Delay: -1}, fmt.Errorf("probe timed out")
	case <-ctx.Done():
		return rpc.DelayResult{Tag: p.Tag, Delay: -1}, ctx.Err()
	}
	res := rpc.DelayResult{Tag: p.Tag, Delay: ms}
	if err != nil {
		res.Delay = -1
		res.Err = err.Error()
	}
	return res, nil
}

// Import accepts pasted links, subscription bodies or Clash YAML.
func (s *Supervisor) Import(p rpc.ImportParams) (rpc.ImportResult, error) {
	res := rpc.ImportResult{}
	var tables []routingTable
	var nodes []config.Node
	var errs []error
	text := strings.TrimSpace(p.Text)
	if text != "" {
		nodes, errs = share.ParseText(text)
		if len(nodes) == 0 {
			// Not a link list: a Clash document brings groups, rules and the
			// proxy providers those groups collect. Any of the three makes the
			// document profile-shaped even without an inline node — a profile
			// that keeps every node behind `proxy-providers:` is exactly that.
			if c, e2 := share.ParseClashConfig([]byte(text), p.Source); len(c.Nodes) > 0 || len(c.Groups) > 0 || len(c.Providers) > 0 {
				nodes, errs = c.Nodes, e2
				tables = append(tables, clashRouting(c, errs))
			}
		}
	}
	for _, url := range p.URLs {
		sub, err := s.fetchSubscription(context.Background(), url, p.Source)
		if err != nil {
			res.Failed++
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", url, err))
			continue
		}
		nodes = append(nodes, sub.Nodes...)
		tables = append(tables, sub.Routing)
	}
	for _, e := range errs {
		if e != nil {
			res.Failed++
			if len(res.Errors) < maxImportErrors {
				res.Errors = append(res.Errors, e.Error())
			}
		}
	}
	source := p.Source
	if source == "" {
		source = p.Name
	}
	for i := range nodes {
		if nodes[i].Source == "" {
			nodes[i].Source = source
		}
	}
	return s.importRows(source, nodes, tables, res)
}

// importRows merges one import's parsed rows into the configuration and then
// fetches the providers that import introduced.
//
// The split is deliberate: parsing belongs to internal/share, which is the only
// layer that sees the document, and the merge plus the fetch belong here. The
// fetch runs after the transaction because a provider URL can take the full
// timeout, and holding the configuration lock across it would stall every other
// write; it is also allowed to fail, because by then the profile's nodes, groups,
// rules and provider definitions are stored and validated. One unreachable
// airport must not cost the user their routing table — it costs their members,
// with a warning that says so.
func (s *Supervisor) importRows(source string, nodes []config.Node, tables []routingTable, res rpc.ImportResult) (rpc.ImportResult, error) {
	// A document that keeps its nodes behind `proxy-providers:` carries none of
	// them, and a group naming a provider it does not define carries none either;
	// both still state routing the user wrote, so neither is an empty import.
	providerCount := 0
	usesProvider := false
	for _, t := range tables {
		providerCount += len(t.Providers)
		for _, g := range t.Groups {
			if len(g.Providers) > 0 {
				usesProvider = true
			}
		}
	}
	if len(nodes) == 0 && providerCount == 0 && !usesProvider {
		return res, fmt.Errorf("no nodes found in input")
	}
	warn := func(msg string) {
		if len(res.Warnings) < maxImportWarnings {
			res.Warnings = append(res.Warnings, msg)
		}
	}
	// fetch collects the providers this import has to download: the ones it
	// defined or redefined, plus any it names in a group while no stored node
	// carries their name yet (an earlier fetch failed, or the definition arrived
	// with another profile).
	var fetch []string
	// The merge runs on the transaction's own copy of the configuration, so a
	// rejected import cannot leave half of itself in the live config.
	err := s.commitConfig(func(cfg *config.Config) error {
		// Tags first: one name is one outbound, so a document must not take a tag
		// another source already holds. This rewrites the document's own member
		// lists and rule actions along with it (see resolveIncomingTags).
		origin := routingOrigin{Source: source, OwnsTable: true}
		documents := make([]*routingTable, len(tables))
		for i := range tables {
			documents[i] = &tables[i]
		}
		for _, w := range resolveIncomingTags(cfg, nodes, documents, origin) {
			warn(w)
		}
		added, updated := mergeNodes(cfg, nodes)
		res.Added, res.Updated = added, updated
		for _, n := range nodes {
			res.Tags = append(res.Tags, n.Tag)
		}
		// Routing last, and per document in input order: mergeNodes appends new
		// nodes to the generated groups, while a group a document curates
		// replaces the stored one of the same tag. The counts are what the
		// documents contributed, not the size of the resulting table.
		//
		// A pasted profile states a complete rule table, so it still owns it: its
		// rules replace every stored rule, and they carry source so a later
		// subscription refresh knows they are not its to replace.
		for _, t := range tables {
			names, pwarnings := mergeProviders(cfg, t.Providers)
			for _, w := range pwarnings {
				warn(w)
			}
			for _, name := range names {
				fetch = append(fetch, name)
			}
			groups, rules, warnings := mergeRoutingTable(cfg, t, origin)
			res.Groups += groups
			res.Rules += rules
			for _, w := range warnings {
				warn(w)
			}
		}
		// The provider half of every group's membership is filled here, so a
		// profile that collects an airport through `use:` validates with the
		// members it is about to have, and an existing provider's nodes are in
		// place before the fetch below decides what still needs downloading.
		for _, w := range expandProviderGroups(cfg) {
			warn(w)
		}
		// Now that the provider half is in place, a pin that still names nothing
		// is genuinely gone and is cleared with a warning.
		for _, w := range clearDanglingSelections(cfg) {
			warn(w)
		}
		for gi := range cfg.Groups {
			for _, name := range cfg.Groups[gi].Providers {
				if findProvider(cfg, name) != nil && providerNodeCount(cfg, name) == 0 {
					fetch = append(fetch, name)
				}
			}
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	for _, name := range dedupeNames(fetch) {
		warnings, err := s.applyProvider(context.Background(), name)
		if err != nil {
			msg := fmt.Sprintf("provider %q: %v", name, err)
			warn(msg)
			s.log.Warnf("%s", msg)
			continue
		}
		for _, w := range warnings {
			warn(w)
		}
		res.Tags = append(res.Tags, s.providerTags(name)...)
	}
	s.log.Infof("imported %d new and %d updated node(s), %d group(s), %d rule(s)",
		res.Added, res.Updated, res.Groups, res.Rules)
	return res, nil
}

// providerTags lists the tags of one provider's stored nodes, in stored order.
func (s *Supervisor) providerTags(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, n := range s.cfg.Nodes {
		if n.Source == name {
			out = append(out, n.Tag)
		}
	}
	return out
}

// dedupeNames keeps the first occurrence of every name, in order.
func dedupeNames(names []string) []string {
	seen := make(map[string]bool, len(names))
	out := make([]string, 0, len(names))
	for _, name := range names {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// Caps on the strings one import may return: a profile with a hundred broken
// rules must not turn the RPC reply into a megabyte the UI has to render.
const (
	maxImportErrors   = 20
	maxImportWarnings = 20
)

// mergeNodes inserts or replaces nodes by tag and ensures a default group. It
// edits cfg, which is the transaction's private copy (see commitConfig).
func mergeNodes(cfg *config.Config, nodes []config.Node) (added, updated int) {
	idx := make(map[string]int, len(cfg.Nodes))
	for i, n := range cfg.Nodes {
		idx[n.Tag] = i
	}
	for _, n := range nodes {
		if i, ok := idx[n.Tag]; ok {
			cfg.Nodes[i] = n
			updated++
			continue
		}
		idx[n.Tag] = len(cfg.Nodes)
		cfg.Nodes = append(cfg.Nodes, n)
		added++
	}
	ensureAutoGroup(cfg)
	growAutoGroups(cfg, nodes)
	return added, updated
}

// ensureAutoGroup creates the generated "proxy" select group when the
// configuration has no groups at all, unless there is not a single node to put
// in it.
//
// The empty case is not hypothetical: a profile that keeps every node behind a
// `proxy-providers:` entry reaches the merge before the provider has been
// fetched, and creating the selector then would store a group with no members —
// which validation refuses, taking the whole import down over a node list that is
// merely still on its way. The same call runs after a provider lands, by which
// time there are nodes to select.
func ensureAutoGroup(cfg *config.Config) {
	if len(cfg.Groups) != 0 || len(cfg.Nodes) == 0 {
		return
	}
	tags := make([]string, 0, len(cfg.Nodes))
	for _, n := range cfg.Nodes {
		tags = append(tags, n.Tag)
	}
	cfg.Groups = []config.Group{{
		Tag:     config.AutoGroupTag,
		Type:    "select",
		Auto:    true,
		Members: tags,
		URL:     config.AutoGroupProbeURL,
	}}
}

// growAutoGroups adds nodes to every generated group. Only generated groups take
// them: a curated group's membership *is* the routing decision — a fallback group
// listing [reject] must keep sending traffic to reject, and a url-test group
// listing two nodes must not start testing a third because a link was pasted
// later. A node already in the group keeps its place.
func growAutoGroups(cfg *config.Config, nodes []config.Node) {
	for gi := range cfg.Groups {
		if !cfg.Groups[gi].Auto {
			continue
		}
		for _, n := range nodes {
			if !contains(cfg.Groups[gi].Members, n.Tag) {
				cfg.Groups[gi].Members = append(cfg.Groups[gi].Members, n.Tag)
			}
		}
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// snapshot copies the live configuration deeply enough that a mutation can be
// validated before it becomes visible. Editing s.cfg in place and validating
// only afterwards left memory and disk disagreeing whenever validation failed,
// and every later write then failed with the same error until the user
// reimported a profile.
func (s *Supervisor) snapshot() config.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg := s.cfg
	cfg.Nodes = append([]config.Node(nil), s.cfg.Nodes...)
	cfg.Groups = make([]config.Group, len(s.cfg.Groups))
	for i, g := range s.cfg.Groups {
		g.Members = append([]string(nil), g.Members...)
		cfg.Groups[i] = g
	}
	cfg.Rules = append([]config.Rule(nil), s.cfg.Rules...)
	cfg.Subscriptions = append([]config.Subscription(nil), s.cfg.Subscriptions...)
	cfg.Providers = append([]config.ProxyProvider(nil), s.cfg.Providers...)
	return cfg
}

// commitConfig is the one door every configuration write goes through.
//
// It holds cfgMu across the whole read-modify-write, which is what keeps the
// writers apart: two callers editing the live configuration and saving on the
// side both wrote the same "config.json.tmp" and one rename then failed with
// "no such file or directory", while memory kept a mix of the two. The mutation
// runs on the transaction's own copy, so a rejected change (an invalid tag, a
// save that fails) leaves both the live configuration and the file untouched;
// only a validated change is written and then published.
//
// The engine is updated inside the lock as well: a reload that ran after the
// lock was released could apply an older snapshot than a writer that committed
// in between, leaving the engine routing by a table nobody else has.
func (s *Supervisor) commitConfig(mutate func(*config.Config) error) error {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	cfg := s.snapshot()
	if mutate != nil {
		if err := mutate(&cfg); err != nil {
			return err
		}
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := config.Save(s.cfgPath, cfg); err != nil {
		return err
	}
	s.mu.Lock()
	prev := s.cfg
	s.cfg = cfg
	eng := s.eng
	s.mu.Unlock()
	if eng == nil {
		return nil
	}
	// A mode switch changes nothing the data path is built from — no outbound,
	// group, rule or resolver differs — so the engine takes it through SetMode,
	// which rebuilds only the matcher. Everything else rebuilds the data path.
	if modeOnlyChange(prev, cfg) {
		return eng.SetMode(cfg.Mode)
	}
	return eng.Reload(cfg)
}

// modeOnlyChange reports whether two configurations differ in nothing but the
// mode, which is the one writer the engine can apply without a rebuild.
func modeOnlyChange(a, b config.Config) bool {
	a.Mode, b.Mode = "", ""
	return reflect.DeepEqual(a, b)
}

// pruneRouting drops references to tags that no longer exist (a deleted node,
// a node renamed by a subscription refresh) and groups left empty. Without this
// a single delete makes the whole configuration invalid, which the UI can only
// recover from by reimporting.
//
// Groups depend on each other, so one pass is not enough: deleting a node empties
// the group that held it, and the group above it is left naming a tag that no
// longer exists. Each round removes what is already gone — first group members
// that name nothing, then the groups left without a member, then the rules that
// addressed them — and the loop repeats until a round changes nothing. Every
// removal strictly shrinks the configuration, so it settles.
func pruneRouting(cfg *config.Config) {
	for {
		known := make(map[string]bool, len(cfg.Nodes)+len(cfg.Groups)+2)
		for _, n := range cfg.Nodes {
			known[n.Tag] = true
		}
		for _, g := range cfg.Groups {
			known[g.Tag] = true
		}
		known["direct"] = true
		known["reject"] = true
		changed := false
		for gi := range cfg.Groups {
			members := make([]string, 0, len(cfg.Groups[gi].Members))
			for _, m := range cfg.Groups[gi].Members {
				if known[m] {
					members = append(members, m)
					continue
				}
				changed = true
			}
			cfg.Groups[gi].Members = members
		}
		groups := make([]config.Group, 0, len(cfg.Groups))
		for _, g := range cfg.Groups {
			// A group whose members are all gone is removed, unless it still
			// names a provider: that group's membership is filled by a fetch, and
			// dropping it would take the provider wiring — and every rule that
			// addresses its tag — with it.
			if len(g.Members) > 0 || len(g.Providers) > 0 {
				groups = append(groups, g)
				continue
			}
			changed = true
		}
		cfg.Groups = groups
		rules := make([]config.Rule, 0, len(cfg.Rules))
		for _, r := range cfg.Rules {
			if r.Action == "" || known[r.Action] {
				rules = append(rules, r)
				continue
			}
			changed = true
		}
		cfg.Rules = rules
		if !changed {
			return
		}
	}
}

func (s *Supervisor) Delete(tag string) error {
	return s.commitConfig(func(cfg *config.Config) error {
		out := make([]config.Node, 0, len(cfg.Nodes))
		found := false
		for _, n := range cfg.Nodes {
			if n.Tag == tag {
				found = true
				continue
			}
			out = append(out, n)
		}
		if !found {
			return fmt.Errorf("node %q not found", tag)
		}
		cfg.Nodes = out
		// Rules and group members that pointed at this node die with it; keeping
		// them would make the whole configuration invalid.
		pruneRouting(cfg)
		return nil
	})
}

// SetConfig replaces the whole configuration.
func (s *Supervisor) SetConfig(cfg config.Config) (state.Status, error) {
	// A client that carries its own model of the configuration drops fields it
	// does not know, and Group.Auto is one of them: without this, one save from
	// the UI would turn the generated selector into a curated group that no longer
	// collects imported nodes. The predicate only matches the exact shape this app
	// generates (see config.MarkGeneratedGroups).
	config.MarkGeneratedGroups(&cfg)
	if err := cfg.Validate(); err != nil {
		return s.Status(), err
	}
	var removedProviders []string
	err := s.commitConfig(func(cur *config.Config) error {
		// A client that sends a configuration without a provider has deleted it.
		// Its nodes arrived from a URL nobody will refresh any more, so they leave
		// with it, together with the membership and rules that only existed to
		// reach them — otherwise the stored configuration keeps outbounds the user
		// cannot see the source of.
		removedProviders = reconcileProviders(cur, &cfg, func(msg string) { s.log.Warnf("%s", msg) })
		*cur = cfg
		return nil
	})
	if err != nil {
		return s.Status(), err
	}
	// A deleted provider's fetch record goes with it: re-adding the same provider
	// has to download it now, not inherit "fetched a minute ago" from a
	// definition that no longer exists.
	if len(removedProviders) > 0 {
		s.mu.Lock()
		for _, name := range removedProviders {
			delete(s.providerFetched, name)
		}
		s.mu.Unlock()
	}
	if lvl := cfg.LogLevel; lvl != "" {
		s.log.SetLevel(logLevel(lvl))
	}
	return s.Status(), nil
}

// addSubscription registers a subscription and imports it immediately.
func (s *Supervisor) addSubscription(p rpc.SubParams) (any, error) {
	if p.URL == "" {
		return nil, fmt.Errorf("subscription url is empty")
	}
	name := p.Name
	if name == "" {
		name = p.URL
	}
	if err := s.commitConfig(func(cfg *config.Config) error {
		for _, sub := range cfg.Subscriptions {
			if sub.URL == p.URL {
				return fmt.Errorf("subscription already exists")
			}
		}
		cfg.Subscriptions = append(cfg.Subscriptions, config.Subscription{
			Name:     name,
			URL:      p.URL,
			Interval: 86400,
		})
		return nil
	}); err != nil {
		return nil, err
	}
	if _, err := s.updateSubscription(context.Background(), name); err != nil {
		return nil, err
	}
	return s.Groups(), nil
}

// updateSubscription re-fetches a subscription and replaces what it contributed
// last time — its nodes, and the groups and rules that a Clash document among
// them carries. Rows from other sources, and rows the user wrote (no source),
// survive the refresh.
func (s *Supervisor) updateSubscription(ctx context.Context, name string) ([]state.NodeStatus, error) {
	// Read the address under the lock, then let go of it. The fetch used to run
	// with cfgMu held, so a provider that took the full 25 seconds stopped every
	// other configuration write for that long.
	url := ""
	s.mu.Lock()
	for _, sub := range s.cfg.Subscriptions {
		if sub.Name == name {
			url = sub.URL
			break
		}
	}
	s.mu.Unlock()
	if url == "" {
		return nil, fmt.Errorf("subscription %q not found", name)
	}
	fetched, err := s.fetchSubscription(context.Background(), url, name)
	if err != nil {
		return nil, err
	}
	nodes := fetched.Nodes
	if len(nodes) == 0 {
		return nil, fmt.Errorf("subscription %q returned no nodes", name)
	}

	var groups, rules int
	var fetchedProviders []string
	err = s.commitConfig(func(cfg *config.Config) error {
		// The fetch ran outside the lock, so the subscription may have been
		// deleted or repointed meanwhile. The body speaks for the address it was
		// fetched from: if that is no longer what this name holds, applying it
		// would install nodes the user just asked to be rid of.
		if err := stillSubscribedAt(cfg, name, url); err != nil {
			return err
		}
		// A tag this subscription used to own may have been taken by a source
		// that arrived later (a pasted profile with the same node, a second
		// subscription defining the same group), so the fetched rows are renamed
		// the same way an import renames them. It runs before the stored rows are
		// replaced, because a tag the subscription itself holds is free.
		origin := routingOrigin{Source: name}
		routing := fetched.Routing
		for _, w := range resolveIncomingTags(cfg, nodes, []*routingTable{&routing}, origin) {
			s.log.Warnf("subscription %s: %s", name, w)
		}
		kept := make([]config.Node, 0, len(cfg.Nodes)+len(nodes))
		for _, n := range cfg.Nodes {
			if n.Source != name {
				kept = append(kept, n)
			}
		}
		cfg.Nodes = append(kept, nodes...)
		for i := range cfg.Subscriptions {
			if cfg.Subscriptions[i].Name == name {
				cfg.Subscriptions[i].Updated = time.Now().Unix()
			}
		}
		// The refresh speaks only for this subscription: mergeRoutingTable drops
		// the groups and rules stamped with its name and merges the new ones, so
		// a document that stopped defining a group or rule takes it along, while
		// the user's own rows and every other source's stay.
		//
		// It runs before the prune below on purpose. mergeSourceRules places the
		// fresh rows in the span the old ones occupied, and a prune that ran
		// first could have emptied that span (a group whose only node was renamed
		// takes its rules with it), dropping the block to the catch-all position
		// — which moves the subscription's rules across the ones the user wrote
		// and changes which of two rules for the same domain matches first.
		var warnings []string
		groups, rules, warnings = mergeRoutingTable(cfg, routing, origin)
		for _, w := range warnings {
			s.log.Warnf("subscription %s: %s", name, w)
		}
		// A subscription body may also define the providers its groups collect
		// (`proxy-providers:` in a Clash document), so a refresh merges those
		// definitions too and remembers which ones changed. They are fetched
		// below, outside the lock, like any other provider.
		pnames, pwarnings := mergeProviders(cfg, routing.Providers)
		for _, w := range pwarnings {
			s.log.Warnf("subscription %s: %s", name, w)
		}
		for _, pname := range pnames {
			fetchedProviders = append(fetchedProviders, pname)
		}
		// Rebuild group membership for the refreshed subscription: members that
		// point at one of its nodes which is gone are dropped, and only the
		// generated groups take the nodes that arrived. A curated group keeps the
		// membership it was given — refreshing the node list must not move a
		// fallback/url-test group's egress (see mergeNodes).
		for gi := range cfg.Groups {
			members := make([]string, 0, len(cfg.Groups[gi].Members)+len(nodes))
			for _, m := range cfg.Groups[gi].Members {
				if nodeSource(cfg.Nodes, m) != name || contains(tagsOf(nodes), m) {
					members = append(members, m)
				}
			}
			if cfg.Groups[gi].Auto {
				for _, n := range nodes {
					if !contains(members, n.Tag) {
						members = append(members, n.Tag)
					}
				}
			}
			cfg.Groups[gi].Members = members
		}
		// Groups that collect a provider through `use:` take their members from
		// that provider, refreshed or not, so the provider half is recomputed from
		// the nodes that are actually stored.
		for _, w := range expandProviderGroups(cfg) {
			s.log.Warnf("subscription %s: %s", name, w)
		}
		// Dropping one of the subscription's groups can leave another rule (one
		// the user wrote) addressing a tag that no longer exists, and emptying a
		// group can strand the groups above it; validation would refuse the whole
		// refresh, so the references go with what they pointed at.
		pruneRouting(cfg)
		for _, w := range clearDanglingSelections(cfg) {
			s.log.Warnf("subscription %s: %s", name, w)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, pname := range dedupeNames(fetchedProviders) {
		if _, err := s.applyProvider(ctx, pname); err != nil {
			s.log.Warnf("subscription %s: provider %s: %v", name, pname, err)
		}
	}
	s.log.Infof("subscription %s updated: %d node(s), %d group(s), %d rule(s)",
		name, len(nodes), groups, rules)
	return s.nodeStatuses(), nil
}

// stillSubscribedAt reports whether the configuration still holds this
// subscription at the address a fetch was made from. It separates "the name
// still means what was fetched" from "someone has moved on since".
func stillSubscribedAt(cfg *config.Config, name, url string) error {
	for _, sub := range cfg.Subscriptions {
		if sub.Name != name {
			continue
		}
		if sub.URL != url {
			return fmt.Errorf("subscription %q was pointed at %q while it was being refreshed; refresh it again", name, sub.URL)
		}
		return nil
	}
	return fmt.Errorf("subscription %q was deleted while it was being refreshed", name)
}

func tagsOf(nodes []config.Node) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = n.Tag
	}
	return out
}

func nodeSource(nodes []config.Node, tag string) string {
	for _, n := range nodes {
		if n.Tag == tag {
			return n.Source
		}
	}
	return ""
}

func (s *Supervisor) deleteSubscription(name string) error {
	return s.commitConfig(func(cfg *config.Config) error {
		subs := make([]config.Subscription, 0, len(cfg.Subscriptions))
		found := false
		for _, sub := range cfg.Subscriptions {
			if sub.Name == name {
				found = true
				continue
			}
			subs = append(subs, sub)
		}
		if !found {
			return fmt.Errorf("subscription %q not found", name)
		}
		cfg.Subscriptions = subs
		nodes := make([]config.Node, 0, len(cfg.Nodes))
		for _, n := range cfg.Nodes {
			if n.Source != name {
				nodes = append(nodes, n)
			}
		}
		cfg.Nodes = nodes
		// The groups and rules the subscription brought go with it. Rows without
		// its name were written by the user or came from another document and are
		// not this delete's to remove.
		groups := make([]config.Group, 0, len(cfg.Groups))
		for _, g := range cfg.Groups {
			if g.Source != name {
				groups = append(groups, g)
			}
		}
		cfg.Groups = groups
		rules := make([]config.Rule, 0, len(cfg.Rules))
		for _, r := range cfg.Rules {
			if r.Source != name {
				rules = append(rules, r)
			}
		}
		cfg.Rules = rules
		pruneRouting(cfg)
		return nil
	})
}

// subscriptionBody is one fetched subscription: the nodes it lists and, when the
// body is a Clash document, the routing table that travels with them. A plain
// share-link list has no routing half and leaves Routing unpopulated.
type subscriptionBody struct {
	Nodes   []config.Node
	Routing routingTable
}

// clashDocument reports whether the parse produced something worth importing as
// a profile. A document may carry no inline proxies at all — the nodes can live
// in a proxy-provider it names — and treating that as "not a Clash document"
// sent it down the share-link path, where it yielded nothing.
func clashDocument(c share.ClashConfig) bool {
	return len(c.Nodes) > 0 || len(c.Providers) > 0 || len(c.Groups) > 0 || len(c.Rules) > 0
}

// fetchSubscription downloads and parses one subscription URL.
func (s *Supervisor) fetchSubscription(ctx context.Context, url, name string) (subscriptionBody, error) {
	// The caller's context, so stopping the supervisor cancels a fetch that is
	// still in flight instead of letting it land in a configuration whose
	// engine is already gone.
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return subscriptionBody{}, err
	}
	req.Header.Set("User-Agent", version.UserAgent)
	req.Header.Set("Accept", "*/*")
	// The protect-aware dialer, like every other socket the core opens: the
	// default transport sends the fetch out of an unprotected socket, which on a
	// device is a packet addressed to the tunnel's own gateway.
	client := &http.Client{
		Timeout: 25 * time.Second,
		Transport: &http.Transport{
			DialContext:           transport.NewDialer().DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
			ForceAttemptHTTP2:     true,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return subscriptionBody{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return subscriptionBody{}, fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return subscriptionBody{}, err
	}
	// The Clash door first, so a document's groups and rules are parsed together
	// with its nodes; share.ParseSubscription is the node-only door and drops
	// them. Providers serve the same document either bare or base64-wrapped, and
	// only the bare form would be reached by the first attempt.
	if c, cerrs := share.ParseClashConfig(body, name); clashDocument(c) {
		return subscriptionBody{Nodes: c.Nodes, Routing: clashRouting(c, cerrs)}, nil
	}
	if decoded := decodeBase64(body); decoded != nil {
		if c, cerrs := share.ParseClashConfig(decoded, name); clashDocument(c) {
			return subscriptionBody{Nodes: c.Nodes, Routing: clashRouting(c, cerrs)}, nil
		}
	}
	nodes, errs := share.ParseSubscription(body, name)
	if len(nodes) == 0 {
		if len(errs) > 0 {
			return subscriptionBody{}, errs[0]
		}
		return subscriptionBody{}, fmt.Errorf("empty subscription")
	}
	return subscriptionBody{Nodes: nodes}, nil
}

// decodeBase64 decodes a subscription body that was served base64-wrapped,
// trying the alphabets providers use. Nil means "not base64", which is the
// answer for every plain link list.
func decodeBase64(body []byte) []byte {
	trimmed := strings.TrimSpace(strings.TrimPrefix(string(body), "\ufeff"))
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if out, err := enc.DecodeString(trimmed); err == nil && len(out) > 0 {
			return out
		}
	}
	return nil
}

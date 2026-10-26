package supervisor

import (
	"testing"

	"veil/internal/config"
)

// TestDeletePrunesNestedGroupDependencies is acceptance (3): group dependencies
// are cleared to a fixed point, not one level deep.
//
// A group survives as long as it lists a member, and the member check ran on the
// set of tags as it was before this prune started. Deleting the node below a
// two-level chain therefore emptied "leaf" and left "parent" pointing at a tag
// that no longer existed — a configuration that still validated but that the
// engine could not build, so the delete looked successful and the group above it
// was silently gone from the tunnel.
func TestDeletePrunesNestedGroupDependencies(t *testing.T) {
	sup := newRuleSupervisor(t)
	cfg := sup.Config()
	cfg.Nodes = []config.Node{{Tag: "node", Type: "direct"}}
	cfg.Groups = []config.Group{
		{Tag: "leaf", Type: "select", Members: []string{"node"}},
		{Tag: "parent", Type: "select", Members: []string{"leaf"}},
	}
	cfg.Rules = []config.Rule{
		{Type: "domain", Value: "nested.test", Action: "parent"},
		{Type: "final", Action: "parent"},
	}
	if _, err := sup.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig(nested groups): %v", err)
	}

	if err := sup.Delete("node"); err != nil {
		t.Fatalf("Delete(%q) = %v, want success", "node", err)
	}

	after := sup.Config()
	if tags := groupTags(after.Groups); len(tags) != 0 {
		t.Fatalf("groups after deleting the node under them = %v, want none", tags)
	}
	for _, r := range after.Rules {
		if r.Action == "parent" || r.Action == "leaf" {
			t.Fatalf("rule %+v still addresses a group that no longer exists", r)
		}
	}
	if err := after.Validate(); err != nil {
		t.Fatalf("config is invalid after the delete: %v", err)
	}

	// The same configuration must survive a restart, and the write path must
	// still accept the next change.
	reopened, err := New(sup.cfgPath, sup.log)
	if err != nil {
		t.Fatalf("reopen supervisor: %v", err)
	}
	if got := groupTags(reopened.Config().Groups); len(got) != 0 {
		t.Fatalf("persisted groups = %v, want none", got)
	}
	after.Mode = config.ModeGlobal
	if _, err := sup.SetConfig(after); err != nil {
		t.Fatalf("SetConfig after the delete = %v, want success", err)
	}
	if got := sup.Config().Mode; got != config.ModeGlobal {
		t.Fatalf("mode = %q, want global", got)
	}
}

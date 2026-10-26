package supervisor

import (
	"reflect"
	"testing"

	"veil/internal/rpc"
)

// Deleting a node that a rule still points at used to leave the configuration
// invalid: the delete edited the live config first and only then validated, so
// the call failed *and* memory kept the edit — every later configuration write
// died with the same "unknown action" error until the profile was reimported.
// The delete must prune the references and succeed.
func TestDeleteNodePrunesRulesAndKeepsConfigWritable(t *testing.T) {
	sup := newRuleSupervisor(t)
	if _, err := sup.Import(rpc.ImportParams{Text: routingYAML(), Source: "clash"}); err != nil {
		t.Fatalf("Import: %v", err)
	}

	before := sup.Config()
	var deleted string
	for _, n := range before.Nodes {
		deleted = n.Tag
	}
	if deleted == "" {
		t.Fatal("no node imported")
	}

	if err := sup.Delete(deleted); err != nil {
		t.Fatalf("Delete(%q) = %v, want success", deleted, err)
	}

	after := sup.Config()
	for _, n := range after.Nodes {
		if n.Tag == deleted {
			t.Fatalf("node %q still present after delete", deleted)
		}
	}
	for _, r := range after.Rules {
		if r.Action == deleted {
			t.Fatalf("rule %+v still points at the deleted node", r)
		}
	}
	if err := after.Validate(); err != nil {
		t.Fatalf("config is invalid after delete: %v", err)
	}

	// The follow-up write that used to fail: any unrelated mutation must work.
	cfg := sup.Config()
	cfg.Mode = "global"
	if _, err := sup.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig after delete = %v, want success", err)
	}
	if got := sup.Config().Mode; got != "global" {
		t.Fatalf("mode = %q, want global", got)
	}

	// And the pruned table is what got persisted, not just what is in memory.
	reopened, err := New(sup.cfgPath, sup.log)
	if err != nil {
		t.Fatalf("reopen supervisor: %v", err)
	}
	if got := reopened.Config().Rules; !reflect.DeepEqual(got, after.Rules) {
		t.Fatalf("persisted rules =\n%+v\nwant\n%+v", got, after.Rules)
	}
}

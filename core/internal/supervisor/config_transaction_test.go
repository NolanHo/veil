package supervisor

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"veil/internal/config"
	"veil/internal/rpc"
)

// TestConfigWritesShareOneTransaction is acceptance (4): set_mode and SetConfig
// are two doors into the same transaction, so a rejected write leaves both
// memory and the file exactly as they were, and an accepted one reaches both.
// A writer that edited the live configuration and saved on the side would pass
// the "accepted" half and fail the "rejected" half.
func TestConfigWritesShareOneTransaction(t *testing.T) {
	sup := newRuleSupervisor(t)
	before := sup.Config()
	beforeDisk, err := config.Load(sup.cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// A write the transaction refuses: unknown mode is caught by Validate inside
	// commitConfig, after the mutation and before the save.
	if _, err := sup.Call(context.Background(), rpc.MethodSetMode, json.RawMessage(`{"mode":"bogus"}`)); err == nil {
		t.Fatal("set_mode accepted an unknown mode")
	}
	if got := sup.Config(); !reflect.DeepEqual(got, before) {
		t.Fatalf("a rejected set_mode changed the live configuration:\ngot  = %+v\nwant = %+v", got, before)
	}
	afterDisk, err := config.Load(sup.cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !reflect.DeepEqual(afterDisk, beforeDisk) {
		t.Fatalf("a rejected set_mode changed the file:\ngot  = %+v\nwant = %+v", afterDisk, beforeDisk)
	}

	// A write the transaction accepts reaches memory and the file.
	if _, err := sup.Call(context.Background(), rpc.MethodSetMode, json.RawMessage(`{"mode":"global"}`)); err != nil {
		t.Fatalf("set_mode: %v", err)
	}
	if got := sup.Config().Mode; got != config.ModeGlobal {
		t.Fatalf("live mode = %q, want %q", got, config.ModeGlobal)
	}
	reopened, err := New(sup.cfgPath, sup.log)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := reopened.Config().Mode; got != config.ModeGlobal {
		t.Fatalf("persisted mode = %q, want %q", got, config.ModeGlobal)
	}

	// The same for the other door: SetConfig validates through commitConfig, so
	// an invalid model from the UI cannot be published.
	bad := sup.Config()
	bad.Nodes = append(bad.Nodes, config.Node{Tag: "direct", Type: "direct"})
	if _, err := sup.SetConfig(bad); err == nil {
		t.Fatal("SetConfig accepted a duplicate outbound tag")
	}
	if got := sup.Config(); !reflect.DeepEqual(got, reopened.Config()) {
		t.Fatalf("a rejected SetConfig changed the live configuration:\ngot  = %+v\nwant = %+v", got, reopened.Config())
	}
}

// Package rpc defines the JSON control protocol shared by the Go core, the
// NAPI bridge and the ArkTS UI.
package rpc

import (
	"context"
	"encoding/json"
)

// Method names. The UI calls these through the single VeilCall entry point.
const (
	// Lifecycle
	MethodStart  = "start"  // params: StartParams
	MethodStop   = "stop"   // params: {}
	MethodStatus = "status" // params: {}

	// Nodes and groups
	MethodNodes     = "nodes"      // params: {} -> []state.NodeStatus
	MethodImport    = "import"     // params: ImportParams -> ImportResult
	MethodSelect    = "select"     // params: SelectParams -> state.GroupStatus
	MethodDelay     = "delay"      // params: DelayParams -> DelayResult
	MethodDelete    = "delete"     // params: DeleteParams -> {}
	MethodGroups    = "groups"     // params: {} -> []state.GroupStatus
	MethodSetMode   = "set_mode"   // params: ModeParams -> state.Status
	MethodSubAdd    = "sub_add"    // params: SubParams -> {}
	MethodSubUpdate = "sub_update" // params: SubUpdateParams -> []state.NodeStatus
	MethodSubDelete = "sub_delete" // params: SubUpdateParams -> {}

	// Runtime
	MethodConns      = "conns"        // params: {} -> []state.Conn
	MethodCloseConn  = "close_conn"   // params: ConnParams -> {}
	MethodCloseAll   = "close_all"    // params: {} -> {}
	MethodLogs       = "logs"         // params: LogsParams -> LogsResult
	MethodConfig     = "config"       // params: {} -> config.Config
	MethodSetConfig  = "set_config"   // params: SetConfigParams -> state.Status
	MethodSetTunFD   = "set_tun_fd"   // params: TunParams -> state.Status
	MethodClearTun   = "clear_tun_fd" // params: {} -> state.Status
	MethodVersion    = "version"      // params: {} -> VersionResult
	MethodResetStats = "reset_stats"  // params: {} -> {}
)

// Handler is implemented by the supervisor.
type Handler interface {
	Call(ctx context.Context, method string, params json.RawMessage) (any, error)
}

// Envelope is the transport shape used by the NAPI bridge.
type Envelope struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Reply is returned by the bridge as JSON.
type Reply struct {
	OK     bool   `json:"ok"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

// StartParams asks the supervisor to bring the engine up. TunFD < 0 means
// "mixed inbound only" (used by the desktop dev harness and by tests).
type StartParams struct {
	TunFD int `json:"tun_fd"`
}

// ImportParams carries raw text pasted by the user: one share link per line,
// a base64 subscription body, a Clash YAML document or a JSON config.
type ImportParams struct {
	Text   string   `json:"text"`
	Name   string   `json:"name,omitempty"`
	Source string   `json:"source,omitempty"`
	URLs   []string `json:"urls,omitempty"`
}

// ImportResult summarises what was imported.
//
// Groups and Rules count what the imported document itself contributed to the
// routing table (a node-only import contributes zero of each); they are not the
// size of the stored table. Warnings lists routing problems that did not fail
// the import, such as a group whose members close a cycle.
type ImportResult struct {
	Added    int      `json:"added"`
	Updated  int      `json:"updated"`
	Failed   int      `json:"failed"`
	Groups   int      `json:"groups"`
	Rules    int      `json:"rules"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

// SelectParams chooses the active member of a group.
type SelectParams struct {
	Group string `json:"group"`
	Tag   string `json:"tag"`
}

// DelayParams triggers a latency probe.
type DelayParams struct {
	Tag     string `json:"tag"`
	Timeout int    `json:"timeout_ms,omitempty"`
}

// DelayResult reports a single probe.
type DelayResult struct {
	Tag   string `json:"tag"`
	Delay int    `json:"delay_ms"`
	Err   string `json:"err,omitempty"`
}

// DeleteParams removes a manually added node.
type DeleteParams struct {
	Tag string `json:"tag"`
}

// ModeParams switches the routing mode.
type ModeParams struct {
	Mode string `json:"mode"`
}

// SubParams adds a subscription.
type SubParams struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// SubUpdateParams refreshes or deletes a subscription by name.
type SubUpdateParams struct {
	Name string `json:"name"`
}

// ConnParams targets one live connection.
type ConnParams struct {
	ID uint64 `json:"id"`
}

// LogsParams reads recent log lines.
type LogsParams struct {
	AfterID uint64 `json:"after_id,omitempty"`
	Limit   int    `json:"limit,omitempty"`
	Level   string `json:"level,omitempty"`
}

// LogsResult is a page of log records.
type LogsResult struct {
	Lines []LogLine `json:"lines"`
	Last  uint64    `json:"last_id"`
}

// LogLine is one log record.
type LogLine struct {
	ID    uint64 `json:"id"`
	Time  int64  `json:"time"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

// SetConfigParams replaces the whole configuration.
type SetConfigParams struct {
	Config json.RawMessage `json:"config"`
}

// TunParams attaches an already-created tun file descriptor.
type TunParams struct {
	FD  int `json:"fd"`
	MTU int `json:"mtu,omitempty"`
}

// VersionResult is returned by MethodVersion.
type VersionResult struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

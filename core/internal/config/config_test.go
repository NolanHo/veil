package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// wgKeys builds WireGuard-shaped keys from bytes so the fixture carries no
// pasted credential.
func wgKeys() (priv, pub string) {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
}

func wgNode() Node {
	priv, pub := wgKeys()
	return Node{
		Tag:           "homelab",
		Type:          "wireguard",
		Server:        "wg.homelab.example",
		Port:          51820,
		PrivateKey:    priv,
		PeerPublicKey: pub,
		Addresses:     []string{"10.173.91.200/32"},
		AllowedIPs:    []string{"10.173.91.0/24"},
	}
}

func TestValidateWireGuard(t *testing.T) {
	// Both spellings of the type are accepted, like hysteria2/hy2.
	for _, typ := range []string{"wireguard", "wg"} {
		n := wgNode()
		n.Type = typ
		cfg := Config{Nodes: []Node{n}}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate(%s): %v", typ, err)
		}
	}

	missingKey := wgNode()
	missingKey.PrivateKey = ""
	if err := (&Config{Nodes: []Node{missingKey}}).Validate(); err == nil {
		t.Fatal("Validate accepted a wireguard node without private_key")
	}

	missingPeer := wgNode()
	missingPeer.PeerPublicKey = ""
	if err := (&Config{Nodes: []Node{missingPeer}}).Validate(); err == nil {
		t.Fatal("Validate accepted a wireguard node without public_key")
	}

	missingServer := wgNode()
	missingServer.Server = ""
	if err := (&Config{Nodes: []Node{missingServer}}).Validate(); err == nil {
		t.Fatal("Validate accepted a wireguard node without server")
	}

	// Without an interface address the userspace stack cannot send anything, so
	// the config is rejected where the UI can still explain it.
	missingAddr := wgNode()
	missingAddr.Addresses = nil
	if err := (&Config{Nodes: []Node{missingAddr}}).Validate(); err == nil {
		t.Fatal("Validate accepted a wireguard node without addresses")
	}
}

func TestWireGuardJSONRoundTrip(t *testing.T) {
	// The JSON names are the on-disk schema (and what the ArkTS UI edits), so
	// pin them: a rename here silently drops the user's keys.
	cfg := Config{Nodes: []Node{wgNode()}}
	cfg.Nodes[0].PresharedKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32))
	cfg.Nodes[0].MTU = 1420
	cfg.Nodes[0].KeepAlive = 25
	cfg.Nodes[0].DNS = []string{"10.173.91.1"}

	blob, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, field := range []string{
		`"private_key"`, `"public_key"`, `"preshared_key"`, `"addresses"`,
		`"allowed_ips"`, `"mtu"`, `"keepalive"`, `"dns"`,
	} {
		if !bytes.Contains(blob, []byte(field)) {
			t.Fatalf("marshalled config misses %s:\n%s", field, blob)
		}
	}

	var back Config
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := back.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	got, want := back.Nodes[0], cfg.Nodes[0]
	if got.PrivateKey != want.PrivateKey || got.PeerPublicKey != want.PeerPublicKey ||
		got.PresharedKey != want.PresharedKey || got.MTU != want.MTU ||
		got.KeepAlive != want.KeepAlive || len(got.Addresses) != 1 ||
		got.Addresses[0] != want.Addresses[0] || len(got.AllowedIPs) != 1 ||
		got.AllowedIPs[0] != want.AllowedIPs[0] || len(got.DNS) != 1 || got.DNS[0] != want.DNS[0] {
		t.Fatalf("round-trip mismatch\ngot:  %+v\nwant: %+v", got, want)
	}
}

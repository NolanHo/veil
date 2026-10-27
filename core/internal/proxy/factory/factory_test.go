package factory

import (
	"bytes"
	"encoding/base64"
	"testing"

	"veil/internal/config"
)

func wgNode(typ string) config.Node {
	return config.Node{
		Tag:           "homelab",
		Type:          typ,
		Server:        "wg.homelab.example",
		Port:          51820,
		PrivateKey:    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
		PeerPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32)),
		Addresses:     []string{"10.9.0.200/32"},
		AllowedIPs:    []string{"10.9.0.0/24"},
	}
}

func TestNewWireGuard(t *testing.T) {
	// "wg" is the alias users type; it must build the same client as the long
	// spelling, which is the name the node list shows.
	for _, typ := range []string{"wireguard", "wg"} {
		ob, err := New(wgNode(typ))
		if err != nil {
			t.Fatalf("New(%s): %v", typ, err)
		}
		if got := ob.Type(); got != "wireguard" {
			t.Fatalf("New(%s).Type() = %q, want wireguard", typ, got)
		}
		if got := ob.Tag(); got != "homelab" {
			t.Fatalf("New(%s).Tag() = %q", typ, got)
		}
		if err := ob.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}

	// An unusable node must fail at build time, not at first dial.
	broken := wgNode("wireguard")
	broken.PrivateKey = ""
	if _, err := New(broken); err == nil {
		t.Fatal("New accepted a wireguard node without private_key")
	}
}

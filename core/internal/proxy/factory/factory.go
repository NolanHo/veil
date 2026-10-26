// Package factory builds outbound protocol clients from configuration.
package factory

import (
	"context"
	"fmt"
	"net"

	"veil/internal/config"
	"veil/internal/outbound"
	"veil/internal/proxy/hysteria2"
	"veil/internal/proxy/ss"
	"veil/internal/proxy/trojan"
	"veil/internal/proxy/vless"
	"veil/internal/proxy/vmess"
	"veil/internal/proxy/wireguard"
	"veil/internal/transport"
)

// Direct is the built-in direct outbound.
type Direct struct{}

// Tag implements outbound.Outbound.
func (Direct) Tag() string { return "direct" }

// Type implements outbound.Outbound.
func (Direct) Type() string { return "direct" }

// DialContext implements outbound.Outbound.
//
// The dialer must be the protect-aware one: a plain net.Dialer sends packets
// back into the tun we own, and the engine then forwards them to itself —
// an endless loop that looks like "VPN connected, nothing loads".
func (Direct) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return transport.NewDialer().DialContext(ctx, network, address)
}

// Close implements outbound.Outbound.
func (Direct) Close() error { return nil }

// Reject drops every connection.
type Reject struct{}

// Tag implements outbound.Outbound.
func (Reject) Tag() string { return "reject" }

// Type implements outbound.Outbound.
func (Reject) Type() string { return "reject" }

// DialContext implements outbound.Outbound.
func (Reject) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, outbound.ErrRejected
}

// Close implements outbound.Outbound.
func (Reject) Close() error { return nil }

// New constructs the client for node n.
func New(n config.Node) (outbound.Outbound, error) {
	switch n.Type {
	case "vless":
		return vless.New(n)
	case "vmess":
		return vmess.New(n)
	case "trojan":
		return trojan.New(n)
	case "ss":
		return ss.New(n)
	case "hysteria2", "hy2":
		return hysteria2.New(n)
	case "wireguard", "wg":
		return wireguard.New(n)
	case "direct":
		return Direct{}, nil
	case "reject":
		return Reject{}, nil
	default:
		return nil, fmt.Errorf("unsupported outbound type %q", n.Type)
	}
}

package transport

import (
	"fmt"
	"strings"

	"veil/internal/config"
)

// Build composes the stream layer for one configuration node:
//
//	TCP -> TLS or REALITY -> (tcp | ws | grpc)
//
// A tls block carrying a REALITY public key means REALITY, whatever the
// "fingerprint"/"alpn" fields say; everything else is a normal uTLS handshake.
//
// The TCP connection to the node's server is a direct, protect-aware dial; see
// BuildWith for the same stack over a connection somebody else opens.
func Build(n config.Node) (Dialer, error) {
	return BuildWith(n, nil)
}

// BuildWith is Build over a caller-supplied base dialer: the connection to the
// node's own endpoint is opened by base, and everything this function layers
// (TLS/REALITY, WebSocket, gRPC) rides on that connection. The peer therefore
// sees the handshake arriving from base's exit, not from this device — which is
// what a chained outbound (mihomo's `dialer-proxy`) means.
//
// base is expected to dial the node's address (the factory binds it to n.Addr()
// so a Dialer, which carries no address of its own, is enough). A nil base is
// the direct TCP dial, exactly like Build.
func BuildWith(n config.Node, base Dialer) (Dialer, error) {
	if base == nil {
		base = TCP(n.Addr())
	}

	tlsCfg := n.TLS
	tr := n.Transport
	transportType := ""
	if tr != nil {
		transportType = strings.ToLower(strings.TrimSpace(tr.Type))
	}

	reality := tlsCfg != nil && tlsCfg.Reality != nil && strings.TrimSpace(tlsCfg.Reality.PublicKey) != ""
	if tlsCfg != nil && (tlsCfg.Enabled || reality) {
		// Work on a copy: Build must not mutate the node's configuration, which
		// may be shared with other goroutines.
		c := *tlsCfg
		if c.ServerName == "" {
			c.ServerName = n.Server
		}
		if len(c.ALPN) == 0 {
			c.ALPN = defaultALPN(transportType)
		}
		var (
			d   Dialer
			err error
		)
		if reality {
			d, err = Reality(base, &c)
			if err != nil {
				return nil, fmt.Errorf("transport: %s: %w", n.Addr(), err)
			}
		} else {
			d, err = TLS(base, &c)
			if err != nil {
				return nil, fmt.Errorf("transport: %s: %w", n.Addr(), err)
			}
		}
		base = d
	}

	switch transportType {
	case "", "tcp", "raw", "none":
		return base, nil
	case "ws", "websocket":
		c := config.Transport{}
		if tr != nil {
			c = *tr
		}
		if c.Host == "" && headerValue(c.Headers, "Host") == "" {
			// Xray falls back to the dialed address for the Host header.
			c.Host = n.Server
		}
		return WS(base, &c), nil
	case "grpc":
		c := config.Transport{}
		if tr != nil {
			c = *tr
		}
		if c.Host == "" {
			c.Host = n.Server
		}
		return GRPC(base, &c)
	case "h2", "http":
		return nil, fmt.Errorf("transport: %q transport is not supported yet", transportType)
	default:
		return nil, fmt.Errorf("transport: unknown transport type %q", transportType)
	}
}

// defaultALPN picks the ALPN list for a transport. WebSocket needs HTTP/1.1,
// gRPC needs h2, and everything else advertises what a browser would.
func defaultALPN(transportType string) []string {
	switch transportType {
	case "ws", "websocket":
		return []string{"http/1.1"}
	case "grpc":
		return []string{"h2"}
	default:
		return append([]string(nil), alpnPlain...)
	}
}

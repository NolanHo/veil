package share

import (
	"fmt"
	"strings"

	"veil/internal/config"
)

// parseHysteria2 parses hysteria2://auth@host:port?params#tag (hy2:// is an
// accepted alias). Hysteria2 always runs over QUIC+TLS, so TLS is enabled
// unconditionally. The model has no dedicated obfuscation field, so the
// salamander obfs settings are carried in Transport.Headers ("obfs",
// "obfs-password") with an empty Transport.Type, which config.Validate accepts.
func parseHysteria2(body, raw string) (config.Node, error) {
	body, frag := splitFragment(body)
	body, rawQuery := splitQuery(body)
	q := parseQuery(rawQuery)

	userinfo, hostport, err := splitUserInfo(body)
	if err != nil {
		return config.Node{}, fmt.Errorf("share: hysteria2: %w", err)
	}
	server, port, err := splitHostPort(hostport)
	if err != nil {
		return config.Node{}, fmt.Errorf("share: hysteria2: %w", err)
	}
	password := percentDecode(userinfo)
	if password == "" {
		return config.Node{}, fmt.Errorf("share: hysteria2: missing password")
	}

	n := config.Node{
		Type:     "hysteria2",
		Server:   server,
		Port:     port,
		Password: password,
	}

	t := ensureTLS(&n)
	t.Enabled = true
	if sni := qget(q, "sni", "peer", "servername"); sni != "" {
		t.ServerName = sni
	} else {
		t.ServerName = server
	}
	t.Insecure = truthy(qget(q, "insecure", "allowInsecure", "skipVerify"))
	// pinSHA256 is the certificate pin (mihomo's spelling for a hysteria2 link).
	// It is the only thing authenticating a self-signed peer, so a value that is
	// not a digest shape is a malformed link to report, never something to drop.
	if pin := qget(q, "pinSHA256", "pin-sha256", "pin_sha256"); pin != "" {
		if !certPinShape(pin) {
			return config.Node{}, fmt.Errorf("share: hysteria2: pinSHA256 %q is not a certificate digest", pin)
		}
		t.Fingerprint = pin
	}

	if obfs := qget(q, "obfs"); obfs != "" && !strings.EqualFold(obfs, "none") {
		n.Transport = &config.Transport{
			Headers: map[string]string{"obfs": obfs},
		}
		if pw := qget(q, "obfs-password", "obfs_password", "obfsParam"); pw != "" {
			n.Transport.Headers["obfs-password"] = pw
		}
	}

	n.Remark = frag
	if n.Remark == "" {
		n.Remark = NormalizeTag(qget(q, "remark", "remarks", "name"))
	}
	return n, nil
}

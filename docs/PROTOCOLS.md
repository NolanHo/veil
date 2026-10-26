# Supported protocols and import formats

## Outbounds

| Type | Transport | Security | UDP | Notes |
| --- | --- | --- | --- | --- |
| `vless` | tcp, ws, grpc | TLS, **REALITY**, `xtls-rprx-vision` | yes (length-framed) | Xray-compatible header, flow addons, hybrid post-quantum key share for REALITY |
| `vmess` | tcp, ws, grpc | TLS | yes | AEAD only (`alterId` ignored; the legacy AES-CFB mode is deliberately unsupported) |
| `trojan` | tcp, ws, grpc | TLS | yes | SHA-224 password digest, SOCKS5-style addressing |
| `ss` | tcp | — | yes | `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305` |
| `hysteria2` | QUIC | TLS 1.3, **certificate pin** | yes | HTTP/3-style auth over our own QPACK encoder; `obfs=salamander` implemented against the upstream reference; a hex `fingerprint` in the node pins the peer certificate (a profile name there still selects uTLS) |
| `wireguard` (`wg`) | UDP | Noise IK, optional PSK | yes | userspace netstack (no OS tun, works inside the VPN extension); interface `ip`, `allowed-ips`, `mtu`, `keepalive`; destinations outside `allowed-ips` fail fast instead of hanging |
| `direct` / `reject` | — | — | — | built-ins for rules |

Transports: plain TCP, TLS 1.3 with uTLS browser fingerprints
(`chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `randomized`),
REALITY, WebSocket (optional early data), gRPC.

`h2`/`http` as a *standalone* transport is not implemented (gRPC uses HTTP/2
internally); nodes asking for it fail with a clear "not supported" error.

## Inbounds

- **mixed** (`socks5` + `http` on one port): SOCKS5 CONNECT/ UDP ASSOCIATE,
  HTTP CONNECT and absolute-form requests.
- **tun** (HarmonyOS VPN extension): gVisor userspace stack, TCP + UDP
  forwarders, in-tunnel DNS answered by the resolver.

## Routing

Rule types: `domain`, `domain-suffix`, `domain-keyword`, `domain-regex`,
`ip-cidr`, `ip-cidr6`, `geoip` (`private`, `cn`), `port`, `network`, `process`,
`final`. First match wins; `no_resolve` skips DNS for that rule. Actions are a
node tag, a group tag, `direct` or `reject`.

Modes: `rule` (evaluate the table), `global` (default outbound), `direct`.

Groups: `select` (manual), `url-test` (lowest latency, flapping guard via
`tolerance`), `fallback` (first healthy on dial), `load-balance` (round robin
with failover).

DNS: UDP, TCP, DoT, DoH upstreams; per-server domain match; optional `detour`
through a proxy; TTL cache with single-flight and negative caching.

## Share links

```
vless://<uuid>@host:port?encryption=none&flow=xtls-rprx-vision&security=reality
      &sni=example.com&fp=chrome&pbk=<x25519 pub>&sid=<hex>&spx=%2F
      &type=tcp|ws|grpc&path=/x&host=cdn.example.com&serviceName=gun#name

vless://<base64("auto:<uuid>@host:port")>?obfs=none&tls=1&peer=example.com
      &xtls=2&pbk=<x25519 pub>&sid=<hex>            # legacy v2rayN form

vmess://<base64(json)>                               # standard v2rayN JSON
vmess://<base64("auto:<uuid>@host:port?obfs=websocket&...")>

trojan://<password>@host:port?sni=example.com&type=ws&path=/x&allowInsecure=1#name

ss://<base64(method:password)>@host:port#name        # SIP002
ss://<base64(method:password@host:port)>#name

hysteria2://<password>@host:port?sni=example.com&insecure=1&obfs=salamander
      &obfs-password=<secret>#name    (hy2:// is an alias)
```

Paste any of these into 规则 → 导入. The importer also accepts:

- a base64 subscription body or a plain list of links;
- a Clash YAML document: `proxies:` (`reality-opts`, `ws-opts`, `grpc-opts`,
  `obfs`, `skip-cert-verify`, `type: wireguard`, `type: hysteria2` with
  `fingerprint`), plus `proxy-groups:` (`select`, `url-test`, `fallback`,
  `load-balance`) and `rules:` (`DOMAIN*`, `IP-CIDR[6]`, `GEOIP`, `DST-PORT`,
  `NETWORK`, `PROCESS-NAME`, `MATCH`; `DIRECT`/`REJECT` map to the built-ins).
  Groups are topologically ordered because the engine builds them in order, and
  an imported rule table **replaces** the stock one (first match wins, so
  appending behind the stock `geoip private → direct` would shadow a split
  tunnel into a private range). `RULE-SET`/`GEOSITE` need external data and are
  skipped with a reported error rather than silently ignored;
- a WireGuard `wg-quick` `.conf` (`[Interface]`/`[Peer]`, possibly repeated
  `Address`/`AllowedIPs`);
- markdown-mangled links, e.g. `peer=[www.icloud.com](http://www.icloud.com)`,
  which are normalised to `www.icloud.com`.

## Control API (JSON, newline framed)

| Method | Params | Result |
| --- | --- | --- |
| `status` | — | `state.Status` |
| `start` / `stop` | `{"tun_fd": -1}` / — | `state.Status` |
| `nodes` / `groups` | — | node or group snapshots |
| `select` | `{"group","tag"}` | groups |
| `delay` | `{"tag","timeout_ms"}` | `{"tag","delay_ms","err"}` |
| `import` | `{"text","name","source","urls"}` | counts + errors |
| `sub_add` / `sub_update` / `sub_delete` | `{"name","url"}` / `{"name"}` | groups / nodes |
| `set_mode` | `{"mode"}` | status |
| `config` / `set_config` | — / `{"config":{...}}` | config / status |
| `conns` / `close_conn` / `close_all` | — / `{"id"}` | live connections |
| `logs` | `{"after_id","limit","level"}` | log page |
| `set_tun_fd` / `clear_tun_fd` | `{"fd","mtu"}` | status |
| `version` / `reset_stats` | — | version / — |

The VPN extension additionally handles host requests from the core:
`protect {fd}`, `tun_up {mtu,ipv4,ipv6,dns}`, `tun_down`.

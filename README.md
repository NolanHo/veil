# Veil

**A proxy client for HarmonyOS NEXT that tells the truth about its state and does not die in the background.**

Veil is a from-scratch replacement for ClashBox. The UI is ArkTS; the engine is a
Go library (`libveil.so`) loaded through NAPI; the tunnel is a `vpnExtension`
tun device handed to the engine as a file descriptor.

```
┌──────────────────────────── ArkTS UI (ArkUI) ────────────────────────────┐
│  Home · Nodes · Rules · Settings        one JSON call: veil.call(...)     │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │ NAPI (napi_init.cpp)
┌──────────────────────────────────▼───────────────────────────────────────┐
│ libveil.so (Go, c-shared)                                                 │
│                                                                          │
│  supervisor ── lifecycle state machine, watchdog, panic isolation         │
│      │                                                                    │
│      ├── engine ── rules → group → outbound ── stats / conn registry      │
│      │      ├── inbound: socks5+http (mixed), DNS server                 │
│      │      └── netstack (gVisor) over the tun fd                        │
│      │                                                                    │
│      └── transports: tcp · tls(uTLS) · REALITY · ws · grpc               │
│           protocols: vless(+vision) · vmess(aead) · trojan · ss · hy2    │
└──────────────────────────────────────────────────────────────────────────┘
```

## Why Go is usable on HarmonyOS

HarmonyOS NEXT runs a Linux kernel. A Go program that only uses the standard
library plus `golang.org/x/*` builds for `GOOS=linux GOARCH=arm64` with the
OpenHarmony NDK clang (`--target=aarch64-linux-ohos`) and links against the
device libc. Veil ships it as a C shared library and calls it from ArkTS via
NAPI, exactly like the mihomo-based client does — but with a much smaller,
auditable core. This was verified in this repository's build script:

```bash
scripts/build-core.sh          # produces entry/src/main/libs/arm64-v8a/libveil.so
```

## Feature set

- **Protocols**: VLESS (REALITY, XTLS-Vision), VMess (AEAD, alterId 0), Trojan,
  Shadowsocks (AEAD-2022 + legacy AEAD), Hysteria2 (QUIC, salamander obfs,
  certificate pinning), WireGuard (userspace netstack, split tunnel by
  `allowed-ips`).
- **Transports**: TCP, TLS 1.3 with browser fingerprints, REALITY, WebSocket
  (early data), gRPC, HTTP/2.
- **Import**: `vless://`, `vmess://` (standard JSON *and* legacy
  `base64(user@host:port?query)`), `trojan://`, `ss://` (SIP002), `hysteria2://`,
  subscription URLs (base64 or plain), pasted Clash YAML — proxies, plus
  `proxy-groups` and `rules` — and a WireGuard `wg-quick` `.conf`.
- **Routing**: ordered rules (domain / suffix / keyword / regex / CIDR / geoip /
  port / network / process / final), policy groups (select, url-test, fallback,
  load-balance), global/rule/direct modes.
- **DNS**: UDP / TCP / DoT / DoH upstreams, TTL cache, per-server detour, DNS
  hijack inside the tunnel.
- **Observation**: live connections with per-connection byte counters, latency
  probes, real traffic rates, log ring buffer.

## Setting it up on a device

Paste the profile you already run elsewhere — Clash Verge, mihomo, whatever
writes a Clash document — into **规则 → 导入**. Proxies, `proxy-groups` and
`rules` all come across, so a profile that sends `10.20.30.0/24` to a WireGuard
peer and everything else through a Hysteria2 node works without retyping the
routing. WireGuard peers can also be pasted as a `wg-quick` `.conf`.

Two behaviours worth knowing:

- an imported rule table replaces the stock one (first match wins; appending
  behind the stock `geoip private → direct` would shadow a split tunnel into a
  private range). A document that says `rules: []` clears it, one that says
  nothing about rules leaves it alone.
- with fake-ip DNS on, a domain reaches the router as a fake address. IP rules
  still need a real one, so the router resolves the name through the
  configured upstream at route time and dials the hostname afterwards — the
  exit node remains the authority. A direct connection, which resolves locally,
  dials the resolved address instead of the fake one.

`GEOIP,CN` uses an APNIC-derived allocation table, so "domestic direct,
everything else through the node" behaves the way a Clash profile expects.

## Why it won't rot

The failures of the original client were lifecycle bugs, not protocol bugs.
Veil treats the process as a supervised service:

1. **One state machine.** `stopped → starting → running → degraded/stopping →
   failed`. Every transition carries a reason string. The UI renders the state;
   it never infers "connected" from an optimistic flag.
2. **Health is measured, not remembered.** A watchdog goroutine ticks every
   second; the supervisor reports the age of the newest tick, goroutine count,
   open descriptors, heap size and restart count. A stalled tick is itself a
   failure signal.
3. **Nothing is allowed to panic into the void.** Every connection handler,
   listener and background loop runs under `recover()`; listener failures are
   restarted with exponential backoff; fatal engine errors restart the engine
   with a bounded, announced backoff instead of silently dying.
4. **Everything has a deadline and an owner.** Connections are registered with
   context cancellation, idle timeouts and a hard cap; shutdown drains them.
   A 30-minute soak test asserts that goroutines return to baseline.

## Building

```bash
# host tests (protocols, routing, supervisor soak)
cd core && GOTOOLCHAIN=go1.27.3 go test ./... -count=1

# HarmonyOS arm64 core (writes entry/libs/arm64-v8a/libveilcore.so)
scripts/build-core.sh

# HAP (compile + package; signing config is optional for a local build)
DEVECO_SDK_HOME=/Applications/DevEco-Studio.app/Contents/sdk \
JAVA_HOME=/Applications/DevEco-Studio.app/Contents/jbr/Contents/Home \
NODE_HOME=/Applications/DevEco-Studio.app/Contents/tools/node \
/Applications/DevEco-Studio.app/Contents/tools/hvigor/bin/hvigorw \
  --mode module -p module=entry@default assembleHap --no-daemon
```

### Install

The HAP is unsigned by default. Open the project in DevEco Studio once and let
it create a debug signing config (Project Structure → Signing Configs), or sign
`entry/build/default/outputs/default/entry-default-unsigned.hap` with your own
certificate, then install with `hdc install <hap>`.

On first start the app asks the system to start its VPN extension. The status
card shows `核心不可用` with the real error if the extension or the native core
cannot start — it never shows a false "connected".

## Verification status

| Target | Command | Result |
| --- | --- | --- |
| Go unit + integration | `cd core && go test ./...` | see `docs/TESTING.md` for the matrix |
| REALITY interop | `go test ./e2e -run TestReality -v` | passes against the official `github.com/xtls/reality` server |
| Whole data path | `go test ./e2e -run ThroughEngine -v` | SOCKS5 → engine → VLESS/REALITY → echo |
| Stability | `go test ./internal/supervisor -run Soak` | 1440 connections, goroutines return to baseline |
| arm64 OHOS core | `scripts/build-core.sh` | `libveilcore.so`, ELF aarch64, links only libc |
| App package | `hvigorw assembleHap` | HAP contains `libs/arm64-v8a/libveil{,.so,core.so}` |

Known limits are listed at the bottom of `docs/TESTING.md` (no live carrier
tests, the VPN extension cannot run on a desktop).


## Layout

| Path | Purpose |
| --- | --- |
| `core/internal/share` | share-link and subscription parsing |
| `core/internal/transport` | stream layer: tcp, tls, REALITY, ws, grpc |
| `core/internal/proxy/*` | protocol clients |
| `core/internal/inbound` | SOCKS5 / HTTP listeners |
| `core/internal/rules` | routing matcher |
| `core/internal/dns` | resolver and in-tunnel DNS |
| `core/internal/engine` | routing, groups, stats, connection registry |
| `core/internal/supervisor` | lifecycle, watchdog, RPC dispatch |
| `core/internal/netstack` | gVisor netstack over the tun fd |
| `entry/src/main/ets` | ArkTS UI and VPN extension |

## License

MIT — see [LICENSE](LICENSE).

This is a client for protocols (VLESS/REALITY/Vision, VMess, Trojan, Shadowsocks,
Hysteria2); it ships no servers, no subscriptions and no credentials.

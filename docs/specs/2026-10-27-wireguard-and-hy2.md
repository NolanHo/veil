# Spec: WireGuard outbound + Hysteria2 socket protection/obfs

Status: approved for implementation (2026-10-27)
Branch: `feat/wireguard-hy2`
Owner: lead (kagari). Implementers: two parallel work streams (A, B) with disjoint write sets.

## 1. Background

`veil` is a HarmonyOS NEXT proxy client: an ArkTS UI plus a Go core
(`core/`) shipped as a C archive linked into `libveil.so`, driven over a unix
socket by a `vpnExtension` that owns the tun fd.

The user runs this on a HarmonyOS 7 tablet and needs the tablet to reproduce the
traffic profile of their macOS setup:

- **Hysteria2** (`hy2`) to the internet — already implemented, but two gaps are
  blocking on-device use (see §3).
- **WireGuard** to their homelab — **not implemented at all**. No `wireguard`
  package, no `wg` case in the factory, no config fields.

Goal: the Go core can dial through both, verified on Linux with real in-process
servers, and compiles for `GOOS=openharmony GOARCH=arm64`.

## 2. Non-goals

- No ArkUI work in this change (the WG config will be editable through the
  existing node editor / import path; a dedicated form is a later change).
- No HAP packaging, signing, or device install here.
- No changes to `docs/PROTOCOLS.md` / `README.md` in this change — the lead
  updates the docs after both streams merge.

## 3. Stream B — Hysteria2 (write set: `core/internal/proxy/hysteria2/` only)

### B1. UDP socket is never protected (correctness bug, blocks all hy2 use)

`core/internal/proxy/hysteria2/client.go:256` does `net.ListenUDP("udp", nil)`.
That socket never passes through `transport.SetProtector`, so on HarmonyOS its
packets are captured by our own tun again — the documented invariant in
`AGENTS.md` ("No socket may bypass `transport.TCP`/`transport.NewDialer`") is
violated, and `transport.ProtectFD` is currently dead code (zero call sites).

Fix: create the QUIC socket through the protect-aware path and call
`transport.ProtectFD` on the raw fd, e.g.

```go
lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error { ... }}
pkt, err := lc.ListenPacket(ctx, "udp", ":0")   // or lc.ListenPacket + ProtectFD on SyscallConn
```

Prefer reusing `transport` so the hook lives in one place. If a small helper is
needed, add it inside the hysteria2 package (do not edit `transport/`).

Acceptance: a test that installs a protector via `transport.SetProtector` and
asserts it was invoked with a plausible fd when the hy2 client dials; the
existing hy2 tests must stay green.

### B2. `obfs=salamander` is parsed but not applied

`core/internal/share/hysteria2.go` and the Clash importer already put
`obfs` / `obfs-password` into `Node.Transport.Headers`, and
`client.go:71-73` documents that nodes with obfs do not work.

Implement salamander obfs (Hysteria2 reference: `hysteria/core/internal/obfs`):
the underlay packet connection is wrapped so that every datagram is XORed with a
keystream derived from `BLAKE2b-256(obfs-password, salt)` where `salt` is a
per-direction random 8-byte prefix carried in clear at the head of each packet,
with an 8-byte counter appended (BLAKE2b output = 8-byte salt + 8-byte counter).
Implement the exact reference construction; do not approximate.

Acceptance: a unit test that round-trips a payload through the wrapper and
asserts the wire format (salt + counter present, ciphertext != plaintext,
decryption restores the payload), plus a hy2 e2e test where a local quic-go
server is wrapped with the same obfs implementation and the client connects
with `obfs=salamander` + password.

## 4. Stream A — WireGuard (write set: `core/internal/proxy/wireguard/` (new),
`core/internal/config/config.go`, `core/internal/proxy/factory/factory.go`,
`core/internal/share/wireguard.go` (new), `core/go.mod`, `core/go.sum`)

### A1. Config

Add to `config.Node` (JSON snake_case, matching the file's style):

| field | JSON | meaning |
| --- | --- | --- |
| PrivateKey | `private_key` | base64 WireGuard private key |
| PeerPublicKey | `public_key` | base64 peer public key |
| PresharedKey | `preshared_key,omitempty` | base64 PSK |
| Addresses | `addresses,omitempty` | interface addrs, e.g. `["10.9.0.200/32"]` |
| AllowedIPs | `allowed_ips,omitempty` | peer allowed IPs, e.g. `["10.9.0.0/24"]` |
| MTU | `mtu,omitempty` | default 1420 |
| KeepAlive | `keepalive,omitempty` | seconds, default 0 |
| DNS | `dns,omitempty` | interface DNS for the userspace stack |

`server` + `port` carry the endpoint (keep them 1:1 with the base64
`Endpoint = host:port`). `Validate` must reject a `wireguard` node missing
`private_key`, `public_key`, or `server`.

`Type` accepts `"wireguard"` and the alias `"wg"`, like `hysteria2`/`hy2`.

### A2. Outbound implementation

Use `golang.zx2c4.com/wireguard` (pin the revision you verify) with
`tun/netstack.CreateNetTUN` — a userspace stack, no OS tun, so it works inside
the VPN extension. The outbound must satisfy `outbound.Outbound` and, when it
works, `outbound.PacketOutbound`:

- `DialContext(ctx, network, address)` → `ns.DialContext` inside the tunnel.
- `DialPacket(ctx, address)` → wrap `ns.DialUDP` as `outbound.PacketConn`.
- Create the `device.Device` lazily on first dial, once, guarded by a mutex
  (mirror the hysteria2 client's lazy `dialMu`/`conn` shape).
- `Close()` tears the device down; the engine calls it on stop/reload.

### A3. The socket MUST be protected

WireGuard needs its own long-lived UDP socket to the peer endpoint. It must be
created through `transport` so `VpnConnection.protect(fd)` runs, otherwise the
tunnel loops into the tun exactly like B1.

Implement a `conn.Bind` (wireguard-go interface) over a `net.PacketConn` opened
with a `protect`-installing `net.ListenConfig.Control`; `conn.NewDefaultBind()`
is **not** acceptable. Reference shape: wireguard-go's `conn.StdNetBind`
(MIT); keep it minimal — `Open`, `Close`, `SetMark` (no-op ok), `Send`,
`Receive`, `ParseEndpoint` for `*net.UDPAddr`, `BatchSize` = 1 if you do not
implement batching.

Also call `transport.ProtectFD` on the raw fd as a belt-and-braces check if the
`ListenConfig` path is used.

### A4. Dependency

Adding `golang.zx2c4.com/wireguard` pulls `gvisor.dev/gvisor` at a newer
revision than the one `core/go.mod` pins today
(`v0.0.0-20240722211153-64c016c92987`). Two acceptable outcomes, in order:

1. `go mod tidy` bumps gvisor; then `go test ./internal/netstack/... ./e2e`
   must stay green (the netstack tests craft real packets through the gVisor
   endpoint). If anything regresses, do **not** paper over it.
2. If the bump breaks veil's netstack, pin an older `wireguard-go` revision
   whose required gvisor ≤ the current pin, and record the reason in the PR
   description.

`go.sum` must be regenerated with the OHOS toolchain available on this host:
`/tmp/wgprobe/toolchain/go1.27.2-ohos`.

### A5. Import

`core/internal/share/wireguard.go`: parse a standard WireGuard `.conf`
(`[Interface]` / `[Peer]`, `PrivateKey`, `Address`, `DNS`, `MTU`,
`PublicKey`, `PresharedKey`, `AllowedIPs`, `Endpoint`, `PersistentKeepalive`)
into a `config.Node`, with a `Tag` derived from `Remark`/`Endpoint`.
Round-trip test required. Reject (with a clear error) anything the outbound
cannot honour (e.g. multiple peers, `Table`, `PreUp`).

## 5. Invariants (both streams)

1. No socket may bypass `transport` — this change exists partly because one
   already does.
2. Every exported behaviour needs a test that fails without the change.
3. `gofmt -l .` clean, `go vet ./...` clean, `go test ./...` green.
4. Match the surrounding code style (comments explain *why*; no new abstraction
   layers; no framework).

## 6. Acceptance (lead runs all of these)

```bash
cd core && GOTOOLCHAIN=go1.27.3 go vet ./...            # clean
cd core && GOTOOLCHAIN=go1.27.3 go test ./... -count=1  # green
cd core/e2e && GOTOOLCHAIN=go1.27.3 go test ./... -count=1   # green
# OHOS cross-compile of the core packages (no cgo needed for this check):
export GOROOT=/tmp/wgprobe/toolchain/go1.27.2-ohos
GOOS=openharmony GOARCH=arm64 CGO_ENABLED=0 GOTOOLCHAIN=local \
  $GOROOT/bin/go build ./...   # in core/
```

Evidence already collected by the lead:

- `golang.zx2c4.com/wireguard` + `tun/netstack` cross-compiles for
  `GOOS=openharmony GOARCH=arm64` with that toolchain (probe binary: ELF
  aarch64 musl).
- `go vet ./...` was red on the base commit (`cmd/vprobe/main.go:77` printf
  verb, `internal/proxy/vless/vision.go:280` unreachable code); both are fixed
  on this branch before the streams start.

## 7. Write-set split

| Stream | May write | Must not touch |
| --- | --- | --- |
| A (WireGuard) | `core/internal/proxy/wireguard/**`, `core/internal/config/**`, `core/internal/proxy/factory/**`, `core/internal/share/wireguard.go`, `core/internal/share/wireguard_test.go`, `core/go.mod`, `core/go.sum` | `core/internal/proxy/hysteria2/**`, `core/internal/transport/**`, `core/internal/netstack/**`, ArkTS |
| B (Hysteria2) | `core/internal/proxy/hysteria2/**` | everything else, in particular `core/internal/config/**` and `core/go.mod` |

Neither stream touches `docs/` or the ArkTS tree.

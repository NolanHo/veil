# Review round 1 — Standards findings (fix list)

Source: independent Standards review (`gpt-6.1-sol`) of branch `feat/wireguard-hy2`,
verdict **CHANGES_REQUIRED**. Every item was reproduced by the reviewer in an
isolated clone with a dedicated test; reproduce the same way before and after
your fix.

Nothing here may be papered over: a "fix" that only loosens a test or skips a
configuration is not a fix.

## Blocking

**S1 — WireGuard endpoint DNS sockets bypass protect**
`core/internal/proxy/wireguard/client.go:313-316`. `transport.NewDialer().DialContext(..., "udp", endpoint)`
protects only the UDP socket created for the dial; the resolver's own sockets
never see `Dialer.Control`. Reviewer observed 8 real DNS sockets with 0 protector
calls. On device that can loop into the tun and break endpoint resolution
(invariant 1).
Required: resolve the endpoint through a path whose sockets are protected, or
resolve via the engine's DNS path; a name that cannot be resolved protected must
fail loudly, not silently fall back. The comment must match what the code does.

**S2 — `Close()` does not own a device still under construction**
`client.go:137-142, 234-244, 251-267`. `start()` builds the device, then
publishes it to `c.dev`; a `Close()` racing the first dial sees nil, returns, and
leaves the local device running (fd still open, verified with `Fstat`).
Required: a Close during first-dial must cancel/close the in-progress device and
every later dial must observe the closed state.

**S3 — Malformed certificate pin silently disables pinning**
`core/internal/proxy/hysteria2/client.go:162-170`. Any non-hex character makes
`certPin` return `(nil, nil)`, so `Fingerprint = 63*"0" + "g"` with
`Insecure=true` connects to an unrelated self-signed server with no
authentication at all.
Required: only a known uTLS profile name may mean "uTLS"; anything else is a
malformed pin and must fail at construction. Never silently drop the only
authentication constraint.

**S4 — Share export downgrades pin to "no authentication"**
`core/internal/share/export.go:278-290`. A node with a valid pin plus
`Insecure=true` exports as `insecure=1` with no pin; the round trip loses the
certificate constraint and the share link authenticates nothing.
Required: either represent the pin losslessly in the link, or refuse to export
that node with a clear error.

## Should-fix

**S5 — Second concurrent dial ignores its own cancel**
`wireguard/client.go:217-220`. Waiting on `dialMu.Lock()` ignores the caller's
deadline. A blocked second dial must return when its context is cancelled.

**S6 — WireGuard identity fields missing from the import de-duplication key**
`share/clash.go:189-197,147`, `share/text.go:135-159`. Two nodes with the same
endpoint but different keys/addresses/AllowedIPs collapse into one, silently.
Include the new identity fields in the dedup key.

**S7 — One bad node aborts the whole Clash import**
`share/clash.go:74-76,122-125`. A typed decode of the whole `[]clashProxy`
happens before per-node handling, so one malformed node (e.g. `allowed-ips`
given as a mapping) drops every sibling. Decode per node; a bad node becomes an
error entry, not a total failure.

**S8 — `allowed-ips` mapping form silently accepted**
`share/clash.go:68-81`. `allowed-ips: {typo: ...}` unmarshals to an empty list
with no warning. Reject unknown shapes instead of producing a route-less peer.

**S9 — Omitted `allowed-ips` yields a zero-route peer**
`share/clash.go:196-197`. In Clash a single-peer WireGuard without `allowed-ips`
defaults to a default route by address family (see mihomo
adapter/outbound/wireguard.go). We keep an empty list, so the node imports
"successfully" and cannot send anything. Apply the Clash default in the Clash
mapping only; the `.conf` semantics stay as-is.

**S10 — `.conf` repeated list keys overwrite instead of accumulate**
`share/wireguard.go:110-113,136-137`. `Address`/`DNS`/`AllowedIPs` may repeat
(wg-quick emits multiple `Address` lines). Appending is required; today the last
line wins and the IPv4 address is lost on round trip.

**S11 — `reserved` is silently dropped**
`share/clash.go:189-200`. `reserved: [1,2,3]` changes the wire format (mihomo
passes it to the bind). If we do not implement it, the node must be skipped with
an error like `dialer-proxy` — not imported as a differently-behaving node.

**S12 — `.conf` export allows directive injection**
`share/wireguard.go:173-178`. A value containing a newline injects a new
directive (`DNS: "10.9.0.1\nPostUp = ..."`). Reject values containing
newlines/whitespace that cannot be represented in the line format.

## Nit

**S13** `share/fingerprint_test.go:117-118` — both lookups take the same element
of `testPin()`, so the case named `bare` is still the colon form and covers
nothing.

## Acceptance for the fix round

- A test per item that fails before the fix and passes after; paste the failing
  output for the four blocking items.
- `cd core && go vet ./... && go test ./... -count=1` green; `cd core/e2e && go test ./... -count=1` green.
- OHOS cross-compile: `GOROOT=/tmp/wgprobe/toolchain/go1.27.2-ohos GOOS=openharmony GOARCH=arm64 CGO_ENABLED=0 GOTOOLCHAIN=local $GOROOT/bin/go build ./...` from `core/`.
- `gofmt -l .` empty.

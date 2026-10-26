# Veil design notes

## Goals, in order

1. **Never lie about state.** A proxy UI that shows "connected" while the
   tunnel is dead is worse than no UI. Every phase carries the reason it was
   entered, and every health number is measured.
2. **Survive the background.** No unbounded goroutines, no leaked file
   descriptors, no listener that dies silently, no config reload that kills the
   tun.
3. **Modern protocols, exactly.** REALITY, XTLS-Vision, VMess AEAD,
   Shadowsocks 2022, Hysteria2 — implemented against the reference wire format,
   not approximated.

## Process architecture on HarmonyOS

```
┌──────────────────────────────┐        ┌───────────────────────────────────┐
│ UI process                   │        │ VPN extension process             │
│  ArkUI pages                 │        │  VeilVpnAbility                   │
│  CoreClient (Unix socket) ───┼───────▶│   ├─ NAPI → libveil.so (shim)     │
└──────────────────────────────┘        │   │           └─ dlopen libveilcore │
                                        │   ├─ core: supervisor + engine    │
                                        │   ├─ VpnConnection (tun fd,       │
                                        │   │   protect(fd))               │
                                        │   └─ control socket (filesDir)    │
                                        └───────────────────────────────────┘
```

The extension is the only process that owns a tun descriptor, so it is the only
place the core can live. The UI is a thin client: it renders status and issues
RPCs. When the extension is not running the UI says so instead of pretending.

### Control protocol

Line-delimited JSON over `filesDir/veil.sock`:

```
UI    -> core  {"id":7,"method":"status","params":{}}
core  -> UI    {"id":7,"ok":true,"result":{...}}

ext   -> core  {"role":"host"}
core  -> ext   {"host":true,"id":1,"method":"protect","params":{"fd":42}}
ext   -> core  {"id":1,"ok":true}
core  -> ext   {"host":true,"id":2,"method":"tun_up","params":{"mtu":1400}}
ext   -> core  {"id":2,"ok":true,"result":{"fd":37}}
```

The host channel is the only way to reach `VpnConnection.protect`, and every
socket the engine opens must be protected before it connects (otherwise the
traffic loops into the tun). `transport.SetProtector` installs that hook into
`net.Dialer.Control`, so it applies uniformly to TCP, TLS, REALITY, WS and gRPC
without each protocol knowing about HarmonyOS.

## Lifecycle

```
stopped ──start──▶ starting ──ok──▶ running ──failure──▶ degraded ──▶ running
   ▲                  │                 │                                │
   └──────stop────────┴────failed◀──────┴──────────────stop──────────────┘
```

- `starting` fails only when no data path could be built at all.
- `degraded` means the mixed proxy works but the tun (or one listener) does
  not; the reason string is shown verbatim in the UI.
- The watchdog ticks every second. Every 2 s it checks: engine alive, mixed
  listener accepts a real TCP connection, heartbeat age < 10 s. Two consecutive
  failures restart the engine on the *same* tun fd (no VPN flap).
- Restart budget: 5 restarts per 10 minutes, then `failed` with the last error.
  This is deliberately visible instead of silently retrying forever.

## Data path

```
tun (gVisor netstack) ─┐
socks5/http (mixed)  ──┼─▶ engine.HandleTCP ─▶ route ─▶ group ─▶ outbound ─▶ wire
                       └─▶ engine.HandleUDP ─▶ route ─▶ udp association cache
```

Routing is lazy about addresses: the matcher walks the rule table in order and
asks for a name's address only when it actually reaches an IP rule (`GEOIP`,
`IP-CIDR`, `IP-CIDR6`) that has none to look at. This is the Clash/mihomo
behaviour, and it matters: resolving up front as soon as the table happened to
contain an IP rule charged every new name a DNS round trip even when a domain
rule matched first — which, under fake-IP, was almost every connection. A
`DOMAIN-SUFFIX,corp.example,DIRECT` above `GEOIP,CN,DIRECT` now classifies
corporate hosts without any query at all.

The lookup goes through the engine's own resolver — the configured DoH/DoT
upstreams, on the same detour-aware path the tunnel DNS uses, never the OS
resolver — with a 3 s budget, a one-minute cache and single-flight collapsing in
the engine, so a page load with dozens of connections to one name costs one
query. It runs at most once per routing decision, and the address it returns
feeds the rest of the walk. The outbound still receives the hostname, so the exit
node performs the authoritative lookup; the local one only classifies traffic.

This is what makes IP rules work for flows that arrive on a fake-IP address. A
fake address (198.18.0.0/15) carries nothing but the requested name, so an IP
rule has no address until the router fetches one — without that fetch
`GEOIP,CN,DIRECT` never fires and domestic traffic falls through to `MATCH`. A
failed lookup is not fatal: the rule that wanted the address simply does not
match, a debug line records why, and evaluation continues with the next rule.

A decision that dials on this device is the one flow that cannot skip the
lookup: a local dial has no exit node to resolve for it, and handing it the
fake address (or a name that only exists inside our DNS) connects to nothing.
So when the walk produced no address and the chosen outbound dials locally, the
router resolves once more, at the dial — the same lookup, from the same cache,
bounded the same way. If that lookup fails too, the decision fails with the
reason it failed ("… dials locally, so the fake address must be resolved on this
device: …"). It is not handed the hostname: a local dial would pass the name to
the system resolver, under fake-IP that answers with the same placeholder, and
the connection dies somewhere the user cannot see. A proxied outbound keeps the
name in every case — the exit node stays the authority for DNS.

Fake-IP does not answer for names the local network owns. A NAS (`nas`,
`nas.lan`), a printer (`printer.local`) or a corporate host under `.internal`
does not exist at the exit node, so a synthetic address is unanswerable: the
public DoH upstreams return NXDOMAIN, and with a local dial the routing decision
fails outright. Those names take the upstream path and get the real answer — or
a real NXDOMAIN, which is a fact about the LAN rather than a pointer to an
address nobody can reach. The list is mihomo's `fake-ip-filter` in its minimal
form: single-label names (the local search suffix and mDNS own them), `.local`,
`.lan`, `.internal`, `.home.arpa` (RFC 8375) and `.localhost` (RFC 6761).
Everything else keeps the fake answer. There is no configuration for it yet —
`config.DNSConfig` has no filter field, so there is nothing to merge with; a
field added later should extend this list, with the configured entries winning.

Whether an outbound dials locally is a group-level question, and the answer
depends on the group type, because the type says whether `current` is a promise
about the member that carries the next connection. A `select` group dials
exactly the member it reports, so it answers for `current` — that is what keeps
the ordinary "selector pinned to DIRECT" profile working. `fallback` and
`load-balance` pick at dial time and may try any member, so they answer for the
member set with an `any`: one member that dials locally is enough. The asymmetry
is deliberate. A real address handed to a proxy member still works, because the
exit node can dial an IP, while a fake address handed to a direct member is a
dead end — that dial asks the system resolver and gets the placeholder back. A
mixed fallback group therefore gives up the remote lookup the proxy member might
have done and keeps the connection that lands on DIRECT; one substitution the
proxy did not need costs a lookup, the broken direct dial costs the page.
`url-test` keeps the older whole-set answer (`true` only when every member dials
locally): it dials `current` like a selector, but its own probe loop can move
`current` between the answer and the dial, so it cannot promise which member it
reported, and a mixed url-test group still loses its DIRECT member under
fake-IP.

`no-resolve` is honoured in both directions. Such a rule never makes the router
resolve, and it never matches an address the router looked up — it only sees a
destination the client sent literally (`rules.Meta.DstFromLookup`), so a
`IP-CIDR,...,no-resolve` rule cannot be fed by a lookup performed for some other
rule.

`PROCESS-NAME` / `PROCESS-PATH` rules import and compile but never match: the tun
hands over packets without the owning application, so `rules.Meta.Process` stays
empty. Making them work requires the ArkTS side to supply an app identity for a
flow (uid → bundle name via `bundleManager`, delivered to the Go side per
connection); until that exists a config that relies on process rules simply
routes those flows with the rest of its table.

## Resource discipline

- Connections are registered in a capped registry (4096). Each gets a tracked
  byte counter and is closed when either side finishes.
- UDP associations are cached per (outbound, destination) and reaped after 60 s
  idle.
- Config reload swaps outbounds without touching the tun; retired clients are
  closed after a 2 minute grace period so live connections survive.
- The soak test (`core/internal/engine/soak_test.go`) opens thousands of
  connections and asserts that goroutines return to the baseline and that the
  registry is empty.
- A url-test or fallback group arms its probe loop on the first connection that
  dials through it — TCP or UDP, since a QUIC/DoH-only group is in use just as
  much — not at startup: an imported group nobody uses must not wake the device
  every interval. A dial the engine makes for itself (the outbound self-check,
  a member probe, a UI latency measurement) is marked internal and does not arm
  anything, so "connected and idle" really is zero wakeups. A group the engine
  has stopped — `Stop`, or a reload that replaced it — stays stopped; a
  connection already routed to it cannot resurrect its loop.
- Measured on the device (MatePad Mini, tunnel up and idle for 61 s, no traffic):
  0.00 % of one core across `com.nolanho.kitsune` and its `:vpn` process, two
  log lines. The watchdog ticks every 5 s but only logs when the status actually
  changed, and probes the inbound every 30 s.

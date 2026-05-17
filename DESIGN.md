# tord — design

`tord` is a VPP-native anonymising SOCKS5 proxy for the IMP appliance.
Functionally it is a SOCKS5 server whose egress is Tor circuits, and
whose circuits ride VPP's session layer instead of the kernel
networking stack. Its first consumer is `dnsd` (DoT-over-Tor for the
recursive forwarder); the SOCKS5 interface keeps it usable by any
other daemon later.

Installed binary on the appliance is `imp-tord` (the `imp-` prefix is
an install/systemd convention only — in this repo it is just `tord`,
mirroring `dnsd`).

## 1. Why this exists

dnsd recently gained DoT/DoH *listeners*: clients reach the router's
resolver over an encrypted channel. But dnsd's *upstream* recursion
still egresses over the operator's ISP link, so every resolved name
remains attributable to the subscriber by the ISP.

Routing dnsd's upstream queries through Tor severs that last-mile
linkage. With **DoT-over-Tor**:

| Party | Sees | Does not see |
|---|---|---|
| ISP | "this line speaks Tor" | any query, any resolver |
| Tor entry guard | subscriber IP, that they use Tor | query content / destination |
| Tor exit | encrypted TLS to `<resolver>:853` | query content |
| Upstream resolver | the queries | the subscriber's IP |

Queries are decoupled from identity. Honest residual exposure: the
upstream resolver still sees query *content* (pick a no-log resolver,
rotate), and the ISP learns the line runs Tor.

## 2. Why a separate daemon (not embedded in dnsd)

- **Shared service.** A SOCKS5 front door is reusable by any daemon;
  embedding in dnsd would make it dnsd-private.
- **Dependency isolation.** arti's dependency tree is large; keeping it
  in its own repo with its own pinned SHA bounds the blast radius and
  keeps dnsd's build lean.
- **Crash/resource isolation.** Tor circuit churn, directory refresh,
  and relay crypto are best-effort background work; DNS resolution is
  critical-path. A fault in arti must not take DNS down.
- **Cleaner threading.** arti gets its own process pinned to its own
  VCL worker-0 thread — no contention with dnsd's single VCL worker.

The cost is one inter-process hop, carried over VCL (§5) so no kernel
sockets are reintroduced.

## 3. The hard constraint: Tor carries TCP only

Tor has no UDP transport. dnsd's normal upstream path is UDP-first.
The Tor path therefore **forces TCP**, and the only good shape is
SOCKS5 `CONNECT` to a DoT (or DoH) resolver — TLS-inside-the-tunnel so
the Tor exit sees only ciphertext.

Rejected: Tor's built-in `DNSPort`. Its `RESOLVE`/`RESOLVE_PTR` SOCKS
extension only does A/AAAA/PTR — no DNSSEC RRs, no MX/TXT/SRV — and the
exit sees cleartext DNS.

## 4. Architecture

```
            ┌──────────────────── dataplane netns ───────────────────────┐
  dnsd      │  ┌────────┐  SOCKS5/VCL   ┌──────────────────────────────┐  │
forwarder ──┼─►│  dnsd  │──────────────►│            tord               │  │
 via: tor   │  └────────┘  (VPP session │  SOCKS5 server (VclListener)   │  │
            │               layer)     │  arti TorClient                │  │
            │                          │  VclNetProvider (NetStream-    │  │
            │                          │    Provider<SocketAddr>)        │  │
            │                          └───────────────┬────────────────┘  │
            │                         VclStream per OR-connection           │
            │                                          ▼                    │
            │                                  VPP session layer ───────────┼─► WAN ─► Tor
            └─────────────────────────────────────────────────────────────────┘
```

No path touches the kernel networking stack. dnsd→tord is a VPP
cut-through/local session; tord→Tor relays are VCL streams.

## 5. The dnsd↔tord interface: SOCKS5 over VCL

tord runs a **SOCKS5 server bound on a `vcl_rs::VclListener`** at a
loopback address inside the dataplane (default `127.0.0.1:9050`,
configurable). dnsd reaches it with `VclStream::connect` — both ends on
the VPP session layer.

SOCKS5 (RFC 1928) is chosen over a bespoke RPC because it is the
universal "proxy my TCP" contract and makes tord reusable for free.
tord implements the `CONNECT` command only; `BIND`/`UDP ASSOCIATE` are
rejected with reply `0x07` (command not supported). Auth: `NO AUTH`
plus optional username/password (RFC 1929) — the username is **not**
used for access control but as the **circuit-isolation token** (§7).

The dnsd side (a SOCKS5 *client* + a per-server `transport: dot`,
`via: tor` forwarder option) is a separate change in the `dnsd` repo
and is out of scope for this repo.

## 6. The VCL NetStreamProvider — the crux

`arti-client` is generic over `tor_rtcompat::Runtime`. We do not fork
arti; we implement one trait and compose a runtime.

`runtime/vcl_net.rs` provides `VclNetProvider`, an implementation of
`tor_rtcompat::NetStreamProvider<std::net::SocketAddr>`:

- `connect(&self, addr)` → opens a `VclStream` via
  `VclStream::connect_async`, wraps it so it satisfies the trait's
  associated `Stream` bounds.
- `listen(&self, _)` → returns `ErrorKind::Unsupported`. A Tor *client*
  never accepts OR connections; only relays listen.

Two adapter problems, both known and bounded:

1. **AsyncRead/AsyncWrite flavor.** `NetStreamProvider::Stream` requires
   the **`futures::io`** flavor; `VclStream` implements the **`tokio::io`**
   flavor. Bridge with `tokio_util::compat::Compat` (`.compat()`).
2. **`StreamOps`.** The `Stream` associated type also requires
   `tor_rtcompat::StreamOps` (socket-option hooks such as TCP_NODELAY).
   VCL exposes a narrower knob set; the impl returns
   `Unsupported`/no-op where VCL has no equivalent. Exact surface to be
   pinned against arti at the version in `Cargo.toml` — see §12.

No DNS resolver is needed in the provider: Tor relays and directory
authorities are IP-addressed in the consensus, and `connect`/`listen`
take `&SocketAddr` precisely to avoid lookups.

## 7. Runtime composition

arti runs on a `CompoundRuntime` assembled in `runtime/mod.rs`:

- task executor + `spawn` → tokio
- `SleepProvider` / `CoarseTimeProvider` → tokio
- `NetStreamProvider<SocketAddr>` (TCP) → **`VclNetProvider`**
- `NetStreamProvider<unix>` → unsupported stub
- UDP provider → unsupported stub (Tor is TCP-only anyway)
- `TlsProvider` → rustls (arti's link TLS runs *over* our VCL stream)

**Threading.** VCL sessions are thread-owned: a session must only be
operated from the OS thread that registered its VCL worker context
(cross-thread → `EBADFD`). tord therefore runs arti on a
**single-threaded (current-thread) tokio runtime** on the thread that
called `VclApp::init` (VCL worker-0). This matches how dnsd already
confines its upstream I/O. arti is comfortable current-thread; client
crypto is light, and as its own process tord has the thread to itself.

`kernel-sockets` build (§11): skip `VclNetProvider` entirely and use
arti's stock `PreferredRuntime` (tokio + kernel sockets) so the daemon
builds and runs on a non-VPP dev machine.

## 8. arti integration

- **State directory** lives under `/persistent/data/tord/` so guard
  selection and the consensus/descriptor cache **persist across
  reboots and image upgrades**. Fresh guards every boot is a privacy
  regression — guards are deliberately sticky.
- **Bootstrap** takes seconds to a minute and needs WAN egress up and a
  roughly-correct clock (consensus validity) — ensure NTP. tord starts
  after `vpp-core`; until `TorClient` reports bootstrapped, SOCKS
  `CONNECT` fails fast (reply `0x01` general failure) so dnsd
  fails closed rather than queueing.
- **Circuit isolation.** The SOCKS username (RFC 1929) is mapped to an
  arti `StreamIsolation` token: distinct usernames → distinct circuits.
  Config exposes `isolation: shared | per-upstream | per-query`.
- **Exit policy.** Port 853 (DoT) is occasionally restricted by exit
  policy; 443 (DoH) is universally allowed. v1 targets DoT; DoH-over-Tor
  is a follow-up if blocked exits are observed in the field.

## 9. Configuration

A top-level `tor:` block in `/persistent/config/router.yaml` (a shared
service, not nested under `dns:`):

```yaml
tor:
  enabled: true
  socks_listen: "127.0.0.1:9050"   # VCL-bound SOCKS5 server
  isolation: per-upstream          # shared | per-upstream | per-query
  state_dir: /persistent/data/tord
  bootstrap_timeout_secs: 120
```

dnsd references it from a forwarder server (dnsd-side schema):

```yaml
dns:
  forwarders:
    - domain: .
      servers:
        - { ip: 9.9.9.9, transport: dot, tls_name: dns.quad9.net, via: tor }
      fail_closed: true
```

SIGHUP re-reads `tor:`. A `socks_listen` change rebinds the listener; a
`state_dir` change is ignored live (logged) — it needs a restart.

## 10. Control socket

`/run/tord.sock`, line-JSON, mirroring `dnsd`'s control protocol.
`tord-query` is the CLI. Commands (v1):

- `status` — bootstrap %/state, uptime, listener address
- `circuits` — open circuit count, age, isolation tokens in use
- `stats` — CONNECT count, success/failure, bytes proxied
- `reload` — SIGHUP-equivalent

## 11. Build & feature flags

Mirrors dnsd:

- `vcl` (default) — SOCKS listener + arti egress on the VPP session
  layer via `vcl-rs`. The production appliance build.
- `kernel-sockets` — no `vcl-rs` link; SOCKS listener on `tokio::net`
  and arti on its stock tokio runtime. For `cargo build`/test on dev
  machines without libvppcom (e.g. macOS).

Exactly one must be enabled (compile_error! guards, as in dnsd's
`io/transport/mod.rs`).

Built by IMP's `build-impd.sh` alongside the other daemons; pinned in
`scripts/external-daemon-versions.txt`; installed as `/usr/local/bin/
imp-tord` + `imp-tord-query`; an impd-supervised child gated on the
`tor:` config section, running in the dataplane netns.

## 12. Phased plan

1. ✅ **Skeleton** — repo, config parse, CLI, single-thread runtime,
   logging, module stubs.
2. ✅ **VclNetProvider** — `NetStreamProvider<SocketAddr>` over
   `VclStream` (backend-generic; `tokio::net::TcpStream` under
   `kernel-sockets`). `StreamOps` no-op, `CompoundRuntime` assembled
   via `RuntimeSubstExt::with_tcp_provider`. Unit-tested against a
   plain TCP echo.
3. ✅ **arti lifecycle** — `TorManager`: bootstrap + persistent state
   dir, `connect()` returning an anonymised stream. (Isolation-token
   wiring still TODO — see §8.)
4. ✅ **SOCKS5 server** — RFC 1928 `CONNECT` over the VCL/TCP
   listener, splice to the arti stream; fail-closed.
5. ✅ **Control socket + tord-query** + metrics. (SIGHUP currently
   logs; live listener rebind still TODO — see §9.)
6. ⏳ **IMP integration** — systemd unit, impd supervisor entry,
   `external-daemon-versions.txt`, install paths; dnsd-side SOCKS
   client + `via: tor` forwarder option (separate `dnsd` change).
7. ⏳ **Hardening** — fail-closed audit (no query may ever bypass Tor),
   bootstrap-not-ready behaviour, exit-policy/DoH fallback, soak test.

**Verification status:** phases 1–5 are `cargo check` + `clippy` +
`test` green on the `kernel-sockets` backend (macOS dev host). Every
`vcl`-feature API call is verified against `vcl-rs` source, but a
`vcl`-feature build against `libvppcom` (build host, Bookworm
container) has not yet been run — that is the first step of phase 6.

## 13. Open questions

- Exact `StreamOps` method surface at the pinned arti version (§6).
- Whether `arti-client` config can be driven entirely in-code or wants
  an on-disk `arti.toml` (prefer in-code from the `tor:` block).
- DoH-over-Tor as a hedge against port-853 exit-policy blocks (§8).
- Whether to extract `VclNetProvider` into a shared crate once a
  second consumer appears (YAGNI until then).

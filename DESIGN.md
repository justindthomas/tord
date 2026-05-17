# tord — design

tord is a VPP-native anonymising SOCKS5 proxy. Functionally it is a
SOCKS5 server whose egress is Tor circuits, and whose circuits ride
VPP's session layer instead of the kernel networking stack. Any TCP
client that can reach a SOCKS5 endpoint can use it.

The motivating consumer is a recursive DNS resolver (DoT-over-Tor for
its upstream queries — see §1), but nothing in tord is DNS-specific:
the SOCKS5 interface keeps it usable by any application.

## 1. Why this exists

A recursive DNS resolver can terminate encrypted DNS (DoT/DoH) from its
clients, so queries reach the resolver privately — but the resolver's
own *upstream* recursion still egresses over the operator's ISP link,
so every resolved name remains attributable to the subscriber by the
ISP.

Routing those upstream queries through Tor severs that last-mile
linkage. With **DoT-over-Tor**:

| Party | Sees | Does not see |
|---|---|---|
| ISP | "this line speaks Tor" | any query, any resolver |
| Tor entry guard | subscriber IP, that they use Tor | query content / destination |
| Tor exit | encrypted TLS to `<resolver>:853` | query content |
| Upstream resolver | the queries | the subscriber's IP |

Queries are decoupled from identity. The honest residual exposure: the
upstream resolver still sees query *content* (pick a no-log resolver,
rotate), and the ISP learns the line runs Tor.

That is the motivating case. tord itself is a general SOCKS5 proxy —
anything that wants anonymised, VPP-native TCP egress can use it.

## 2. Why a separate daemon (not a library)

tord is built to run as its own process rather than as a crate linked
into a consumer:

- **Shared service.** A SOCKS5 front door is reusable by any client;
  embedding it in one consumer would make it that consumer's private
  code.
- **Dependency isolation.** arti's dependency tree is large; keeping it
  in its own process bounds the blast radius and keeps consumers lean.
- **Crash/resource isolation.** Tor circuit churn, directory refresh
  and relay crypto are best-effort background work. A fault in arti
  must not take a latency-critical consumer (e.g. DNS resolution) down.
- **Cleaner threading.** arti gets its own process pinned to its own
  VCL worker-0 thread — no contention with a consumer's VCL worker.

The cost is one inter-process hop, carried over VCL (§5), so no kernel
sockets are reintroduced.

## 3. The hard constraint: Tor carries TCP only

Tor has no UDP transport. A DNS resolver's upstream path is typically
UDP-first; the Tor path therefore **forces TCP**, and the only good
shape is SOCKS5 `CONNECT` to a DoT (or DoH) resolver — TLS inside the
tunnel, so the Tor exit sees only ciphertext.

Rejected: Tor's built-in `DNSPort`. Its `RESOLVE`/`RESOLVE_PTR` SOCKS
extension only does A/AAAA/PTR — no DNSSEC RRs, no MX/TXT/SRV — and the
exit sees cleartext DNS.

This constraint is intrinsic to Tor, not to any one consumer: tord
proxies TCP streams only.

## 4. Architecture

```
            ┌──────────────────── VPP host ───────────────────────────┐
 SOCKS5     │  ┌────────┐  SOCKS5/VCL   ┌──────────────────────────┐   │
 client ────┼─►│ client │──────────────►│            tord           │   │
            │  └────────┘  (VPP session │  SOCKS5 server (VclListener)│  │
            │               layer)     │  arti TorClient            │   │
            │                          │  VclNetProvider (NetStream-│   │
            │                          │    Provider<SocketAddr>)   │   │
            │                          └───────────────┬────────────┘   │
            │                         VclStream per OR-connection        │
            │                                          ▼                 │
            │                                  VPP session layer ────────┼─► WAN ─► Tor
            └──────────────────────────────────────────────────────────────┘
```

No path touches the kernel networking stack. The client→tord hop is a
VPP cut-through/local session; tord→Tor relays are VCL streams.

## 5. The client↔tord interface: SOCKS5

tord runs a **SOCKS5 server (RFC 1928, `CONNECT` only)** on a
`vcl_rs::VclListener`. SOCKS5 is chosen over a bespoke RPC because it
is the universal "proxy my TCP" contract — it makes tord reusable by
anything that speaks SOCKS5, not by one consumer.

`BIND` / `UDP ASSOCIATE` are rejected with reply `0x07` (Tor has no
UDP transport; a client never needs `BIND`). Auth: `NO AUTH` plus
optional username/password (RFC 1929) — the username is **not** an
access credential, it is the **circuit-isolation token** (§8).
Domain-name targets (`ATYP 0x03`) are passed to arti **unresolved**,
so the Tor exit does the lookup — a SOCKS5 client configured for
"remote DNS" leaks no name resolution.

Because the listener is a `VclListener`, VPP's session layer
terminates the connection — and that serves **two classes of client**:

**1. Co-located VCL daemons.** Another VCL app (e.g. a DNS resolver
doing DoT-over-Tor) reaches `socks_listen` with `VclStream::connect`;
VPP gives it a cut-through/local session — no NIC, no kernel. This is
the path the motivating DNS use case takes.

**2. Network clients — the LAN SOCKS gateway.** A `VclListener` also
accepts ordinary TCP arriving from the wire (the same way a VPP-native
DNS resolver's DoT listener serves real LAN clients). So with
`socks_listen` set to a **routable address VPP owns** rather than a
loopback, any host that can route to it — a laptop browser, `ssh` via
`ProxyCommand`, `curl --socks5-hostname` — can use tord as a Tor SOCKS
gateway for a whole network segment.

The SOCKS5 *client* — co-located daemon or LAN host — is out of scope
for this repo; tord only provides the server.

### 5.1 Running the LAN SOCKS gateway

To expose tord to LAN clients:

- Set `socks_listen` to a LAN-reachable IP VPP owns (a dataplane
  loopback or interface address), **not** the `127.0.0.1` default.
  The default is loopback precisely so tord is *not* network-exposed
  unless the operator opts in.
- **Gate the port with the host firewall.** An open SOCKS proxy is
  free Tor egress for anyone who can reach it; the firewall must allow
  `socks_listen` only from the intended client prefix(es). Treat an
  ungated SOCKS port as a misconfiguration, not a default.
- Tell clients to use **remote DNS** (`socks5h://` for curl, "Proxy
  DNS when using SOCKS v5" in Firefox) so name resolution also rides
  Tor — tord already passes domain targets through unresolved (above).
- **QUIC / HTTP-3 will not traverse tord** — it is UDP, and Tor is
  TCP-only. Browsers fall back to TCP; `ssh` and plain HTTPS are
  unaffected. This is a Tor limitation, not a tord one.
- Per-client circuit isolation needs the client to present a distinct
  SOCKS username (the isolation token, §8). Browsers rarely expose
  that, so LAN-gateway traffic typically shares circuits per the
  `isolation` policy.

## 6. The VCL NetStreamProvider — the crux

`arti-client` is generic over `tor_rtcompat::Runtime`. tord does not
fork arti; it implements one trait and composes a runtime.

`runtime/net.rs` provides `TordNetProvider`, an implementation of
`tor_rtcompat::NetStreamProvider<std::net::SocketAddr>`:

- `connect(&self, addr)` → opens a `VclStream` via
  `VclStream::connect_async`, wrapped so it satisfies the trait's
  associated `Stream` bounds.
- `listen(&self, _)` → returns `ErrorKind::Unsupported`. A Tor *client*
  never accepts OR connections; only relays listen.

Two adapter concerns, both bounded:

1. **AsyncRead/AsyncWrite flavour.** `NetStreamProvider::Stream`
   requires the **`futures::io`** flavour; `VclStream` implements the
   **`tokio::io`** flavour. Bridge with `tokio_util::compat::Compat`.
2. **`StreamOps`.** The `Stream` associated type also requires
   `tor_rtcompat::StreamOps` (socket-option hooks). VCL exposes no
   equivalent knobs; both `StreamOps` methods have defaults
   (`set_tcp_notsent_lowat` reports unsupported, `new_handle` yields a
   no-op handle), which is the correct behaviour here.

The provider is backend-generic: under `kernel-sockets` the underlying
stream is a `tokio::net::TcpStream`, so the same provider code compiles
and unit-tests on a host without `libvppcom`.

No DNS resolver is needed in the provider: Tor relays and directory
authorities are IP-addressed, and `connect` takes `&SocketAddr`.

## 7. Runtime composition

arti runs on a runtime assembled in `runtime/mod.rs` by swapping the
TCP provider of a stock `TokioRustlsRuntime`
(`RuntimeSubstExt::with_tcp_provider`): tokio keeps the task executor,
timers, coarse clock and OR-link TLS; only TCP egress is replaced by
`TordNetProvider`.

**Threading.** VCL sessions are thread-owned: a session must only be
operated from the OS thread that registered its VCL worker context
(cross-thread → `EBADFD`). tord therefore runs arti on a
**single-threaded (current-thread) tokio runtime** on the thread that
called `VclApp::init` (VCL worker-0), inside a `LocalSet` so each
SOCKS connection handler `spawn_local`s onto that same thread. arti is
comfortable current-thread; client crypto is light, and as its own
process tord has the thread to itself.

The `kernel-sockets` build uses the same `TordNetProvider` over
`tokio::net`, so the daemon builds and runs on a non-VPP dev host.

## 8. arti integration

- **State directory.** arti's guard selection and consensus/descriptor
  cache live in a persistent directory (default `/var/lib/tord`, also
  the deployment can point it elsewhere). It must survive restarts —
  re-picking guards on every start is a privacy regression.
- **Bootstrap** takes seconds to a minute and needs WAN egress up and a
  roughly-correct clock (consensus validity). Until `TorClient` reports
  bootstrapped, SOCKS `CONNECT` fails fast so consumers fail closed
  rather than queueing.
- **Circuit isolation.** The SOCKS username (RFC 1929) is mapped to an
  arti `StreamIsolation` token: distinct usernames → distinct circuits.
  Config exposes `isolation: shared | per-upstream | per-query`.
- **Exit policy.** Port 853 (DoT) is occasionally restricted by exit
  policy; 443 (DoH) is universally allowed. v1 targets DoT; DoH-over-Tor
  is a follow-up if blocked exits are observed.

## 9. Configuration

tord reads a **YAML configuration file** and takes its settings from a
top-level `tor:` mapping. Reading just one mapping means the file may
be tord's own config, or a section of a larger shared config in an
integrated deployment — the config path is set with `--config`.

```yaml
tor:
  enabled: true
  socks_listen: "127.0.0.1:9050"   # loopback = local consumers only;
                                   # a routable IP = LAN gateway (§5.1)
  isolation: per-upstream          # shared | per-upstream | per-query
  state_dir: /var/lib/tord
  bootstrap_timeout_secs: 120
```

SIGHUP re-reads `tor:`. A `socks_listen` change rebinds the listener
(follow-up); a `state_dir` change needs a restart.

## 10. Control socket

`/run/tord.sock`, line-JSON. The `tord query <cmd>` subcommand is the
operator CLI — a subcommand of the daemon binary, not a separate
binary (matching the imp-bgpd / imp-ospfd pattern). Commands (v1):

- `status` — uptime, SOCKS listener address
- `stats` — CONNECT counts, bytes proxied
- `reload` — SIGHUP-equivalent (config re-read)
- `ping` — liveness

`circuits` (per-circuit detail) is a follow-up — arti does not expose a
circuit list through a stable public API yet.

## 11. Build & feature flags

Exactly one transport feature must be enabled (`compile_error!`
guards):

- `vcl` (default) — SOCKS listener + arti egress on the VPP session
  layer via `vcl-rs`; needs `libvppcom`. The deployment build.
- `kernel-sockets` — no `vcl-rs` link; SOCKS listener on `tokio::net`
  and arti's TCP egress over `tokio::net`. For `cargo build`/test on
  dev hosts without `libvppcom` (e.g. macOS).

Building against arti pulls `aws-lc-sys` (the rustls crypto backend),
which needs `cmake` + `nasm`, and `libsqlite3-sys` (arti's state
store); tord depends on the latter directly with the `bundled` feature
so SQLite is compiled in — no system `libsqlite3` to install or ship.

Integrating tord into a host project means: pinning its source,
building it for the target with the `vcl` feature, installing the
`tord` + `tord-query` binaries, supervising it as a process, and
gating it on the `tor:` config block. (For the project tord was first
built for, that wiring lives in that project's build scripts and
service manager.)

## 12. Phased plan

1. ✅ **Skeleton** — repo, config parse, CLI, single-thread runtime,
   logging, module stubs.
2. ✅ **VclNetProvider** — `NetStreamProvider<SocketAddr>` over
   `VclStream` (backend-generic; `tokio::net::TcpStream` under
   `kernel-sockets`). `StreamOps` no-op, runtime assembled via
   `RuntimeSubstExt::with_tcp_provider`. Unit-tested against a plain
   TCP echo.
3. ✅ **arti lifecycle** — `TorManager`: bootstrap + persistent state
   dir, `connect()` returning an anonymised stream. (Isolation-token
   wiring still TODO — see §8.)
4. ✅ **SOCKS5 server** — RFC 1928 `CONNECT` over the VCL/TCP
   listener, splice to the arti stream; fail-closed.
5. ✅ **Control socket + `tord query`** + metrics. (SIGHUP currently
   logs; live listener rebind still TODO — see §9.)
6. ⏳ **Host integration** — pin + build for the target, install the
   binaries, supervise the process, gate on the `tor:` config block;
   plus the consumer-side SOCKS client (e.g. a DNS resolver's
   DoT-over-Tor forwarder option).
7. ⏳ **Hardening** — fail-closed audit (no traffic may ever bypass
   Tor), bootstrap-not-ready behaviour, exit-policy/DoH fallback, soak
   test.

**Verification status:** phases 1–5 are `cargo check` + `clippy` +
`test` green on the `kernel-sockets` backend. The `vcl`-feature build
is verified too: a full `cargo build` in a Debian Bookworm container
links against VPP 25.10 `libvppcom` — every vcl-gated path
(`TordNetProvider`, `connect_async`, `VclListener`) compiles and links,
with SQLite bundled static so the binary's only non-libc dynamic
dependency is `libvppcom.so`. Remaining work is host integration
(phase 6).

## 13. Open questions

- Exact `StreamOps`/`NetStreamProvider` trait surface tracks the arti
  version pinned in `Cargo.toml` — it is not API-frozen; treat arti
  bumps as code changes to `runtime/net.rs`.
- Whether `arti-client` config can be driven entirely in-code or wants
  an on-disk `arti.toml` (prefer in-code from the `tor:` block).
- DoH-over-Tor as a hedge against port-853 exit-policy blocks (§8).

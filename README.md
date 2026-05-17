# tord

A VPP-native anonymising SOCKS5 proxy with Tor egress.

tord is a SOCKS5 server whose egress is **Tor circuits**, and whose
circuits ride **VPP's session layer** (via [`vcl-rs`](https://github.com/justindthomas/vcl-rs))
rather than the kernel networking stack. It embeds
[arti](https://gitlab.torproject.org/tpo/core/arti) and drives it
through a custom `tor_rtcompat` runtime, so no Tor traffic ever touches
a kernel socket.

Any application that can reach a SOCKS5 endpoint gets anonymised,
VPP-native TCP egress — tord is a general-purpose component, not bound
to a single consumer.

## Why VPP-native

On a host built around [VPP](https://fd.io/) (Vector Packet
Processing), application traffic reaches the network through VPP's
userspace session layer, not the kernel stack. A stock Tor client — or
arti with its default runtime — opens kernel sockets and bypasses that
path. tord keeps Tor's circuit egress on the VPP session layer, so it
composes cleanly with a VPP dataplane and adds no dependency on
kernel-side networking.

## Motivating use case

tord was first built to anonymise the upstream traffic of a recursive
DNS resolver: the resolver terminates DoT/DoH from its clients, then
forwards each query (DoT-over-Tor, through tord's SOCKS5 endpoint) to a
public resolver. The operator's ISP sees only Tor traffic; the upstream
resolver sees a Tor exit rather than the subscriber. The SOCKS5
interface is generic, though — any TCP client can use it.

## Status

Early development. See **DESIGN.md** for the architecture and the
phased build plan; **CLAUDE.md** for the load-bearing invariants.

## Build

tord has two transport backends, selected by Cargo feature — exactly
one must be enabled:

- `vcl` (default) — TCP egress on the VPP session layer via `vcl-rs`;
  requires `libvppcom` at build and run time.
- `kernel-sockets` — TCP egress over `tokio::net`, no VPP dependency.
  For development and testing on hosts without VPP.

```sh
# Default (vcl) — needs libvppcom.
cargo build --release

# Dev build on a host without VPP.
cargo build --no-default-features --features kernel-sockets
```

## License

AGPL-3.0-or-later.

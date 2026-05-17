# tord

VPP-native anonymising SOCKS5 proxy for the [IMP](https://github.com/Emerald-Broadband/imp)
appliance.

tord is a SOCKS5 server whose egress is **Tor circuits**, and whose
circuits ride **VPP's session layer** (via [`vcl-rs`](https://github.com/justindthomas/vcl-rs))
instead of the kernel networking stack. It embeds [arti](https://gitlab.torproject.org/tpo/core/arti)
and drives it through a custom `tor_rtcompat` runtime so no Tor
traffic ever touches a kernel socket.

## Why

Its first consumer is `dnsd`. dnsd already terminates DoT/DoH from
LAN clients, but its upstream recursion still egresses over the
operator's ISP link — so resolved names remain attributable to the
subscriber. Pointing dnsd's upstream forwarder at tord
(DoT-over-Tor-over-SOCKS) severs that last-mile linkage: the ISP sees
only Tor traffic, and the upstream resolver sees a Tor exit instead of
the subscriber.

The SOCKS5 interface is generic — any daemon that wants anonymised,
VPP-native TCP egress can use tord, not just dnsd.

## Status

Early scaffolding. See **DESIGN.md** for the architecture and the
phased build plan; **CLAUDE.md** for the load-bearing invariants.

## Build

```sh
# Production (default `vcl` feature — needs libvppcom; built on the
# IMP build host).
cargo build --release

# Dev on a non-VPP host (macOS): arti on its stock tokio runtime.
cargo build --no-default-features --features kernel-sockets
```

## License

AGPL-3.0-or-later.

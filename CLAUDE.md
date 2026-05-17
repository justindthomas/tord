# tord notes

`tord` is a VPP-native anonymising SOCKS5 proxy with Tor egress.
Full design and the phased build plan: **DESIGN.md**. The binary is
`tord`; an integrating project may install it under another name.

## Don't reintroduce kernel sockets

The entire point of this daemon is that arti's circuit egress rides
VPP's session layer via `TordNetProvider` (a custom
`tor_rtcompat::NetStreamProvider`). If an arti API change ever tempts
a switch to arti's default tokio runtime in a `vcl` build — don't.
That silently routes Tor traffic through the kernel networking stack
and defeats the daemon's entire purpose. The `kernel-sockets` feature
exists for dev hosts (no libvppcom) only.

## VCL is thread-owned

arti runs on a **single-threaded** tokio runtime pinned to VCL
worker-0 (the thread that calls `VclApp::init`). Do not move arti onto
a multi-threaded runtime — cross-thread VCL session ops fault /
`EBADFD`.

## arti version pinning

`arti-client` / `tor-rtcompat` track the arti workspace, and the
trait surface this daemon implements (`NetStreamProvider`,
`StreamOps`) is **not** API-frozen — it has churned across releases.
Pin exact versions in `Cargo.toml` and treat every arti bump as a
code change to `runtime/net.rs`.

## Build

Default: `cargo build --release` (`vcl` feature; needs libvppcom,
built for the target platform). Dev on a non-VPP host:
`cargo build --no-default-features --features kernel-sockets`.

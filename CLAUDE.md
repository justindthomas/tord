# tord notes

`tord` is a VPP-native anonymising SOCKS5 proxy with Tor egress.
Full design and the phased build plan: **DESIGN.md**. Installed on the
appliance as `imp-tord` (the `imp-` prefix is an install/systemd
convention only — in this repo the binary is `tord`, mirroring
`dnsd`).

## Don't reintroduce kernel sockets

The entire point of this daemon is that arti's circuit egress rides
VPP's session layer via `VclNetProvider` (a custom
`tor_rtcompat::NetStreamProvider`). If an arti API change ever tempts
a switch to arti's default tokio runtime on the *appliance* build —
don't. That silently routes Tor traffic through linux_cp TAPs and
makes dnsd's resolver path depend on linux_cp, which it otherwise
never touches. The `kernel-sockets` feature exists for dev hosts
(macOS, no libvppcom) only.

## VCL is thread-owned

arti runs on a **single-threaded** tokio runtime pinned to VCL
worker-0 (the thread that calls `VclApp::init`). Do not move arti onto
a multi-threaded runtime — cross-thread VCL session ops fault /
`EBADFD`. Same constraint dnsd documents in its `worker.rs` header.

## arti version pinning

`arti-client` / `tor-rtcompat` track the arti workspace, and the
trait surface this daemon implements (`NetStreamProvider`,
`StreamOps`) is **not** API-frozen — it has churned across releases.
Pin exact versions in `Cargo.toml` and treat every arti bump as a
code change to `runtime/vcl_net.rs`.

## Build

Production: `cargo build --release` (default `vcl` feature; needs
libvppcom — build on the IMP build host via `build-impd.sh`).
Dev on a non-VPP host: `cargo build --no-default-features --features
kernel-sockets`.

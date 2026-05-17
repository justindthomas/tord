//! `VclNetProvider` — a `tor_rtcompat::NetStreamProvider<SocketAddr>`
//! whose TCP streams ride VPP's session layer via `vcl-rs`.
//!
//! This is the crux of tord: it is what makes arti's circuit egress
//! bypass the kernel networking stack. See DESIGN.md §6.
//!
//! Implementation plan (phase 2):
//!
//!   * `connect(&self, &SocketAddr)` — open a `VclStream` via
//!     `VclStream::connect_async`, then wrap it so it satisfies the
//!     `NetStreamProvider::Stream` bounds:
//!       - `AsyncRead + AsyncWrite`: the trait wants the
//!         **`futures::io`** flavour; `VclStream` implements the
//!         **`tokio::io`** flavour. Bridge with
//!         `tokio_util::compat::TokioAsyncReadCompatExt::compat()`.
//!       - `tor_rtcompat::StreamOps`: socket-option hooks. VCL
//!         exposes a narrower knob set than a kernel socket — return
//!         `Unsupported` / no-op where there is no equivalent. The
//!         exact required method set must be pinned against the arti
//!         version in Cargo.toml (DESIGN.md §13).
//!
//!   * `listen(&self, _)` — return `io::ErrorKind::Unsupported`. A
//!     Tor *client* never accepts OR connections; only relays listen.
//!
//!   * No DNS resolver is needed: relays and directory authorities
//!     are IP-addressed, and `connect` takes `&SocketAddr`.
//!
//! The provider must only be driven from the VCL worker-0 thread (the
//! single-threaded runtime in `main.rs`) — see DESIGN.md §7.

// TODO(phase 2): pub struct VclNetProvider { reactor: vcl_rs::VclReactor }
// TODO(phase 2): impl tor_rtcompat::NetStreamProvider<std::net::SocketAddr>
//                for VclNetProvider.

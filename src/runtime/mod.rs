//! Runtime composition.
//!
//! arti is driven through a `tor_rtcompat` runtime assembled from a
//! `CompoundRuntime`: tokio supplies the task executor, timers and
//! coarse clock; `VclNetProvider` supplies TCP streams over VPP's
//! session layer; rustls supplies the OR-link TLS. See DESIGN.md §6–§7.
//!
//! Exactly one transport feature must be enabled:
//!   * `vcl`            — production: arti egress over `vcl-rs`.
//!   * `kernel-sockets` — dev only: arti's stock tokio runtime.

#[cfg(all(feature = "vcl", feature = "kernel-sockets"))]
compile_error!("tord: features `vcl` and `kernel-sockets` are mutually exclusive");

#[cfg(not(any(feature = "vcl", feature = "kernel-sockets")))]
compile_error!("tord: enable exactly one of `vcl` or `kernel-sockets`");

#[cfg(feature = "vcl")]
pub mod vcl_net;

// TODO(phase 2): `pub fn build_runtime(...) -> impl tor_rtcompat::Runtime`
//   * vcl build           → CompoundRuntime(tokio exec/timers + rustls
//                            TLS + VclNetProvider).
//   * kernel-sockets build → tor_rtcompat::PreferredRuntime::create().

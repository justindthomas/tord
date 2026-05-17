//! Runtime composition.
//!
//! arti is driven through a `tor_rtcompat` runtime built by swapping
//! the TCP provider of a stock tokio runtime for `TordNetProvider`
//! (`runtime::net`). tokio still supplies the task executor, timers,
//! coarse clock and OR-link TLS; only TCP egress is replaced. See
//! DESIGN.md §6–§7.
//!
//! Exactly one transport feature must be enabled:
//!   * `vcl`            — production: TCP egress over `vcl-rs`.
//!   * `kernel-sockets` — dev: TCP egress over `tokio::net`.

#[cfg(all(feature = "vcl", feature = "kernel-sockets"))]
compile_error!("tord: features `vcl` and `kernel-sockets` are mutually exclusive");

#[cfg(not(any(feature = "vcl", feature = "kernel-sockets")))]
compile_error!("tord: enable exactly one of `vcl` or `kernel-sockets`");

pub mod net;

use anyhow::{Context, Result};
use tor_rtcompat::{Runtime, RuntimeSubstExt};

/// Build the `tor_rtcompat::Runtime` arti runs on.
///
/// Must be called from within the tokio runtime context (it attaches
/// to the current runtime via `TokioRustlsRuntime::current`), which
/// is also the VCL worker-0 thread — see DESIGN.md §7.
#[cfg(feature = "vcl")]
pub fn build_runtime(reactor: vcl_rs::VclReactor) -> Result<impl Runtime> {
    use tor_rtcompat::tokio::TokioRustlsRuntime;
    let base = TokioRustlsRuntime::current().context("attaching to current tokio runtime")?;
    Ok(base.with_tcp_provider(net::TordNetProvider::new(reactor)))
}

#[cfg(feature = "kernel-sockets")]
pub fn build_runtime() -> Result<impl Runtime> {
    use tor_rtcompat::tokio::TokioRustlsRuntime;
    let base = TokioRustlsRuntime::current().context("attaching to current tokio runtime")?;
    Ok(base.with_tcp_provider(net::TordNetProvider::new()))
}

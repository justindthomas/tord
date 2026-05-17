//! tord entry point.
//!
//! Responsibilities (see DESIGN.md §7, §12):
//!   1. Load the `tor:` section of router.yaml.
//!   2. Build a *current-thread* tokio runtime inside a `LocalSet` —
//!      VCL sessions are thread-owned, so arti, the SOCKS listener
//!      and every connection handler must run on the one thread that
//!      registers VCL worker-0. Hence no `#[tokio::main]`, and
//!      per-connection tasks use `spawn_local`.
//!   3. Bootstrap the Tor client.
//!   4. Serve the SOCKS5 server until SIGTERM.
//!   5. (phase 5) Serve the control socket; SIGHUP reload.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "tord", about = "VPP-native anonymising SOCKS5 proxy (Tor egress)")]
struct Args {
    /// Path to router.yaml — only the `tor:` section is read.
    #[arg(long, default_value = tord::config::DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    /// Control socket path.
    #[arg(long, default_value = tord::control::DEFAULT_SOCKET)]
    control_socket: PathBuf,
}

fn main() -> Result<()> {
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let cfg = match tord::config::load(&args.config)? {
        Some(c) if c.enabled => c,
        Some(_) => {
            tracing::info!("tor: section present but disabled — exiting");
            return Ok(());
        }
        None => {
            tracing::info!("no tor: section in {} — exiting", args.config.display());
            return Ok(());
        }
    };
    tracing::info!(?cfg, "tord starting");

    // VCL worker-0 is registered against *this* thread; the
    // current-thread runtime + LocalSet then run every task on it.
    // See DESIGN.md §7.
    #[cfg(feature = "vcl")]
    let _vcl_app = vcl_rs::VclApp::init("tord").context("initialising VCL")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building current-thread tokio runtime")?;
    let local = tokio::task::LocalSet::new();

    local.block_on(&rt, run(cfg, args.control_socket))
}

async fn run(cfg: tord::config::TorConfig, control_socket: PathBuf) -> Result<()> {
    #[cfg(feature = "vcl")]
    let reactor = vcl_rs::VclReactor::new().context("creating VCL reactor")?;

    #[cfg(feature = "vcl")]
    let runtime = tord::runtime::build_runtime(reactor.clone())?;
    #[cfg(feature = "kernel-sockets")]
    let runtime = tord::runtime::build_runtime()?;

    tracing::info!(state_dir = %cfg.state_dir.display(), "bootstrapping Tor client");
    let tor = Arc::new(
        tord::tor::TorManager::bootstrap(runtime, &cfg)
            .await
            .context("Tor bootstrap")?,
    );
    tracing::info!("Tor client bootstrapped");

    let server = Arc::new(tord::socks::SocksServer::new(cfg.isolation, tor));

    // TODO(phase 5): control socket at `control_socket`; SIGHUP reload.
    let _ = &control_socket;

    #[cfg(feature = "vcl")]
    let socks = server.serve(cfg.socks_listen, reactor);
    #[cfg(feature = "kernel-sockets")]
    let socks = server.serve(cfg.socks_listen);

    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    tokio::select! {
        _ = sigterm.recv() => tracing::info!("SIGTERM received — shutting down"),
        r = socks => match r {
            Ok(()) => tracing::warn!("SOCKS server exited unexpectedly"),
            Err(e) => tracing::error!(error = %e, "SOCKS server failed"),
        },
    }
    Ok(())
}

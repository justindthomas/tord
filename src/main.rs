//! tord entry point.
//!
//! Responsibilities (see DESIGN.md §7, §12):
//!   1. Load the `tor:` section of router.yaml.
//!   2. Build a *current-thread* tokio runtime — VCL sessions are
//!      thread-owned, so arti + the SOCKS listener must run on the
//!      thread that registers VCL worker-0. Hence no `#[tokio::main]`.
//!   3. Bootstrap the Tor client.
//!   4. (phase 4) Bind the SOCKS5 server.
//!   5. (phase 5) Serve the control socket.
//!   Handle SIGTERM (clean shutdown); SIGHUP reload is phase 5.

use std::path::PathBuf;

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
    // current-thread runtime then runs every task (arti included) on
    // it. See DESIGN.md §7.
    #[cfg(feature = "vcl")]
    let _vcl_app = vcl_rs::VclApp::init("tord").context("initialising VCL")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building current-thread tokio runtime")?;

    rt.block_on(run(cfg, args.control_socket))
}

async fn run(cfg: tord::config::TorConfig, control_socket: PathBuf) -> Result<()> {
    #[cfg(feature = "vcl")]
    let runtime = {
        let reactor = vcl_rs::VclReactor::new().context("creating VCL reactor")?;
        tord::runtime::build_runtime(reactor)?
    };
    #[cfg(feature = "kernel-sockets")]
    let runtime = tord::runtime::build_runtime()?;

    tracing::info!(state_dir = %cfg.state_dir.display(), "bootstrapping Tor client");
    let tor = tord::tor::TorManager::bootstrap(runtime, &cfg)
        .await
        .context("Tor bootstrap")?;
    tracing::info!("Tor client bootstrapped");

    // TODO(phase 4): SOCKS5 server bound on cfg.socks_listen, wired to
    //                `tor`. TODO(phase 5): control socket; SIGHUP.
    let _ = (&tor, &control_socket);

    // Stay up until SIGTERM so bootstrap can be observed end-to-end.
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    sigterm.recv().await;
    tracing::info!("SIGTERM received — shutting down");
    Ok(())
}

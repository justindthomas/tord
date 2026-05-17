//! tord entry point.
//!
//! Responsibilities (see DESIGN.md §7, §12):
//!   1. Load the `tor:` section of router.yaml.
//!   2. Build a *current-thread* tokio runtime — VCL sessions are
//!      thread-owned, so arti + the SOCKS listener must run on the
//!      thread that registers VCL worker-0. This is why there is no
//!      `#[tokio::main]`.
//!   3. (phase 3) Bootstrap the Tor client.
//!   4. (phase 4) Bind the SOCKS5 server.
//!   5. (phase 5) Serve the control socket; handle SIGTERM/SIGHUP.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
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

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building current-thread tokio runtime")?;

    rt.block_on(run(cfg, args.control_socket))
}

async fn run(cfg: tord::config::TorConfig, control_socket: PathBuf) -> Result<()> {
    // TODO(phase 1): VclApp::init under the `vcl` feature — registers
    //                VCL worker-0 on this thread.
    // TODO(phase 3): tord::tor::TorManager::bootstrap(&cfg).
    // TODO(phase 4): tord::socks server bound on cfg.socks_listen,
    //                wired to the TorManager.
    // TODO(phase 5): control socket at `control_socket`; SIGTERM =
    //                clean shutdown, SIGHUP = reload.
    let _ = (cfg, control_socket);
    anyhow::bail!("tord run loop not yet implemented — see DESIGN.md §12");
}

//! tord entry point.
//!
//! `tord` runs the daemon; `tord query <cmd>` is the operator CLI for
//! the control socket — a subcommand of the same binary, matching the
//! imp-bgpd / imp-ospfd pattern (no separate query binary).
//!
//! Daemon responsibilities (see DESIGN.md §7, §12):
//!   1. Load the `tor:` section of the config file.
//!   2. Build a *current-thread* tokio runtime inside a `LocalSet` —
//!      VCL sessions are thread-owned, so arti, the SOCKS listener
//!      and every connection handler must run on the one thread that
//!      registers VCL worker-0. Hence no `#[tokio::main]`, and
//!      per-connection tasks use `spawn_local`.
//!   3. Build the Tor client; bootstrap runs on a background task.
//!   4. Serve the SOCKS5 server + control socket until SIGTERM.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::signal::unix::{signal, SignalKind};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "tord", about = "VPP-native anonymising SOCKS5 proxy (Tor egress)")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to the YAML config file — only the `tor:` section is read.
    #[arg(long, default_value = tord::config::DEFAULT_CONFIG_PATH, global = true)]
    config: PathBuf,

    /// Control socket path.
    #[arg(long, default_value = tord::control::DEFAULT_SOCKET, global = true)]
    control_socket: PathBuf,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Query the running daemon over its control socket and print the
    /// JSON reply.
    Query {
        /// Control command: status, stats, reload, or ping.
        #[arg(default_value = "status")]
        command: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // `tord query …` — a plain synchronous control-socket round-trip.
    // No logging subscriber, no runtime, no VCL.
    if let Some(Command::Query { command }) = &cli.command {
        let reply = tord::control::query(&cli.control_socket, command)
            .with_context(|| format!("querying tord at {}", cli.control_socket.display()))?;
        print!("{reply}");
        return Ok(());
    }

    // Otherwise: run the daemon.
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = match tord::config::load(&cli.config)? {
        Some(c) if c.enabled => c,
        Some(_) => {
            tracing::info!("tor: section present but disabled — exiting");
            return Ok(());
        }
        None => {
            tracing::info!("no tor: section in {} — exiting", cli.config.display());
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

    local.block_on(&rt, run(cfg, cli.control_socket))
}

async fn run(cfg: tord::config::TorConfig, control_socket: PathBuf) -> Result<()> {
    use std::time::{Duration, Instant};

    #[cfg(feature = "vcl")]
    let reactor = vcl_rs::VclReactor::new().context("creating VCL reactor")?;

    #[cfg(feature = "vcl")]
    let runtime =
        tord::runtime::build_runtime(reactor.clone(), cfg.source_v4, cfg.source_v6)?;
    #[cfg(feature = "kernel-sockets")]
    let runtime = tord::runtime::build_runtime()?;

    // Build the Tor client without blocking on bootstrap, then drive
    // bootstrap on a background task — the control + SOCKS sockets
    // must come up even while Tor is still bootstrapping (or failing
    // to), so the daemon stays observable and killable.
    let tor = Arc::new(tord::tor::TorManager::new(runtime, &cfg).context("Tor client")?);
    {
        let tor = tor.clone();
        let timeout = Duration::from_secs(cfg.bootstrap_timeout_secs);
        tracing::info!(state_dir = %cfg.state_dir.display(), "bootstrapping Tor client");
        tokio::task::spawn_local(async move {
            match tor.bootstrap(timeout).await {
                Ok(()) => tracing::info!("Tor client bootstrapped"),
                Err(e) => tracing::error!(
                    error = %e,
                    "Tor bootstrap failed — SOCKS CONNECTs fail closed until it recovers"
                ),
            }
        });
    }

    let metrics = Arc::new(tord::metrics::Metrics::default());
    let server = Arc::new(tord::socks::SocksServer::new(
        cfg.isolation,
        tor,
        metrics.clone(),
    ));
    let control_state = Arc::new(tord::control::ControlState {
        started: Instant::now(),
        socks_listen: cfg.socks_listen,
        metrics,
    });

    // SIGHUP: live reconfigure. Re-binding listeners on a config
    // change is a follow-up — for now the request is logged. See
    // DESIGN.md §9.
    let mut sighup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;
    tokio::task::spawn_local(async move {
        while sighup.recv().await.is_some() {
            tracing::info!("SIGHUP — live reconfigure is a follow-up (see DESIGN.md §9)");
        }
    });

    #[cfg(feature = "vcl")]
    let socks = server.serve(cfg.socks_listen, reactor);
    #[cfg(feature = "kernel-sockets")]
    let socks = server.serve(cfg.socks_listen);
    let control = tord::control::serve(control_socket, control_state);

    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    tokio::select! {
        _ = sigterm.recv() => tracing::info!("SIGTERM received — shutting down"),
        r = socks => match r {
            Ok(()) => tracing::warn!("SOCKS server exited unexpectedly"),
            Err(e) => tracing::error!(error = %e, "SOCKS server failed"),
        },
        r = control => match r {
            Ok(()) => tracing::warn!("control socket exited unexpectedly"),
            Err(e) => tracing::error!(error = %e, "control socket failed"),
        },
    }
    Ok(())
}

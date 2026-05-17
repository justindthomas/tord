//! Control socket — line-JSON over a Unix socket, mirroring dnsd's
//! control protocol. Queried by `tord-query`. See DESIGN.md §10.
//!
//! Protocol: the client writes one line — a bare command word — and
//! reads one line of JSON back. Commands:
//!   * `status`  — uptime, SOCKS listener address
//!   * `stats`   — the metrics counters
//!   * `reload`  — raise SIGHUP on self (config re-read)
//!   * `ping`    — liveness check
//!
//! `circuits` (per-circuit detail) is a follow-up — arti does not
//! expose a circuit list through a stable public API yet.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::metrics::Metrics;

pub const DEFAULT_SOCKET: &str = "/run/tord.sock";

/// Read-only state the control socket reports on.
pub struct ControlState {
    pub started: Instant,
    pub socks_listen: SocketAddr,
    pub metrics: Arc<Metrics>,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
enum Reply {
    Ok(serde_json::Value),
    Error { message: String },
}

/// Bind the control socket and serve it forever.
pub async fn serve(path: PathBuf, state: Arc<ControlState>) -> Result<()> {
    // A stale socket from a previous run blocks bind(); the daemon
    // owns the path, so removing it is safe.
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)
        .with_context(|| format!("binding control socket {}", path.display()))?;
    tracing::info!(socket = %path.display(), "control socket listening");
    loop {
        let (stream, _) = listener.accept().await.context("control accept")?;
        let state = state.clone();
        tokio::task::spawn_local(async move {
            if let Err(e) = handle(stream, state).await {
                tracing::warn!(error = %e, "control connection failed");
            }
        });
    }
}

async fn handle(stream: UnixStream, state: Arc<ControlState>) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.context("reading command")?;

    let reply = dispatch(line.trim(), &state);
    let mut json = serde_json::to_string(&reply).context("encoding reply")?;
    json.push('\n');
    reader
        .into_inner()
        .write_all(json.as_bytes())
        .await
        .context("writing reply")?;
    Ok(())
}

fn dispatch(cmd: &str, state: &ControlState) -> Reply {
    match cmd {
        "ping" => Reply::Ok(serde_json::json!({ "pong": true })),
        "status" => Reply::Ok(serde_json::json!({
            "uptime_secs": state.started.elapsed().as_secs(),
            "socks_listen": state.socks_listen.to_string(),
        })),
        "stats" => match serde_json::to_value(state.metrics.snapshot()) {
            Ok(v) => Reply::Ok(v),
            Err(e) => Reply::Error { message: e.to_string() },
        },
        "reload" => match nix::sys::signal::raise(nix::sys::signal::Signal::SIGHUP) {
            Ok(()) => Reply::Ok(serde_json::json!({ "reload": "signalled" })),
            Err(e) => Reply::Error { message: format!("raise SIGHUP: {e}") },
        },
        other => Reply::Error {
            message: format!("unknown command {other:?}"),
        },
    }
}

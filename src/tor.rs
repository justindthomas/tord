//! `TorManager` — arti `TorClient` lifecycle. See DESIGN.md §8.
//!
//! Phase 3 scope: build + bootstrap a `TorClient` on the runtime from
//! `runtime::build_runtime`, with the state directory pointed at
//! persistent storage so guard selection survives reboots.
//!
//! Still TODO: circuit-isolation token mapping from the SOCKS
//! username (DESIGN.md §8), and a readiness probe so SOCKS CONNECTs
//! can fail closed while bootstrap is still in flight.

use anyhow::{Context, Result};
use arti_client::config::CfgPath;
use arti_client::{DataStream, IntoTorAddr, TorClient, TorClientConfig};
use tor_rtcompat::Runtime;

use crate::config::TorConfig;

/// Owns the bootstrapped Tor client. Generic over the runtime so the
/// opaque `impl Runtime` from `runtime::build_runtime` can flow
/// straight through.
pub struct TorManager<R: Runtime> {
    client: TorClient<R>,
}

impl<R: Runtime> TorManager<R> {
    /// Build the arti client on `runtime` and bootstrap it onto the
    /// Tor network. Blocks until the client is usable or the attempt
    /// fails.
    pub async fn bootstrap(runtime: R, cfg: &TorConfig) -> Result<Self> {
        let arti_cfg = build_arti_config(cfg)?;
        let client = TorClient::with_runtime(runtime)
            .config(arti_cfg)
            .create_bootstrapped()
            .await
            .context("bootstrapping the Tor client")?;
        Ok(Self { client })
    }

    /// Open an anonymised stream to `target`. Accepts anything arti
    /// treats as an address — notably `(&str, u16)`, where the host
    /// may be a domain that the Tor *exit* resolves. Resolving the
    /// name locally would leak the lookup, so we never do.
    pub async fn connect<A: IntoTorAddr>(&self, target: A) -> Result<DataStream> {
        self.client
            .connect(target)
            .await
            .context("opening anonymised Tor stream")
    }
}

/// Translate the `tor:` config block into an arti `TorClientConfig`.
///
/// The state and cache directories live under `cfg.state_dir` so
/// guard selection and the consensus cache persist across restarts —
/// re-picking guards on every start is a privacy regression
/// (DESIGN.md §8).
fn build_arti_config(cfg: &TorConfig) -> Result<TorClientConfig> {
    let mut builder = TorClientConfig::builder();
    builder
        .storage()
        .state_dir(CfgPath::new_literal(cfg.state_dir.join("state")))
        .cache_dir(CfgPath::new_literal(cfg.state_dir.join("cache")));
    builder.build().context("building arti TorClientConfig")
}

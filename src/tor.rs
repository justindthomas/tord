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
use arti_client::{DataStream, TorClient, TorClientConfig};
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

    /// Open an anonymised stream to `target` (`"host:port"`). The
    /// hostname is resolved by the Tor exit, never locally — resolving
    /// here would leak the lookup.
    pub async fn connect(&self, target: &str) -> Result<DataStream> {
        self.client
            .connect(target)
            .await
            .with_context(|| format!("opening anonymised stream to {target}"))
    }
}

/// Translate the `tor:` config block into an arti `TorClientConfig`.
///
/// The state and cache directories live under `cfg.state_dir`
/// (`/persistent/data/tord`) so guard selection and the consensus
/// cache persist across reboots and image upgrades — re-picking
/// guards every boot is a privacy regression (DESIGN.md §8).
fn build_arti_config(cfg: &TorConfig) -> Result<TorClientConfig> {
    let mut builder = TorClientConfig::builder();
    builder
        .storage()
        .state_dir(CfgPath::new_literal(cfg.state_dir.join("state")))
        .cache_dir(CfgPath::new_literal(cfg.state_dir.join("cache")));
    builder.build().context("building arti TorClientConfig")
}

//! `TorManager` — arti `TorClient` lifecycle. See DESIGN.md §8.
//!
//! The client is built *unbootstrapped* and bootstraps in the
//! background (`OnDemand`), so `main` can bring the control + SOCKS
//! sockets up immediately — a slow or failing bootstrap must not
//! leave the daemon unobservable. The state directory is pointed at
//! persistent storage so guard selection survives restarts.
//!
//! Still TODO: circuit-isolation token mapping from the SOCKS
//! username (DESIGN.md §8).

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use arti_client::config::CfgPath;
use arti_client::{BootstrapBehavior, DataStream, IntoTorAddr, TorClient, TorClientConfig};
use tor_rtcompat::Runtime;

use crate::config::TorConfig;

/// Owns the Tor client. Generic over the runtime so the opaque
/// `impl Runtime` from `runtime::build_runtime` flows straight
/// through.
pub struct TorManager<R: Runtime> {
    client: TorClient<R>,
}

impl<R: Runtime> TorManager<R> {
    /// Build the Tor client *without* blocking on bootstrap. Created
    /// `OnDemand`, so it bootstraps lazily on the first `connect()`;
    /// `bootstrap()` can also drive it eagerly. Returning immediately
    /// lets `main` bring the control + SOCKS sockets up while Tor is
    /// still bootstrapping.
    pub fn new(runtime: R, cfg: &TorConfig) -> Result<Self> {
        let arti_cfg = build_arti_config(cfg)?;
        let client = TorClient::with_runtime(runtime)
            .config(arti_cfg)
            .bootstrap_behavior(BootstrapBehavior::OnDemand)
            .create_unbootstrapped()
            .context("building the Tor client")?;
        Ok(Self { client })
    }

    /// Drive bootstrap to completion, bounded by `timeout`. Meant to
    /// run as a background task; `connect()`s arriving before it
    /// finishes bootstrap on demand.
    pub async fn bootstrap(&self, timeout: Duration) -> Result<()> {
        tokio::time::timeout(timeout, self.client.bootstrap())
            .await
            .map_err(|_| anyhow!("Tor bootstrap did not finish within {timeout:?}"))?
            .context("Tor bootstrap")
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

//! `TorManager` — arti `TorClient` lifecycle. See DESIGN.md §8.
//!
//! The client is built *unbootstrapped* and bootstraps in the
//! background (`OnDemand`), so `main` can bring the control + SOCKS
//! sockets up immediately — a slow or failing bootstrap must not
//! leave the daemon unobservable. The state directory is pointed at
//! persistent storage so guard selection survives restarts.
//!
//! Circuit isolation (DESIGN.md §8): the SOCKS username (RFC 1929) is
//! mapped to an arti `IsolationToken` per the configured `Isolation`
//! mode. Streams carrying the same token may share circuits; streams
//! with different tokens get separate circuit families.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use arti_client::config::CfgPath;
use arti_client::{
    BootstrapBehavior, DataStream, IntoTorAddr, IsolationToken, StreamPrefs, TorClient,
    TorClientConfig,
};
use serde::Serialize;
use tor_rtcompat::Runtime;

use crate::config::{Isolation, TorConfig};

/// Owns the Tor client. Generic over the runtime so the opaque
/// `impl Runtime` from `runtime::build_runtime` flows straight
/// through.
pub struct TorManager<R: Runtime> {
    client: TorClient<R>,
    /// Configured circuit-isolation policy.
    isolation: Isolation,
    /// Process-stable token shared by every stream in `Shared` mode,
    /// and used as the default (no-username) token in `PerUpstream`.
    default_token: IsolationToken,
    /// Username → token map for `PerUpstream`: same username always
    /// resolves to the same token for the process lifetime, so its
    /// streams share circuits. Unused in `Shared` / `PerQuery`.
    per_upstream: Mutex<HashMap<String, IsolationToken>>,
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
        Ok(Self {
            client,
            isolation: cfg.isolation,
            default_token: IsolationToken::new(),
            per_upstream: Mutex::new(HashMap::new()),
        })
    }

    /// Resolve the `IsolationToken` for a stream, given the SOCKS
    /// username (the RFC 1929 `iso_user`) and the configured policy:
    ///
    /// * `Shared` — always the one `default_token`; every stream
    ///   shares circuits.
    /// * `PerUpstream` — a token keyed by `user`. The same username
    ///   always maps to the same token (held in `per_upstream`), so
    ///   its streams share circuits while different usernames get
    ///   separate circuit families. No username ⇒ `default_token`.
    /// * `PerQuery` — a fresh unique token every call; every stream
    ///   is isolated.
    fn isolation_token(&self, user: Option<&str>) -> IsolationToken {
        match self.isolation {
            Isolation::Shared => self.default_token,
            Isolation::PerQuery => IsolationToken::new(),
            Isolation::PerUpstream => match user {
                None => self.default_token,
                Some(u) => {
                    let mut map = self
                        .per_upstream
                        .lock()
                        .expect("per_upstream isolation map poisoned");
                    *map.entry(u.to_owned())
                        .or_insert_with(IsolationToken::new)
                }
            },
        }
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
    ///
    /// `iso_user` is the SOCKS RFC 1929 username (if any); it drives
    /// circuit isolation per the configured `Isolation` mode — see
    /// [`Self::isolation_token`].
    pub async fn connect<A: IntoTorAddr>(
        &self,
        target: A,
        iso_user: Option<&str>,
    ) -> Result<DataStream> {
        let mut prefs = StreamPrefs::new();
        prefs.set_isolation(self.isolation_token(iso_user));
        self.client
            .connect_with_prefs(target, &prefs)
            .await
            .context("opening anonymised Tor stream")
    }

    /// The configured circuit-isolation policy — for logging.
    pub fn isolation(&self) -> Isolation {
        self.isolation
    }

    /// Snapshot arti's current bootstrap status. Cheap (a lock plus
    /// a small clone) — safe to poll on a timer.
    pub fn bootstrap_status(&self) -> BootstrapSnapshot {
        let s = self.client.bootstrap_status();
        BootstrapSnapshot {
            ready: s.ready_for_traffic(),
            fraction: s.as_frac(),
            blocked: s.blocked().map(|b| b.message().to_string()),
        }
    }
}

/// Live Tor bootstrap state, shared (`Arc`) between the task that
/// polls it and the control socket that reports it. Kept non-generic
/// so `control::ControlState` need not carry the runtime type
/// parameter.
#[derive(Default)]
pub struct BootstrapState {
    ready: AtomicBool,
    /// Bootstrap progress in per-mille (0..=1000).
    frac_permille: AtomicU32,
    blocked: Mutex<Option<String>>,
}

/// Serialisable view of `BootstrapState`, also returned directly by
/// `TorManager::bootstrap_status`.
#[derive(Serialize, Clone)]
pub struct BootstrapSnapshot {
    /// True once Tor can carry traffic.
    pub ready: bool,
    /// Bootstrap progress, 0.0..=1.0.
    pub fraction: f32,
    /// Human-readable reason bootstrap is stalled, if any.
    pub blocked: Option<String>,
}

impl BootstrapState {
    /// Overwrite the stored state with a fresh reading.
    pub fn store(&self, snap: &BootstrapSnapshot) {
        self.ready.store(snap.ready, Ordering::Relaxed);
        self.frac_permille.store(
            (snap.fraction.clamp(0.0, 1.0) * 1000.0) as u32,
            Ordering::Relaxed,
        );
        *self.blocked.lock().unwrap() = snap.blocked.clone();
    }

    /// Read the stored state back out for reporting.
    pub fn snapshot(&self) -> BootstrapSnapshot {
        BootstrapSnapshot {
            ready: self.ready.load(Ordering::Relaxed),
            fraction: self.frac_permille.load(Ordering::Relaxed) as f32 / 1000.0,
            blocked: self.blocked.lock().unwrap().clone(),
        }
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

//! `TorManager` — arti `TorClient` lifecycle. See DESIGN.md §8.
//!
//! Responsibilities (phase 3):
//!
//!   * Build a `TorClient` on the `CompoundRuntime` from
//!     `runtime::build_runtime` (tokio executor + `VclNetProvider`
//!     egress + rustls).
//!   * Point arti's state directory at `cfg.state_dir`
//!     (`/persistent/data/tord`) so guard selection and the
//!     consensus/descriptor cache persist across reboots and image
//!     upgrades — fresh guards every boot is a privacy regression.
//!   * Bootstrap with a `cfg.bootstrap_timeout_secs` deadline; expose
//!     a readiness flag so SOCKS CONNECTs fail fast (fail-closed)
//!     until the client is up.
//!   * Map a SOCKS username to an arti `StreamIsolation` token per
//!     `cfg.isolation` (shared / per-upstream / per-query).
//!   * `connect(host, port, isolation_token)` — open an anonymised
//!     stream the SOCKS server splices client traffic onto.
//!
//! arti config is built in-code from the `tor:` block; tord does not
//! read an `arti.toml` (DESIGN.md §13).

// TODO(phase 3): pub struct TorManager { ... }
// TODO(phase 3): impl TorManager { async fn bootstrap(cfg) -> Result<Self>; ... }

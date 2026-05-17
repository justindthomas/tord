//! Control socket — line-JSON over a Unix socket, mirroring dnsd's
//! control protocol. Queried by `tord-query`. See DESIGN.md §10.
//!
//! Commands (phase 5):
//!   * `status`   — bootstrap state/percent, uptime, listener address
//!   * `circuits` — open circuit count, age, isolation tokens in use
//!   * `stats`    — CONNECT count, success/failure, bytes proxied
//!   * `reload`   — SIGHUP-equivalent reconfigure

pub const DEFAULT_SOCKET: &str = "/run/tord.sock";

// TODO(phase 5): pub struct ControlServer { ... } + line-JSON dispatch.

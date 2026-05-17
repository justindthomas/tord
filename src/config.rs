//! tord configuration — the `tor:` section of router.yaml.
//!
//! tord reads only its own section; every other key in router.yaml is
//! ignored. See DESIGN.md §9.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

pub const DEFAULT_CONFIG_PATH: &str = "/persistent/config/router.yaml";
pub const DEFAULT_SOCKS_LISTEN: &str = "127.0.0.1:9050";
pub const DEFAULT_STATE_DIR: &str = "/persistent/data/tord";
pub const DEFAULT_BOOTSTRAP_TIMEOUT_SECS: u64 = 120;

/// Circuit-isolation policy. The SOCKS username (RFC 1929) is mapped
/// to an arti `StreamIsolation` token per this setting — see
/// DESIGN.md §8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Isolation {
    /// All proxied streams share circuits.
    Shared,
    /// One circuit set per distinct SOCKS username (e.g. per upstream
    /// resolver). The default.
    #[default]
    PerUpstream,
    /// A fresh circuit per CONNECT — maximum unlinkability, highest
    /// latency.
    PerQuery,
}

/// The `tor:` block.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TorConfig {
    /// Master switch. When false (or the section is absent) tord
    /// exits cleanly — impd's supervisor gates the daemon on this.
    pub enabled: bool,
    /// Address the SOCKS5 server binds (on a VclListener under the
    /// `vcl` feature). dnsd connects here.
    pub socks_listen: SocketAddr,
    /// Circuit-isolation policy.
    pub isolation: Isolation,
    /// arti state directory — guard selection + consensus cache.
    /// Must be on persistent storage so guards survive reboots.
    pub state_dir: PathBuf,
    /// How long to wait for the Tor client to bootstrap before
    /// CONNECTs start failing fast (fail-closed).
    pub bootstrap_timeout_secs: u64,
}

impl Default for TorConfig {
    fn default() -> Self {
        TorConfig {
            enabled: false,
            socks_listen: DEFAULT_SOCKS_LISTEN
                .parse()
                .expect("DEFAULT_SOCKS_LISTEN is a valid SocketAddr"),
            isolation: Isolation::default(),
            state_dir: PathBuf::from(DEFAULT_STATE_DIR),
            bootstrap_timeout_secs: DEFAULT_BOOTSTRAP_TIMEOUT_SECS,
        }
    }
}

/// Just enough of router.yaml to pull out `tor:`. Unknown keys (every
/// other section) are ignored by serde.
#[derive(Deserialize, Default)]
#[serde(default)]
struct RouterYaml {
    tor: Option<TorConfig>,
}

/// Load the `tor:` section from `path`. Returns `Ok(None)` when the
/// file is absent or has no `tor:` block — both mean "nothing to do".
pub fn load(path: &Path) -> Result<Option<TorConfig>> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let doc: RouterYaml = serde_yaml::from_str(&raw)
        .with_context(|| format!("parsing {}", path.display()))?;
    Ok(doc.tor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_section_is_none() {
        let doc: RouterYaml = serde_yaml::from_str("system: {}\n").unwrap();
        assert!(doc.tor.is_none());
    }

    #[test]
    fn defaults_fill_missing_fields() {
        let cfg: TorConfig = serde_yaml::from_str("enabled: true\n").unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.isolation, Isolation::PerUpstream);
        assert_eq!(cfg.bootstrap_timeout_secs, DEFAULT_BOOTSTRAP_TIMEOUT_SECS);
    }

    #[test]
    fn isolation_parses_kebab_case() {
        let cfg: TorConfig =
            serde_yaml::from_str("enabled: true\nisolation: per-query\n").unwrap();
        assert_eq!(cfg.isolation, Isolation::PerQuery);
    }
}

//! Process-wide counters, surfaced over the control socket.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// Atomic counters incremented by the SOCKS server.
#[derive(Default)]
pub struct Metrics {
    pub connects_total: AtomicU64,
    pub connects_ok: AtomicU64,
    pub connects_failed: AtomicU64,
    pub bytes_to_upstream: AtomicU64,
    pub bytes_to_client: AtomicU64,
}

/// A consistent-enough (`Relaxed`) read of every counter, for JSON.
#[derive(Serialize)]
pub struct MetricsSnapshot {
    pub connects_total: u64,
    pub connects_ok: u64,
    pub connects_failed: u64,
    pub bytes_to_upstream: u64,
    pub bytes_to_client: u64,
}

impl Metrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            connects_total: self.connects_total.load(Ordering::Relaxed),
            connects_ok: self.connects_ok.load(Ordering::Relaxed),
            connects_failed: self.connects_failed.load(Ordering::Relaxed),
            bytes_to_upstream: self.bytes_to_upstream.load(Ordering::Relaxed),
            bytes_to_client: self.bytes_to_client.load(Ordering::Relaxed),
        }
    }
}

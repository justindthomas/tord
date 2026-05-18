//! Live registry of in-flight proxied connections.
//!
//! Every SOCKS connection that gets past target parsing is recorded
//! here for the lifetime of the splice, so `tord query streams` can
//! report what is connected through tord and where to. The registry
//! also backs the `streams_active` count in `stats` — that is just
//! the row count.
//!
//! This is *tord's own* view of its connections; it is not Tor
//! circuit detail (relay hops, guards). `arti-client` does not
//! expose a public circuit-enumeration API — see `control.rs`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::Serialize;

/// Per-connection state. The byte counters are bumped in place by
/// the `Metered` adapter as traffic flows.
pub struct StreamEntry {
    pub id: u64,
    pub peer: SocketAddr,
    pub target: String,
    pub isolation: Option<String>,
    pub started: Instant,
    pub to_upstream: AtomicU64,
    pub to_client: AtomicU64,
}

/// Serialisable view of one `StreamEntry`.
#[derive(Serialize)]
pub struct StreamSnapshot {
    pub id: u64,
    pub peer: String,
    pub target: String,
    pub isolation: Option<String>,
    pub age_secs: u64,
    pub bytes_to_upstream: u64,
    pub bytes_to_client: u64,
}

/// Process-wide registry of live proxied connections.
#[derive(Default)]
pub struct StreamRegistry {
    inner: Mutex<HashMap<u64, Arc<StreamEntry>>>,
    next_id: AtomicU64,
}

impl StreamRegistry {
    /// Record a new connection. The returned `StreamHandle` removes
    /// the row when it is dropped — i.e. when the handler returns,
    /// however it returns.
    pub fn register(
        self: &Arc<Self>,
        peer: SocketAddr,
        target: String,
        isolation: Option<String>,
    ) -> StreamHandle {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let entry = Arc::new(StreamEntry {
            id,
            peer,
            target,
            isolation,
            started: Instant::now(),
            to_upstream: AtomicU64::new(0),
            to_client: AtomicU64::new(0),
        });
        self.inner.lock().unwrap().insert(id, entry.clone());
        StreamHandle {
            registry: self.clone(),
            entry,
        }
    }

    /// Number of live connections.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// True when no connection is being proxied.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot every live connection, ordered by id for stable
    /// display.
    pub fn snapshot(&self) -> Vec<StreamSnapshot> {
        let mut rows: Vec<StreamSnapshot> = self
            .inner
            .lock()
            .unwrap()
            .values()
            .map(|e| StreamSnapshot {
                id: e.id,
                // A cut-through (same-VPP app-to-app) client has no
                // IP 5-tuple — VCL reports the unspecified address.
                // Every co-located consumer (e.g. dnsd) lands here;
                // show it as `local` rather than a bogus 0.0.0.0:0.
                peer: if e.peer.ip().is_unspecified() {
                    "local".to_string()
                } else {
                    e.peer.to_string()
                },
                target: e.target.clone(),
                isolation: e.isolation.clone(),
                age_secs: e.started.elapsed().as_secs(),
                bytes_to_upstream: e.to_upstream.load(Ordering::Relaxed),
                bytes_to_client: e.to_client.load(Ordering::Relaxed),
            })
            .collect();
        rows.sort_by_key(|r| r.id);
        rows
    }
}

/// RAII registry row: present while the connection is proxied,
/// removed on `Drop` no matter how the handler task ends.
pub struct StreamHandle {
    registry: Arc<StreamRegistry>,
    entry: Arc<StreamEntry>,
}

impl StreamHandle {
    /// The shared entry — handed to `Metered` so its byte counters
    /// update the row in place.
    pub fn entry(&self) -> Arc<StreamEntry> {
        self.entry.clone()
    }
}

impl Drop for StreamHandle {
    fn drop(&mut self) {
        self.registry.inner.lock().unwrap().remove(&self.entry.id);
    }
}

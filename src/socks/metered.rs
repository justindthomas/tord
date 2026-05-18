//! `Metered` — an `AsyncRead`/`AsyncWrite` adapter that counts bytes
//! as they flow.
//!
//! Wrapping the *client* half of the proxied splice captures both
//! directions: bytes read from the client are bytes bound for the
//! Tor upstream; bytes written to the client are bytes that came
//! back from it. Counting inside the poll methods — rather than from
//! `copy_bidirectional`'s return value — keeps the totals correct
//! even when the copy ends with an error (the return value is lost
//! in that case).
//!
//! Every byte is counted twice over: into the process-wide
//! `Metrics` totals, and into the per-connection `StreamEntry` row.

use std::io;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::metrics::Metrics;
use crate::streams::StreamEntry;

/// Wraps the client stream. Reads count toward `bytes_to_upstream`,
/// writes toward `bytes_to_client`.
pub struct Metered<S> {
    inner: S,
    metrics: Arc<Metrics>,
    entry: Arc<StreamEntry>,
}

impl<S> Metered<S> {
    pub fn new(inner: S, metrics: Arc<Metrics>, entry: Arc<StreamEntry>) -> Self {
        Self {
            inner,
            metrics,
            entry,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let r = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let n = (buf.filled().len() - before) as u64;
            if n > 0 {
                this.metrics.bytes_to_upstream.fetch_add(n, Ordering::Relaxed);
                this.entry.to_upstream.fetch_add(n, Ordering::Relaxed);
            }
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let r = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            let n = *n as u64;
            this.metrics.bytes_to_client.fetch_add(n, Ordering::Relaxed);
            this.entry.to_client.fetch_add(n, Ordering::Relaxed);
        }
        r
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

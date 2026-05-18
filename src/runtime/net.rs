//! `TordNetProvider` — a `tor_rtcompat::NetStreamProvider<SocketAddr>`
//! that hands arti TCP streams which do not touch the kernel network
//! stack. This is the crux of tord. See DESIGN.md §6.
//!
//! The provider is backend-generic:
//!
//!   * `vcl` (production) — the underlying stream is a
//!     `vcl_rs::VclStream`, so arti's circuit egress rides VPP's
//!     session layer.
//!   * `kernel-sockets` (dev) — the underlying stream is a
//!     `tokio::net::TcpStream`. Functionally this is just a stock
//!     TCP socket, but it lets the *exact same provider code* be
//!     compiled and unit-tested on a host without libvppcom.
//!
//! arti's `NetStreamProvider::Stream` wants the `futures::io`
//! flavour of `AsyncRead`/`AsyncWrite`; both `VclStream` and
//! `tokio::net::TcpStream` implement the `tokio::io` flavour, so the
//! inner stream is bridged with `tokio_util::compat::Compat`.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use tor_rtcompat::{NetStreamListener, NetStreamProvider, StreamOps};

/// Connect timeout for a single underlying TCP open. arti applies its
/// own per-hop timeouts on top of this.
const CONNECT_TIMEOUT_SECS: u64 = 10;

// --- backend-selected underlying stream --------------------------------

#[cfg(feature = "vcl")]
type Inner = vcl_rs::VclStream;
#[cfg(feature = "kernel-sockets")]
type Inner = tokio::net::TcpStream;

// --- provider ----------------------------------------------------------

/// TCP-stream provider for arti's `CompoundRuntime`.
#[derive(Clone)]
pub struct TordNetProvider {
    #[cfg(feature = "vcl")]
    reactor: vcl_rs::VclReactor,
    /// Explicit source addresses for outbound connections. VPP's FIB
    /// source-selection can hand a VCL client session an unusable
    /// source, so an explicit WAN address is what makes circuits
    /// actually establish. `None` → let the stack choose.
    #[cfg(feature = "vcl")]
    source_v4: Option<std::net::Ipv4Addr>,
    #[cfg(feature = "vcl")]
    source_v6: Option<std::net::Ipv6Addr>,
}

impl TordNetProvider {
    /// Construct the provider. The `vcl` build needs the VCL reactor
    /// the streams register readiness against, plus the source
    /// addresses outbound connections bind.
    #[cfg(feature = "vcl")]
    pub fn new(
        reactor: vcl_rs::VclReactor,
        source_v4: Option<std::net::Ipv4Addr>,
        source_v6: Option<std::net::Ipv6Addr>,
    ) -> Self {
        Self {
            reactor,
            source_v4,
            source_v6,
        }
    }

    #[cfg(feature = "kernel-sockets")]
    pub fn new() -> Self {
        Self {}
    }

    async fn connect_inner(&self, addr: &SocketAddr) -> io::Result<Inner> {
        #[cfg(feature = "vcl")]
        {
            // Bind an explicit source so VPP's FIB does not hand the
            // session an unusable source address.
            let source = match addr.ip() {
                std::net::IpAddr::V4(_) => {
                    self.source_v4.map(|s| SocketAddr::new(s.into(), 0))
                }
                std::net::IpAddr::V6(_) => {
                    self.source_v6.map(|s| SocketAddr::new(s.into(), 0))
                }
            };
            vcl_rs::VclStream::connect_async(
                *addr,
                source,
                self.reactor.clone(),
                std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS),
            )
            .await
            .map_err(io::Error::other)
        }
        #[cfg(feature = "kernel-sockets")]
        {
            let _ = CONNECT_TIMEOUT_SECS;
            tokio::net::TcpStream::connect(addr).await
        }
    }
}

#[cfg(feature = "kernel-sockets")]
impl Default for TordNetProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NetStreamProvider<SocketAddr> for TordNetProvider {
    type Stream = TordStream;
    type Listener = TordListener;

    async fn connect(&self, addr: &SocketAddr) -> io::Result<TordStream> {
        let inner = self.connect_inner(addr).await?;
        Ok(TordStream {
            inner: inner.compat(),
        })
    }

    async fn listen(&self, _addr: &SocketAddr) -> io::Result<TordListener> {
        // A Tor *client* never accepts OR connections — only relays
        // listen. arti-client never calls this for client use, so an
        // error here is correct rather than load-bearing.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tord: inbound listening is not supported (Tor client only)",
        ))
    }
}

// --- stream ------------------------------------------------------------

/// arti's `NetStreamProvider::Stream`. A newtype over `Compat<Inner>`
/// is required (rather than using `Compat` directly) so we can
/// implement `tor_rtcompat::StreamOps` — the orphan rule forbids
/// implementing a foreign trait on a foreign type.
pub struct TordStream {
    inner: Compat<Inner>,
}

impl AsyncRead for TordStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TordStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

// VCL exposes none of the kernel TCP socket-option knobs `StreamOps`
// abstracts (TCP_NOTSENT_LOWAT etc.). Both trait methods have
// defaults — `set_tcp_notsent_lowat` reports unsupported, `new_handle`
// yields a no-op handle — which is exactly the correct behaviour here.
impl StreamOps for TordStream {}

// --- listener stub -----------------------------------------------------

/// `NetStreamProvider::Listener` is a required associated type, but
/// `listen()` always errors (client-only), so this type is never
/// constructed. An empty enum satisfies the trait bounds with no
/// reachable code.
pub enum TordListener {}

impl NetStreamListener<SocketAddr> for TordListener {
    type Stream = TordStream;
    type Incoming = futures::stream::Empty<io::Result<(TordStream, SocketAddr)>>;

    fn incoming(self) -> Self::Incoming {
        match self {}
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        match *self {}
    }
}

#[cfg(all(test, feature = "kernel-sockets"))]
mod tests {
    use super::*;
    use futures::io::{AsyncReadExt, AsyncWriteExt};

    // DESIGN.md §12 phase 2: the provider is unit-testable against a
    // plain TCP echo with no VPP in the picture.
    #[tokio::test]
    async fn connect_and_echo() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut b = [0u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut s, &mut b)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut s, &b)
                .await
                .unwrap();
        });

        let provider = TordNetProvider::new();
        let mut stream = provider.connect(&addr).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut out = [0u8; 4];
        stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"ping");
    }
}

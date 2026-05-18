//! SOCKS5 server (RFC 1928) — the client-facing front door. See
//! DESIGN.md §5.
//!
//! Scope: the `CONNECT` command only. `BIND` / `UDP ASSOCIATE` are
//! rejected (Tor has no UDP transport and a client never needs
//! BIND). Auth: `NO AUTH` and username/password (RFC 1929) — the
//! username is *not* an access credential, it is the circuit-
//! isolation token (DESIGN.md §8); any credentials are accepted.
//!
//! Fail-closed: if the Tor client cannot open the stream, the client
//! gets a SOCKS general-failure reply — never a direct fallback.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tor_rtcompat::Runtime;

use crate::metrics::Metrics;
use crate::socks::metered::Metered;
use crate::streams::StreamRegistry;
use crate::tor::TorManager;

const SOCKS5: u8 = 0x05;
const METHOD_NOAUTH: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_NONE: u8 = 0xff;
const AUTH_USERPASS_VER: u8 = 0x01;
const CMD_CONNECT: u8 = 0x01;
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// The SOCKS5 server. Cloneable via `Arc`; one is shared across all
/// accepted connections.
pub struct SocksServer<R: Runtime> {
    tor: Arc<TorManager<R>>,
    metrics: Arc<Metrics>,
    streams: Arc<StreamRegistry>,
}

impl<R: Runtime> SocksServer<R> {
    /// The circuit-isolation policy now lives in `TorManager` (it
    /// owns the username→token map), so it is no longer a field
    /// here — the username is read off each connection and handed
    /// straight to `TorManager::connect`.
    pub fn new(
        tor: Arc<TorManager<R>>,
        metrics: Arc<Metrics>,
        streams: Arc<StreamRegistry>,
    ) -> Self {
        Self {
            tor,
            metrics,
            streams,
        }
    }

    /// Accept loop. Binds `listen` and serves forever; each accepted
    /// connection is handled on its own `spawn_local` task (local,
    /// not `spawn`, because VCL sessions are thread-owned — see
    /// DESIGN.md §7).
    #[cfg(feature = "vcl")]
    pub async fn serve(
        self: Arc<Self>,
        listen: SocketAddr,
        reactor: vcl_rs::VclReactor,
    ) -> Result<()> {
        let listener = vcl_rs::VclListener::bind(listen, reactor)
            .map_err(|e| anyhow::anyhow!("binding SOCKS listener on {listen}: {e}"))?;
        tracing::info!(%listen, isolation = ?self.tor.isolation(), "SOCKS5 server listening");
        loop {
            match listener.accept().await {
                Ok((client, peer)) => self.clone().spawn_connection(client, peer),
                // A failed accept is per-connection and transient —
                // e.g. ECONNABORTED, when a client gives up before
                // we accept it (common under a burst). It must never
                // kill the server: log, briefly back off so a
                // persistent error can't spin the CPU, keep going.
                Err(e) => {
                    tracing::warn!(error = %e, "SOCKS accept failed; continuing");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    #[cfg(feature = "kernel-sockets")]
    pub async fn serve(self: Arc<Self>, listen: SocketAddr) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding SOCKS listener on {listen}"))?;
        tracing::info!(%listen, isolation = ?self.tor.isolation(), "SOCKS5 server listening");
        loop {
            match listener.accept().await {
                Ok((client, peer)) => self.clone().spawn_connection(client, peer),
                // See the `vcl` variant: a per-connection accept
                // error must not kill the server.
                Err(e) => {
                    tracing::warn!(error = %e, "SOCKS accept failed; continuing");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    fn spawn_connection<S>(self: Arc<Self>, client: S, peer: SocketAddr)
    where
        S: AsyncRead + AsyncWrite + Unpin + 'static,
    {
        tokio::task::spawn_local(async move {
            if let Err(e) = self.handle(client, peer).await {
                tracing::warn!(%peer, error = %e, "SOCKS connection failed");
            }
        });
    }

    async fn handle<S>(&self, mut client: S, peer: SocketAddr) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + 'static,
    {
        // --- method negotiation (RFC 1928 §3) ---
        let mut greeting = [0u8; 2];
        client
            .read_exact(&mut greeting)
            .await
            .context("reading SOCKS greeting")?;
        if greeting[0] != SOCKS5 {
            bail!("not a SOCKS5 client (version {})", greeting[0]);
        }
        let mut methods = vec![0u8; greeting[1] as usize];
        client
            .read_exact(&mut methods)
            .await
            .context("reading SOCKS auth methods")?;

        // The username (if user/pass is offered) is the circuit-
        // isolation token: it is handed to `TorManager::connect`,
        // which maps it to an arti `IsolationToken` per the
        // configured `Isolation` mode — see DESIGN.md §8.
        let mut iso_user: Option<String> = None;
        if methods.contains(&METHOD_USERPASS) {
            client.write_all(&[SOCKS5, METHOD_USERPASS]).await?;
            iso_user = Some(read_userpass(&mut client).await?);
            client.write_all(&[AUTH_USERPASS_VER, REP_SUCCESS]).await?;
        } else if methods.contains(&METHOD_NOAUTH) {
            client.write_all(&[SOCKS5, METHOD_NOAUTH]).await?;
        } else {
            client.write_all(&[SOCKS5, METHOD_NONE]).await?;
            bail!("client offered no acceptable SOCKS auth method");
        }

        // --- connect request (RFC 1928 §4) ---
        let mut req = [0u8; 4];
        client
            .read_exact(&mut req)
            .await
            .context("reading SOCKS request")?;
        if req[0] != SOCKS5 {
            bail!("bad SOCKS request version {}", req[0]);
        }
        if req[1] != CMD_CONNECT {
            send_reply(&mut client, REP_CMD_NOT_SUPPORTED).await?;
            bail!("unsupported SOCKS command {} (only CONNECT)", req[1]);
        }
        let (host, port) = match read_target(&mut client, req[3]).await {
            Ok(t) => t,
            Err(e) => {
                send_reply(&mut client, REP_ATYP_NOT_SUPPORTED).await?;
                return Err(e);
            }
        };

        // --- open the anonymised stream (fail closed) ---
        let target = format!("{host}:{port}");
        tracing::debug!(%peer, %target, isolation_user = ?iso_user, "SOCKS CONNECT");
        self.metrics.connects_total.fetch_add(1, Ordering::Relaxed);
        // Register the connection so `tord query streams` can see it;
        // the handle removes the row when this function returns,
        // however it returns.
        let stream = self.streams.register(peer, target, iso_user.clone());
        let mut upstream = match self
            .tor
            .connect((host.as_str(), port), iso_user.as_deref())
            .await
        {
            Ok(s) => s,
            Err(e) => {
                self.metrics.connects_failed.fetch_add(1, Ordering::Relaxed);
                send_reply(&mut client, REP_GENERAL_FAILURE).await?;
                return Err(e.context("Tor CONNECT failed — failing closed"));
            }
        };
        send_reply(&mut client, REP_SUCCESS).await?;
        self.metrics.connects_ok.fetch_add(1, Ordering::Relaxed);

        // --- splice client <-> Tor circuit ---
        // `Metered` counts bytes as they flow — into the process
        // totals and the per-connection row — so the counts are right
        // even when the copy ends with an error (`copy_bidirectional`
        // discards its return value in that case).
        let mut client = Metered::new(client, self.metrics.clone(), stream.entry());
        tokio::io::copy_bidirectional(&mut client, &mut upstream)
            .await
            .context("proxying SOCKS stream")?;
        Ok(())
    }
}

/// Read an RFC 1929 username/password sub-negotiation. Any
/// credentials are accepted; only the username is returned (it is the
/// isolation token, not a secret).
async fn read_userpass<S>(client: &mut S) -> Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut ver = [0u8; 1];
    client
        .read_exact(&mut ver)
        .await
        .context("reading RFC1929 auth version")?;
    if ver[0] != AUTH_USERPASS_VER {
        bail!("bad RFC1929 auth version {}", ver[0]);
    }
    let mut ulen = [0u8; 1];
    client.read_exact(&mut ulen).await?;
    let mut uname = vec![0u8; ulen[0] as usize];
    client.read_exact(&mut uname).await?;
    let mut plen = [0u8; 1];
    client.read_exact(&mut plen).await?;
    let mut _passwd = vec![0u8; plen[0] as usize];
    client.read_exact(&mut _passwd).await?;
    String::from_utf8(uname).context("SOCKS username is not UTF-8")
}

/// Read the request's destination address + port. Domain names are
/// returned verbatim — never resolved here (the Tor exit resolves
/// them, so resolving locally would leak the lookup).
async fn read_target<S>(client: &mut S, atyp: u8) -> Result<(String, u16)>
where
    S: AsyncRead + Unpin,
{
    let host = match atyp {
        ATYP_IPV4 => {
            let mut a = [0u8; 4];
            client.read_exact(&mut a).await?;
            Ipv4Addr::from(a).to_string()
        }
        ATYP_IPV6 => {
            let mut a = [0u8; 16];
            client.read_exact(&mut a).await?;
            Ipv6Addr::from(a).to_string()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            client.read_exact(&mut name).await?;
            String::from_utf8(name).context("SOCKS domain name is not UTF-8")?
        }
        other => bail!("unsupported SOCKS address type {other}"),
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port).await?;
    Ok((host, u16::from_be_bytes(port)))
}

/// Send a SOCKS5 reply. The bound address is reported as `0.0.0.0:0`
/// — tord has no meaningful bound address to advertise.
async fn send_reply<S>(client: &mut S, rep: u8) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    client
        .write_all(&[SOCKS5, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await
}

//! SOCKS5 server implementation. See DESIGN.md §5.
//!
//! Scope (phase 4):
//!
//!   * RFC 1928 handshake. Auth methods: `NO AUTH` (0x00) and
//!     username/password (RFC 1929, 0x02). The username is **not**
//!     an access-control credential — it is the circuit-isolation
//!     token (DESIGN.md §8); any username is accepted.
//!   * `CONNECT` (0x01) only. `BIND` and `UDP ASSOCIATE` are
//!     rejected with reply 0x07 (command not supported) — Tor has no
//!     UDP transport and a client never needs BIND.
//!   * Address types: IPv4 (0x01), IPv6 (0x04), domain name (0x03).
//!     Domain names are passed to arti unresolved so the exit does
//!     the lookup — never resolve locally (that would leak).
//!   * On CONNECT: ask `TorManager::connect` for an anonymised
//!     stream, send the SOCKS success reply, then splice bidirectionally
//!     until either side closes.
//!   * Fail-closed: if the Tor client is not bootstrapped, reply
//!     0x01 (general failure) immediately — never fall back to a
//!     direct connection.
//!
//! Listener: `VclListener` under `vcl`, `tokio::net::TcpListener`
//! under `kernel-sockets`.

// TODO(phase 4): pub async fn serve(listen: SocketAddr, tor: TorManager) -> Result<()>

//! SOCKS5 server (RFC 1928) — the dnsd↔tord front door.
//!
//! See DESIGN.md §5. The server binds on a `vcl_rs::VclListener`
//! (under the `vcl` feature) so dnsd reaches it over the VPP session
//! layer with no kernel sockets in the path.

pub mod server;

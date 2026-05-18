//! tord — VPP-native anonymising SOCKS5 proxy with Tor egress.
//!
//! tord is a SOCKS5 server whose egress is Tor circuits, and whose
//! circuits ride VPP's session layer (via `vcl-rs`) instead of the
//! kernel networking stack. Any TCP client that can reach a SOCKS5
//! endpoint can use it; the motivating consumer is a recursive DNS
//! resolver doing DoT-over-Tor for its upstream queries.
//!
//! See DESIGN.md for the full design and the phased build plan.

pub mod config;
pub mod control;
pub mod format;
pub mod metrics;
pub mod runtime;
pub mod socks;
pub mod streams;
pub mod tor;

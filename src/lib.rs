//! tord — VPP-native anonymising SOCKS5 proxy with Tor egress.
//!
//! tord is a SOCKS5 server whose egress is Tor circuits, and whose
//! circuits ride VPP's session layer (via `vcl-rs`) instead of the
//! kernel networking stack. Its first consumer is `dnsd`
//! (DoT-over-Tor for the recursive forwarder).
//!
//! See DESIGN.md for the full design and the phased build plan.

pub mod config;
pub mod control;
pub mod runtime;
pub mod socks;
pub mod tor;

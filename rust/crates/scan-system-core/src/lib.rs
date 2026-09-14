//! Platform-independent logic ported from `scanner_windows.py`: scoring, text matching,
//! network/rate formatting, datetime parsing, startup-entry fingerprinting.
//!
//! Deliberately excludes anything touching the registry, PowerShell/Defender, or the
//! network (threat feed fetch) — those need a real Windows machine and land in
//! `scan-system-platform`/`scan-system-sysmon` (phase 2 of the Rust migration). This
//! crate is the part of the Python original that already had unit tests
//! (`tests/test_scoring.py`, 37 cases) with zero Windows dependency — ported 1:1, same
//! test names/assertions, verifiable without Windows.

mod net;
mod scoring;
mod startup;
mod text;
mod time;

pub use net::{
    build_threat_feed_ip_set, format_rate, is_public_ipv4, ThreatFeed, ThreatFeedsRefresh,
};
pub use scoring::{suspicious_score, NetworkAuditSummary, ScoreInputs, ScoreResult};
pub use startup::{startup_fingerprint, StartupEntry};
pub use text::looks_suspicious_text;
pub use time::parse_any_datetime;

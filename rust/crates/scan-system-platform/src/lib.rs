//! Windows-only integrations ported from `scanner_windows.py`: registry, Defender
//! (PowerShell), firewall, `tracert`, cancellable hidden-window process execution.
//!
//! This whole crate is `cfg(windows)` — unlike the Python original, which kept a
//! defensive `winreg = None`/`try: import psutil` fallback for import-time safety on
//! non-Windows, `scanner_windows.py`'s own `main()` refuses to run on anything but
//! Windows (`platform.system().lower() != "windows"`), so there is no real
//! cross-platform contract to preserve here — this crate simply doesn't exist as a
//! compilation target anywhere else.
#![cfg(windows)]

mod defender;
mod events;
mod firewall;
mod network;
mod process;
mod registry;

pub use defender::{
    common_scan_paths, defender_full_scan, defender_offline_scan, defender_quick_scan,
    defender_remove_threats, defender_signature_update, defender_status, defender_targeted_scan,
    defender_threat_detections, DefenderActionResult, DefenderResult, PathScanResult,
};
pub use events::{recent_installs, recent_persistence_events, RecentInstall};
pub use firewall::{block_remote_ip, ensure_app_firewall_rule};
pub use network::trace_remote_ip;
pub use process::{decode_oem, AuditHandle, HiddenCommandOutput, PowerShellOutput, ProcessError};
pub use registry::{
    detect_windows_theme, is_startup_monitoring_enabled, iter_uninstall_registry,
    set_startup_monitoring_enabled, startup_run_entries, UninstallEntry,
};

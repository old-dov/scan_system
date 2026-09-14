//! `tracert` — ported from `trace_remote_ip` in `scanner_windows.py`.

use std::{process::Command, time::Duration};

use crate::process::{AuditHandle, HiddenCommandOutput, ProcessError};

/// Runs `tracert -d <remote_ip>` (`-d`: skip DNS reverse lookups, same as the Python
/// original — a trace is for path/latency, not hostnames).
///
/// # Errors
///
/// Only [`ProcessError::Cancelled`] propagates.
pub fn trace_remote_ip(
    handle: &AuditHandle,
    remote_ip: &str,
) -> Result<HiddenCommandOutput, ProcessError> {
    let mut command = Command::new("tracert");
    command.args(["-d", remote_ip]);
    handle.run_hidden_command(command, Duration::from_secs(180))
}

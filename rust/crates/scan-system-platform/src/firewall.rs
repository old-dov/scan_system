//! `netsh advfirewall` rule management — ported from `block_remote_ip`/
//! `ensure_app_firewall_rule` in `scanner_windows.py`.

use std::{path::Path, process::Command, time::Duration};

use crate::process::{AuditHandle, HiddenCommandOutput, ProcessError};

fn combine(first: HiddenCommandOutput, second: HiddenCommandOutput) -> HiddenCommandOutput {
    let ok = first.ok && second.ok;
    HiddenCommandOutput {
        ok,
        stdout: [first.stdout, second.stdout]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        stderr: [first.stderr, second.stderr]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        return_code: if !second.ok {
            second.return_code
        } else {
            first.return_code
        },
    }
}

/// Adds a pair of `netsh advfirewall` rules (in + out) blocking every connection to
/// `remote_ip` for this machine. Rule names are derived from the IP
/// (`ScanSystem_Block_{IN,OUT}_1_2_3_4`) so a repeat block of the same IP updates
/// rather than duplicates.
///
/// # Errors
///
/// Only [`ProcessError::Cancelled`] — every `netsh` failure is folded into `ok: false`
/// on the returned [`HiddenCommandOutput`].
pub fn block_remote_ip(
    handle: &AuditHandle,
    remote_ip: &str,
) -> Result<HiddenCommandOutput, ProcessError> {
    let safe_name = remote_ip.replace('.', "_");
    let rule_out = format!("ScanSystem_Block_OUT_{safe_name}");
    let rule_in = format!("ScanSystem_Block_IN_{safe_name}");

    let mut cmd_out = Command::new("netsh");
    cmd_out.args([
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &format!("name={rule_out}"),
        "dir=out",
        "action=block",
        &format!("remoteip={remote_ip}"),
        "enable=yes",
    ]);
    let mut cmd_in = Command::new("netsh");
    cmd_in.args([
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &format!("name={rule_in}"),
        "dir=in",
        "action=block",
        &format!("remoteip={remote_ip}"),
        "enable=yes",
    ]);

    let result_out = handle.run_hidden_command(cmd_out, Duration::from_secs(60))?;
    let result_in = handle.run_hidden_command(cmd_in, Duration::from_secs(60))?;
    Ok(combine(result_out, result_in))
}

/// Adds an allow rule (in + out) for `program_path`, used when background monitoring
/// starts so the app itself isn't blocked by a strict firewall profile. `false` with an
/// error when `program_path` doesn't exist — matches the Python original's guard.
///
/// # Errors
///
/// Only [`ProcessError::Cancelled`] propagates.
pub fn ensure_app_firewall_rule(
    handle: &AuditHandle,
    program_path: &str,
) -> Result<HiddenCommandOutput, ProcessError> {
    if program_path.is_empty() || !Path::new(program_path).exists() {
        return Ok(HiddenCommandOutput {
            ok: false,
            stdout: String::new(),
            stderr: "Executable introuvable".to_string(),
            return_code: 1,
        });
    }
    let rule_name = "ScanSystem_BackgroundMonitor";

    let mut cmd_in = Command::new("netsh");
    cmd_in.args([
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &format!("name={rule_name}"),
        "dir=in",
        "action=allow",
        &format!("program={program_path}"),
        "enable=yes",
    ]);
    let mut cmd_out = Command::new("netsh");
    cmd_out.args([
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &format!("name={rule_name}_OUT"),
        "dir=out",
        "action=allow",
        &format!("program={program_path}"),
        "enable=yes",
    ]);

    let result_in = handle.run_hidden_command(cmd_in, Duration::from_secs(60))?;
    let result_out = handle.run_hidden_command(cmd_out, Duration::from_secs(60))?;
    let combined = combine(result_in, result_out);

    // "already exists" is a success outcome for an idempotent "ensure" call, same
    // tolerance the Python original grants via `"Ok." not in out and "exist" not in
    // out.lower()`.
    if !combined.ok
        && !combined.stdout.contains("Ok.")
        && !combined.stdout.to_lowercase().contains("exist")
    {
        return Ok(combined);
    }
    Ok(HiddenCommandOutput {
        ok: true,
        ..combined
    })
}

//! Windows Defender control via PowerShell's `Mp*` cmdlets — ported from
//! `defender_status`/`defender_signature_update`/`defender_quick_scan`/
//! `defender_threat_detections`/`defender_remove_threats`/`defender_full_scan`/
//! `defender_offline_scan`/`defender_targeted_scan`/`common_scan_paths` in
//! `scanner_windows.py`.
//!
//! Every Defender cmdlet result is kept as [`serde_json::Value`] rather than a strongly
//! typed struct — `ConvertTo-Json`'s field set already varies across Windows/Defender
//! versions in the Python original (it was never strongly typed there either), and the
//! only consumers (the JSON report, `suspicious_score`'s counts) need exactly this
//! dynamic shape, not a fixed schema this crate would have to keep re-guessing.

use std::{collections::HashSet, env, path::Path, time::Duration};

use serde_json::Value;

use crate::process::{AuditHandle, ProcessError};

/// Result of a Defender query that returns structured data on success.
#[derive(Debug, Clone)]
pub struct DefenderResult {
    pub ok: bool,
    pub data: Option<Value>,
    pub error: Option<String>,
}

fn ok_json(value: Value) -> DefenderResult {
    DefenderResult {
        ok: true,
        data: Some(value),
        error: None,
    }
}

fn err(message: impl Into<String>) -> DefenderResult {
    DefenderResult {
        ok: false,
        data: None,
        error: Some(message.into()),
    }
}

/// `Get-MpComputerStatus`, the subset of fields the report cares about.
///
/// # Errors
///
/// Only [`ProcessError::Cancelled`] propagates.
pub fn defender_status(handle: &AuditHandle) -> Result<DefenderResult, ProcessError> {
    let script = "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntispywareEnabled,\
        AntivirusEnabled,AntivirusSignatureLastUpdated,AntivirusSignatureVersion,\
        QuickScanAge,FullScanAge,RealTimeProtectionEnabled | ConvertTo-Json -Depth 3";
    let out = handle.run_powershell(script, Duration::from_secs(90))?;
    if !out.ok {
        return Ok(err(out.output));
    }
    Ok(match serde_json::from_str(&out.output) {
        Ok(value) => ok_json(value),
        Err(_) => err("Sortie JSON Defender invalide"),
    })
}

/// `Update-MpSignature`. Unlike every other function here, a JSON parse failure on
/// success is *not* an error — the Python original returns `{"ok": true, "raw": ...}`
/// in that case (an unexpected but non-fatal shape), reflected here as `data: None`
/// with the raw text still recoverable from [`DefenderResult::error`]... except that
/// field is for genuine failures. To keep the success/raw-fallback distinction visible
/// without overloading `error`, this returns the raw string directly as a JSON string
/// value (`Value::String`) rather than `None` — callers checking `.data` still get
/// *something* usable either way.
///
/// # Errors
///
/// Only [`ProcessError::Cancelled`] propagates.
pub fn defender_signature_update(handle: &AuditHandle) -> Result<DefenderResult, ProcessError> {
    let script = "Update-MpSignature; Get-MpComputerStatus | Select AntivirusSignatureVersion,\
        AntivirusSignatureLastUpdated | ConvertTo-Json";
    let out = handle.run_powershell(script, Duration::from_secs(600))?;
    if !out.ok {
        return Ok(err(out.output));
    }
    Ok(match serde_json::from_str(&out.output) {
        Ok(value) => ok_json(value),
        Err(_) => ok_json(Value::String(out.output)),
    })
}

/// A one-shot Defender action (`Start-MpScan`/`Remove-MpThreat`/`Start-MpWDOScan`) whose
/// success value is just a text result, not structured data.
#[derive(Debug, Clone)]
pub struct DefenderActionResult {
    pub ok: bool,
    pub output: String,
}

fn run_action(
    handle: &AuditHandle,
    script: &str,
    timeout: Duration,
) -> Result<DefenderActionResult, ProcessError> {
    let out = handle.run_powershell(script, timeout)?;
    Ok(DefenderActionResult {
        ok: out.ok,
        output: out.output,
    })
}

/// `Start-MpScan -ScanType QuickScan`. Usually blocking until the scan completes; the
/// timeout (1h) is generous rather than tuned, same as the Python original's comment
/// notes ("le delai depend de la machine").
///
/// # Errors
///
/// Only [`ProcessError::Cancelled`] propagates.
pub fn defender_quick_scan(handle: &AuditHandle) -> Result<DefenderActionResult, ProcessError> {
    run_action(
        handle,
        "Start-MpScan -ScanType QuickScan; 'quick_scan_done'",
        Duration::from_secs(3600),
    )
}

/// `Start-MpScan -ScanType FullScan`.
///
/// # Errors
///
/// Only [`ProcessError::Cancelled`] propagates.
pub fn defender_full_scan(handle: &AuditHandle) -> Result<DefenderActionResult, ProcessError> {
    run_action(
        handle,
        "Start-MpScan -ScanType FullScan; 'full_scan_done'",
        Duration::from_secs(7200),
    )
}

/// `Start-MpWDOScan` (Defender Offline) — only *requests* the reboot-into-offline-scan,
/// does not wait for it to run (that happens after a restart, outside this process'
/// lifetime), hence the much shorter timeout than the other scan types.
///
/// # Errors
///
/// Only [`ProcessError::Cancelled`] propagates.
pub fn defender_offline_scan(handle: &AuditHandle) -> Result<DefenderActionResult, ProcessError> {
    run_action(
        handle,
        "Start-MpWDOScan; 'offline_scan_requested'",
        Duration::from_secs(300),
    )
}

/// `Remove-MpThreat` — asks Defender to act on every currently detected threat using
/// its own default remediation for each (matches `Remove-MpThreat`'s own semantics; this
/// crate does not choose per-threat actions).
///
/// # Errors
///
/// Only [`ProcessError::Cancelled`] propagates.
pub fn defender_remove_threats(handle: &AuditHandle) -> Result<DefenderActionResult, ProcessError> {
    run_action(
        handle,
        "Remove-MpThreat; 'threat_cleanup_done'",
        Duration::from_secs(1800),
    )
}

/// `Get-MpThreatDetection`. A command failure or empty output is treated as "no
/// threats", not an error (Defender's own behavior when nothing was ever detected) —
/// only a genuinely malformed JSON body on an otherwise-successful call is an error.
///
/// # Errors
///
/// Only [`ProcessError::Cancelled`] propagates.
pub fn defender_threat_detections(handle: &AuditHandle) -> Result<DefenderResult, ProcessError> {
    let script = "Get-MpThreatDetection | Select-Object InitialDetectionTime,\
        LastThreatStatusChangeTime,ThreatName,Resources,ActionSuccess,\
        CurrentThreatExecutionStatusID | ConvertTo-Json -Depth 6";
    let out = handle.run_powershell(script, Duration::from_secs(90))?;
    if !out.ok || out.output.is_empty() {
        return Ok(ok_json(Value::Array(vec![])));
    }
    Ok(match serde_json::from_str::<Value>(&out.output) {
        Ok(Value::Array(items)) => ok_json(Value::Array(items)),
        Ok(single) => ok_json(Value::Array(vec![single])),
        Err(_) => err("Sortie JSON menaces invalide"),
    })
}

/// One targeted-scan path's outcome.
#[derive(Debug, Clone)]
pub struct PathScanResult {
    pub path: String,
    pub ok: bool,
    pub result: String,
}

/// `Start-MpScan -ScanType CustomScan` over each of `paths`, one PowerShell invocation
/// per path (matches the Python original — Defender's custom scan takes one path at a
/// time). `result` is truncated to the last 1000 characters, same as the original
/// (PowerShell's scan-progress chatter can be long, only the tail matters).
///
/// # Errors
///
/// Only [`ProcessError::Cancelled`] propagates.
pub fn defender_targeted_scan(
    handle: &AuditHandle,
    paths: &[String],
) -> Result<(bool, Vec<PathScanResult>), ProcessError> {
    let mut scanned = Vec::with_capacity(paths.len());
    for path in paths {
        let escaped = path.replace('\'', "''");
        let script =
            format!("Start-MpScan -ScanType CustomScan -ScanPath '{escaped}' ; 'custom_scan_done'");
        let out = handle.run_powershell(&script, Duration::from_secs(3600))?;
        let tail: String = out
            .output
            .chars()
            .rev()
            .take(1000)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        scanned.push(PathScanResult {
            path: path.clone(),
            ok: out.ok,
            result: tail,
        });
    }
    let overall_ok = scanned.iter().all(|item| item.ok);
    Ok((overall_ok, scanned))
}

/// Directories a targeted scan checks by default: temp locations, Downloads, and the
/// Startup folders for both the current user and all users. Deduplicated (a normalized
/// path seen twice, e.g. `%TEMP%` and `%LOCALAPPDATA%\Temp` pointing at the same real
/// directory, is only scanned once) and filtered to paths that actually exist.
#[must_use]
pub fn common_scan_paths() -> Vec<String> {
    let home = dirs_home();
    let candidates = [
        env::var("TEMP").unwrap_or_default(),
        env::var("TMP").unwrap_or_default(),
        home.map(|h| format!("{h}\\Downloads")).unwrap_or_default(),
        join_env("APPDATA", r"Microsoft\Windows\Start Menu\Programs\Startup"),
        join_env(
            "PROGRAMDATA",
            r"Microsoft\Windows\Start Menu\Programs\Startup",
        ),
        join_env("LOCALAPPDATA", "Temp"),
    ];

    let mut seen = HashSet::new();
    let mut paths = Vec::new();
    for value in candidates {
        if value.is_empty() {
            continue;
        }
        let normalized = value.trim_end_matches(['\\', '/']).to_string();
        if !seen.insert(normalized.clone()) {
            continue;
        }
        if Path::new(&normalized).exists() {
            paths.push(normalized);
        }
    }
    paths
}

fn join_env(var: &str, suffix: &str) -> String {
    match env::var(var) {
        Ok(base) if !base.is_empty() => format!("{base}\\{suffix}"),
        _ => String::new(),
    }
}

fn dirs_home() -> Option<String> {
    env::var("USERPROFILE").ok().filter(|v| !v.is_empty())
}

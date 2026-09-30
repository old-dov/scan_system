//! Audit report orchestration, ported from `generate_report` in
//! `scanner_windows.py`. Report keys are kept stable for existing JSON readers.
#![cfg(windows)]

mod realtime;
pub use realtime::RealtimePersistenceMonitor;

use std::{
    env, fs,
    io::{self, Read},
    path::{Path, PathBuf},
    time::Duration,
};

use chrono::Utc;
use scan_system_core::{
    build_threat_feed_ip_set, suspicious_score, NetworkAuditSummary, ScoreInputs, StartupEntry,
    ThreatFeedsRefresh,
};
use scan_system_platform::{
    common_scan_paths, defender_quick_scan, defender_signature_update, defender_status,
    defender_targeted_scan, defender_threat_detections, recent_installs, recent_persistence_events,
    startup_run_entries, AuditHandle, DefenderActionResult, DefenderResult, ProcessError,
};
use scan_system_sysmon::network_audit_snapshot;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy)]
pub struct AuditOptions {
    pub days: i64,
    pub update_signatures: bool,
    pub run_quick_scan: bool,
}

#[derive(Debug)]
pub enum AuditError {
    Process(ProcessError),
    Io(io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Process(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "{error}"),
            Self::Json(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AuditError {}

impl From<ProcessError> for AuditError {
    fn from(error: ProcessError) -> Self {
        Self::Process(error)
    }
}

impl From<io::Error> for AuditError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for AuditError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

const THREAT_FEEDS: &[&str] = &[
    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
];

fn feed_lines(body: &str) -> Vec<String> {
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

/// Refreshes the same two text feeds as Python and writes the same cache file.
/// A failed feed stays in the result with `ok: false`; only cancellation or a
/// cache write error aborts the audit. `-UseBasicParsing` is required on Windows
/// PowerShell 5.1 to avoid interactive page parsing during a headless audit.
pub fn refresh_threat_feeds_cache(
    handle: &AuditHandle,
    output_dir: &Path,
) -> Result<Value, AuditError> {
    fs::create_dir_all(output_dir)?;
    let cache_path = output_dir.join("threat_feeds_cache.json");
    let mut feeds = Vec::new();
    for &url in THREAT_FEEDS {
        check_cancelled(handle)?;
        let script = format!(
            "$ErrorActionPreference = 'Stop'; \
             (Invoke-WebRequest -UseBasicParsing -Uri '{url}' -TimeoutSec 25 \
             -UserAgent 'scan-system/1.0').Content"
        );
        let response = handle.run_powershell(&script, Duration::from_secs(35))?;
        if response.ok {
            let lines = feed_lines(&response.output);
            feeds.push(json!({
                "url": url, "ok": true, "entries": lines.len(),
                "sample": lines.iter().take(20).collect::<Vec<_>>(), "ips": lines,
            }));
        } else {
            feeds.push(json!({
                "url": url, "ok": false, "entries": 0, "error": response.output,
            }));
        }
    }
    let result = json!({
        "updated_at": chrono::Local::now().to_rfc3339(),
        "feeds": feeds,
        "cache_path": cache_path.to_string_lossy(),
    });
    fs::write(&cache_path, serde_json::to_string_pretty(&result)?)?;
    Ok(result)
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            days: 14,
            update_signatures: true,
            run_quick_scan: true,
        }
    }
}

fn defender_json(result: DefenderResult) -> Value {
    if result.ok {
        json!({"ok": true, "data": result.data})
    } else if let Some(Value::String(raw)) = result.data {
        json!({"ok": false, "error": result.error.unwrap_or_default(), "raw": raw})
    } else {
        json!({"ok": false, "error": result.error.unwrap_or_default()})
    }
}

fn signature_update_json(result: DefenderResult) -> Value {
    // Python uses `raw` for a successful but non-JSON signature-update result.
    // The platform crate preserves that text as Value::String in `data`.
    if result.ok {
        if let Some(Value::String(raw)) = result.data {
            json!({"ok": true, "raw": raw})
        } else {
            json!({"ok": true, "data": result.data})
        }
    } else {
        json!({"ok": false, "error": result.error.unwrap_or_default()})
    }
}

fn action_json(result: DefenderActionResult) -> Value {
    if result.ok {
        json!({"ok": true, "result": result.output})
    } else {
        json!({"ok": false, "error": result.output})
    }
}

fn check_cancelled(handle: &AuditHandle) -> Result<(), ProcessError> {
    if handle.is_cancelled() {
        Err(ProcessError::Cancelled)
    } else {
        Ok(())
    }
}

fn step(
    handle: &AuditHandle,
    progress: &mut impl FnMut(&str, u8),
    label: &str,
    percent: u8,
) -> Result<(), ProcessError> {
    check_cancelled(handle)?;
    progress(label, percent);
    Ok(())
}

fn threat_feed_ips(refresh: &Value) -> std::collections::HashSet<String> {
    let parsed: ThreatFeedsRefresh = serde_json::from_value(refresh.clone()).unwrap_or_default();
    build_threat_feed_ip_set(&parsed)
}

fn sha256_file(path: &Path) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    // Windows' default thread stack is commonly 1 MiB. A 1 MiB local buffer
    // can overflow it before the first read; 64 KiB keeps hashing streamed.
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).ok()?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

/// Mirrors Python's quoted/unquoted leading drive-path extraction. Arguments
/// after the first whitespace are never interpreted as part of an unquoted path.
fn command_executable(command: &str) -> Option<&Path> {
    let path = if let Some(rest) = command.strip_prefix('"') {
        rest.split_once('"')?.0
    } else {
        command.split_whitespace().next()?
    };
    let bytes = path.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return None;
    }
    Some(Path::new(path))
}

fn startup_folder_entries(variable: &str, suffix: &str) -> Vec<Value> {
    let Ok(root) = env::var(variable) else {
        return Vec::new();
    };
    let directory = Path::new(&root).join(suffix);
    let Ok(items) = fs::read_dir(&directory) else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    for item in items.flatten() {
        let Ok(metadata) = item.metadata() else {
            continue;
        };
        let modified = metadata.modified().ok().map(|time| {
            let timestamp: chrono::DateTime<chrono::Local> = time.into();
            timestamp.format("%Y-%m-%dT%H:%M:%S%.f").to_string()
        });
        entries.push(json!({
            "source": directory.to_string_lossy(),
            "name": item.file_name().to_string_lossy(),
            "command": item.path().to_string_lossy(),
            "modified": modified,
        }));
    }
    entries
}

/// Registry Run entries plus both Windows Startup folders, in the same shape
/// as the Python report. Hashing is best effort, just as `sha256_file` was.
#[must_use]
pub fn startup_entries() -> Vec<Value> {
    let mut entries: Vec<Value> = startup_run_entries()
        .into_iter()
        .map(
            |StartupEntry {
                 source,
                 name,
                 command,
             }| { json!({"source": source, "name": name, "command": command}) },
        )
        .collect();
    entries.extend(startup_folder_entries(
        "APPDATA",
        r"Microsoft\Windows\Start Menu\Programs\Startup",
    ));
    entries.extend(startup_folder_entries(
        "PROGRAMDATA",
        r"Microsoft\Windows\Start Menu\Programs\StartUp",
    ));
    for entry in &mut entries {
        let Some(command) = entry.get("command").and_then(Value::as_str) else {
            continue;
        };
        let Some(path) = command_executable(command) else {
            continue;
        };
        if path.is_file() {
            entry["sha256"] = json!(sha256_file(path));
        }
    }
    entries
}

/// Builds the same top-level report as Python's `generate_report`.
/// With an output directory, refreshes and caches threat feeds at the same
/// point in the audit as Python. `None` keeps offline smoke runs possible.
///
/// `run_quick_scan` also runs the targeted scan, matching the Python option.
/// Cancellation propagates through the current PowerShell child and between
/// steps. As in Python, a cancellation after the last step does not discard an
/// already-complete report.
pub fn generate_report(
    handle: &AuditHandle,
    options: AuditOptions,
    output_dir: Option<&Path>,
    mut progress: impl FnMut(&str, u8),
) -> Result<Value, AuditError> {
    let mut report = json!({
        "generated_at_utc": Utc::now().to_rfc3339(),
        "host": {
            "hostname": sysinfo::System::host_name().unwrap_or_default(),
            "os": format!("Windows {}", sysinfo::System::os_version().unwrap_or_default()),
            "python": "Rust migration",
        },
        "parameters": {
            "days": options.days,
            "update_signatures": options.update_signatures,
            "run_quick_scan": options.run_quick_scan,
        },
    });

    step(handle, &mut progress, "Etat Defender...", 5)?;
    report["defender_status"] = defender_json(defender_status(handle)?);
    if options.update_signatures {
        step(
            handle,
            &mut progress,
            "Mise a jour des signatures Defender...",
            15,
        )?;
        report["defender_signature_update"] =
            signature_update_json(defender_signature_update(handle)?);
    }
    if options.run_quick_scan {
        step(handle, &mut progress, "Scan rapide Defender...", 40)?;
        report["defender_quick_scan"] = action_json(defender_quick_scan(handle)?);
        step(handle, &mut progress, "Scan cible Defender...", 70)?;
        let (ok, paths) = defender_targeted_scan(handle, &common_scan_paths())?;
        report["defender_targeted_scan"] = json!({
            "ok": ok,
            "paths": paths.into_iter().map(|path| json!({
                "path": path.path, "ok": path.ok, "result": path.result
            })).collect::<Vec<_>>()
        });
    }

    step(handle, &mut progress, "Menaces detectees...", 80)?;
    report["defender_threat_detections"] = defender_json(defender_threat_detections(handle)?);
    step(handle, &mut progress, "Installations recentes...", 83)?;
    let (installs, install_error) = recent_installs(handle, options.days)?;
    report["recent_installs_collection"] = match install_error {
        Some(error) => json!({"ok": false, "error": error}),
        None => json!({"ok": true}),
    };
    report["recent_installs"] = json!(installs);
    step(handle, &mut progress, "Services et taches recents...", 87)?;
    let (tasks, services) = match recent_persistence_events(handle, options.days, None) {
        Ok(events) => {
            report["persistence_collection"] = json!({"ok": true});
            events
        }
        Err(ProcessError::Cancelled) => return Err(ProcessError::Cancelled.into()),
        Err(error) => {
            report["persistence_collection"] = json!({"ok": false, "error": error.to_string()});
            (Vec::new(), Vec::new())
        }
    };
    report["recent_service_installs"] = json!(services);
    report["recent_task_registrations"] = json!(tasks);

    step(
        handle,
        &mut progress,
        "Mise a jour des flux de menaces...",
        92,
    )?;
    let refresh = if let Some(directory) = output_dir {
        refresh_threat_feeds_cache(handle, directory)?
    } else {
        json!({"feeds": [], "note": "output_dir non fourni"})
    };
    report["threat_feeds_refresh"] = refresh.clone();
    step(handle, &mut progress, "Audit reseau...", 95)?;
    report["network_audit"] = json!(network_audit_snapshot(&threat_feed_ips(&refresh)));
    step(handle, &mut progress, "Entrees de demarrage...", 98)?;
    report["startup_entries"] = json!(startup_entries());
    report["risk"] = risk_from_report(&report);
    progress("Termine", 100);
    Ok(report)
}

/// Reuses the already-ported pure scoring rules against the assembled report.
#[must_use]
pub fn risk_from_report(report: &Value) -> Value {
    let count = |key: &str| -> usize {
        report
            .get(key)
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    };
    let network = &report["network_audit"];
    let threat_matches = network["connections"].as_array().map_or(0, |connections| {
        connections
            .iter()
            .filter(|conn| conn["threat_feed_match"] == true)
            .count()
    });
    let anomalies = network["anomalies"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let inputs = ScoreInputs {
        defender_threats_count: report["defender_threat_detections"]["data"]
            .as_array()
            .map_or(0, |items| {
                items
                    .iter()
                    .filter(|item| defender_detection_needs_attention(item))
                    .count()
            }),
        recent_installs_count: count("recent_installs"),
        recent_service_installs_count: count("recent_service_installs"),
        recent_task_registrations_count: count("recent_task_registrations"),
        network_audit: NetworkAuditSummary {
            connection_threat_matches: threat_matches,
            anomalies,
        },
    };
    let risk = suspicious_score(&inputs);
    json!({"risk_score_100": risk.risk_score_100, "reasons": risk.reasons})
}

/// Whether every requested Defender step and threat feed completed successfully.
/// The score remains available on partial audits, but must not be presented as
/// a complete assessment when one of its inputs could not be collected.
#[must_use]
pub fn audit_is_complete(report: &Value) -> bool {
    if report["persistence_collection"]["ok"] == false
        || report["recent_installs_collection"]["ok"] == false
    {
        return false;
    }
    if report["defender_status"]["ok"] != true || report["defender_threat_detections"]["ok"] != true
    {
        return false;
    }
    if report["parameters"]["update_signatures"] == true
        && report["defender_signature_update"]["ok"] != true
    {
        return false;
    }
    if report["parameters"]["run_quick_scan"] == true
        && (report["defender_quick_scan"]["ok"] != true
            || report["defender_targeted_scan"]["ok"] != true)
    {
        return false;
    }
    report["threat_feeds_refresh"]["feeds"]
        .as_array()
        .is_none_or(|feeds| feeds.iter().all(|feed| feed["ok"] == true))
}

/// Whether a Defender history entry has not been confirmed handled.
#[must_use]
pub fn defender_detection_needs_attention(item: &Value) -> bool {
    // Defender returns historical detections too. Only a successful action
    // together with Blocked (1) or NotExecuting (4) is safe to exclude.
    item["ActionSuccess"] != true
        || !matches!(item["CurrentThreatExecutionStatusID"].as_i64(), Some(1 | 4))
}

fn display(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn rows<'a>(report: &'a Value, key: &str) -> &'a [Value] {
    report[key].as_array().map_or(&[], Vec::as_slice)
}

/// Human-readable companion to the JSON report. Section headings and the
/// fields used by the Python TXT report are preserved for existing readers.
#[must_use]
pub fn render_txt_report(report: &Value) -> String {
    let mut lines = vec![
        "=== RAPPORT SCAN SECURITE WINDOWS ===".to_string(),
        format!("Genere le: {}", display(&report["generated_at_utc"])),
        format!(
            "Machine: {} ({})",
            display(&report["host"]["hostname"]),
            display(&report["host"]["os"])
        ),
        String::new(),
        format!(
            "Score de risque (0-100): {}",
            display(&report["risk"]["risk_score_100"])
        ),
    ];
    for reason in rows(&report["risk"], "reasons") {
        lines.push(format!("- {}", display(reason)));
    }
    lines.extend([
        String::new(),
        "[Defender status]".to_string(),
        serde_json::to_string_pretty(&report["defender_status"]).unwrap_or_default(),
        String::new(),
        "[Menaces detectees]".to_string(),
        serde_json::to_string_pretty(&report["defender_threat_detections"]).unwrap_or_default(),
        String::new(),
        "[Installations recentes]".to_string(),
    ]);
    for (index, app) in rows(report, "recent_installs").iter().enumerate() {
        lines.push(format!(
            "{}. {} | {} | {}",
            index + 1,
            display(&app["display_name"]),
            display(&app["install_date"]),
            display(&app["publisher"])
        ));
    }
    if rows(report, "recent_installs").is_empty() {
        lines.push(if report["recent_installs_collection"]["ok"] == false {
            "Collecte incomplete".to_string()
        } else {
            "Aucune installation recente detectee".to_string()
        });
    }
    lines.push(String::new());
    lines.push("[Services installes recemment]".to_string());
    for event in rows(report, "recent_service_installs") {
        let message: String = display(&event["Message"]).chars().take(200).collect();
        lines.push(format!(
            "- {} | ID={} | {}",
            display(&event["TimeCreated"]),
            display(&event["Id"]),
            message
        ));
    }
    if rows(report, "recent_service_installs").is_empty() {
        lines.push(if report["persistence_collection"]["ok"] == false {
            "Collecte incomplete".to_string()
        } else {
            "Aucun".to_string()
        });
    }
    lines.push(String::new());
    lines.push("[Taches planifiees enregistrees recemment]".to_string());
    for event in rows(report, "recent_task_registrations") {
        let message: String = display(&event["Message"]).chars().take(200).collect();
        lines.push(format!(
            "- {} | ID={} | {}",
            display(&event["TimeCreated"]),
            display(&event["Id"]),
            message
        ));
    }
    if rows(report, "recent_task_registrations").is_empty() {
        lines.push(if report["persistence_collection"]["ok"] == false {
            "Collecte incomplete".to_string()
        } else {
            "Aucune".to_string()
        });
    }
    lines.push(String::new());
    lines.push("[Startup entries]".to_string());
    for entry in rows(report, "startup_entries") {
        lines.push(format!(
            "- {} | {} | {}",
            display(&entry["source"]),
            display(&entry["name"]),
            display(&entry["command"])
        ));
    }
    if rows(report, "startup_entries").is_empty() {
        lines.push("Aucune entree startup".to_string());
    }
    lines.push(String::new());
    lines.push("[Audit reseau]".to_string());
    let net = &report["network_audit"];
    let total =
        net["upload_bps"].as_f64().unwrap_or(0.0) + net["download_bps"].as_f64().unwrap_or(0.0);
    lines.push(format!(
        "CPU: {:.0}% | Debit observe: {}",
        net["cpu_percent"].as_f64().unwrap_or(0.0),
        scan_system_core::format_rate(total)
    ));
    let connections = rows(net, "connections");
    if connections.is_empty() {
        lines.push("Aucune connexion publique observee".to_string());
    } else {
        lines.push(format!(
            "Connexions publiques observees: {}",
            connections.len()
        ));
        for connection in connections.iter().take(50) {
            let name = display(&connection["process_name"]);
            let flag = if connection["threat_feed_match"] == true {
                " [MENACE CONNUE]"
            } else {
                ""
            };
            lines.push(format!(
                "- {} -> {} ({}){}",
                if name.is_empty() { "inconnu" } else { &name },
                display(&connection["remote"]),
                display(&connection["status"]),
                flag
            ));
        }
    }
    if !rows(net, "anomalies").is_empty() {
        lines.push("Anomalies reseau:".to_string());
        for anomaly in rows(net, "anomalies") {
            lines.push(format!("  - {}", display(anomaly)));
        }
    }
    lines.extend([
        String::new(),
        String::new(),
        "[Mise a jour liste de menaces]".to_string(),
    ]);
    let feeds = rows(&report["threat_feeds_refresh"], "feeds");
    for feed in feeds {
        if feed["ok"] == true {
            lines.push(format!(
                "- OK | {} | entrees={}",
                display(&feed["url"]),
                display(&feed["entries"])
            ));
        } else {
            lines.push(format!(
                "- KO | {} | erreur={}",
                display(&feed["url"]),
                display(&feed["error"])
            ));
        }
    }
    if feeds.is_empty() {
        lines.push("Aucune mise a jour effectuee".to_string());
    }
    lines.join("\n")
}

/// Writes the JSON and TXT reports under the same timestamped names as Python.
/// JSON is written before TXT, matching the original behavior on a write error.
pub fn save_reports(report: &Value, output_dir: &Path) -> Result<(PathBuf, PathBuf), AuditError> {
    fs::create_dir_all(output_dir)?;
    let stamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let json_path = output_dir.join(format!("scan_report_{stamp}.json"));
    let txt_path = output_dir.join(format!("scan_report_{stamp}.txt"));
    fs::write(&json_path, serde_json::to_string_pretty(report)?)?;
    fs::write(&txt_path, render_txt_report(report))?;
    Ok((json_path, txt_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_score_counts_defender_and_network_signals() {
        let report = json!({
            "defender_threat_detections": {"ok": true, "data": [{"ThreatName": "x"}]},
            "recent_installs": [{}, {}, {}],
            "recent_service_installs": [],
            "recent_task_registrations": [],
            "network_audit": {
                "connections": [{"threat_feed_match": true}],
                "anomalies": ["IP presente dans une liste de blocage menace"]
            }
        });
        let risk = risk_from_report(&report);
        assert_eq!(risk["risk_score_100"], 60);
    }

    #[test]
    fn report_score_excludes_handled_defender_history() {
        let report = json!({
            "defender_threat_detections": {"data": [
                {"ActionSuccess": true, "CurrentThreatExecutionStatusID": 1},
                {"ActionSuccess": true, "CurrentThreatExecutionStatusID": 4},
                {"ActionSuccess": false, "CurrentThreatExecutionStatusID": 1},
                {"ActionSuccess": true, "CurrentThreatExecutionStatusID": 2}
            ]}
        });
        let risk = risk_from_report(&report);
        assert_eq!(risk["risk_score_100"], 40);
        assert_eq!(risk["reasons"][0], "Detections Defender a verifier: 2");
    }

    #[test]
    fn failed_defender_collection_marks_audit_incomplete() {
        let report = json!({
            "parameters": {"update_signatures": false, "run_quick_scan": false},
            "defender_status": {"ok": true},
            "defender_threat_detections": {"ok": false, "error": "access denied"},
            "threat_feeds_refresh": {"feeds": [{"ok": true}]}
        });
        assert!(!audit_is_complete(&report));
    }

    #[test]
    fn failed_persistence_collection_marks_audit_incomplete() {
        let report = json!({
            "parameters": {"update_signatures": false, "run_quick_scan": false},
            "defender_status": {"ok": true},
            "defender_threat_detections": {"ok": true},
            "persistence_collection": {"ok": false, "error": "access denied"},
            "threat_feeds_refresh": {"feeds": [{"ok": true}]},
            "recent_service_installs": [],
            "recent_task_registrations": []
        });
        assert!(!audit_is_complete(&report));
        assert!(render_txt_report(&report).contains("Collecte incomplete"));
    }

    #[test]
    fn failed_msi_collection_marks_audit_incomplete() {
        let report = json!({
            "parameters": {"update_signatures": false, "run_quick_scan": false},
            "defender_status": {"ok": true},
            "defender_threat_detections": {"ok": true},
            "recent_installs_collection": {"ok": false, "error": "access denied"},
            "threat_feeds_refresh": {"feeds": [{"ok": true}]},
            "recent_installs": []
        });
        assert!(!audit_is_complete(&report));
        assert!(render_txt_report(&report).contains("Collecte incomplete"));
    }

    #[test]
    fn feed_refresh_uses_ips_before_sample() {
        let refresh = json!({"feeds": [{"ips": ["8.8.8.8"], "sample": ["1.1.1.1"]}]});
        assert!(threat_feed_ips(&refresh).contains("8.8.8.8"));
        assert!(!threat_feed_ips(&refresh).contains("1.1.1.1"));
    }

    #[test]
    fn command_path_extraction_respects_quotes_and_drive_prefix() {
        assert_eq!(
            command_executable(r#""C:\Program Files\app.exe" --start"#),
            Some(Path::new(r"C:\Program Files\app.exe"))
        );
        assert_eq!(
            command_executable(r"C:\app.exe --start"),
            Some(Path::new(r"C:\app.exe"))
        );
        assert_eq!(command_executable("powershell.exe -File app.ps1"), None);
    }

    #[test]
    fn text_report_preserves_legacy_sections_and_threat_marker() {
        let report = json!({
            "risk": {"risk_score_100": 30, "reasons": []},
            "network_audit": {
                "connections": [{"process_name": "x.exe", "remote": "8.8.8.8:443",
                    "status": "ESTABLISHED", "threat_feed_match": true}],
                "anomalies": []
            },
            "threat_feeds_refresh": {"feeds": []}
        });
        let text = render_txt_report(&report);
        assert!(text.contains("[Audit reseau]"));
        assert!(text.contains("[MENACE CONNUE]"));
        assert!(text.contains("Score de risque (0-100): 30"));
    }

    #[test]
    fn feed_parser_ignores_comments_and_blanks() {
        assert_eq!(
            feed_lines("# header\n8.8.8.8\n \n 1.1.1.1 \n"),
            ["8.8.8.8", "1.1.1.1"]
        );
    }

    #[test]
    fn signature_update_raw_fallback_uses_legacy_key() {
        let result = DefenderResult {
            ok: true,
            data: Some(Value::String("unparsed output".into())),
            error: None,
        };
        assert_eq!(
            signature_update_json(result),
            json!({"ok": true, "raw": "unparsed output"})
        );
    }

    #[test]
    fn invalid_defender_json_preserves_raw_output() {
        let result = DefenderResult {
            ok: false,
            data: Some(Value::String("invalid output".into())),
            error: Some("Sortie JSON Defender invalide".into()),
        };
        assert_eq!(
            defender_json(result),
            json!({"ok": false, "error": "Sortie JSON Defender invalide", "raw": "invalid output"})
        );
    }
}

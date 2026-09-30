//! Read-only local audit: skips signature updates, scans, and threat-feed downloads.
//! Prints counts only, never the report's machine-specific contents.

use scan_system_audit::{generate_report, AuditOptions};
use scan_system_platform::AuditHandle;
use std::collections::BTreeMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let report = generate_report(
        &AuditHandle::new(),
        AuditOptions {
            days: 1,
            update_signatures: false,
            run_quick_scan: false,
        },
        None,
        |label, percent| eprintln!("{percent}% {label}"),
    )?;
    let count = |key: &str| report[key].as_array().map_or(0, Vec::len);
    println!(
        "defender_ok={} defender_threats={} installs={} msi_ok={} services={} tasks={} persistence_ok={} startup={} public_connections={} network_anomalies={} risk={}",
        report["defender_threat_detections"]["ok"],
        report["defender_threat_detections"]["data"]
            .as_array()
            .map_or(0, Vec::len),
        count("recent_installs"),
        report["recent_installs_collection"]["ok"],
        count("recent_service_installs"),
        count("recent_task_registrations"),
        report["persistence_collection"]["ok"],
        count("startup_entries"),
        report["network_audit"]["connections"]
            .as_array()
            .map_or(0, Vec::len),
        report["network_audit"]["anomalies"]
            .as_array()
            .map_or(0, Vec::len),
        report["risk"]["risk_score_100"]
    );
    let mut statuses = BTreeMap::<&str, usize>::new();
    if let Some(connections) = report["network_audit"]["connections"].as_array() {
        for connection in connections {
            let status = connection["status"].as_str().unwrap_or("unknown");
            *statuses.entry(status).or_default() += 1;
        }
    }
    println!("connection_statuses={statuses:?}");
    Ok(())
}

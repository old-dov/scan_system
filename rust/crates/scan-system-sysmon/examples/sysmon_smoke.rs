//! Read-only check against the local Windows host. No report is written.

use std::collections::HashSet;

use scan_system_sysmon::{network_audit_snapshot, RealtimeMonitor};

fn main() {
    let audit = network_audit_snapshot(&HashSet::new());
    println!(
        "audit: cpu={:.0}% public_connections={} anomalies={}",
        audit.cpu_percent,
        audit.connections.len(),
        audit.anomalies.len()
    );
    for anomaly in &audit.anomalies {
        println!("  {anomaly}");
    }

    let mut monitor = RealtimeMonitor::new();
    let realtime = monitor.snapshot();
    println!(
        "realtime: cpu={:.0}% public_connections={} anomalies={}",
        realtime.cpu_percent,
        realtime.connections.len(),
        realtime.anomalies.len()
    );
}

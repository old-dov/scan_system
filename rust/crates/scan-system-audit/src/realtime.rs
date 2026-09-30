//! Slower persistence checks for the GUI's realtime sampler.

use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use chrono::{Local, NaiveDateTime};
use scan_system_core::{
    looks_suspicious_text, parse_any_datetime, startup_fingerprint, StartupEntry,
};
use scan_system_platform::{recent_persistence_events, AuditHandle, ProcessError};
use serde_json::Value;

use crate::startup_entries;

/// Keeps startup and event baselines between GUI samples. The expensive Windows
/// event query runs at most once per minute, as in the Python application.
#[derive(Default)]
pub struct RealtimePersistenceMonitor {
    last_scan: Option<Instant>,
    startup_fp: Option<HashSet<String>>,
    seen_tasks: HashSet<String>,
    seen_services: HashSet<String>,
}

impl RealtimePersistenceMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns newly found persistence anomalies, or an empty list between scans.
    ///
    /// # Errors
    ///
    /// Propagates cancellation of the Windows event query.
    pub fn poll(&mut self, handle: &AuditHandle) -> Result<Vec<String>, ProcessError> {
        if self
            .last_scan
            .is_some_and(|last| last.elapsed() < Duration::from_secs(60))
        {
            return Ok(Vec::new());
        }
        self.last_scan = Some(Instant::now());

        let mut anomalies = Vec::new();
        self.check_startup(&startup_entries(), &mut anomalies);

        let now = Local::now().naive_local();
        let since = now - chrono::Duration::seconds(90);
        let cutoff = now - chrono::Duration::minutes(70);
        let (tasks, services) = recent_persistence_events(handle, 1, Some(since))?;
        append_event_anomalies(
            &tasks,
            &mut self.seen_tasks,
            cutoff,
            "Nouvelle tache planifiee suspecte detectee",
            &mut anomalies,
        );
        append_event_anomalies(
            &services,
            &mut self.seen_services,
            cutoff,
            "Nouveau service potentiellement suspect detecte",
            &mut anomalies,
        );
        Ok(anomalies)
    }

    fn check_startup(&mut self, rows: &[Value], anomalies: &mut Vec<String>) {
        let entries: Vec<_> = rows
            .iter()
            .map(|row| StartupEntry {
                source: row["source"].as_str().unwrap_or_default().into(),
                name: row["name"].as_str().unwrap_or_default().into(),
                command: row["command"].as_str().unwrap_or_default().into(),
            })
            .collect();
        let current = startup_fingerprint(&entries);
        let Some(previous) = &self.startup_fp else {
            self.startup_fp = Some(current);
            return;
        };
        let mut added: Vec<_> = current.difference(previous).cloned().collect();
        added.sort();
        for row in added.iter().take(5) {
            let label = row
                .split('|')
                .nth(1)
                .filter(|part| !part.is_empty())
                .unwrap_or(row);
            anomalies.push(format!("Nouvelle entree startup detectee: {label}"));
        }
        // Python only replaces the baseline when it observes an addition.
        if !added.is_empty() {
            self.startup_fp = Some(current);
        }
    }
}

fn append_event_anomalies(
    events: &[Value],
    seen: &mut HashSet<String>,
    cutoff: NaiveDateTime,
    label: &str,
    anomalies: &mut Vec<String>,
) {
    for item in events {
        let Some(timestamp) = parse_any_datetime(item["TimeCreated"].as_str()) else {
            continue;
        };
        if timestamp < cutoff {
            continue;
        }
        let message = item["Message"].as_str().unwrap_or_default();
        let signature = format!(
            "{}|{}",
            timestamp.format("%Y-%m-%dT%H:%M:%S%.f"),
            message.chars().take(180).collect::<String>()
        );
        if seen.insert(signature) && looks_suspicious_text(message) {
            anomalies.push(label.into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn startup_baseline_only_alerts_on_new_entries() {
        let mut monitor = RealtimePersistenceMonitor::new();
        let first = [json!({"source":"HKCU", "name":"Existing", "command":"old.exe"})];
        let second = [
            first[0].clone(),
            json!({"source":"HKCU", "name":"New", "command":"new.exe"}),
        ];
        let mut anomalies = Vec::new();
        monitor.check_startup(&first, &mut anomalies);
        assert!(anomalies.is_empty());
        monitor.check_startup(&second, &mut anomalies);
        assert_eq!(anomalies, ["Nouvelle entree startup detectee: new"]);
        anomalies.clear();
        monitor.check_startup(&second, &mut anomalies);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn suspicious_event_is_reported_once() {
        let cutoff =
            NaiveDateTime::parse_from_str("2026-09-28T12:00:00", "%Y-%m-%dT%H:%M:%S").unwrap();
        let rows =
            [json!({"TimeCreated":"2026-09-28T12:01:00", "Message":"powershell -enc payload"})];
        let mut seen = HashSet::new();
        let mut anomalies = Vec::new();
        append_event_anomalies(&rows, &mut seen, cutoff, "task", &mut anomalies);
        append_event_anomalies(&rows, &mut seen, cutoff, "task", &mut anomalies);
        assert_eq!(anomalies, ["task"]);
    }

    #[test]
    fn powershell_event_timestamp_reaches_persistence_alert() {
        let timestamp = "/Date(1790752330097)/";
        let cutoff = parse_any_datetime(Some(timestamp)).unwrap() - chrono::Duration::minutes(1);
        let rows = [json!({
            "TimeCreated": timestamp,
            "Message": "powershell -enc payload",
        })];
        let mut seen = HashSet::new();
        let mut anomalies = Vec::new();
        append_event_anomalies(&rows, &mut seen, cutoff, "service", &mut anomalies);
        assert_eq!(anomalies, ["service"]);
    }
}

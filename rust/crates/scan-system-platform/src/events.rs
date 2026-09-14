//! `Get-WinEvent` queries for scheduled-task/service persistence and MSI installs, plus
//! the registry-derived recent-installs list — ported from `recent_persistence_events`/
//! `recent_installs`/`parse_install_date`/`_event_log_start_expr` in
//! `scanner_windows.py`.

use std::time::Duration;

use serde_json::Value;

use crate::{
    process::{AuditHandle, ProcessError},
    registry::{iter_uninstall_registry, UninstallEntry},
};

/// `yyyymmdd`, the format the `Uninstall` registry key's `InstallDate` value uses — a
/// distinct, stricter format from [`scan_system_core::parse_any_datetime`]'s three
/// (ISO/US/SQL), which is why it stays a separate function rather than folding into
/// that one.
#[must_use]
fn parse_install_date(raw: &str) -> Option<chrono::NaiveDate> {
    let raw = raw.trim();
    if raw.len() != 8 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    chrono::NaiveDate::parse_from_str(raw, "%Y%m%d").ok()
}

/// Either a registry `Uninstall` entry (has every field) or a fallback derived from an
/// MSI installer event log entry (only the fields `event_id`/`event_message` fill,
/// `display_name` is the literal `"(MSI event)"`) — mirrors the two shapes
/// `recent_installs` appends to the same list in the Python original.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RecentInstall {
    pub display_name: String,
    pub display_version: String,
    pub publisher: String,
    pub install_date: String,
    pub install_location: String,
    pub uninstall_string: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_message: Option<String>,
    pub registry_subkey: String,
}

/// Registry entries installed within the last `days` days, plus an MSI-installer
/// event-log fallback (`Id=11707`) for installs the registry's `InstallDate` value
/// missed. `days` bounds both sources identically (same lookback window).
///
/// # Errors
///
/// Only [`ProcessError::Cancelled`] propagates from the event-log half; the registry
/// half cannot fail (a permission error on one hive is already handled as "no entries"
/// by [`iter_uninstall_registry`]).
pub fn recent_installs(
    handle: &AuditHandle,
    days: i64,
) -> Result<Vec<RecentInstall>, ProcessError> {
    let cutoff = chrono::Local::now().date_naive() - chrono::Duration::days(days);
    let mut out = Vec::new();

    for entry in iter_uninstall_registry() {
        if let Some(date) = parse_install_date(&entry.install_date_raw) {
            if date >= cutoff {
                out.push(from_uninstall_entry(entry, date));
            }
        }
    }

    let script = format!(
        "Get-WinEvent -FilterHashtable @{{LogName='Application'; ProviderName='MsiInstaller'; \
         Id=11707; StartTime=(Get-Date).AddDays(-{days})}} | \
         Select-Object TimeCreated, Id, LevelDisplayName, Message | ConvertTo-Json -Depth 4"
    );
    let result = handle.run_powershell(&script, Duration::from_secs(120))?;
    if result.ok && !result.output.is_empty() {
        if let Ok(value) = serde_json::from_str::<Value>(&result.output) {
            let items: Vec<Value> = match value {
                Value::Array(items) => items,
                other => vec![other],
            };
            for item in items {
                let message = item
                    .get("Message")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                out.push(RecentInstall {
                    display_name: "(MSI event)".to_string(),
                    install_date: item
                        .get("TimeCreated")
                        .map(value_to_display_string)
                        .unwrap_or_default(),
                    event_id: item.get("Id").and_then(Value::as_i64),
                    event_message: Some(message.chars().take(1200).collect()),
                    ..RecentInstall::default()
                });
            }
        }
    }

    Ok(out)
}

fn from_uninstall_entry(entry: UninstallEntry, date: chrono::NaiveDate) -> RecentInstall {
    RecentInstall {
        display_name: entry.display_name,
        display_version: entry.display_version,
        publisher: entry.publisher,
        install_date: date.format("%Y-%m-%d").to_string(),
        install_location: entry.install_location,
        uninstall_string: entry.uninstall_string,
        event_id: None,
        event_message: None,
        registry_subkey: entry.registry_subkey,
    }
}

fn value_to_display_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn event_log_start_expr(days: i64, since: Option<chrono::NaiveDateTime>) -> String {
    match since {
        Some(dt) => format!("[datetime]'{}'", dt.format("%Y-%m-%dT%H:%M:%S")),
        None => format!("(Get-Date).AddDays(-{days})"),
    }
}

/// Newly registered scheduled tasks (event 106) and newly installed services (event
/// 7045), fetched in one merged `Get-WinEvent` call rather than two — the dominant cost
/// of a PowerShell round trip is starting `powershell.exe` itself (observed 3-7s), not
/// the query, so merging halves that fixed cost on every call. `since` narrows the
/// window to a short recent slice (the GUI's 60s realtime poll); `None` uses the full
/// `days`-day lookback (a manual audit).
///
/// # Errors
///
/// Only [`ProcessError::Cancelled`] propagates; every other failure (including
/// unparseable JSON) returns two empty lists rather than an error, matching the Python
/// original's bare `except json.JSONDecodeError: return [], []`.
pub fn recent_persistence_events(
    handle: &AuditHandle,
    days: i64,
    since: Option<chrono::NaiveDateTime>,
) -> Result<(Vec<Value>, Vec<Value>), ProcessError> {
    let start_expr = event_log_start_expr(days, since);
    let script = format!(
        "$tasks = @(Get-WinEvent -FilterHashtable @{{\
            LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=106; StartTime={start_expr}\
        }} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message)\n\
        $services = @(Get-WinEvent -FilterHashtable @{{\
            LogName='System'; Id=7045; StartTime={start_expr}\
        }} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, ProviderName, Message)\n\
        [PSCustomObject]@{{ tasks = $tasks; services = $services }} | ConvertTo-Json -Depth 4"
    );
    let result = handle.run_powershell(&script, Duration::from_secs(120))?;
    if !result.ok || result.output.is_empty() {
        return Ok((vec![], vec![]));
    }
    let Ok(data) = serde_json::from_str::<Value>(&result.output) else {
        return Ok((vec![], vec![]));
    };
    let as_list = |key: &str| -> Vec<Value> {
        match data.get(key) {
            Some(Value::Array(items)) => items.clone(),
            Some(single @ Value::Object(_)) => vec![single.clone()],
            _ => vec![],
        }
    };
    Ok((as_list("tasks"), as_list("services")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_install_date_valid() {
        assert_eq!(
            parse_install_date("20260825"),
            chrono::NaiveDate::from_ymd_opt(2026, 8, 25)
        );
    }

    #[test]
    fn parse_install_date_rejects_wrong_shape() {
        assert_eq!(parse_install_date(""), None);
        assert_eq!(parse_install_date("2026-08-25"), None);
        assert_eq!(parse_install_date("2026082"), None);
        assert_eq!(parse_install_date("abcdefgh"), None);
    }

    #[test]
    fn event_log_start_expr_uses_since_when_given() {
        let since = chrono::NaiveDate::from_ymd_opt(2026, 9, 14)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap();
        assert_eq!(
            event_log_start_expr(14, Some(since)),
            "[datetime]'2026-09-14T10:00:00'"
        );
    }

    #[test]
    fn event_log_start_expr_falls_back_to_days() {
        assert_eq!(event_log_start_expr(14, None), "(Get-Date).AddDays(-14)");
    }
}

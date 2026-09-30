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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_date_raw: Option<String>,
    pub install_location: String,
    pub uninstall_string: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quiet_uninstall_string: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_icon: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_installer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_package: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hive: Option<String>,
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
/// The second return value reports an MSI event-log failure while retaining the
/// registry entries. A genuine empty event log returns `None` instead.
///
/// # Errors
///
/// Cancellation propagates from the event-log query.
pub fn recent_installs(
    handle: &AuditHandle,
    days: i64,
) -> Result<(Vec<RecentInstall>, Option<String>), ProcessError> {
    // Python compares midnight of InstallDate against the current wall-clock
    // instant minus `days`; an entry dated exactly `days` ago is therefore too
    // old after midnight. Keep that boundary rather than comparing dates only.
    let cutoff = chrono::Local::now().naive_local() - chrono::Duration::days(days);
    let mut out = Vec::new();

    for entry in iter_uninstall_registry() {
        if let Some(date) = parse_install_date(&entry.install_date_raw) {
            if date.and_hms_opt(0, 0, 0).is_some_and(|time| time >= cutoff) {
                out.push(from_uninstall_entry(entry, date));
            }
        }
    }

    let script = format!(
        "try {{ $events = @(Get-WinEvent -FilterHashtable @{{LogName='Application'; ProviderName='MsiInstaller'; \
         Id=11707; StartTime=(Get-Date).AddDays(-{days})}} -ErrorAction Stop | \
         Select-Object TimeCreated, Id, LevelDisplayName, Message) }}\n\
         catch {{ if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {{ throw }}; $events = @() }}\n\
         ConvertTo-Json -InputObject $events -Depth 4"
    );
    let result = handle.run_powershell(&script, Duration::from_secs(120))?;
    if !result.ok {
        return Ok((out, Some(result.output)));
    }
    let value = match serde_json::from_str::<Value>(&result.output) {
        Ok(Value::Array(items)) => items,
        Ok(Value::Object(item)) => vec![Value::Object(item)],
        Ok(_) => return Ok((out, Some("JSON MSI invalide".into()))),
        Err(error) => return Ok((out, Some(format!("JSON MSI invalide: {error}")))),
    };
    if value.iter().any(|item| !item.is_object()) {
        return Ok((out, Some("JSON MSI invalide".into())));
    }
    for item in value {
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

    Ok((out, None))
}

fn from_uninstall_entry(entry: UninstallEntry, date: chrono::NaiveDate) -> RecentInstall {
    RecentInstall {
        display_name: entry.display_name,
        display_version: entry.display_version,
        publisher: entry.publisher,
        install_date: date.format("%Y-%m-%d").to_string(),
        install_date_raw: Some(entry.install_date_raw),
        install_location: entry.install_location,
        uninstall_string: entry.uninstall_string,
        quiet_uninstall_string: Some(entry.quiet_uninstall_string),
        display_icon: Some(entry.display_icon),
        windows_installer: Some(entry.windows_installer),
        local_package: Some(entry.local_package),
        registry_hive: Some(entry.registry_hive),
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
/// Returns an error when either log is inaccessible or PowerShell returns invalid
/// data. A genuine `NoMatchingEventsFound` result still produces empty lists.
pub fn recent_persistence_events(
    handle: &AuditHandle,
    days: i64,
    since: Option<chrono::NaiveDateTime>,
) -> Result<(Vec<Value>, Vec<Value>), ProcessError> {
    let start_expr = event_log_start_expr(days, since);
    let script = format!(
        "try {{ $tasks = @(Get-WinEvent -FilterHashtable @{{\
            LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=106; StartTime={start_expr}\
        }} -ErrorAction Stop | Select-Object TimeCreated, Id, Message) }}\n\
        catch {{ if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {{ throw }}; $tasks = @() }}\n\
        try {{ $services = @(Get-WinEvent -FilterHashtable @{{\
            LogName='System'; Id=7045; StartTime={start_expr}\
        }} -ErrorAction Stop | Select-Object TimeCreated, Id, ProviderName, Message) }}\n\
        catch {{ if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {{ throw }}; $services = @() }}\n\
        [PSCustomObject]@{{ tasks = $tasks; services = $services }} | ConvertTo-Json -Depth 4"
    );
    let result = handle.run_powershell(&script, Duration::from_secs(120))?;
    parse_persistence_output(result)
}

fn parse_persistence_output(
    result: crate::process::PowerShellOutput,
) -> Result<(Vec<Value>, Vec<Value>), ProcessError> {
    if !result.ok {
        return Err(ProcessError::Command(result.output));
    }
    let data = serde_json::from_str::<Value>(&result.output)
        .map_err(|error| ProcessError::Command(format!("JSON evenements invalide: {error}")))?;
    let is_list_or_single = |value: &Value| value.is_array() || value.is_object();
    if !is_list_or_single(&data["tasks"]) || !is_list_or_single(&data["services"]) {
        return Err(ProcessError::Command(
            "Listes taches/services absentes du resultat PowerShell".into(),
        ));
    }
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
    fn registry_install_keeps_python_report_fields() {
        let entry = UninstallEntry {
            display_name: "Example".into(),
            install_date_raw: "20260928".into(),
            registry_hive: "HKLM".into(),
            quiet_uninstall_string: String::new(),
            ..UninstallEntry::default()
        };
        let date = chrono::NaiveDate::from_ymd_opt(2026, 9, 28).unwrap();
        let value = serde_json::to_value(from_uninstall_entry(entry, date)).unwrap();
        assert_eq!(value["install_date_raw"], "20260928");
        assert_eq!(value["registry_hive"], "HKLM");
        assert_eq!(value["quiet_uninstall_string"], "");
        assert!(value.get("event_id").is_none());
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

    #[test]
    fn persistence_failure_is_not_reported_as_no_events() {
        let failure = crate::process::PowerShellOutput {
            ok: false,
            output: "access denied".into(),
        };
        assert!(parse_persistence_output(failure).is_err());
        let no_events = crate::process::PowerShellOutput {
            ok: true,
            output: r#"{"tasks":[],"services":[]}"#.into(),
        };
        assert!(
            matches!(parse_persistence_output(no_events), Ok((tasks, services)) if tasks.is_empty() && services.is_empty())
        );
    }
}

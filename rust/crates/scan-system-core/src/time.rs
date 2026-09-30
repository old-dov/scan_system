//! Ported from `scanner_windows.parse_any_datetime`.

use chrono::{DateTime, Local, NaiveDateTime, Utc};

const US_FORMAT: &str = "%m/%d/%Y %I:%M:%S %p";
const SQL_FORMAT: &str = "%Y-%m-%d %H:%M:%S";

/// Parses a timestamp in whichever shape the source (Windows event log,
/// registry, JSON) happens to hand back: PowerShell `/Date(milliseconds)/`,
/// RFC3339/ISO-8601 (`Z` normalized to `+00:00`
/// first, same pre-processing as the Python original), the US `Get-Date` default
/// (`MM/DD/YYYY hh:mm:ss AM/PM`), naive ISO-8601, or the SQL-ish
/// `YYYY-MM-DD HH:MM:SS`.
///
/// Returns a plain [`NaiveDateTime`] in every case — unlike the Python original, which
/// keeps a timezone-aware `datetime` for the RFC3339/`Z` branch and a naive one for the
/// other two. Every caller in this codebase eventually compares the result against a
/// naive `now()`-based cutoff anyway, so a value with an explicit offset is normalized
/// to its UTC wall-clock time (`Z`/`+00:00` becomes a no-op numerically, matching the
/// one fixture this crate is tested against) rather than carried as a distinct,
/// harder-to-compare type.
#[must_use]
pub fn parse_any_datetime(raw: Option<&str>) -> Option<NaiveDateTime> {
    let raw = raw?;
    let text = raw.trim();
    if text.is_empty() {
        return None;
    }
    if let Some(body) = text
        .strip_prefix("/Date(")
        .and_then(|s| s.strip_suffix(")/"))
    {
        // Windows PowerShell 5.1 ConvertTo-Json uses UTC epoch milliseconds.
        // Convert to local naive time for the monitor's local-time cutoff.
        let offset_start = body
            .char_indices()
            .skip(1)
            .find(|(_, ch)| *ch == '+' || *ch == '-')
            .map(|(index, _)| index)
            .unwrap_or(body.len());
        let (milliseconds, offset) = body.split_at(offset_start);
        if !offset.is_empty()
            && (offset.len() != 5
                || !matches!(offset.as_bytes()[0], b'+' | b'-')
                || !offset.as_bytes()[1..].iter().all(u8::is_ascii_digit))
        {
            return None;
        }
        let milliseconds = milliseconds.parse::<i64>().ok()?;
        return DateTime::<Utc>::from_timestamp_millis(milliseconds)
            .map(|date| date.with_timezone(&Local).naive_local());
    }
    let normalized = text.replace('Z', "+00:00");

    if let Ok(parsed) = DateTime::parse_from_rfc3339(&normalized) {
        return Some(parsed.naive_utc());
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", US_FORMAT, SQL_FORMAT] {
        if let Ok(parsed) = NaiveDateTime::parse_from_str(&normalized, fmt) {
            return Some(parsed);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDate;

    use super::*;

    #[test]
    fn parse_any_datetime_iso_with_z_suffix() {
        let result = parse_any_datetime(Some("2026-08-25T10:00:00Z"));
        assert_eq!(
            result,
            NaiveDate::from_ymd_opt(2026, 8, 25)
                .unwrap()
                .and_hms_opt(10, 0, 0)
        );
    }

    #[test]
    fn parse_any_datetime_us_format() {
        let result = parse_any_datetime(Some("08/25/2026 10:00:00 AM"));
        assert_eq!(
            result,
            NaiveDate::from_ymd_opt(2026, 8, 25)
                .unwrap()
                .and_hms_opt(10, 0, 0)
        );
    }

    #[test]
    fn parse_any_datetime_naive_iso_with_fractional_seconds() {
        let result = parse_any_datetime(Some("2026-09-28T13:05:06.123456"));
        assert_eq!(
            result,
            NaiveDate::from_ymd_opt(2026, 9, 28)
                .unwrap()
                .and_hms_micro_opt(13, 5, 6, 123456)
        );
    }

    #[test]
    fn parse_any_datetime_sql_format() {
        let result = parse_any_datetime(Some("2026-08-25 10:00:00"));
        assert_eq!(
            result,
            NaiveDate::from_ymd_opt(2026, 8, 25)
                .unwrap()
                .and_hms_opt(10, 0, 0)
        );
    }

    #[test]
    fn parse_any_datetime_powershell_event_json() {
        let milliseconds = 1_790_752_330_097;
        let expected = DateTime::<Utc>::from_timestamp_millis(milliseconds)
            .unwrap()
            .with_timezone(&Local)
            .naive_local();
        assert_eq!(
            parse_any_datetime(Some("/Date(1790752330097)/")),
            Some(expected)
        );
        assert_eq!(
            parse_any_datetime(Some("/Date(1790752330097+0200)/")),
            Some(expected)
        );
        assert_eq!(parse_any_datetime(Some("/Date(invalid)/")), None);
    }

    #[test]
    fn parse_any_datetime_none_or_blank_or_garbage() {
        assert_eq!(parse_any_datetime(None), None);
        assert_eq!(parse_any_datetime(Some("")), None);
        assert_eq!(parse_any_datetime(Some("   ")), None);
        assert_eq!(parse_any_datetime(Some("pas une date")), None);
    }
}

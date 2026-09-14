//! Ported from `scanner_windows.parse_any_datetime`.

use chrono::{DateTime, NaiveDateTime};

const US_FORMAT: &str = "%m/%d/%Y %I:%M:%S %p";
const SQL_FORMAT: &str = "%Y-%m-%d %H:%M:%S";

/// Parses a timestamp in whichever of three shapes the source (Windows event log,
/// registry, JSON) happens to hand back: RFC3339/ISO-8601 (`Z` normalized to `+00:00`
/// first, same pre-processing as the Python original), the US `Get-Date` default
/// (`MM/DD/YYYY hh:mm:ss AM/PM`), or the SQL-ish `YYYY-MM-DD HH:MM:SS`.
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
    let normalized = text.replace('Z', "+00:00");

    if let Ok(parsed) = DateTime::parse_from_rfc3339(&normalized) {
        return Some(parsed.naive_utc());
    }
    for fmt in [US_FORMAT, SQL_FORMAT] {
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
    fn parse_any_datetime_none_or_blank_or_garbage() {
        assert_eq!(parse_any_datetime(None), None);
        assert_eq!(parse_any_datetime(Some("")), None);
        assert_eq!(parse_any_datetime(Some("   ")), None);
        assert_eq!(parse_any_datetime(Some("pas une date")), None);
    }
}

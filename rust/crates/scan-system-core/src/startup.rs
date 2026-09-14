//! Ported from `scanner_windows.startup_fingerprint`.

use std::collections::HashSet;

/// One startup entry (a registry `Run` value, or a Startup-folder shortcut) — the
/// subset of fields the fingerprint needs. The real source (`scan-system-platform`,
/// phase 2) carries more (e.g. `modified`), irrelevant to identity comparison here.
#[derive(Debug, Clone, Default)]
pub struct StartupEntry {
    pub source: String,
    pub name: String,
    pub command: String,
}

/// A case-insensitive identity fingerprint per entry (`source|name|command`), used to
/// diff two startup snapshots and flag genuinely new entries — case folded because the
/// same registry value can be read back with different casing across polls without
/// actually having changed.
#[must_use]
pub fn startup_fingerprint(entries: &[StartupEntry]) -> HashSet<String> {
    entries
        .iter()
        .map(|item| {
            format!(
                "{}|{}|{}",
                item.source.to_lowercase(),
                item.name.to_lowercase(),
                item.command.to_lowercase()
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(source: &str, name: &str, command: &str) -> StartupEntry {
        StartupEntry {
            source: source.to_string(),
            name: name.to_string(),
            command: command.to_string(),
        }
    }

    #[test]
    fn startup_fingerprint_dedupes_case_insensitively() {
        let entries = [
            entry("HKLM", "Foo", "foo.exe"),
            entry("hklm", "FOO", "FOO.EXE"),
        ];
        assert_eq!(startup_fingerprint(&entries).len(), 1);
    }

    #[test]
    fn startup_fingerprint_distinguishes_different_entries() {
        let entries = [
            entry("HKLM", "Foo", "foo.exe"),
            entry("HKCU", "Bar", "bar.exe"),
        ];
        assert_eq!(startup_fingerprint(&entries).len(), 2);
    }

    #[test]
    fn startup_fingerprint_empty_list() {
        assert_eq!(startup_fingerprint(&[]), HashSet::new());
    }
}

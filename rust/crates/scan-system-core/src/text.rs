//! Ported from `scanner_windows.looks_suspicious_text`.

/// Substring patterns (case-insensitive) associated with common living-off-the-land /
/// dropper techniques on Windows. Not a detection engine — a cheap first-pass flag used
/// to highlight startup entries, connections and event-log messages worth a human look.
const SUSPICIOUS_PATTERNS: &[&str] = &[
    "powershell -enc",
    "frombase64string",
    "\\temp\\",
    "\\users\\public\\",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "bitsadmin",
    "certutil",
    "schtasks /create",
];

/// `true` if `value` (case-insensitive) contains any of [`SUSPICIOUS_PATTERNS`].
#[must_use]
pub fn looks_suspicious_text(value: &str) -> bool {
    let lowered = value.to_lowercase();
    SUSPICIOUS_PATTERNS
        .iter()
        .any(|pattern| lowered.contains(pattern))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_suspicious_text_matches_known_patterns() {
        assert!(looks_suspicious_text("powershell -enc SGVsbG8="));
        assert!(looks_suspicious_text("POWERSHELL -ENC SGVsbG8=")); // case-insensitive
        assert!(looks_suspicious_text(r"C:\Users\Public\payload.exe"));
        assert!(looks_suspicious_text(
            "rundll32.exe shell32.dll,Control_RunDLL"
        ));
        assert!(looks_suspicious_text(
            "schtasks /create /tn evil /tr evil.exe"
        ));
    }

    #[test]
    fn looks_suspicious_text_benign_text_not_flagged() {
        assert!(!looks_suspicious_text("notepad.exe"));
        assert!(!looks_suspicious_text(
            r"C:\Program Files\Vendor\app.exe --start"
        ));
        assert!(!looks_suspicious_text(""));
    }
}

//! Registry reads/writes — ported from `detect_windows_theme`,
//! `is_startup_monitoring_enabled`/`set_startup_monitoring_enabled`,
//! `iter_uninstall_registry`, `startup_entries` in `scanner_windows.py`.

use scan_system_core::StartupEntry;
use winreg::{
    enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE},
    RegKey,
};

/// `"light"` or `"dark"`, from the same registry value Windows itself uses for
/// system-wide app theme. Falls back to `"light"` on any read failure (missing key on
/// an older Windows build, permission issue) — same default as the Python original.
#[must_use]
pub fn detect_windows_theme() -> &'static str {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let read = || -> std::io::Result<u32> {
        let key =
            hkcu.open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")?;
        key.get_value("AppsUseLightTheme")
    };
    match read() {
        Ok(1) => "light",
        Ok(_) => "dark",
        Err(_) => "light",
    }
}

const STARTUP_RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const STARTUP_VALUE_NAME: &str = "ScanSystemMonitor";

/// `true` if the `HKCU\...\Run\ScanSystemMonitor` value exists and its command line
/// still carries `--monitoring-enabled` (a stale value from an older exe path is still
/// "enabled" by this check, matching the Python original's plain substring test).
#[must_use]
pub fn is_startup_monitoring_enabled() -> bool {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let read = || -> std::io::Result<String> {
        let key = hkcu.open_subkey(STARTUP_RUN_KEY)?;
        key.get_value(STARTUP_VALUE_NAME)
    };
    read().is_ok_and(|value| value.contains("--monitoring-enabled"))
}

/// Sets or clears the startup-monitoring `Run` value. `command` is the full command
/// line to register when `enabled` — computing it (quoting the exe path, appending
/// `--gui --monitoring-enabled --start-minimized`) is the caller's job
/// (`scan-system-audit`, phase 2), not this module's — mirrors `startup_monitor_command`
/// being a separate function from `set_startup_monitoring_enabled` in the original.
///
/// # Errors
///
/// The registry error message, when the `Run` key can't be opened for writing (e.g. a
/// locked-down machine) or the value can't be set/deleted.
pub fn set_startup_monitoring_enabled(enabled: bool, command: &str) -> Result<(), String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu
        .open_subkey_with_flags(STARTUP_RUN_KEY, winreg::enums::KEY_SET_VALUE)
        .map_err(|e| e.to_string())?;
    if enabled {
        key.set_value(STARTUP_VALUE_NAME, &command)
            .map_err(|e| e.to_string())
    } else {
        // Deleting a value that isn't there is not an error (matches the Python
        // original's bare `except OSError: pass`).
        match key.delete_value(STARTUP_VALUE_NAME) {
            Ok(()) | Err(_) => Ok(()),
        }
    }
}

/// One entry from `...\Uninstall\<subkey>` — an installed program, as Windows' own "Apps
/// & Features" panel reads it. Every field defaults to empty string when the value is
/// absent, same as the Python original's `qv()` helper.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct UninstallEntry {
    pub display_name: String,
    pub display_version: String,
    pub publisher: String,
    pub install_date_raw: String,
    pub install_location: String,
    pub uninstall_string: String,
    pub quiet_uninstall_string: String,
    pub display_icon: String,
    pub windows_installer: String,
    pub local_package: String,
    pub registry_hive: String,
    pub registry_subkey: String,
}

fn read_string_value(key: &RegKey, name: &str) -> String {
    key.get_value(name).unwrap_or_default()
}

/// Walks every `...\Uninstall\<subkey>` under the three hives Windows actually
/// populates (native HKLM, WOW6432Node for 32-bit apps on 64-bit Windows, and
/// per-user HKCU installs) and returns every entry that has a `DisplayName` — entries
/// without one are Windows Installer components, not user-visible programs, same
/// filter the Python original applies.
#[must_use]
pub fn iter_uninstall_registry() -> Vec<UninstallEntry> {
    const HIVES: &[(winreg::HKEY, &str, &str)] = &[
        (
            HKEY_LOCAL_MACHINE,
            "HKLM",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            HKEY_LOCAL_MACHINE,
            "HKLM",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            HKEY_CURRENT_USER,
            "HKCU",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
    ];

    let mut entries = Vec::new();
    for &(hive, hive_name, key_path) in HIVES {
        let root = RegKey::predef(hive);
        let Ok(root_key) = root.open_subkey(key_path) else {
            continue;
        };
        for sub_name in root_key.enum_keys().filter_map(Result::ok) {
            let Ok(sk) = root_key.open_subkey(&sub_name) else {
                continue;
            };
            let display_name = read_string_value(&sk, "DisplayName");
            if display_name.is_empty() {
                continue;
            }
            entries.push(UninstallEntry {
                display_name,
                display_version: read_string_value(&sk, "DisplayVersion"),
                publisher: read_string_value(&sk, "Publisher"),
                install_date_raw: read_string_value(&sk, "InstallDate"),
                install_location: read_string_value(&sk, "InstallLocation"),
                uninstall_string: read_string_value(&sk, "UninstallString"),
                quiet_uninstall_string: read_string_value(&sk, "QuietUninstallString"),
                display_icon: read_string_value(&sk, "DisplayIcon"),
                windows_installer: read_string_value(&sk, "WindowsInstaller"),
                local_package: read_string_value(&sk, "LocalPackage"),
                registry_hive: hive_name.to_string(),
                registry_subkey: format!("{key_path}\\{sub_name}"),
            });
        }
    }
    entries
}

/// Reads both `Run` keys (HKLM and HKCU) into [`scan_system_core::StartupEntry`] —
/// deliberately not the Startup-folder shortcuts the Python original also scans
/// (`%APPDATA%\...\Startup`, filesystem globbing, not registry) — that half lives in
/// `scan-system-platform::filesystem` alongside it once that module exists, kept
/// separate here since this function is specifically the registry half.
#[must_use]
pub fn startup_run_entries() -> Vec<StartupEntry> {
    const RUN_KEYS: &[(winreg::HKEY, &str, &str)] = &[
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM",
        ),
        (
            HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU",
        ),
    ];

    let mut entries = Vec::new();
    for &(hive, key_path, hive_name) in RUN_KEYS {
        let root = RegKey::predef(hive);
        let Ok(key) = root.open_subkey(key_path) else {
            continue;
        };
        for (name, value) in key.enum_values().filter_map(Result::ok) {
            entries.push(StartupEntry {
                source: format!("{hive_name}\\{key_path}"),
                name,
                command: value.to_string(),
            });
        }
    }
    entries
}

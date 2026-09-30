//! Throwaway smoke test against the real machine's registry/Defender — not part of the
//! crate's public surface, deleted once phase 2 has its own CLI to do this properly.

use std::time::Duration;

use scan_system_platform::{
    common_scan_paths, detect_windows_theme, is_startup_monitoring_enabled,
    iter_uninstall_registry, startup_run_entries, AuditHandle,
};

fn main() {
    println!("theme: {}", detect_windows_theme());
    println!(
        "startup monitoring enabled: {}",
        is_startup_monitoring_enabled()
    );

    let uninstall = iter_uninstall_registry();
    println!("uninstall registry entries: {}", uninstall.len());
    for entry in uninstall.iter().take(3) {
        println!(
            "  - {} ({}) [{}]",
            entry.display_name, entry.display_version, entry.registry_hive
        );
    }

    let startup = startup_run_entries();
    println!("startup run entries: {}", startup.len());
    for entry in &startup {
        println!("  - {} | {} | {}", entry.source, entry.name, entry.command);
    }

    let paths = common_scan_paths();
    println!("common scan paths: {paths:?}");

    let handle = AuditHandle::new();
    match handle.run_powershell(
        "Get-MpComputerStatus | Select AntivirusEnabled | ConvertTo-Json",
        Duration::from_secs(30),
    ) {
        Ok(out) => println!("defender ok={} output={}", out.ok, out.output),
        Err(e) => println!("defender call error: {e}"),
    }
}

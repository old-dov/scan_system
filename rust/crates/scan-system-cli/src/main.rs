//! CLI counterpart of `scanner_windows.py main()`. The GUI is a later phase.
#![cfg(windows)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::Parser;
use scan_system_audit::{audit_is_complete, generate_report, save_reports, AuditOptions};
use scan_system_platform::AuditHandle;

#[derive(Debug, Parser)]
#[command(
    about = "Audit securite Windows: Defender + installations + persistence + reseau",
    arg_required_else_help = true
)]
struct Args {
    /// Nombre de jours a inspecter (1 a 180, defaut 14)
    #[arg(long, default_value_t = 14)]
    days: i64,

    /// Dossier de sortie des rapports
    #[arg(long, default_value = "reports")]
    output: PathBuf,

    /// Ne pas forcer la mise a jour des signatures Defender
    #[arg(long)]
    skip_signature_update: bool,

    /// Ne pas lancer les scans Defender rapide et cibles
    #[arg(long)]
    skip_quick_scan: bool,
}

fn default_reports_dir() -> PathBuf {
    let base = env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("ScanSystem").join("reports")
}

fn resolve_output_dir(raw: &Path) -> std::io::Result<PathBuf> {
    // Preserve Python's relative-path rule, including its default `reports`
    // subdirectory beneath the application's default reports directory.
    let fallback = default_reports_dir();
    let requested = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        fallback.join(raw)
    };
    if fs::create_dir_all(&requested).is_ok() {
        Ok(requested)
    } else {
        fs::create_dir_all(&fallback)?;
        Ok(fallback)
    }
}

fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let days = args.days.clamp(1, 180);
    let output_dir = resolve_output_dir(&args.output)?;
    println!("[+] Demarrage audit securite...");
    println!("    - Fenetre d'analyse: {days} jours");
    println!("    - Dossier rapport: {}", output_dir.display());

    let handle = AuditHandle::new();
    let report = generate_report(
        &handle,
        AuditOptions {
            days,
            update_signatures: !args.skip_signature_update,
            run_quick_scan: !args.skip_quick_scan,
        },
        Some(&output_dir),
        |label, percent| println!("[{percent}%] {label}"),
    )?;
    let (json_path, txt_path) = save_reports(&report, &output_dir)?;
    println!("[+] Audit termine");
    println!("    - Rapport JSON: {}", json_path.display());
    println!("    - Rapport TXT : {}", txt_path.display());
    if !audit_is_complete(&report) {
        println!("[!] Audit incomplet : une collecte, un scan ou un flux de menaces a echoue. Verifie le JSON avant d'interpreter le score.");
        return Ok(());
    }
    match report["risk"]["risk_score_100"].as_u64().unwrap_or(0) {
        60.. => println!("[!] Niveau de risque eleve: isole le PC du reseau et lance un scan complet hors ligne."),
        30..=59 => println!("[!] Niveau de risque modere: verifie les installations recentes et les taches/services."),
        _ => println!("[+] Aucun signal fort detecte dans cet audit, reste vigilant."),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Erreur audit: {error}");
            ExitCode::FAILURE
        }
    }
}

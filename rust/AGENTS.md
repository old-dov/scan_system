# scan_system — Rust migration — brief pour Codex

Ce fichier existe pour donner à un agent qui démarre à froid (Codex) le contexte
qu'un agent Claude Code a accumulé sur ce projet au fil de plusieurs sessions.
Lis-le avant de toucher au code.

## Le projet, en une phrase

`scan_system` est un scanner de sécurité Windows perso de l'utilisateur (repo
public `old-dov/scan_system`), écrit à l'origine en Python
(`scanner_windows.py`, racine du repo), packagé en `.exe` (PyInstaller) +
installeur Inno Setup, avec CI/release GitHub Actions déjà en place côté
Python. Ce dossier `rust/` est une réécriture complète en Rust, en cours,
**pas encore terminée, pas encore mergée sur main**.

## Où on en est (vérifié dans le code, pas juste dans la mémoire)

Branche git : `rust-migration` (locale, **pas encore pushée sur origin** —
vérifie avant de supposer qu'elle existe côté remote).

Deux crates livrées et testées :

- `scan-system-core` (commit `55cf6ba`) : port 1:1 des fonctions pures
  (`suspicious_score`, `looks_suspicious_text`, `is_public_ipv4`,
  `format_rate`, `build_threat_feed_ip_set`, `parse_any_datetime`,
  `startup_fingerprint`) + les 30 tests portés depuis
  `tests/test_scoring.py`. Testable sans machine Windows (logique pure).
- `scan-system-platform` (commit `8a98e96`, partie 1/3 de la phase 2) :
  `process.rs` (exécution annulable, fenêtre cachée `CREATE_NO_WINDOW`,
  décodage codepage OEM via `GetOEMCP`/`MultiByteToWideChar` — réplique le fix
  `encoding="oem"` du Python pour les accents dans les messages
  `Get-WinEvent`), `registry.rs` (thème, démarrage auto, énumération
  Uninstall sur 3 ruches, entrées Run), `defender.rs` (cmdlets `Mp*`, gardés
  en `serde_json::Value` non typé comme l'original Python), `events.rs`
  (installs récents, événements de persistance récents, parsing de date
  d'install). Vérifié contre le vrai système (227 vraies entrées Uninstall,
  13 vraies entrées Run, vrai appel Defender).

## Reste à faire (le plan complet en 4 phases)

1. ~~`scan-system-core`~~ — FAIT.
2. `scan-system-platform` (registre/Defender, FAIT ci-dessus) +
   **`scan-system-sysmon`** (netstat2 + sysinfo, pas commencé) +
   **`scan-system-audit`** (orchestration, équivalent de `generate_report()`,
   pas commencé) + **`scan-system-cli`** (clap, pas commencé).
3. **`scan-system-gui`** — iced (architecture Elm) + `tray-icon`. Choix
   assumé par l'utilisateur malgré un coût de portage plus élevé qu'egui,
   pour une architecture d'état plus propre à terme. Pas commencé, la phase
   la plus grosse/risquée du plan.
4. **Packaging/release** — adapter `installer.iss`/`ci.yml`/`release.yml`
   (actuellement pensés pour PyInstaller) vers `cargo build --release`. Pas
   commencé.

## Contraintes de compatibilité — ne pas casser

- `AppId` Inno Setup (doit rester identique pour que les mises à jour
  s'installent par-dessus proprement).
- Dossier `%LOCALAPPDATA%\ScanSystem`.
- Format des rapports JSON/TXT généré (des scripts/habitudes existent peut-être
  dessus).
- Le prompt de suppression des données à la désinstallation.
- **Pas de signature de code.** Décision assumée de l'utilisateur (revisiter
  seulement s'il change de statut pro — freelance, société). Ne pas proposer
  de certificat de signature, ne pas signaler l'absence de signature comme un
  blocage.

## Environnement de build

- Toolchain Rust installée nativement sur Windows (rustup, MSVC stable) —
  utilisée pour la phase 2 (accès registre/Defender réels). La phase 1 a
  aussi été validée sous WSL (logique pure, portable).
- `cargo test` / `cargo clippy -D warnings` / `cargo fmt --check` doivent
  rester verts avant tout commit — c'est la barre que Claude Code a tenue sur
  tout ce qui est livré jusqu'ici.
- Une divergence assumée : `parse_any_datetime` (dans `scan-system-core`)
  retourne toujours un `NaiveDateTime`, jamais tantôt aware tantôt naive comme
  le faisait la version Python — documenté dans `time.rs`, sans impact
  observé (tous les appelants comparent déjà contre un `now()` naïf).

## Ce qui n'est PAS dans ce dossier

- Le Python original (`scanner_windows.py`, `tests/`, `installer.iss`,
  `build_exe.bat`, `build_installer.bat`, `.github/workflows/`) vit un niveau
  au-dessus, à la racine du repo — **continue de fonctionner en parallèle**
  jusqu'à parité complète. Pas de big-bang : ne supprime rien côté Python
  sans feu vert explicite de l'utilisateur.

## Style de code attendu

Le code déjà livré suit un style précis (à observer dans `scan-system-core`
et `scan-system-platform` avant d'écrire du nouveau code) : commentaires qui
expliquent le *pourquoi* d'un choix (pas juste le *quoi*), fonctions
documentées avec `///`, tests unitaires systématiques pour toute logique
portée depuis le Python, honnêteté explicite sur les divergences de
comportement plutôt que de les cacher.

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

Branche git : `rust-migration` (suit actuellement `origin/rust-migration` ;
vérifie son état avant de supposer que les modifications locales sont poussées).

Crates livrées et testées :

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
- `scan-system-sysmon` (travail local en cours, non commité) : port de la collecte
  CPU/débit réseau et des connexions IPv4 publiques via `sysinfo` et `netstat2`,
  avec instantanés d'audit et temps réel. Les clés de rapport Python sont
  préservées. Tests du workspace, Clippy et formatage verts ; lecture réelle
  Windows validée (43 connexions publiques observées au dernier essai). Les
  contrôles de persistance du sondage temps réel sont intégrés à la GUI par
  `RealtimePersistenceMonitor` (entrées startup et événements tâches/services).
- `scan-system-audit` et `scan-system-cli` (travail local non commité) :
  orchestration de `generate_report`, score, entrées Run et dossiers Startup,
  hachage SHA-256, rapports JSON/TXT, cache des deux flux de menaces et CLI
  `clap` avec `--days`, `--output` et les deux options de saut des scans.
  Parcours d'audit local validé avec mises à jour et scans désactivés, puis
  exécution CLI avec écriture JSON/TXT dans `rust/target/` : état Defender lu,
  deux flux téléchargés, cache et rapports créés. L'exécution a montré 15
  détections enregistrées par Defender et 0 correspondance des connexions
  avec les flux ; l'ancien score élevé provenait donc de ces détections et
  des événements de service, pas d'une correspondance réseau. Le 30 septembre,
  un interpréteur a été retrouvé dans `.venv` et un audit comparé a été réalisé
  sur le même poste avec `--skip-signature-update --skip-quick-scan` : même
  score (95), mêmes raisons, mêmes nombres de détections Defender (25),
  installations (7), services (10), entrées de démarrage (16) et entrées dans
  les deux flux (1 + 632). Les chemins de champs JSON et les sections TXT
  concordent. Les connexions publiques variaient de 10 à 9 entre deux relevés
  successifs. Rapports dans `rust/target/parity-python` et
  `rust/target/parity-rust-elevated`.
  Après ce contrôle, le score a été corrigé dans Python et Rust : les
  détections dont l'action Defender a réussi et dont l'exécution est bloquée
  ou arrêtée restent dans l'historique sans ajouter de points. Le rapport du
  30 septembre qui donnait 95 donne désormais 35 (7 installations récentes,
  10 services). La CLI Rust a été relancée et confirme ce score ; les 25
  détections restent présentes dans le JSON.

## Reste à faire (le plan complet en 4 phases)

1. ~~`scan-system-core`~~ — FAIT.
2. `scan-system-platform`, `scan-system-sysmon`, `scan-system-audit` et
   `scan-system-cli` sont présents. Un premier audit comparé Rust/Python sur
   la même machine est validé, sans scan Defender. Restent la comparaison du
   parcours complet et la validation des alertes de persistance sur le poste
   avant de considérer la phase 2 comme achevée. Le format `/Date(...)/` émis
   par `Get-WinEvent` sous Windows PowerShell 5.1 est désormais décodé dans
   Python et Rust. Le 30 septembre, un test utilisateur de création d'entrée Run
   temporaire a confirmé l'affichage « Nouvelle entree startup detectee » dans
   Temps réel de la GUI Rust. Les rapports avant/après ont le même score 35 ;
   le script avait supprimé l'entrée temporaire avant le second rapport.
3. **`scan-system-gui`** — iced (architecture Elm) + `tray-icon`. Choix
   assumé par l'utilisateur malgré un coût de portage plus élevé qu'egui.
   Première interface locale compilée : quatre onglets, lancement et annulation
   d'audit, lecture des menaces, moniteur temps réel persistant, rapports et
   icône de notification avec ouverture/quitter. Les actions Defender manuelles
   (nettoyage, scan complet, scan hors ligne) demandent confirmation avant
   exécution. Le sondage de persistance et l'historique récent des alertes sont
   présents. Le lancement avec Windows utilise une valeur Run distincte de
   celle du Python et démarre l'interface réduite avec le monitoring actif.
   L'envoi d'une notification Windows par l'icône de zone de notification est
   codé, compilé et son affichage dans la barre des tâches a été confirmé par
   l'utilisateur. Les autres parcours interactifs de l'interface restent à
   vérifier.
4. **Packaging/release** — `installer_rust.iss`, `rust/build_release.ps1` et
   `rust-ci.yml` préparent une construction Rust séparée, sans toucher au
   packaging Python. La compilation Inno Setup passe désormais sans avertissement
   `HKCU` : l'installateur ne modifie plus directement les valeurs Run du profil.
   La GUI migre l'ancienne entrée de démarrage dans la session de l'utilisateur
   lorsque son chemin correspond exactement à l'exécutable installé. La migration
   réelle depuis Python a été validée localement : installation Python 1.0.0,
   entrée de démarrage `ScanSystemMonitor`, mise à jour par l'installateur Rust
   Inno Setup 7.1.0 stable, puis premier lancement Rust qui a remplacé l'entrée
   par `ScanSystemRustMonitor`. Un fichier témoin dans les données a été conservé.
   La désinstallation silencieuse a retiré l'application et l'entrée Rust ; le
   témoin temporaire a ensuite été supprimé. Le script de build
   refuse le compilateur Inno Setup preview local ; la CI prépare un installateur
   de test avec Inno Setup stable
   comme artefact, sans publier de release. Aucun workflow Rust ne publie de release.

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

# Migration Rust de ScanSystem

Cette branche porte progressivement le scanner Windows Python. Le code Python,
ses installateurs et ses workflows restent utilisables pendant la migration.

## Crates

- `scan-system-core` : règles pures de score, texte, réseau et dates.
- `scan-system-platform` : registre, Defender, journaux Windows, pare-feu et
  exécution PowerShell annulable.
- `scan-system-sysmon` : CPU, débits réseau et connexions IPv4 publiques.
- `scan-system-audit` : rapport d'audit, flux de menaces, score et sorties JSON/TXT.
- `scan-system-cli` : point d'entrée en ligne de commande.
- `scan-system-gui` : interface iced avec onglets Audit, Menaces, Temps réel et Rapports.

## Vérification sans scan Defender ni téléchargement

Depuis `rust/`, sous Windows :

```powershell
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo run -p scan-system-audit --example audit_smoke
```

L'exemple lit l'état Defender, les installations, les journaux, les démarrages
et les connexions du poste, mais n'écrit aucun rapport et ne télécharge pas de
flux de menaces. Il n'affiche que des comptes et le score.

## CLI

```powershell
cargo run -p scan-system-cli -- --help
cargo run -p scan-system-cli -- --days 14 --skip-signature-update --skip-quick-scan
```

Sans argument, la CLI affiche l'aide ; l'interface Rust se lance avec le binaire
séparé ci-dessous. La seconde commande exécute un audit, télécharge les deux flux de menaces et
écrit les rapports JSON/TXT dans le dossier de l'application. Sans options de
saut, elle lance aussi la mise à jour des signatures et les scans Defender.
Un premier audit comparé au Python sur le même poste a validé la structure
des rapports et le score avec les scans Defender désactivés. Le parcours
complet doit encore être comparé avant publication.

Le score conserve les détections Defender dans le rapport, mais ne pénalise
plus celles dont l'action de nettoyage a réussi et dont l'exécution est
bloquée ou arrêtée. Les détections incertaines ou non résolues restent
comptées.

Le suivi détaillé et les contraintes de compatibilité sont dans `AGENTS.md`.

## Interface graphique

```powershell
cargo run -p scan-system-gui
```

L'audit demande une action explicite. L'onglet Temps réel peut suivre les
connexions toutes les deux secondes et vérifie les nouveaux éléments de
persistance environ une fois par minute. La fermeture de la fenêtre la masque dans
la zone de notification ; son menu permet de l'ouvrir ou de quitter. Cette
première interface inclut les actions Defender manuelles avec confirmation.
L'option « Lancer avec Windows » inscrit uniquement le binaire Rust au démarrage
avec `--monitoring-enabled --start-minimized`, sans modifier l'entrée Python.
Le menu déroulant de langue propose Français et English. Le choix est conservé dans
`%LOCALAPPDATA%\ScanSystem\ui_language.txt` ; l'installateur définit la langue
initiale d'après sa langue d'installation. `--lang=fr` et `--lang=en` permettent
de forcer une langue au lancement. L'interface suit le thème clair ou sombre de
Windows, y compris lorsque celui-ci change pendant son exécution.
Les nouvelles anomalies du moniteur apparaissent dans Temps réel et demandent
une notification Windows via l'icône de la zone de notification. Windows peut
masquer ces notifications selon ses réglages. Un test utilisateur a confirmé
l'affichage dans la barre des tâches le 30 septembre 2026.

## Préparer les binaires de release

Depuis la racine du dépôt :

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\rust\build_release.ps1 -SkipInstaller
```

Avec Inno Setup 6 stable installé, retirer `-SkipInstaller` prépare l'installateur
`rust/installer_output/ScanSystemRustSetup-1.1.1.exe`. Il désinstalle la version
précédente portant le même AppId avant de copier les nouveaux binaires. La
désinstallation silencieuse conserve `%LOCALAPPDATA%\ScanSystem` et ses rapports.
Un compilateur stable installé ailleurs peut être passé avec `-IsccPath` ; le
script refuse les versions preview ou beta. La CI Rust conserve l'installateur
construit avec Inno Setup stable comme artefact de test, sans publier de release.
L'installateur ne modifie pas directement le profil utilisateur. Au premier
lancement de la GUI installée, une ancienne entrée `ScanSystemMonitor` pointant
vers le même exécutable est transférée à `ScanSystemRustMonitor`. La migration
depuis Python encore installé a été validée localement avec Python 1.0.0 et
l'installateur Rust construit par Inno Setup 7.1.0 stable. Au premier lancement,
l'entrée de démarrage Python a été remplacée par l'entrée Rust. Un fichier témoin
dans `%LOCALAPPDATA%\ScanSystem` a survécu à la mise à jour. La désinstallation
silencieuse a ensuite supprimé l'application et l'entrée de démarrage Rust.
À la désinstallation, seules les entrées de démarrage du profil courant qui
pointent vers l'exécutable installé sont supprimées. Le prompt de suppression
des données montre le chemin exact du profil concerné.

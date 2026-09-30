#![cfg(windows)]
#![windows_subsystem = "windows"]

use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{mpsc, Arc, LazyLock},
    thread,
    time::{Duration, Instant},
};

use iced::{
    time,
    widget::{
        button, canvas, checkbox, column, container, image, pick_list, progress_bar, row,
        scrollable, text, text_input,
    },
    window, Color, Element, Fill, Point, Rectangle, Renderer, Subscription, Task, Theme,
};
use scan_system_audit::{
    audit_is_complete, defender_detection_needs_attention, generate_report, save_reports,
    AuditOptions, RealtimePersistenceMonitor,
};
use scan_system_core::format_rate;
use scan_system_platform::{
    defender_full_scan, defender_offline_scan, defender_remove_threats, defender_threat_detections,
    detect_windows_theme, is_rust_startup_monitoring_enabled, migrate_legacy_startup_monitoring,
    set_rust_startup_monitoring_enabled, AuditHandle,
};
use scan_system_sysmon::{NetworkSnapshot, RealtimeMonitor};
use serde_json::Value;
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem},
    Icon, TrayIcon, TrayIconBuilder, TrayIconEvent,
};
use windows_sys::{
    core::GUID,
    Win32::UI::Shell::{
        Shell_NotifyIconW, NIF_GUID, NIF_INFO, NIIF_WARNING, NIM_MODIFY, NOTIFYICONDATAW,
    },
};

// A stable identity lets Windows address this tray icon even though tray-icon's
// numeric identifier is private and changes between application launches.
const TRAY_GUID: u128 = 0x920b6103_f18c_46ae_9aef_75e2d9c0f438;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Audit,
    Threats,
    Realtime,
    Reports,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Language {
    French,
    English,
}

impl Language {
    fn choose(self, french: &'static str, english: &'static str) -> &'static str {
        if self == Self::English {
            english
        } else {
            french
        }
    }
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::French => "Français",
            Self::English => "English",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThreatAction {
    Cleanup,
    FullScan,
    OfflineScan,
}

impl ThreatAction {
    fn label(self, language: Language) -> &'static str {
        match self {
            Self::Cleanup => language.choose("Nettoyage Defender", "Defender cleanup"),
            Self::FullScan => language.choose("Scan complet Defender", "Full Defender scan"),
            Self::OfflineScan => {
                language.choose("Scan hors ligne Defender", "Offline Defender scan")
            }
        }
    }

    fn confirmation(self, language: Language) -> &'static str {
        match self {
            Self::Cleanup => language.choose("Defender traitera toutes les menaces actives connues sur cette machine. Continuer ?", "Defender will process all known active threats on this computer. Continue?"),
            Self::FullScan => language.choose("Lancer un scan complet Defender ? Il peut durer longtemps.", "Start a full Defender scan? It may take a while."),
            Self::OfflineScan => language.choose("Demander un scan hors ligne Defender ? Windows peut demander un redémarrage.", "Start an offline Defender scan? Windows may need to restart."),
        }
    }
}

#[derive(Debug, Clone)]
enum Message {
    Page(Page),
    Language(Language),
    DaysChanged(String),
    OutputChanged(String),
    UpdateSignatures(bool),
    QuickScan(bool),
    StartAudit,
    CancelAudit,
    RefreshThreats,
    RequestThreatAction(ThreatAction),
    ConfirmThreatAction,
    CancelThreatAction,
    RefreshRealtime,
    MonitoringChanged(bool),
    StartupChanged(bool),
    RefreshReports,
    OpenReportsFolder,
    OpenReport(PathBuf),
    CloseRequested(window::Id),
    RestoreWindow(Option<window::Id>),
    Tick,
}

#[derive(Debug)]
struct AuditResult {
    report: Value,
    json_path: PathBuf,
    txt_path: PathBuf,
}

enum WorkerEvent {
    Progress(String, u8),
    AuditFinished(Result<AuditResult, String>),
    ThreatsFinished(Result<Vec<Value>, String>),
    ThreatActionFinished(ThreatAction, Result<String, String>),
    RealtimeFinished(NetworkSnapshot),
}

enum RealtimeCommand {
    Snapshot,
    Monitoring(bool),
}

struct State {
    page: Page,
    language: Language,
    dark: bool,
    last_theme_check: Instant,
    days: String,
    output: String,
    update_signatures: bool,
    quick_scan: bool,
    audit_running: bool,
    audit_started: Option<Instant>,
    progress: f32,
    audit_status: String,
    log: Vec<String>,
    handle: Arc<AuditHandle>,
    sender: mpsc::Sender<WorkerEvent>,
    receiver: mpsc::Receiver<WorkerEvent>,
    threats: Vec<Value>,
    threats_loading: bool,
    threats_loaded: bool,
    threat_action_running: bool,
    threat_action_started: Option<Instant>,
    pending_threat_action: Option<ThreatAction>,
    threat_status: String,
    realtime: Option<NetworkSnapshot>,
    anomaly_history: Vec<String>,
    last_anomaly: HashMap<String, Instant>,
    realtime_loading: bool,
    monitoring_enabled: bool,
    startup_enabled: bool,
    startup_status: String,
    realtime_sender: mpsc::Sender<RealtimeCommand>,
    reports: Vec<PathBuf>,
    tray: Option<TrayIcon>,
    tray_attempted: bool,
    initially_hidden: bool,
}

struct GeometryMark;

static APP_LOGO: LazyLock<image::Handle> = LazyLock::new(|| {
    image::Handle::from_bytes(include_bytes!("../../../../pictures/icon_128x128.png").as_slice())
});

fn app_icon() -> window::Icon {
    let logo = ::image::load_from_memory(include_bytes!("../../../../pictures/icon_32x32.png"))
        .expect("valid Scan System logo")
        .into_rgba8();
    window::icon::from_rgba(logo.into_raw(), 32, 32).expect("valid Scan System window icon")
}

impl canvas::Program<Message> for GeometryMark {
    type State = ();

    fn draw(
        &self,
        _state: &Self::State,
        renderer: &Renderer,
        theme: &Theme,
        bounds: Rectangle,
        _cursor: iced::mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let color = if theme.palette().background.relative_luminance() > 0.5 {
            Color::from_rgb8(227, 228, 228)
        } else {
            Color::from_rgb8(101, 116, 131)
        };
        let stroke = canvas::Stroke::default().with_color(color).with_width(1.0);
        for (from, to) in [
            ((0.0, 0.0), (120.0, 76.0)),
            ((40.0, 0.0), (120.0, 52.0)),
            ((0.0, 56.0), (32.0, 76.0)),
            ((120.0, 0.0), (0.0, 76.0)),
        ] {
            frame.stroke(
                &canvas::Path::line(Point::new(from.0, from.1), Point::new(to.0, to.1)),
                stroke,
            );
        }
        vec![frame.into_geometry()]
    }
}

impl State {
    fn new(
        auto_monitoring: bool,
        start_hidden: bool,
        requested_language: Option<Language>,
    ) -> Self {
        if let Ok(exe) = env::current_exe() {
            let _ = migrate_legacy_startup_monitoring(&exe);
        }
        let language = requested_language
            .or_else(|| read_language(&user_language_path()))
            .or_else(|| read_language(&installed_language_path()))
            .unwrap_or(Language::French);
        let (sender, receiver) = mpsc::channel();
        let (realtime_sender, realtime_receiver) = mpsc::channel();
        let worker_sender = sender.clone();
        thread::spawn(move || realtime_worker(realtime_receiver, worker_sender));
        if auto_monitoring {
            let _ = realtime_sender.send(RealtimeCommand::Monitoring(true));
        }
        let output = default_reports_dir()
            .join("reports")
            .to_string_lossy()
            .into_owned();
        let mut state = Self {
            page: Page::Audit,
            language,
            dark: detect_windows_theme() == "dark",
            last_theme_check: Instant::now(),
            days: "14".into(),
            output,
            update_signatures: true,
            quick_scan: true,
            audit_running: false,
            audit_started: None,
            progress: 0.0,
            audit_status: language.choose("Prêt", "Ready").into(),
            log: Vec::new(),
            handle: Arc::new(AuditHandle::new()),
            sender,
            receiver,
            threats: Vec::new(),
            threats_loading: false,
            threats_loaded: false,
            threat_action_running: false,
            threat_action_started: None,
            pending_threat_action: None,
            threat_status: String::new(),
            realtime: None,
            anomaly_history: Vec::new(),
            last_anomaly: HashMap::new(),
            realtime_loading: false,
            monitoring_enabled: auto_monitoring,
            startup_enabled: is_rust_startup_monitoring_enabled(),
            startup_status: String::new(),
            realtime_sender,
            reports: Vec::new(),
            tray: None,
            tray_attempted: false,
            initially_hidden: start_hidden,
        };
        state.load_reports();
        state
    }

    fn load_reports(&mut self) {
        let Ok(output_dir) = resolve_output_dir(&self.output) else {
            self.reports.clear();
            return;
        };
        let Ok(items) = fs::read_dir(output_dir) else {
            self.reports.clear();
            return;
        };
        let mut paths: Vec<PathBuf> = items
            .filter_map(Result::ok)
            .map(|item| item.path())
            .filter(|path| {
                path.extension().is_some_and(|ext| ext == "json")
                    && path
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy().starts_with("scan_report_"))
            })
            .collect();
        paths.sort_by(|a, b| b.cmp(a));
        self.reports = paths;
    }

    fn append_log(&mut self, message: impl Into<String>) {
        self.log.push(message.into());
        if self.log.len() > 300 {
            self.log.drain(..self.log.len() - 300);
        }
    }

    fn process_events(&mut self) {
        while let Ok(event) = self.receiver.try_recv() {
            match event {
                WorkerEvent::Progress(label, percent) => {
                    self.progress = f32::from(percent);
                    self.audit_status =
                        format!("{} ({percent}%)", progress_label(self.language, &label));
                }
                WorkerEvent::AuditFinished(result) => {
                    self.audit_running = false;
                    match result {
                        Ok(done) => {
                            self.progress = 100.0;
                            let risk = done.report["risk"]["risk_score_100"].as_u64().unwrap_or(0);
                            let complete = audit_is_complete(&done.report);
                            self.audit_status = format!(
                                "{} {risk}/100",
                                if complete {
                                    self.language.choose("Terminé · score", "Complete · score")
                                } else {
                                    self.language.choose(
                                        "Audit incomplet · score partiel",
                                        "Incomplete audit · partial score",
                                    )
                                }
                            );
                            if !complete {
                                self.append_log(self.language.choose(
                                    "Collecte Defender, scan ou flux de menaces en échec : vérifier le JSON.",
                                    "Defender collection, scan, or threat feed failed: check the JSON.",
                                ));
                            }
                            self.append_log(format!(
                                "{} {}",
                                self.language.choose("Rapport JSON :", "JSON report:"),
                                done.json_path.display()
                            ));
                            self.append_log(format!(
                                "{} {}",
                                self.language.choose("Rapport TXT :", "TXT report:"),
                                done.txt_path.display()
                            ));
                            self.append_log(format!(
                                "{} {risk}/100",
                                self.language.choose("Score de risque :", "Risk score:")
                            ));
                            self.threats = done.report["defender_threat_detections"]["data"]
                                .as_array()
                                .cloned()
                                .unwrap_or_default();
                            self.threats_loaded = true;
                            self.load_reports();
                        }
                        Err(error) if self.handle.is_cancelled() => {
                            self.audit_status = self
                                .language
                                .choose("Audit annulé", "Audit cancelled")
                                .into();
                            self.append_log(self.language.choose("Audit annulé ; un scan Defender déjà lancé peut continuer côté Windows.", "Audit cancelled; a Defender scan already started may continue in Windows."));
                            self.append_log(error);
                        }
                        Err(error) => {
                            self.audit_status = self
                                .language
                                .choose("Échec de l'audit", "Audit failed")
                                .into();
                            self.append_log(format!(
                                "{} {error}",
                                self.language.choose("Erreur :", "Error:")
                            ));
                        }
                    }
                }
                WorkerEvent::ThreatsFinished(result) => {
                    self.threats_loading = false;
                    match result {
                        Ok(items) => {
                            self.threats = items;
                            self.threats_loaded = true;
                        }
                        Err(error) => self.append_log(format!(
                            "{} {error}",
                            self.language
                                .choose("Lecture des menaces :", "Threat retrieval:")
                        )),
                    }
                }
                WorkerEvent::ThreatActionFinished(action, result) => {
                    self.threat_action_running = false;
                    self.threat_action_started = None;
                    match result {
                        Ok(output) => {
                            self.threat_status = format!(
                                "{} {}",
                                action.label(self.language),
                                self.language.choose("terminé", "complete")
                            );
                            self.append_log(format!("{} : {output}", action.label(self.language)));
                        }
                        Err(error) => {
                            self.threat_status = format!(
                                "{} {}",
                                action.label(self.language),
                                self.language.choose("échoué", "failed")
                            );
                            self.append_log(format!("{} : {error}", action.label(self.language)));
                        }
                    }
                }
                WorkerEvent::RealtimeFinished(snapshot) => {
                    self.realtime_loading = false;
                    for anomaly in &snapshot.anomalies {
                        let key = anomaly_kind(anomaly);
                        let now = Instant::now();
                        if self
                            .last_anomaly
                            .get(key)
                            .is_some_and(|last| now.duration_since(*last) < Duration::from_secs(60))
                        {
                            continue;
                        }
                        self.last_anomaly.insert(key.to_owned(), now);
                        self.anomaly_history.push(anomaly.clone());
                        if let Some(tray) = &self.tray {
                            if !notify_anomaly(tray, &anomaly_display(self.language, anomaly)) {
                                self.append_log(self.language.choose(
                                    "Notification Windows indisponible",
                                    "Windows notification unavailable",
                                ));
                            }
                        }
                        if self.anomaly_history.len() > 20 {
                            self.anomaly_history.remove(0);
                        }
                    }
                    self.realtime = Some(snapshot);
                }
            }
        }
    }

    fn ensure_tray(&mut self) {
        if self.tray_attempted {
            return;
        }
        self.tray_attempted = true;
        match create_tray(self.language) {
            Ok(tray) => self.tray = Some(tray),
            Err(error) => self.append_log(format!(
                "{} {error}",
                self.language.choose(
                    "Icône de notification indisponible :",
                    "Tray icon unavailable:"
                )
            )),
        }
    }
}

fn progress_label(language: Language, label: &str) -> &str {
    if language == Language::French {
        return label;
    }
    match label {
        "Etat Defender..." => "Checking Defender status...",
        "Mise a jour des signatures Defender..." => "Updating Defender signatures...",
        "Scan rapide Defender..." => "Running Defender quick scan...",
        "Scan cible Defender..." => "Running Defender targeted scan...",
        "Menaces detectees..." => "Checking detected threats...",
        "Installations recentes..." => "Checking recent installations...",
        "Services et taches recents..." => "Checking recent services and tasks...",
        "Mise a jour des flux de menaces..." => "Updating threat feeds...",
        "Audit reseau..." => "Auditing network...",
        "Entrees de demarrage..." => "Checking startup entries...",
        "Termine" => "Complete",
        _ => label,
    }
}

fn anomaly_display(language: Language, anomaly: &str) -> String {
    if language == Language::French {
        return anomaly.into();
    }
    let prefixes = [
        ("CPU eleve soutenu:", "Sustained high CPU:"),
        ("CPU eleve:", "High CPU:"),
        ("Debit reseau eleve:", "High network traffic:"),
        (
            "Connexion potentiellement suspecte:",
            "Potentially suspicious connection:",
        ),
        (
            "Lecture connexions echouee:",
            "Connection retrieval failed:",
        ),
        ("Lecture persistance échouée :", "Persistence check failed:"),
        (
            "Nouvelle entree startup detectee:",
            "New startup entry detected:",
        ),
        (
            "Nouvelle tache planifiee suspecte detectee",
            "New suspicious scheduled task detected",
        ),
        (
            "Nouveau service potentiellement suspect detecte",
            "New potentially suspicious service detected",
        ),
    ];
    for (french, english) in prefixes {
        if let Some(rest) = anomaly.strip_prefix(french) {
            return format!("{english}{rest}");
        }
    }
    if anomaly.starts_with("IP ") && anomaly.contains(" presente dans une liste de blocage menace")
    {
        return anomaly
            .replace(
                " presente dans une liste de blocage menace",
                " found in a threat blocklist",
            )
            .replace("(processus: inconnu)", "(process: unknown)")
            .replace("(processus:", "(process:");
    }
    anomaly.into()
}

fn anomaly_kind(message: &str) -> &str {
    if message.starts_with("CPU eleve") || message.starts_with("Debit reseau eleve") {
        message.split_once(':').map_or(message, |(kind, _)| kind)
    } else {
        message
    }
}

fn realtime_worker(receiver: mpsc::Receiver<RealtimeCommand>, sender: mpsc::Sender<WorkerEvent>) {
    let mut monitor = RealtimeMonitor::new();
    let mut persistence = RealtimePersistenceMonitor::new();
    let persistence_handle = AuditHandle::new();
    let mut monitoring = false;
    loop {
        match receiver.recv_timeout(Duration::from_secs(2)) {
            Ok(RealtimeCommand::Snapshot) => {}
            Ok(RealtimeCommand::Monitoring(enabled)) => {
                monitoring = enabled;
                if !enabled {
                    continue;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) if monitoring => {}
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        let mut snapshot = monitor.snapshot();
        match persistence.poll(&persistence_handle) {
            Ok(anomalies) => snapshot.anomalies.extend(anomalies),
            Err(error) => snapshot
                .anomalies
                .push(format!("Lecture persistance échouée : {error}")),
        }
        if sender
            .send(WorkerEvent::RealtimeFinished(snapshot))
            .is_err()
        {
            break;
        }
    }
}

fn create_tray(language: Language) -> Result<TrayIcon, String> {
    let logo = ::image::load_from_memory(include_bytes!("../../../../pictures/icon_32x32.png"))
        .map_err(|error| error.to_string())?
        .into_rgba8();
    let icon = Icon::from_rgba(logo.into_raw(), 32, 32).map_err(|error| error.to_string())?;
    let open = MenuItem::with_id(
        "open",
        language.choose("Ouvrir Scan System", "Open Scan System"),
        true,
        None,
    );
    let quit = MenuItem::with_id("quit", language.choose("Quitter", "Quit"), true, None);
    let menu = Menu::with_items(&[&open, &quit]).map_err(|error| error.to_string())?;
    TrayIconBuilder::new()
        .with_icon(icon)
        .with_guid(TRAY_GUID)
        .with_tooltip("Scan System")
        .with_menu(Box::new(menu))
        .build()
        .map_err(|error| error.to_string())
}

fn notify_anomaly(tray: &TrayIcon, message: &str) -> bool {
    let mut data = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: tray.window_handle(),
        uFlags: NIF_GUID | NIF_INFO,
        guidItem: GUID::from_u128(TRAY_GUID),
        dwInfoFlags: NIIF_WARNING,
        ..NOTIFYICONDATAW::default()
    };
    let title_limit = data.szInfoTitle.len() - 1;
    for (dest, code_unit) in data
        .szInfoTitle
        .iter_mut()
        .take(title_limit)
        .zip("Scan System".encode_utf16())
    {
        *dest = code_unit;
    }
    let message_limit = data.szInfo.len() - 1;
    for (dest, code_unit) in data
        .szInfo
        .iter_mut()
        .take(message_limit)
        .zip(message.encode_utf16())
    {
        *dest = code_unit;
    }
    // Windows may still suppress display according to the user's notification settings.
    unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) != 0 }
}

fn read_defender_threats() -> Result<Vec<Value>, String> {
    let result =
        defender_threat_detections(&AuditHandle::new()).map_err(|error| error.to_string())?;
    if !result.ok {
        return Err(result.error.unwrap_or_default());
    }
    Ok(result
        .data
        .and_then(|data| data.as_array().cloned())
        .unwrap_or_default())
}

fn run_threat_action(action: ThreatAction) -> Result<String, String> {
    let handle = AuditHandle::new();
    let result = match action {
        ThreatAction::Cleanup => defender_remove_threats(&handle),
        ThreatAction::FullScan => defender_full_scan(&handle),
        ThreatAction::OfflineScan => defender_offline_scan(&handle),
    }
    .map_err(|error| error.to_string())?;
    if result.ok {
        Ok(result.output)
    } else {
        Err(result.output)
    }
}

fn default_reports_dir() -> PathBuf {
    let base = env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("ScanSystem").join("reports")
}

fn user_language_path() -> PathBuf {
    default_reports_dir().with_file_name("ui_language.txt")
}

fn installed_language_path() -> PathBuf {
    env::current_exe()
        .ok()
        .and_then(|path| {
            path.parent()
                .map(|parent| parent.join("default_language.txt"))
        })
        .unwrap_or_else(|| PathBuf::from("default_language.txt"))
}

fn read_language(path: &Path) -> Option<Language> {
    match fs::read_to_string(path).ok()?.trim() {
        "en" => Some(Language::English),
        "fr" => Some(Language::French),
        _ => None,
    }
}

fn save_language(language: Language) -> std::io::Result<()> {
    let path = user_language_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, language.choose("fr", "en"))
}

fn resolve_output_dir(raw: &str) -> Result<PathBuf, String> {
    let path = Path::new(raw.trim());
    if raw.trim().is_empty() {
        return Err("Choisis un dossier pour les rapports".into());
    }
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        default_reports_dir().join(path)
    })
}

fn update(state: &mut State, message: Message) -> Task<Message> {
    match message {
        Message::Language(language) => {
            state.language = language;
            if let Err(error) = save_language(language) {
                state.append_log(format!(
                    "{} {error}",
                    language.choose("Langue non enregistrée :", "Could not save language:")
                ));
            }
            state.tray = None;
            state.tray_attempted = false;
            if !state.audit_running && state.progress == 0.0 {
                state.audit_status = language.choose("Prêt", "Ready").into();
            }
        }
        Message::Page(page) => {
            state.page = page;
            if page == Page::Threats && !state.threats_loaded && !state.threats_loading {
                state.threats_loading = true;
                let sender = state.sender.clone();
                thread::spawn(move || {
                    let _ = sender.send(WorkerEvent::ThreatsFinished(read_defender_threats()));
                });
            }
            if page == Page::Realtime && state.realtime.is_none() {
                let _ = state.realtime_sender.send(RealtimeCommand::Snapshot);
                state.realtime_loading = true;
            }
        }
        Message::DaysChanged(value) => state.days = value,
        Message::OutputChanged(value) => state.output = value,
        Message::UpdateSignatures(value) => state.update_signatures = value,
        Message::QuickScan(value) => state.quick_scan = value,
        Message::StartAudit if !state.audit_running && !state.threat_action_running => {
            let Ok(days) = state.days.trim().parse::<i64>() else {
                state.append_log(state.language.choose(
                    "Le nombre de jours doit être un entier.",
                    "The number of days must be an integer.",
                ));
                return Task::none();
            };
            let Ok(output_dir) = resolve_output_dir(&state.output) else {
                state.append_log(state.language.choose(
                    "Choisis un dossier de rapport valide.",
                    "Choose a valid report folder.",
                ));
                return Task::none();
            };
            let options = AuditOptions {
                days: days.clamp(1, 180),
                update_signatures: state.update_signatures,
                run_quick_scan: state.quick_scan,
            };
            state.audit_running = true;
            state.pending_threat_action = None;
            state.audit_started = Some(Instant::now());
            state.progress = 0.0;
            state.audit_status = state.language.choose("Démarrage...", "Starting...").into();
            state.append_log(state.language.choose(
                "[Début] Audit Windows lancé.",
                "[Start] Windows audit started.",
            ));
            state.handle.reset();
            let handle = Arc::clone(&state.handle);
            let sender = state.sender.clone();
            thread::spawn(move || {
                let result =
                    generate_report(&handle, options, Some(&output_dir), |label, percent| {
                        let _ = sender.send(WorkerEvent::Progress(label.to_string(), percent));
                    })
                    .and_then(|report| {
                        save_reports(&report, &output_dir).map(|(json_path, txt_path)| {
                            AuditResult {
                                report,
                                json_path,
                                txt_path,
                            }
                        })
                    })
                    .map_err(|error| error.to_string());
                let _ = sender.send(WorkerEvent::AuditFinished(result));
            });
        }
        Message::StartAudit => {}
        Message::CancelAudit if state.audit_running => {
            state.audit_status = state
                .language
                .choose("Annulation demandée...", "Cancellation requested...")
                .into();
            state.handle.request_cancel();
        }
        Message::CancelAudit => {}
        Message::RefreshThreats if !state.threats_loading => {
            state.threats_loading = true;
            let sender = state.sender.clone();
            thread::spawn(move || {
                let _ = sender.send(WorkerEvent::ThreatsFinished(read_defender_threats()));
            });
        }
        Message::RefreshThreats => {}
        Message::RequestThreatAction(action)
            if !state.audit_running && !state.threat_action_running && !state.threats_loading =>
        {
            if action == ThreatAction::Cleanup
                && !state.threats.iter().any(defender_detection_needs_attention)
            {
                state.threat_status = state
                    .language
                    .choose(
                        "Aucune détection non résolue à nettoyer.",
                        "No unresolved detection to clean up.",
                    )
                    .into();
            } else {
                state.pending_threat_action = Some(action);
            }
        }
        Message::RequestThreatAction(_) => {}
        Message::CancelThreatAction => state.pending_threat_action = None,
        Message::ConfirmThreatAction if !state.audit_running && !state.threat_action_running => {
            if let Some(action) = state.pending_threat_action.take() {
                state.threat_action_running = true;
                state.threat_action_started = Some(Instant::now());
                state.threat_status = format!(
                    "{} {}",
                    action.label(state.language),
                    state.language.choose("en cours...", "in progress...")
                );
                let sender = state.sender.clone();
                thread::spawn(move || {
                    let result = run_threat_action(action);
                    let refresh = result.is_ok() && action != ThreatAction::OfflineScan;
                    let _ = sender.send(WorkerEvent::ThreatActionFinished(action, result));
                    if refresh {
                        let _ = sender.send(WorkerEvent::ThreatsFinished(read_defender_threats()));
                    }
                });
            }
        }
        Message::ConfirmThreatAction => {}
        Message::RefreshRealtime if !state.realtime_loading => {
            state.realtime_loading = true;
            let _ = state.realtime_sender.send(RealtimeCommand::Snapshot);
        }
        Message::RefreshRealtime => {}
        Message::MonitoringChanged(enabled) => {
            state.monitoring_enabled = enabled;
            let _ = state
                .realtime_sender
                .send(RealtimeCommand::Monitoring(enabled));
        }
        Message::StartupChanged(enabled) => {
            let result = env::current_exe()
                .map_err(|error| error.to_string())
                .and_then(|exe| {
                    let command = format!(
                        "\"{}\" --monitoring-enabled --start-minimized",
                        exe.display()
                    );
                    set_rust_startup_monitoring_enabled(enabled, &command)
                });
            match result {
                Ok(()) => {
                    state.startup_enabled = enabled;
                    state.startup_status = if enabled {
                        state
                            .language
                            .choose(
                                "Lancement avec Windows activé",
                                "Start with Windows enabled",
                            )
                            .into()
                    } else {
                        state
                            .language
                            .choose(
                                "Lancement avec Windows désactivé",
                                "Start with Windows disabled",
                            )
                            .into()
                    };
                }
                Err(error) => {
                    state.startup_status = format!(
                        "{} {error}",
                        state
                            .language
                            .choose("Démarrage auto :", "Automatic startup:")
                    )
                }
            }
        }
        Message::RefreshReports => state.load_reports(),
        Message::OpenReportsFolder => {
            if let Ok(path) = resolve_output_dir(&state.output) {
                if let Err(error) = Command::new("explorer").arg(path).spawn() {
                    state.append_log(format!(
                        "{} {error}",
                        state
                            .language
                            .choose("Ouverture du dossier :", "Opening folder:")
                    ));
                }
            }
        }
        Message::OpenReport(path) => {
            if let Err(error) = Command::new("explorer").arg(path).spawn() {
                state.append_log(format!(
                    "{} {error}",
                    state
                        .language
                        .choose("Ouverture du rapport :", "Opening report:")
                ));
            }
        }
        Message::CloseRequested(id) => {
            if state.tray.is_some() {
                return window::set_mode(id, window::Mode::Hidden);
            }
            return iced::exit();
        }
        Message::RestoreWindow(Some(id)) => {
            return window::set_mode(id, window::Mode::Windowed);
        }
        Message::RestoreWindow(None) => {}
        Message::Tick => {
            if state.last_theme_check.elapsed() >= Duration::from_secs(1) {
                state.dark = detect_windows_theme() == "dark";
                state.last_theme_check = Instant::now();
            }
            state.ensure_tray();
            if state.initially_hidden && state.tray.is_none() {
                state.initially_hidden = false;
                return window::latest().map(Message::RestoreWindow);
            }
            state.process_events();
            while let Ok(event) = MenuEvent::receiver().try_recv() {
                match event.id.as_ref() {
                    "open" => return window::latest().map(Message::RestoreWindow),
                    "quit" => return iced::exit(),
                    _ => {}
                }
            }
            while let Ok(event) = TrayIconEvent::receiver().try_recv() {
                if matches!(event, TrayIconEvent::DoubleClick { .. }) {
                    return window::latest().map(Message::RestoreWindow);
                }
            }
        }
    }
    Task::none()
}

fn tab(label: &'static str, page: Page, current: Page) -> iced::widget::Button<'static, Message> {
    let button = button(label).on_press(Message::Page(page));
    if page == current {
        button.style(button::primary)
    } else {
        button
    }
}

fn audit_view(state: &State) -> Element<'_, Message> {
    let language = state.language;
    let settings = column![
        row![
            text(language.choose("Jours à analyser", "Days to analyze")),
            text_input("14", &state.days)
                .on_input(Message::DaysChanged)
                .width(80),
            text(language.choose("Dossier rapports", "Reports folder")),
            text_input(language.choose("Dossier", "Folder"), &state.output)
                .on_input(Message::OutputChanged)
                .width(Fill),
        ]
        .spacing(10),
        row![
            checkbox(state.update_signatures)
                .label(language.choose(
                    "Mettre à jour les signatures Defender",
                    "Update Defender signatures"
                ))
                .on_toggle(Message::UpdateSignatures),
            checkbox(state.quick_scan)
                .label(language.choose("Lancer les scans Defender", "Run Defender scans"))
                .on_toggle(Message::QuickScan),
        ]
        .spacing(20),
    ]
    .spacing(10);
    let mut actions = row![].spacing(10);
    if state.audit_running {
        actions = actions.push(
            button(language.choose("Arrêter l'audit", "Stop audit")).on_press(Message::CancelAudit),
        );
    } else {
        actions = actions.push(
            button(language.choose("Lancer audit complet", "Start full audit"))
                .on_press(Message::StartAudit),
        );
    }
    actions = actions.push(
        button(language.choose("Ouvrir dossier rapports", "Open reports folder"))
            .on_press(Message::OpenReportsFolder),
    );
    let elapsed = state
        .audit_started
        .map_or(0, |started| started.elapsed().as_secs());
    let mut log = column![].spacing(4);
    for line in &state.log {
        log = log.push(text(line));
    }
    column![
        settings,
        progress_bar(0.0..=100.0, state.progress),
        row![
            text(&state.audit_status),
            text(format!("{:02}:{:02}", elapsed / 60, elapsed % 60))
        ]
        .spacing(20),
        actions,
        scrollable(log).height(Fill),
    ]
    .spacing(14)
    .into()
}

fn threats_view(state: &State) -> Element<'_, Message> {
    let language = state.language;
    let needs_attention = state
        .threats
        .iter()
        .filter(|item| defender_detection_needs_attention(item))
        .count();
    let label = if state.threats_loading {
        language.choose("Lecture en cours...", "Loading...")
    } else {
        language.choose("Rafraîchir menaces", "Refresh threats")
    };
    let mut items = column![
        text(format!(
            "{} {}",
            state.threats.len(),
            language.choose("détection(s) enregistrée(s)", "recorded detection(s)")
        )),
        text(format!(
            "{} {}",
            needs_attention,
            language.choose("à vérifier", "requiring attention")
        ))
    ]
    .spacing(8);
    for threat in &state.threats {
        let name = threat["ThreatName"]
            .as_str()
            .unwrap_or(language.choose("Menace sans nom", "Unnamed threat"));
        let time = threat["InitialDetectionTime"].as_str().unwrap_or("");
        let success = threat["ActionSuccess"].as_bool().unwrap_or(false);
        let resources = threat["Resources"].to_string();
        items = items.push(text(format!(
            "{name} | {time} | {}: {success} | {resources}",
            language.choose("Action OK", "Action successful")
        )));
    }
    let mut actions = row![button(label).on_press(Message::RefreshThreats)].spacing(8);
    for (caption, action) in [
        (
            language.choose("Nettoyer avec Defender", "Clean with Defender"),
            ThreatAction::Cleanup,
        ),
        (
            language.choose("Scan complet", "Full scan"),
            ThreatAction::FullScan,
        ),
        (
            language.choose("Scan hors ligne", "Offline scan"),
            ThreatAction::OfflineScan,
        ),
    ] {
        let control = button(caption);
        actions = actions.push(
            if state.threat_action_running
                || state.audit_running
                || state.threats_loading
                || (action == ThreatAction::Cleanup && needs_attention == 0)
            {
                control
            } else {
                control.on_press(Message::RequestThreatAction(action))
            },
        );
    }
    let mut content = column![actions, text(&state.threat_status)].spacing(12);
    if let Some(action) = state.pending_threat_action {
        content = content.push(
            column![
                text(action.confirmation(language)),
                row![
                    button(language.choose("Confirmer", "Confirm"))
                        .on_press(Message::ConfirmThreatAction),
                    button(language.choose("Annuler", "Cancel"))
                        .on_press(Message::CancelThreatAction),
                ]
                .spacing(8)
            ]
            .spacing(8),
        );
    }
    if let Some(started) = state.threat_action_started {
        content = content.push(text(format!(
            "{} {} s",
            language.choose("Durée :", "Duration:"),
            started.elapsed().as_secs()
        )));
    }
    column![content, scrollable(items).height(Fill),]
        .spacing(12)
        .into()
}

fn realtime_view(state: &State) -> Element<'_, Message> {
    let language = state.language;
    let label = if state.realtime_loading {
        language.choose("Lecture en cours...", "Loading...")
    } else {
        language.choose("Rafraîchir temps réel", "Refresh real-time data")
    };
    let mut content = column![].spacing(8);
    if let Some(snapshot) = &state.realtime {
        content = content.push(text(format!(
            "CPU: {:.0}% | {}: {} | {}: {}",
            snapshot.cpu_percent,
            language.choose("Réseau", "Network"),
            format_rate(snapshot.upload_bps + snapshot.download_bps),
            language.choose("Connexions publiques", "Public connections"),
            snapshot.connections.len()
        )));
        content = content.push(text(format!(
            "{} {}",
            language.choose("Alertes récentes :", "Recent alerts:"),
            state.anomaly_history.len()
        )));
        for anomaly in &state.anomaly_history {
            content = content.push(text(format!(
                "{} {}",
                language.choose("Anomalie :", "Anomaly:"),
                anomaly_display(language, anomaly)
            )));
        }
        for connection in &snapshot.connections {
            content = content.push(text(format!(
                "{} ({}) | {} -> {} | {}",
                connection.process_name,
                connection.pid,
                connection.local,
                connection.remote,
                connection.status
            )));
        }
    } else {
        content = content.push(text(
            language.choose("Aucun instantané chargé.", "No snapshot loaded."),
        ));
    }
    column![
        row![
            button(label).on_press(Message::RefreshRealtime),
            checkbox(state.monitoring_enabled)
                .label(language.choose("Monitoring en arrière-plan", "Background monitoring"))
                .on_toggle(Message::MonitoringChanged),
            checkbox(state.startup_enabled)
                .label(language.choose("Lancer avec Windows", "Start with Windows"))
                .on_toggle(Message::StartupChanged),
        ]
        .spacing(16),
        text(&state.startup_status),
        scrollable(content).height(Fill)
    ]
    .spacing(12)
    .into()
}

fn reports_view(state: &State) -> Element<'_, Message> {
    let language = state.language;
    let mut items = column![text(format!(
        "{} {}",
        state.reports.len(),
        language.choose("rapport(s)", "report(s)")
    ))]
    .spacing(8);
    for path in &state.reports {
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        items = items.push(button(text(name)).on_press(Message::OpenReport(path.clone())));
    }
    column![
        row![
            button(language.choose("Rafraîchir", "Refresh")).on_press(Message::RefreshReports),
            button(language.choose("Ouvrir dossier rapports", "Open reports folder"))
                .on_press(Message::OpenReportsFolder),
        ]
        .spacing(10),
        scrollable(items).height(Fill),
    ]
    .spacing(12)
    .into()
}

fn view(state: &State) -> Element<'_, Message> {
    let content = match state.page {
        Page::Audit => audit_view(state),
        Page::Threats => threats_view(state),
        Page::Realtime => realtime_view(state),
        Page::Reports => reports_view(state),
    };
    let footer = if let Some(snapshot) = &state.realtime {
        format!(
            "CPU {:.0}%    {} {}",
            snapshot.cpu_percent,
            state.language.choose("Réseau", "Network"),
            format_rate(snapshot.upload_bps + snapshot.download_bps)
        )
    } else {
        state
            .language
            .choose(
                "Scan System · migration Rust",
                "Scan System · Rust migration",
            )
            .into()
    };
    let ink = if state.dark {
        Color::from_rgb8(82, 96, 110)
    } else {
        Color::from_rgb8(48, 48, 48)
    };
    let header_background = if state.dark {
        Color::from_rgb8(34, 40, 48)
    } else {
        Color::from_rgb8(255, 255, 255)
    };
    container(
        column![
            container(
                row![
                    image(APP_LOGO.clone()).width(64).height(64),
                    column![
                        text("Scan System").size(32),
                        text(state.language.choose(
                            "Audit et surveillance Windows",
                            "Windows auditing and monitoring"
                        ))
                        .size(15),
                    ]
                    .spacing(3),
                    iced::widget::Space::new().width(Fill),
                    canvas::Canvas::new(GeometryMark).width(120).height(76),
                ]
                .spacing(12)
                .align_y(iced::Alignment::Center)
            )
            .padding(10)
            .width(Fill)
            .style(move |_| container::Style::default().background(header_background)),
            container(iced::widget::Space::new())
                .height(8)
                .width(Fill)
                .style(move |_| container::Style::default().background(ink)),
            row![
                tab("Audit", Page::Audit, state.page),
                tab(
                    state.language.choose("Menaces", "Threats"),
                    Page::Threats,
                    state.page
                ),
                tab(
                    state.language.choose("Temps réel", "Real-time"),
                    Page::Realtime,
                    state.page
                ),
                tab(
                    state.language.choose("Rapports", "Reports"),
                    Page::Reports,
                    state.page
                ),
                iced::widget::Space::new().width(Fill),
                row![
                    text(state.language.choose("Langue :", "Language:")),
                    pick_list(
                        [Language::French, Language::English],
                        Some(state.language),
                        Message::Language,
                    )
                    .width(140),
                ]
                .spacing(8)
                .align_y(iced::Alignment::Center),
            ]
            .spacing(8),
            content,
            text(footer).size(14),
        ]
        .spacing(16),
    )
    .padding(16)
    .width(Fill)
    .height(Fill)
    .into()
}

fn subscription(_state: &State) -> Subscription<Message> {
    Subscription::batch([
        time::every(Duration::from_millis(100)).map(|_| Message::Tick),
        window::close_requests().map(Message::CloseRequested),
    ])
}

fn theme(state: &State) -> Theme {
    if state.dark {
        Theme::custom(
            "Carte sombre",
            iced::theme::Palette {
                background: Color::from_rgb8(23, 27, 32),
                text: Color::from_rgb8(237, 240, 243),
                primary: Color::from_rgb8(70, 89, 107),
                success: Color::from_rgb8(78, 172, 126),
                warning: Color::from_rgb8(227, 169, 68),
                danger: Color::from_rgb8(226, 92, 84),
            },
        )
    } else {
        Theme::custom(
            "Carte claire",
            iced::theme::Palette {
                background: Color::from_rgb8(250, 250, 249),
                text: Color::from_rgb8(16, 16, 16),
                primary: Color::from_rgb8(48, 48, 48),
                success: Color::from_rgb8(40, 112, 81),
                warning: Color::from_rgb8(151, 93, 23),
                danger: Color::from_rgb8(177, 52, 44),
            },
        )
    }
}

fn main() -> iced::Result {
    let args: Vec<_> = env::args_os().collect();
    let auto_monitoring = args.iter().any(|arg| arg == "--monitoring-enabled");
    let start_hidden = args.iter().any(|arg| arg == "--start-minimized");
    let language = if args.iter().any(|arg| arg == "--lang=en") {
        Some(Language::English)
    } else if args.iter().any(|arg| arg == "--lang=fr") {
        Some(Language::French)
    } else {
        None
    };
    iced::application(
        move || State::new(auto_monitoring, start_hidden, language),
        update,
        view,
    )
    .window(window::Settings {
        size: (1220.0, 760.0).into(),
        visible: !start_hidden,
        exit_on_close_request: false,
        icon: Some(app_icon()),
        ..window::Settings::default()
    })
    .subscription(subscription)
    .theme(theme)
    .run()
}

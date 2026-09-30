#!/usr/bin/env python3
"""
Scanner securite Windows (defensif)
- Met a jour les signatures Defender
- Lance un scan rapide Defender
- Recupere les menaces detectees Defender
- Liste les installations recentes
- Liste des indices de persistance recents (startup, taches, services)
- Audite les connexions reseau publiques et les compare aux flux de menaces (feodotracker,
  Emerging Threats)
- Genere un rapport JSON + TXT

Usage:
  scanner_windows.exe --days 14 --output reports
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import os
import platform
import re
import subprocess
import sys
import textwrap
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    import winreg  # type: ignore
except Exception:  # pragma: no cover
    winreg = None

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None


THREAT_FEEDS = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
]


def resource_path(relative: str) -> Path:
    """Resout un fichier ressource bundle (icones...), en script comme en exe PyInstaller
    --onefile (extrait dans sys._MEIPASS a l'execution)."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / relative


def app_log_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA", str(Path.home()))
    p = Path(base) / "ScanSystem"
    p.mkdir(parents=True, exist_ok=True)
    return p


def default_reports_dir() -> Path:
    p = app_log_dir() / "reports"
    p.mkdir(parents=True, exist_ok=True)
    return p


def resolve_output_dir(raw: str | Path | None) -> Path:
    # Relative paths are resolved under LOCALAPPDATA\ScanSystem to avoid
    # permission issues when app runs from Program Files.
    if raw is None:
        candidate = default_reports_dir()
    else:
        candidate = Path(str(raw)).expanduser()
        if not candidate.is_absolute():
            candidate = default_reports_dir() / candidate

    try:
        candidate.mkdir(parents=True, exist_ok=True)
        return candidate
    except OSError:
        fallback = default_reports_dir()
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def crash_log_path() -> Path:
    return app_log_dir() / "scan_system_crash.log"


def write_crash_log(message: str) -> None:
    stamp = dt.datetime.now().isoformat()
    log = crash_log_path()
    with log.open("a", encoding="utf-8") as f:
        f.write(f"\n[{stamp}]\n{message}\n")


class AuditCancelled(Exception):
    """Levee quand l'utilisateur demande l'arret d'un audit en cours (bouton GUI)."""


# Un seul audit actif a la fois (impose cote GUI par `audit_running`) : un simple etat module
# suffit, pas besoin de faire transiter un token a travers chaque fonction defender_*/recent_*.
_audit_cancel_event = threading.Event()
_audit_current_proc: subprocess.Popen | None = None
_audit_proc_lock = threading.Lock()


def reset_audit_cancel() -> None:
    _audit_cancel_event.clear()


def request_audit_cancel() -> None:
    _audit_cancel_event.set()
    with _audit_proc_lock:
        if _audit_current_proc is not None:
            try:
                _audit_current_proc.kill()
            except Exception:
                pass


def _check_audit_cancelled() -> None:
    if _audit_cancel_event.is_set():
        raise AuditCancelled()


def _run_cancellable(popen_args, popen_kwargs: dict[str, Any], timeout: int) -> tuple[str, str, int]:
    """Popen + sondage court, annulable via _audit_cancel_event, plutot qu'un subprocess.run()
    bloquant qui ne rendrait la main qu'a la fin du timeout complet."""
    global _audit_current_proc
    _check_audit_cancelled()
    proc = subprocess.Popen(popen_args, **popen_kwargs)
    with _audit_proc_lock:
        _audit_current_proc = proc
    try:
        deadline = time.time() + timeout
        while True:
            try:
                stdout, stderr = proc.communicate(timeout=0.5)
                return stdout, stderr, proc.returncode
            except subprocess.TimeoutExpired:
                if _audit_cancel_event.is_set():
                    proc.kill()
                    proc.communicate()
                    raise AuditCancelled()
                if time.time() >= deadline:
                    proc.kill()
                    proc.communicate()
                    raise TimeoutError(f"timeout apres {timeout}s")
    finally:
        with _audit_proc_lock:
            _audit_current_proc = None


def run_powershell(command: str, timeout: int = 180) -> tuple[bool, str]:
    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        command,
    ]
    startupinfo = None
    creationflags = 0
    if platform.system().lower() == "windows":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    try:
        stdout, stderr, returncode = _run_cancellable(
            cmd,
            {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "text": True,
                # powershell.exe (sans console allouee, CREATE_NO_WINDOW) ecrit sa sortie dans la
                # codepage OEM de la machine (ex: cp850), pas en UTF-8 -- "oem" est l'alias Windows
                # de Python qui s'adapte a la codepage OEM reelle, sinon les caracteres accentues
                # (messages Get-WinEvent en francais, etc.) sont corrompus a la lecture.
                "encoding": "oem",
                "errors": "replace",
                "startupinfo": startupinfo,
                "creationflags": creationflags,
            },
            timeout,
        )
    except AuditCancelled:
        raise
    except Exception as exc:
        return False, f"ERREUR execution PowerShell: {exc}"

    out = (stdout or "").strip()
    err = (stderr or "").strip()
    if returncode != 0:
        return False, f"Code={returncode}; STDERR={err}; STDOUT={out}"
    return True, out


def run_hidden_command(command: list[str], timeout: int = 180) -> tuple[bool, str, str, int]:
    startupinfo = None
    creationflags = 0
    if platform.system().lower() == "windows":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    try:
        stdout, stderr, returncode = _run_cancellable(
            command,
            {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "text": True,
                "encoding": "oem",
                "errors": "replace",
                "startupinfo": startupinfo,
                "creationflags": creationflags,
            },
            timeout,
        )
        return returncode == 0, (stdout or "").strip(), (stderr or "").strip(), returncode
    except AuditCancelled:
        raise
    except Exception as exc:
        return False, "", str(exc), 1


def detect_windows_theme() -> str:
    if winreg is None:
        return "light"
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            return "light" if int(value) == 1 else "dark"
    except OSError:
        return "light"


# Keep the desktop colors in step with OSINTBox's light and dark card themes.
UI_COLORS = {
    "light": {
        "bg": "#fafaf9", "fg": "#101010", "surface": "#ffffff",
        "header": "#ffffff", "divider": "#303030", "border": "#dedfdf",
        "mark": "#e3e4e4", "button": "#303030", "button_hover": "#101010",
        "button_disabled": "#ebebea", "disabled_fg": "#777777",
        "selection": "#303030", "selection_fg": "#ffffff",
    },
    "dark": {
        "bg": "#171b20", "fg": "#edf0f3", "surface": "#232a32",
        "header": "#222830", "divider": "#52606e", "border": "#4a5561",
        "mark": "#657483", "button": "#46596b", "button_hover": "#587087",
        "button_disabled": "#303740", "disabled_fg": "#a0aab4",
        "selection": "#769cbd", "selection_fg": "#10161c",
    },
}


def format_rate(bytes_per_sec: float) -> str:
    bits = max(0.0, bytes_per_sec * 8.0)
    if bits >= 1_000_000_000:
        return f"{bits / 1_000_000_000:.1f} Gbps"
    if bits >= 1_000_000:
        return f"{bits / 1_000_000:.1f} Mbps"
    if bits >= 1_000:
        return f"{bits / 1_000:.1f} Kbps"
    return f"{bits:.0f} bps"


def is_public_ipv4(value: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(value)
        return isinstance(ip_obj, ipaddress.IPv4Address) and not (
            ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_link_local
        )
    except ValueError:
        return False


def parse_any_datetime(raw: Any) -> dt.datetime | None:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    # Windows PowerShell 5.1 ConvertTo-Json serializes Get-WinEvent dates this way.
    # The number is UTC milliseconds; compare it as local naive time like the
    # other event timestamps and the realtime monitor's local cutoff.
    powershell_date = re.fullmatch(r"/Date\((-?\d+)(?:[+-]\d{4})?\)/", text)
    if powershell_date:
        try:
            return dt.datetime.fromtimestamp(int(powershell_date.group(1)) / 1000)
        except (OverflowError, OSError, ValueError):
            return None
    text = text.replace("Z", "+00:00")
    try:
        return dt.datetime.fromisoformat(text)
    except ValueError:
        pass
    for fmt in ("%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S"):
        try:
            return dt.datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def looks_suspicious_text(value: str) -> bool:
    lowered = value.lower()
    patterns = [
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
    ]
    return any(pattern in lowered for pattern in patterns)


def startup_fingerprint(entries: list[dict[str, Any]]) -> set[str]:
    out: set[str] = set()
    for item in entries:
        source = str(item.get("source", "")).lower()
        name = str(item.get("name", "")).lower()
        command = str(item.get("command", "")).lower()
        out.add(f"{source}|{name}|{command}")
    return out


def list_public_connections() -> list[dict[str, Any]]:
    connections: list[dict[str, Any]] = []
    for conn in psutil.net_connections(kind="inet"):
        if not conn.raddr:
            continue
        remote_ip = str(conn.raddr.ip)
        if not is_public_ipv4(remote_ip):
            continue
        process_name = ""
        if conn.pid:
            try:
                process_name = psutil.Process(conn.pid).name()
            except Exception:
                process_name = ""
        connections.append(
            {
                "pid": conn.pid or 0,
                "process_name": process_name,
                "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                "remote": f"{remote_ip}:{conn.raddr.port}",
                "remote_ip": remote_ip,
                "status": conn.status,
            }
        )
    return sorted(connections, key=lambda item: (item["process_name"], item["remote"]))[:200]


# Sondage temps reel uniquement (cf. collect_realtime_snapshot) -- pas l'audit ponctuel
# (network_audit_snapshot), qui reste a 85% instantane : un seul tir par audit, pas de risque
# de spam de notifications repetees.
CPU_ANOMALY_THRESHOLD = 95
CPU_ANOMALY_SUSTAINED_SAMPLES = 3  # ~6s a raison d'un cycle de 2s, filtre les pics ponctuels


def collect_realtime_snapshot(previous: dict[str, Any]) -> dict[str, Any]:
    snapshot: dict[str, Any] = {
        "cpu_percent": 0.0,
        "download_bps": 0.0,
        "upload_bps": 0.0,
        "connections": [],
        "anomalies": [],
    }
    if psutil is None:
        snapshot["anomalies"].append("psutil indisponible")
        return snapshot

    snapshot["cpu_percent"] = psutil.cpu_percent(interval=None)
    now = time.time()
    counters = psutil.net_io_counters()
    prev_ts = previous.get("ts", now)
    prev_sent = previous.get("sent", float(counters.bytes_sent))
    prev_recv = previous.get("recv", float(counters.bytes_recv))
    elapsed = max(now - prev_ts, 1.0)

    snapshot["upload_bps"] = max(0.0, (counters.bytes_sent - prev_sent) / elapsed)
    snapshot["download_bps"] = max(0.0, (counters.bytes_recv - prev_recv) / elapsed)
    previous["ts"] = now
    previous["sent"] = float(counters.bytes_sent)
    previous["recv"] = float(counters.bytes_recv)

    # Seuil releve (85 -> 95) et exige plusieurs cycles consecutifs au-dessus du seuil (pas
    # un seul instantane) avant de compter comme anomalie : avec plusieurs grosses applications
    # legitimes ouvertes en meme temps (Discord/Outlook/Edge/VSCode), le CPU dépasse 85% en
    # continu sans rien d'anormal -- un seul echantillon a 85-94% n'est pas un signal fiable,
    # cause de notifications percues comme des faux positifs frequents.
    if snapshot["cpu_percent"] >= CPU_ANOMALY_THRESHOLD:
        previous["cpu_high_streak"] = previous.get("cpu_high_streak", 0) + 1
    else:
        previous["cpu_high_streak"] = 0
    if previous["cpu_high_streak"] >= CPU_ANOMALY_SUSTAINED_SAMPLES:
        snapshot["anomalies"].append(f"CPU eleve soutenu: {snapshot['cpu_percent']:.0f}%")
    total_bps = snapshot["upload_bps"] + snapshot["download_bps"]
    if total_bps >= 5 * 1024 * 1024:
        snapshot["anomalies"].append(f"Debit reseau eleve: {format_rate(total_bps)}")

    try:
        snapshot["connections"] = list_public_connections()
        for conn in snapshot["connections"]:
            if looks_suspicious_text(f"{conn['process_name']} {conn['remote_ip']}"):
                snapshot["anomalies"].append(
                    f"Connexion potentiellement suspecte: {conn['process_name'] or 'inconnu'} -> {conn['remote_ip']}"
                )
    except Exception as exc:
        snapshot["anomalies"].append(f"Lecture connexions echouee: {exc}")

    # Refresh persistence checks at a slower cadence to keep UI responsive.
    last_persistence_scan = float(previous.get("persistence_ts", 0.0) or 0.0)
    if now - last_persistence_scan >= 60.0:
        previous["persistence_ts"] = now

        current_startup = startup_entries()
        current_fp = startup_fingerprint(current_startup)
        baseline_fp = previous.get("startup_fp")
        if not isinstance(baseline_fp, set):
            previous["startup_fp"] = current_fp
        else:
            added = sorted(current_fp - baseline_fp)
            if added:
                for row in added[:5]:
                    parts = row.split("|", 2)
                    label = parts[1] if len(parts) > 1 and parts[1] else row
                    snapshot["anomalies"].append(f"Nouvelle entree startup detectee: {label}")
                previous["startup_fp"] = current_fp

        lookback = dt.datetime.now() - dt.timedelta(minutes=70)
        # Fenetre resserree a la cadence de sondage (+marge) plutot que 24h a chaque passage :
        # cf. _event_log_start_expr, gain direct sur le cout CPU de chaque Get-WinEvent.
        since = dt.datetime.now() - dt.timedelta(seconds=90)
        try:
            task_events, service_events = recent_persistence_events(1, since=since)
        except RuntimeError as exc:
            snapshot["anomalies"].append(f"Lecture persistance echouee: {exc}")
            task_events, service_events = [], []

        seen_tasks = previous.get("seen_tasks")
        seen_services = previous.get("seen_services")
        if not isinstance(seen_tasks, set):
            seen_tasks = set()
        if not isinstance(seen_services, set):
            seen_services = set()

        for item in task_events:
            ts = parse_any_datetime(item.get("TimeCreated"))
            msg = str(item.get("Message", ""))
            if ts and ts >= lookback:
                sig = f"{ts.isoformat()}|{msg[:180]}"
                if sig not in seen_tasks:
                    seen_tasks.add(sig)
                    if looks_suspicious_text(msg):
                        snapshot["anomalies"].append("Nouvelle tache planifiee suspecte detectee")

        for item in service_events:
            ts = parse_any_datetime(item.get("TimeCreated"))
            msg = str(item.get("Message", ""))
            if ts and ts >= lookback:
                sig = f"{ts.isoformat()}|{msg[:180]}"
                if sig not in seen_services:
                    seen_services.add(sig)
                    if looks_suspicious_text(msg):
                        snapshot["anomalies"].append("Nouveau service potentiellement suspect detecte")

        previous["seen_tasks"] = seen_tasks
        previous["seen_services"] = seen_services

    return snapshot


def network_audit_snapshot(threat_feed_ips: set[str] | None = None) -> dict[str, Any]:
    """Instantane reseau autonome (sans etat partage) pour un audit ponctuel, contrairement
    a collect_realtime_snapshot() qui s'appuie sur un dict `previous` alimente par des appels
    repetes depuis la boucle de sondage de la GUI."""
    snapshot: dict[str, Any] = {
        "cpu_percent": 0.0,
        "download_bps": 0.0,
        "upload_bps": 0.0,
        "connections": [],
        "anomalies": [],
    }
    if psutil is None:
        snapshot["anomalies"].append("psutil indisponible")
        return snapshot

    threat_feed_ips = threat_feed_ips or set()

    counters_before = psutil.net_io_counters()
    snapshot["cpu_percent"] = psutil.cpu_percent(interval=1.0)
    counters_after = psutil.net_io_counters()
    snapshot["upload_bps"] = max(0.0, float(counters_after.bytes_sent - counters_before.bytes_sent))
    snapshot["download_bps"] = max(0.0, float(counters_after.bytes_recv - counters_before.bytes_recv))

    if snapshot["cpu_percent"] >= 85:
        snapshot["anomalies"].append(f"CPU eleve: {snapshot['cpu_percent']:.0f}%")
    total_bps = snapshot["upload_bps"] + snapshot["download_bps"]
    if total_bps >= 5 * 1024 * 1024:
        snapshot["anomalies"].append(f"Debit reseau eleve: {format_rate(total_bps)}")

    try:
        snapshot["connections"] = list_public_connections()
    except Exception as exc:
        snapshot["anomalies"].append(f"Lecture connexions echouee: {exc}")
        return snapshot

    for conn in snapshot["connections"]:
        remote_ip = conn["remote_ip"]
        if remote_ip in threat_feed_ips:
            conn["threat_feed_match"] = True
            snapshot["anomalies"].append(
                f"IP {remote_ip} presente dans une liste de blocage menace "
                f"(processus: {conn['process_name'] or 'inconnu'})"
            )
        if looks_suspicious_text(f"{conn['process_name']} {remote_ip}"):
            snapshot["anomalies"].append(
                f"Connexion potentiellement suspecte: {conn['process_name'] or 'inconnu'} -> {remote_ip}"
            )

    return snapshot


def build_threat_feed_ip_set(threat_feeds_refresh: dict[str, Any]) -> set[str]:
    ips: set[str] = set()
    for feed in threat_feeds_refresh.get("feeds", []):
        for entry in feed.get("ips", feed.get("sample", [])):
            entry = str(entry).strip()
            if entry:
                ips.add(entry)
    return ips


def trace_remote_ip(remote_ip: str) -> dict[str, Any]:
    ok, out, err, code = run_hidden_command(["tracert", "-d", remote_ip], timeout=180)
    return {"ok": ok, "stdout": out, "stderr": err, "return_code": code}


def block_remote_ip(remote_ip: str) -> dict[str, Any]:
    safe_name = remote_ip.replace(".", "_")
    rule_out = f"ScanSystem_Block_OUT_{safe_name}"
    rule_in = f"ScanSystem_Block_IN_{safe_name}"
    cmd_out = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_out}", "dir=out", "action=block", f"remoteip={remote_ip}", "enable=yes",
    ]
    cmd_in = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_in}", "dir=in", "action=block", f"remoteip={remote_ip}", "enable=yes",
    ]
    ok1, out1, err1, code1 = run_hidden_command(cmd_out, timeout=60)
    ok2, out2, err2, code2 = run_hidden_command(cmd_in, timeout=60)
    ok = ok1 and ok2
    return {
        "ok": ok,
        "stdout": "\n".join(part for part in [out1, out2] if part),
        "stderr": "\n".join(part for part in [err1, err2] if part),
        "return_code": code2 if not ok2 else code1,
    }


def ensure_app_firewall_rule(program_path: str) -> dict[str, Any]:
    if not program_path or not Path(program_path).exists():
        return {"ok": False, "error": "Executable introuvable"}
    rule_name = "ScanSystem_BackgroundMonitor"
    cmd_in = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}", "dir=in", "action=allow", f"program={program_path}", "enable=yes",
    ]
    cmd_out = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}_OUT", "dir=out", "action=allow", f"program={program_path}", "enable=yes",
    ]
    ok1, out1, err1, code1 = run_hidden_command(cmd_in, timeout=60)
    ok2, out2, err2, code2 = run_hidden_command(cmd_out, timeout=60)
    out = "\n".join(part for part in [out1, out2] if part)
    err = "\n".join(part for part in [err1, err2] if part)
    ok = ok1 and ok2
    if not ok and "Ok." not in out and "exist" not in out.lower():
        return {"ok": False, "stdout": out, "stderr": err, "return_code": code2 if not ok2 else code1}
    return {"ok": True, "stdout": out, "stderr": err, "return_code": code2 if not ok2 else code1}


def startup_monitor_command() -> str:
    exe = Path(sys.executable)
    if getattr(sys, "frozen", False):
        return f'"{exe}" --gui --monitoring-enabled --start-minimized'
    script = Path(__file__).resolve()
    return f'"{exe}" "{script}" --gui --monitoring-enabled --start-minimized'


def is_startup_monitoring_enabled() -> bool:
    if winreg is None:
        return False
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            value, _ = winreg.QueryValueEx(key, "ScanSystemMonitor")
            return "--monitoring-enabled" in str(value)
    except OSError:
        return False


def set_startup_monitoring_enabled(enabled: bool) -> dict[str, Any]:
    if winreg is None:
        return {"ok": False, "error": "winreg indisponible"}
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            if enabled:
                winreg.SetValueEx(key, "ScanSystemMonitor", 0, winreg.REG_SZ, startup_monitor_command())
            else:
                try:
                    winreg.DeleteValue(key, "ScanSystemMonitor")
                except OSError:
                    pass
        return {"ok": True}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}


def common_scan_paths() -> list[str]:
    values = [
        os.environ.get("TEMP", ""),
        os.environ.get("TMP", ""),
        str(Path.home() / "Downloads"),
        os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        os.path.join(os.environ.get("PROGRAMDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp"),
    ]
    paths: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value:
            continue
        normalized = str(Path(value))
        if normalized in seen:
            continue
        seen.add(normalized)
        if Path(normalized).exists():
            paths.append(normalized)
    return paths


def defender_targeted_scan(paths: list[str]) -> dict[str, Any]:
    scanned: list[dict[str, Any]] = []
    for path in paths:
        ok, out = run_powershell(f"$ErrorActionPreference = 'Stop'; Start-MpScan -ScanType CustomScan -ScanPath '{path.replace("'", "''")}'; 'custom_scan_done'", timeout=3600)
        scanned.append({"path": path, "ok": ok, "result": out[-1000:] if out else ""})
    return {"ok": all(item["ok"] for item in scanned) if scanned else True, "paths": scanned}


def now_utc_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def parse_install_date(raw: str) -> dt.datetime | None:
    # Format attendu: yyyymmdd
    if not raw:
        return None
    raw = raw.strip()
    if not re.fullmatch(r"\d{8}", raw):
        return None
    try:
        return dt.datetime.strptime(raw, "%Y%m%d")
    except ValueError:
        return None


def sha256_file(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def defender_status() -> dict[str, Any]:
    ps = (
        "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntispywareEnabled,"
        "AntivirusEnabled,AntivirusSignatureLastUpdated,AntivirusSignatureVersion,"
        "QuickScanAge,FullScanAge,RealTimeProtectionEnabled | ConvertTo-Json -Depth 3"
    )
    ok, out = run_powershell(ps, timeout=90)
    if not ok:
        return {"ok": False, "error": out}
    try:
        return {"ok": True, "data": json.loads(out)}
    except json.JSONDecodeError:
        return {"ok": False, "error": "Sortie JSON Defender invalide", "raw": out}


def defender_signature_update() -> dict[str, Any]:
    ps = "$ErrorActionPreference = 'Stop'; Update-MpSignature; Get-MpComputerStatus | Select AntivirusSignatureVersion,AntivirusSignatureLastUpdated | ConvertTo-Json"
    ok, out = run_powershell(ps, timeout=600)
    if not ok:
        return {"ok": False, "error": out}
    try:
        return {"ok": True, "data": json.loads(out)}
    except json.JSONDecodeError:
        return {"ok": True, "raw": out}


def defender_quick_scan() -> dict[str, Any]:
    # QuickScan est bloquant dans la plupart des cas, mais le delai depend de la machine.
    ps = "$ErrorActionPreference = 'Stop'; Start-MpScan -ScanType QuickScan; 'quick_scan_done'"
    ok, out = run_powershell(ps, timeout=3600)
    if not ok:
        return {"ok": False, "error": out}
    return {"ok": True, "result": out}


def defender_threat_detections() -> dict[str, Any]:
    ps = (
        "Get-MpThreatDetection | "
        "Select-Object InitialDetectionTime,LastThreatStatusChangeTime,ThreatName,Resources,ActionSuccess,CurrentThreatExecutionStatusID | "
        "ConvertTo-Json -Depth 6"
    )
    ok, out = run_powershell(ps, timeout=90)
    if not ok:
        return {"ok": False, "error": out}

    if not out:
        return {"ok": True, "data": []}

    try:
        data = json.loads(out)
        if isinstance(data, list):
            return {"ok": True, "data": data}
        return {"ok": True, "data": [data]}
    except json.JSONDecodeError:
        return {"ok": False, "error": "Sortie JSON menaces invalide", "raw": out}


def defender_remove_threats() -> dict[str, Any]:
    ok, out = run_powershell("$ErrorActionPreference = 'Stop'; Remove-MpThreat; 'threat_cleanup_done'", timeout=1800)
    if not ok:
        return {"ok": False, "error": out}
    return {"ok": True, "result": out}


def defender_full_scan() -> dict[str, Any]:
    ok, out = run_powershell("$ErrorActionPreference = 'Stop'; Start-MpScan -ScanType FullScan; 'full_scan_done'", timeout=7200)
    if not ok:
        return {"ok": False, "error": out}
    return {"ok": True, "result": out}


def defender_offline_scan() -> dict[str, Any]:
    ok, out = run_powershell("$ErrorActionPreference = 'Stop'; Start-MpWDOScan; 'offline_scan_requested'", timeout=300)
    if not ok:
        return {"ok": False, "error": out}
    return {"ok": True, "result": out}


def iter_uninstall_registry() -> list[dict[str, Any]]:
    if winreg is None:
        return []

    hives = [
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, "HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    entries: list[dict[str, Any]] = []

    for hive, hive_name, key_path in hives:
        try:
            with winreg.OpenKey(hive, key_path) as root:
                sub_count, _, _ = winreg.QueryInfoKey(root)
                for i in range(sub_count):
                    try:
                        sub_name = winreg.EnumKey(root, i)
                        with winreg.OpenKey(root, sub_name) as sk:
                            def qv(name: str) -> str:
                                try:
                                    v, _ = winreg.QueryValueEx(sk, name)
                                    return str(v)
                                except OSError:
                                    return ""

                            display_name = qv("DisplayName")
                            if not display_name:
                                continue
                            entries.append(
                                {
                                    "display_name": display_name,
                                    "display_version": qv("DisplayVersion"),
                                    "publisher": qv("Publisher"),
                                    "install_date_raw": qv("InstallDate"),
                                    "install_location": qv("InstallLocation"),
                                    "uninstall_string": qv("UninstallString"),
                                    "quiet_uninstall_string": qv("QuietUninstallString"),
                                    "display_icon": qv("DisplayIcon"),
                                    "windows_installer": qv("WindowsInstaller"),
                                    "local_package": qv("LocalPackage"),
                                    "registry_hive": hive_name,
                                    "registry_subkey": f"{key_path}\\{sub_name}",
                                }
                            )
                    except OSError:
                        continue
        except OSError:
            continue

    return entries


def refresh_threat_feeds_cache(output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_path = output_dir / "threat_feeds_cache.json"

    result: dict[str, Any] = {
        "updated_at": dt.datetime.now().isoformat(),
        "feeds": [],
        "cache_path": str(cache_path),
    }

    for url in THREAT_FEEDS:
        feed_info: dict[str, Any] = {"url": url, "ok": False, "entries": 0}
        req = Request(url, headers={"User-Agent": "scan-system/1.0"})
        try:
            with urlopen(req, timeout=25) as resp:
                text = resp.read().decode("utf-8", errors="replace")
            lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
            feed_info["ok"] = True
            feed_info["entries"] = len(lines)
            feed_info["sample"] = lines[:20]
            feed_info["ips"] = lines
        except (HTTPError, URLError, TimeoutError) as exc:
            feed_info["error"] = str(exc)
        result["feeds"].append(feed_info)

    cache_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def recent_installs(days: int, status: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    if status is None:
        status = {}
    status.clear()
    status["ok"] = True
    cutoff = dt.datetime.now() - dt.timedelta(days=days)
    out: list[dict[str, Any]] = []

    for e in iter_uninstall_registry():
        d = parse_install_date(e.get("install_date_raw", ""))
        if d and d >= cutoff:
            e2 = dict(e)
            e2["install_date"] = d.strftime("%Y-%m-%d")
            out.append(e2)

    # Fallback via event log MSI pour detecter certains installs sans InstallDate registre.
    ps = textwrap.dedent(
        f"""
        try {{
            $events = @(Get-WinEvent -FilterHashtable @{{LogName='Application'; ProviderName='MsiInstaller'; Id=11707; StartTime=(Get-Date).AddDays(-{days})}} -ErrorAction Stop |
                Select-Object TimeCreated, Id, LevelDisplayName, Message)
        }} catch {{
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {{ throw }}
            $events = @()
        }}
        ConvertTo-Json -InputObject $events -Depth 4
        """
    ).strip()
    ok, raw = run_powershell(ps, timeout=120)
    if not ok:
        status.update(ok=False, error=raw)
        return out
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        status.update(ok=False, error=f"JSON MSI invalide: {exc}")
        return out
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
        status.update(ok=False, error="JSON MSI invalide")
        return out
    for item in data:
        out.append(
            {
                "display_name": "(MSI event)",
                "display_version": "",
                "publisher": "",
                "install_date": str(item.get("TimeCreated", "")),
                "install_location": "",
                "uninstall_string": "",
                "event_id": item.get("Id"),
                "event_message": str(item.get("Message", ""))[:1200],
                "registry_subkey": "",
            }
        )

    return out


def startup_entries() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    if winreg is None:
        return entries

    run_keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
    ]

    for hive, key_path, hive_name in run_keys:
        try:
            with winreg.OpenKey(hive, key_path) as key:
                value_count = winreg.QueryInfoKey(key)[1]
                for i in range(value_count):
                    name, value, _ = winreg.EnumValue(key, i)
                    entries.append(
                        {
                            "source": f"{hive_name}\\{key_path}",
                            "name": name,
                            "command": str(value),
                        }
                    )
        except OSError:
            continue

    startup_dirs = [
        Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
        Path(os.environ.get("PROGRAMDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\StartUp",
    ]
    for d in startup_dirs:
        if not d.exists():
            continue
        for item in d.glob("*"):
            try:
                stat = item.stat()
                entries.append(
                    {
                        "source": str(d),
                        "name": item.name,
                        "command": str(item),
                        "modified": dt.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    }
                )
            except OSError:
                continue

    return entries


def _event_log_start_expr(days: int, since: dt.datetime | None) -> str:
    # `since` permet de ne rescanner qu'une petite fenetre recente (utilise par le sondage temps
    # reel, toutes les 60s) plutot que les `days` complets a chaque appel (utilise par l'audit
    # complet) -- un `Get-WinEvent` sur 24h repete toutes les minutes est le principal poste de
    # cout CPU du sondage en arriere-plan, sans rapport avec un audit manuel.
    if since is not None:
        return f"[datetime]'{since.strftime('%Y-%m-%dT%H:%M:%S')}'"
    return f"(Get-Date).AddDays(-{days})"


def recent_persistence_events(
    days: int, since: dt.datetime | None = None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Taches planifiees (event 106) + services installes (event 7045) en un seul appel
    PowerShell plutot que deux. Mesure faite : le cout dominant d'un `run_powershell()` est le
    demarrage de powershell.exe lui-meme (3-7s observes sur cette machine), pas la requete
    Get-WinEvent -- fusionner les deux requetes divise ce cout fixe par 2, a chaque cycle du
    sondage temps reel (toutes les 60s) et a chaque audit complet."""
    start_expr = _event_log_start_expr(days, since)
    ps = textwrap.dedent(
        f"""
        try {{
            $tasks = @(Get-WinEvent -FilterHashtable @{{
                LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=106; StartTime={start_expr}
            }} -ErrorAction Stop | Select-Object TimeCreated, Id, Message)
        }} catch {{
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {{ throw }}
            $tasks = @()
        }}
        try {{
            $services = @(Get-WinEvent -FilterHashtable @{{
                LogName='System'; Id=7045; StartTime={start_expr}
            }} -ErrorAction Stop | Select-Object TimeCreated, Id, ProviderName, Message)
        }} catch {{
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {{ throw }}
            $services = @()
        }}
        [PSCustomObject]@{{ tasks = $tasks; services = $services }} | ConvertTo-Json -Depth 4
        """
    ).strip()
    ok, out = run_powershell(ps, timeout=120)
    if not ok or not out:
        raise RuntimeError(f"Collecte journaux Windows echouee: {out}")
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"JSON evenements invalide: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("Objet taches/services absent")
    tasks = data.get("tasks")
    services = data.get("services")
    if not isinstance(tasks, (dict, list)) or not isinstance(services, (dict, list)):
        raise RuntimeError("Listes taches/services invalides")
    if isinstance(tasks, dict):
        tasks = [tasks]
    if isinstance(services, dict):
        services = [services]
    return tasks, services


def defender_detection_needs_attention(item: dict[str, Any]) -> bool:
    """Conserver le doute sauf si Defender confirme nettoyage et arrêt/blocage."""
    return not (
        item.get("ActionSuccess") is True
        and item.get("CurrentThreatExecutionStatusID") in (1, 4)
    )


def suspicious_score(report: dict[str, Any]) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []

    # Get-MpThreatDetection includes past detections. A successful cleaning
    # action plus a blocked/not-executing status is evidence this record was
    # handled; keep it in the report, but do not score it as a current signal.
    threats = [
        item for item in report.get("defender_threat_detections", {}).get("data", [])
        if defender_detection_needs_attention(item)
    ]
    if threats:
        score += min(60, 20 * len(threats))
        reasons.append(f"Detections Defender a verifier: {len(threats)}")

    installs = report.get("recent_installs", [])
    if len(installs) >= 6:
        score += 20
        reasons.append(f"Beaucoup d'installations recentes ({len(installs)})")
    elif len(installs) >= 3:
        score += 10
        reasons.append(f"Plusieurs installations recentes ({len(installs)})")

    services = report.get("recent_service_installs", [])
    if services:
        score += min(15, len(services) * 3)
        reasons.append(f"Services installes recemment: {len(services)}")

    tasks = report.get("recent_task_registrations", [])
    if len(tasks) >= 5:
        score += 10
        reasons.append(f"Taches planifiees nouvellement enregistrees: {len(tasks)}")

    network_audit = report.get("network_audit", {})
    threat_matches = sum(
        1 for c in network_audit.get("connections", []) if c.get("threat_feed_match")
    )
    if threat_matches:
        score += 30
        reasons.append(
            f"Connexion(s) vers une IP presente dans une liste de blocage menace: {threat_matches}"
        )
    other_net_anomalies = [
        a for a in network_audit.get("anomalies", []) if "liste de blocage" not in a
    ]
    if other_net_anomalies:
        score += min(20, 5 * len(other_net_anomalies))
        reasons.append(f"Anomalies reseau detectees: {len(other_net_anomalies)}")

    score = max(0, min(100, score))
    return {"risk_score_100": score, "reasons": reasons}


def audit_is_complete(report: dict[str, Any]) -> bool:
    """Ne pas présenter un score partiel comme un audit complet."""
    if (report.get("persistence_collection", {}).get("ok") is False
            or report.get("recent_installs_collection", {}).get("ok") is False):
        return False
    if not report.get("defender_status", {}).get("ok"):
        return False
    if not report.get("defender_threat_detections", {}).get("ok"):
        return False
    params = report.get("parameters", {})
    if params.get("update_signatures") and not report.get("defender_signature_update", {}).get("ok"):
        return False
    if params.get("run_quick_scan") and (
        not report.get("defender_quick_scan", {}).get("ok")
        or not report.get("defender_targeted_scan", {}).get("ok")
    ):
        return False
    return all(feed.get("ok") for feed in report.get("threat_feeds_refresh", {}).get("feeds", []))


def write_txt_report(path: Path, report: dict[str, Any]) -> None:
    lines: list[str] = []
    lines.append("=== RAPPORT SCAN SECURITE WINDOWS ===")
    lines.append(f"Genere le: {report.get('generated_at_utc')}")
    lines.append(f"Machine: {report.get('host', {}).get('hostname')} ({report.get('host', {}).get('os')})")
    lines.append("")

    risk = report.get("risk", {})
    lines.append(f"Score de risque (0-100): {risk.get('risk_score_100')}")
    for reason in risk.get("reasons", []):
        lines.append(f"- {reason}")
    lines.append("")

    st = report.get("defender_status", {})
    lines.append("[Defender status]")
    lines.append(json.dumps(st, ensure_ascii=False, indent=2))
    lines.append("")

    lines.append("[Menaces detectees]")
    lines.append(json.dumps(report.get("defender_threat_detections", {}), ensure_ascii=False, indent=2))
    lines.append("")

    lines.append("[Installations recentes]")
    for i, app in enumerate(report.get("recent_installs", []), start=1):
        name = app.get("display_name", "")
        date = app.get("install_date", app.get("install_date_raw", ""))
        pub = app.get("publisher", "")
        lines.append(f"{i}. {name} | {date} | {pub}")
    if not report.get("recent_installs"):
        lines.append("Collecte incomplete" if report.get("recent_installs_collection", {}).get("ok") is False else "Aucune installation recente detectee")
    lines.append("")

    lines.append("[Services installes recemment]")
    for e in report.get("recent_service_installs", []):
        lines.append(f"- {e.get('TimeCreated')} | ID={e.get('Id')} | {str(e.get('Message', ''))[:200]}")
    if not report.get("recent_service_installs"):
        lines.append("Collecte incomplete" if report.get("persistence_collection", {}).get("ok") is False else "Aucun")
    lines.append("")

    lines.append("[Taches planifiees enregistrees recemment]")
    for e in report.get("recent_task_registrations", []):
        lines.append(f"- {e.get('TimeCreated')} | ID={e.get('Id')} | {str(e.get('Message', ''))[:200]}")
    if not report.get("recent_task_registrations"):
        lines.append("Collecte incomplete" if report.get("persistence_collection", {}).get("ok") is False else "Aucune")
    lines.append("")

    lines.append("[Startup entries]")
    for s in report.get("startup_entries", []):
        lines.append(f"- {s.get('source')} | {s.get('name')} | {s.get('command')}")
    if not report.get("startup_entries"):
        lines.append("Aucune entree startup")
    lines.append("")

    lines.append("[Audit reseau]")
    net = report.get("network_audit", {})
    total_bps = net.get("upload_bps", 0.0) + net.get("download_bps", 0.0)
    lines.append(f"CPU: {net.get('cpu_percent', 0):.0f}% | Debit observe: {format_rate(total_bps)}")
    conns = net.get("connections", [])
    if conns:
        lines.append(f"Connexions publiques observees: {len(conns)}")
        for c in conns[:50]:
            flag = " [MENACE CONNUE]" if c.get("threat_feed_match") else ""
            lines.append(f"- {c.get('process_name') or 'inconnu'} -> {c.get('remote')} ({c.get('status')}){flag}")
    else:
        lines.append("Aucune connexion publique observee")
    net_anomalies = net.get("anomalies", [])
    if net_anomalies:
        lines.append("Anomalies reseau:")
        for a in net_anomalies:
            lines.append(f"  - {a}")
    lines.append("")

    lines.append("")
    lines.append("[Mise a jour liste de menaces]")
    feed_refresh = report.get("threat_feeds_refresh", {})
    feeds = feed_refresh.get("feeds", [])
    for feed in feeds:
        if feed.get("ok"):
            lines.append(f"- OK | {feed.get('url')} | entrees={feed.get('entries')}")
        else:
            lines.append(f"- KO | {feed.get('url')} | erreur={feed.get('error', '')}")
    if not feeds:
        lines.append("Aucune mise a jour effectuee")

    path.write_text("\n".join(lines), encoding="utf-8")


def generate_report(
    days: int,
    do_update: bool,
    do_scan: bool,
    output_dir: Path | None = None,
    progress: Callable[[str, int], None] | None = None,
) -> dict[str, Any]:
    def step(label: str, pct: int) -> None:
        _check_audit_cancelled()
        if progress is not None:
            try:
                progress(label, pct)
            except Exception:
                pass

    hostname = platform.node()
    os_name = f"{platform.system()} {platform.release()}"

    report: dict[str, Any] = {
        "generated_at_utc": now_utc_iso(),
        "host": {
            "hostname": hostname,
            "os": os_name,
            "python": sys.version,
        },
        "parameters": {
            "days": days,
            "update_signatures": do_update,
            "run_quick_scan": do_scan,
        },
    }

    step("Etat Defender...", 5)
    report["defender_status"] = defender_status()
    if do_update:
        step("Mise a jour des signatures Defender...", 15)
        report["defender_signature_update"] = defender_signature_update()
    if do_scan:
        step("Scan rapide Defender...", 40)
        report["defender_quick_scan"] = defender_quick_scan()
        step("Scan cible Defender...", 70)
        report["defender_targeted_scan"] = defender_targeted_scan(common_scan_paths())

    step("Menaces detectees...", 80)
    report["defender_threat_detections"] = defender_threat_detections()
    step("Installations recentes...", 83)
    installs_status: dict[str, Any] = {}
    report["recent_installs"] = recent_installs(days, installs_status)
    report["recent_installs_collection"] = installs_status
    step("Services et taches recents...", 87)
    try:
        task_events, service_events = recent_persistence_events(days)
        report["persistence_collection"] = {"ok": True}
    except RuntimeError as exc:
        task_events, service_events = [], []
        report["persistence_collection"] = {"ok": False, "error": str(exc)}
    report["recent_service_installs"] = service_events
    report["recent_task_registrations"] = task_events
    step("Mise a jour des flux de menaces...", 92)
    if output_dir is not None:
        report["threat_feeds_refresh"] = refresh_threat_feeds_cache(output_dir)
    else:
        report["threat_feeds_refresh"] = {"feeds": [], "note": "output_dir non fourni"}

    step("Audit reseau...", 95)
    threat_feed_ips = build_threat_feed_ip_set(report["threat_feeds_refresh"])
    report["network_audit"] = network_audit_snapshot(threat_feed_ips)

    step("Entrees de demarrage...", 98)
    startup = startup_entries()
    for item in startup:
        # Si la commande ressemble a un chemin local, on ajoute un hash SHA-256.
        cmd = str(item.get("command", ""))
        m = re.match(r'^"([A-Za-z]:\\[^\"]+)"', cmd) or re.match(r"^([A-Za-z]:\\[^\s]+)", cmd)
        if m:
            p = Path(m.group(1))
            if p.exists() and p.is_file():
                item["sha256"] = sha256_file(p)
    report["startup_entries"] = startup

    report["risk"] = suspicious_score(report)
    # Pas de _check_audit_cancelled() ici : le travail est fini, une annulation demandee au
    # tout dernier instant ne doit pas jeter un rapport deja complet.
    if progress is not None:
        try:
            progress("Termine", 100)
        except Exception:
            pass
    return report


def save_reports(report: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = output_dir / f"scan_report_{stamp}.json"
    txt_path = output_dir / f"scan_report_{stamp}.txt"

    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    write_txt_report(txt_path, report)
    return json_path, txt_path


def history_file_path(output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir / "actions_history.jsonl"


def append_history_event(output_dir: Path, event: dict[str, Any]) -> None:
    path = history_file_path(output_dir)
    payload = {"timestamp": dt.datetime.now().isoformat(), **event}
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Audit securite Windows: Defender + installations recentes + persistence + reseau",
    )
    p.add_argument("--days", type=int, default=14, help="Nombre de jours a inspecter (defaut: 14)")
    p.add_argument("--output", type=str, default="reports", help="Dossier de sortie des rapports")
    p.add_argument(
        "--skip-signature-update",
        action="store_true",
        help="Ne pas forcer la mise a jour des signatures Defender",
    )
    p.add_argument(
        "--skip-quick-scan",
        action="store_true",
        help="Ne pas lancer le scan rapide Defender",
    )
    p.add_argument(
        "--gui",
        action="store_true",
        help="Lance l'interface graphique",
    )
    p.add_argument(
        "--start-minimized",
        action="store_true",
        help="Demarre l'interface reduite",
    )
    p.add_argument(
        "--monitoring-enabled",
        action="store_true",
        help="Active le monitoring arriere-plan au demarrage",
    )
    return p


def launch_gui(
    default_days: int = 14,
    default_output: str = "reports",
    start_minimized: bool = False,
    auto_monitoring: bool = False,
) -> int:
    import tkinter as tk
    from tkinter import messagebox, ttk

    try:
        import pystray  # type: ignore
        from PIL import Image  # type: ignore
    except Exception:
        pystray = None
        Image = None

    root = tk.Tk()
    root.title("Scan System - Audit securite Windows")
    root.geometry("1220x760")
    try:
        root.iconbitmap(default=str(resource_path("pictures/scan_system.ico")))
    except Exception:
        pass

    style = ttk.Style()
    current_theme = detect_windows_theme()
    palette = UI_COLORS[current_theme]
    try:
        style.theme_use("clam")
    except Exception:
        pass
    bg = palette["bg"]
    fg = palette["fg"]
    box_bg = palette["surface"]
    rule = palette["divider"]
    hairline = palette["mark"]

    def set_titlebar_theme(window: tk.Misc) -> None:
        if platform.system().lower() != "windows":
            return
        try:
            import ctypes

            user32 = ctypes.windll.user32
            user32.GetParent.argtypes = [ctypes.c_void_p]
            user32.GetParent.restype = ctypes.c_void_p
            client_hwnd = window.winfo_id()
            hwnd = user32.GetParent(client_hwnd) or client_hwnd
            enabled = ctypes.c_int(current_theme == "dark")
            dwm_set_attribute = ctypes.windll.dwmapi.DwmSetWindowAttribute
            dwm_set_attribute.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                                          ctypes.c_void_p, ctypes.c_uint]
            dwm_set_attribute(
                hwnd, 20, ctypes.byref(enabled), ctypes.sizeof(enabled)
            )
        except (AttributeError, OSError, tk.TclError):
            pass

    def configure_theme_styles() -> None:
        root.configure(bg=bg)
        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("TNotebook", background=bg, bordercolor=palette["border"],
                        relief="flat")
        style.configure("TNotebook.Tab", background=palette["header"], foreground=fg,
                        bordercolor=palette["border"], padding=(10, 4), relief="flat")
        style.map("TNotebook.Tab", background=[("selected", palette["button"]),
                                                ("active", palette["button_hover"])],
                  foreground=[("selected", "#ffffff"), ("active", "#ffffff")])
        style.configure("TButton", background=palette["button"], foreground="#ffffff",
                        bordercolor=palette["border"], padding=(8, 4), relief="flat")
        style.map("TButton", background=[("disabled", palette["button_disabled"]),
                                          ("active", palette["button_hover"])],
                  foreground=[("disabled", palette["disabled_fg"])])
        style.configure("TCheckbutton", background=bg, foreground=fg)
        style.configure("TEntry", fieldbackground=box_bg, foreground=fg,
                        bordercolor=palette["border"], insertcolor=fg)
        style.configure("Vertical.TScrollbar", background=palette["divider"],
                        troughcolor=box_bg, bordercolor=palette["border"])
        style.configure("Treeview", background=box_bg, fieldbackground=box_bg, foreground=fg)
        style.configure("Treeview.Heading", background=palette["header"], foreground=fg)
        style.map("Treeview", background=[("selected", palette["selection"])],
                  foreground=[("selected", palette["selection_fg"])])
        style.configure("Audit.Horizontal.TProgressbar", background=palette["button"],
                        troughcolor=box_bg, bordercolor=box_bg,
                        lightcolor=palette["button"], darkcolor=palette["button"])

    configure_theme_styles()

    threat_items: list[dict[str, Any]] = []
    realtime_items: list[dict[str, Any]] = []
    last_json_report = ""
    last_txt_report = ""
    audit_running = False
    realtime_state: dict[str, Any] = {}
    tray_icon = None
    tray_thread = None
    monitoring_enabled = tk.BooleanVar(value=auto_monitoring)
    startup_enabled = tk.BooleanVar(value=is_startup_monitoring_enabled())

    def anomaly_kind(text: str) -> str:
        # CPU/reseau embarquent une valeur qui fluctue en continu (ex. "CPU eleve: 87%" puis
        # "89%") -- sans normaliser, chaque variation defait toute dedup par texte exact et spam
        # les notifications alors que c'est le meme signal qui reste vrai en continu (cas reel :
        # plusieurs grosses applications ouvertes en meme temps, Discord/Outlook/Edge/VSCode).
        # Les autres anomalies (connexion suspecte, nouvelle entree startup...) embarquent une
        # info distincte a chaque occurrence (IP, nom de process) -- texte complet pour elles,
        # volontairement, deux alertes differentes ne doivent pas se supprimer l'une l'autre.
        if text.startswith("CPU eleve") or text.startswith("Debit reseau eleve"):
            return text.split(":", 1)[0]
        return text

    # Anti-spam par "type" d'anomalie plutot que par texte exact : cooldown avant de re-signaler
    # le meme type, au lieu d'un "vu une fois, plus jamais" (qui masquerait un vrai probleme
    # persistant apres la purge des 20 dernieres entrees) ou d'un "jamais vu, toujours nouveau"
    # (le bug corrige ici).
    last_anomaly_ts: dict[str, float] = {}
    LOG_ANOMALY_COOLDOWN_S = 60.0
    last_notified_ts: dict[str, float] = {}
    NOTIFY_ANOMALY_COOLDOWN_S = 300.0

    days_var = tk.StringVar(value=str(default_days))
    output_var = tk.StringVar(value=str(resolve_output_dir(default_output)))
    header = tk.Frame(root, bg=palette["header"], height=76, highlightthickness=0)
    header.pack(fill="x")
    header.pack_propagate(False)
    logo_image = tk.PhotoImage(file=str(resource_path("pictures/icon_64x64.png")))
    logo_label = tk.Label(header, image=logo_image, bg=palette["header"], borderwidth=0)
    logo_label.pack(side="left", padx=(18, 6))
    title_label = tk.Label(header, text="Scan System", bg=palette["header"], fg=fg,
                           font=("Segoe UI", 24, "bold"))
    title_label.pack(side="left", padx=(0, 20))
    geometry = tk.Canvas(header, width=94, height=60, bg=palette["header"], highlightthickness=0)
    geometry.pack(side="right", padx=18)
    geometry_border = geometry.create_rectangle(1, 1, 93, 59, outline=hairline)
    for coords in ((1, 1, 93, 59), (27, 1, 93, 49), (93, 1, 1, 59), (93, 27, 63, 59)):
        geometry.create_line(*coords, fill=hairline, width=1)
    divider = tk.Frame(root, bg=rule, height=6)
    divider.pack(fill="x")
    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=10, pady=10)

    tab_audit = ttk.Frame(notebook, padding=10)
    tab_threats = ttk.Frame(notebook, padding=10)
    tab_realtime = ttk.Frame(notebook, padding=10)
    tab_reports = ttk.Frame(notebook, padding=10)
    notebook.add(tab_audit, text="Audit")
    notebook.add(tab_threats, text="Menaces")
    notebook.add(tab_realtime, text="Temps reel")
    notebook.add(tab_reports, text="Rapports")

    # Audit tab
    audit_top = ttk.Frame(tab_audit)
    audit_top.pack(fill="x")
    ttk.Label(audit_top, text="Jours a analyser:").pack(side="left")
    ttk.Entry(audit_top, width=8, textvariable=days_var).pack(side="left", padx=(6, 12))
    ttk.Label(audit_top, text="Dossier rapports:").pack(side="left")
    ttk.Entry(audit_top, width=36, textvariable=output_var).pack(side="left", padx=(6, 12))

    audit_progress_var = tk.DoubleVar(value=0.0)
    audit_status_var = tk.StringVar(value="")
    audit_elapsed_var = tk.StringVar(value="")

    audit_progress_row = ttk.Frame(tab_audit)
    audit_progress_row.pack(fill="x", pady=(6, 0))
    ttk.Progressbar(
        audit_progress_row,
        variable=audit_progress_var,
        maximum=100,
        length=280,
        style="Audit.Horizontal.TProgressbar",
    ).pack(side="left")
    ttk.Label(audit_progress_row, textvariable=audit_status_var).pack(side="left", padx=(10, 0))
    ttk.Label(audit_progress_row, textvariable=audit_elapsed_var).pack(side="right")

    audit_actions = ttk.Frame(tab_audit)
    audit_actions.pack(fill="x", pady=(10, 8))

    audit_log = tk.Text(tab_audit, wrap="word", height=28, bg=box_bg, fg=fg,
                        insertbackground=fg, highlightbackground=palette["border"])
    audit_log.pack(fill="both", expand=True)

    # Threats tab
    threat_actions = ttk.Frame(tab_threats)
    threat_actions.pack(fill="x", pady=(0, 8))

    threat_status_var = tk.StringVar(value="")
    threat_elapsed_var = tk.StringVar(value="")

    threat_progress_row = ttk.Frame(tab_threats)
    threat_progress_row.pack(fill="x", pady=(0, 8))
    threat_progress_bar = ttk.Progressbar(
        threat_progress_row,
        mode="indeterminate",
        length=280,
        style="Audit.Horizontal.TProgressbar",
    )
    threat_progress_bar.pack(side="left")
    ttk.Label(threat_progress_row, textvariable=threat_status_var).pack(side="left", padx=(10, 0))
    ttk.Label(threat_progress_row, textvariable=threat_elapsed_var).pack(side="right")

    threat_cols = ("name", "detected", "status", "resources")
    threat_tree = ttk.Treeview(tab_threats, columns=threat_cols, show="headings", selectmode="extended")
    threat_tree.heading("name", text="Menace")
    threat_tree.heading("detected", text="Detection")
    threat_tree.heading("status", text="Action OK")
    threat_tree.heading("resources", text="Ressources")
    threat_tree.column("name", width=250)
    threat_tree.column("detected", width=180)
    threat_tree.column("status", width=100)
    threat_tree.column("resources", width=580)
    threat_tree.pack(fill="both", expand=True, side="left")
    threat_scroll = ttk.Scrollbar(tab_threats, orient="vertical", command=threat_tree.yview)
    threat_scroll.pack(fill="y", side="right")
    threat_tree.configure(yscrollcommand=threat_scroll.set)

    # Realtime tab
    rt_actions = ttk.Frame(tab_realtime)
    rt_actions.pack(fill="x", pady=(0, 8))

    ttk.Checkbutton(rt_actions, text="Monitoring arriere-plan", variable=monitoring_enabled, command=lambda: toggle_background_monitoring()).pack(side="left")

    rt_cols = ("process", "pid", "local", "remote", "status")
    rt_tree = ttk.Treeview(tab_realtime, columns=rt_cols, show="headings", selectmode="extended")
    rt_tree.heading("process", text="Processus")
    rt_tree.heading("pid", text="PID")
    rt_tree.heading("local", text="Local")
    rt_tree.heading("remote", text="Remote")
    rt_tree.heading("status", text="Etat")
    rt_tree.column("process", width=220)
    rt_tree.column("pid", width=80)
    rt_tree.column("local", width=220)
    rt_tree.column("remote", width=260)
    rt_tree.column("status", width=120)
    rt_tree.pack(fill="both", expand=True, side="left")
    rt_scroll = ttk.Scrollbar(tab_realtime, orient="vertical", command=rt_tree.yview)
    rt_scroll.pack(fill="y", side="right")
    rt_tree.configure(yscrollcommand=rt_scroll.set)

    rt_anomalies = tk.Text(tab_realtime, wrap="word", height=7, bg=box_bg, fg=fg,
                           insertbackground=fg, highlightbackground=palette["border"])
    rt_anomalies.pack(fill="x", pady=(8, 0))

    # Reports tab
    rep_top = ttk.Frame(tab_reports)
    rep_top.pack(fill="x", pady=(0, 8))
    report_list = tk.Listbox(tab_reports, height=25, bg=box_bg, fg=fg,
                             selectbackground=palette["selection"],
                             selectforeground=palette["selection_fg"],
                             highlightbackground=palette["border"])
    report_list.pack(fill="both", expand=True)

    rep_bottom = ttk.Frame(tab_reports)
    rep_bottom.pack(fill="x", pady=(8, 0))
    rep_status = tk.StringVar(value="Aucun rapport charge")
    ttk.Label(rep_bottom, textvariable=rep_status).pack(side="left")

    status_frame = ttk.Frame(root, padding=(10, 0, 10, 8))
    status_frame.pack(fill="x", side="bottom")
    theme_var = tk.StringVar(value=f"Theme: {current_theme}")
    cpu_var = tk.StringVar(value="CPU: 0%")
    net_var = tk.StringVar(value="Net: 0 bps")
    ttk.Label(status_frame, textvariable=theme_var).pack(side="left")
    ttk.Label(status_frame, textvariable=net_var).pack(side="right")
    ttk.Label(status_frame, textvariable=cpu_var).pack(side="right", padx=(0, 16))

    def refresh_theme() -> None:
        nonlocal current_theme, palette, bg, fg, box_bg, rule, hairline
        new_theme = detect_windows_theme()
        if new_theme != current_theme:
            current_theme = new_theme
            palette = UI_COLORS[current_theme]
            bg = palette["bg"]
            fg = palette["fg"]
            box_bg = palette["surface"]
            rule = palette["divider"]
            hairline = palette["mark"]
            try:
                style.theme_use("clam")
            except Exception:
                pass
            configure_theme_styles()
            set_titlebar_theme(root)
            header.configure(bg=palette["header"])
            logo_label.configure(bg=palette["header"])
            title_label.configure(bg=palette["header"], fg=fg)
            geometry.configure(bg=palette["header"])
            geometry.itemconfigure(geometry_border, outline=hairline)
            for item_id in geometry.find_all():
                if item_id != geometry_border:
                    geometry.itemconfigure(item_id, fill=hairline)
            divider.configure(bg=rule)
            for text_widget in (audit_log, rt_anomalies):
                text_widget.configure(bg=box_bg, fg=fg, insertbackground=fg,
                                      highlightbackground=palette["border"])
            report_list.configure(bg=box_bg, fg=fg,
                                  selectbackground=palette["selection"],
                                  selectforeground=palette["selection_fg"],
                                  highlightbackground=palette["border"])
            for child in root.winfo_children():
                if isinstance(child, tk.Toplevel):
                    child.configure(bg=bg)
                    set_titlebar_theme(child)
                    for widget in child.winfo_children():
                        if isinstance(widget, tk.Text):
                            widget.configure(bg=box_bg, fg=fg, insertbackground=fg,
                                             highlightbackground=palette["border"])
            theme_var.set(f"Theme: {current_theme}")
        root.after(1000, refresh_theme)

    def log_line(msg: str) -> None:
        audit_log.insert("end", msg + "\n")
        audit_log.see("end")
        root.update_idletasks()

    def log_line_async(msg: str) -> None:
        root.after(0, lambda: log_line(msg))

    def clear_threat_tree() -> None:
        for item_id in threat_tree.get_children():
            threat_tree.delete(item_id)

    def read_days() -> int:
        try:
            return max(1, min(180, int(days_var.get().strip())))
        except ValueError:
            return default_days

    def selected_threat_items() -> list[dict[str, Any]]:
        selected = threat_tree.selection()
        return [threat_items[int(i)] for i in selected if i.isdigit() and int(i) < len(threat_items)]

    def populate_threats(items: list[dict[str, Any]]) -> None:
        nonlocal threat_items
        threat_items = items
        clear_threat_tree()
        for idx, item in enumerate(threat_items):
            resources = item.get("Resources", [])
            if not isinstance(resources, list):
                resources = [str(resources)] if resources else []
            threat_tree.insert(
                "",
                "end",
                iid=str(idx),
                values=(
                    item.get("ThreatName", ""),
                    item.get("InitialDetectionTime", ""),
                    str(item.get("ActionSuccess", "")),
                    " | ".join(str(r) for r in resources[:4]),
                ),
            )

    def selected_realtime_items() -> list[dict[str, Any]]:
        selected = rt_tree.selection()
        return [realtime_items[int(i)] for i in selected if i.isdigit() and int(i) < len(realtime_items)]

    def populate_realtime(items: list[dict[str, Any]]) -> None:
        nonlocal realtime_items
        realtime_items = items
        for item_id in rt_tree.get_children():
            rt_tree.delete(item_id)
        for idx, item in enumerate(realtime_items):
            rt_tree.insert(
                "",
                "end",
                iid=str(idx),
                values=(
                    item.get("process_name", ""),
                    str(item.get("pid", "")),
                    item.get("local", ""),
                    item.get("remote", ""),
                    item.get("status", ""),
                ),
            )

    def append_anomaly_lines(lines: list[str]) -> None:
        if not lines:
            return
        now_ts = time.time()
        for line in lines:
            kind = anomaly_kind(line)
            if now_ts - last_anomaly_ts.get(kind, 0.0) < LOG_ANOMALY_COOLDOWN_S:
                continue
            last_anomaly_ts[kind] = now_ts
            rt_anomalies.insert("end", f"[{dt.datetime.now().strftime('%H:%M:%S')}] {line}\n")
            rt_anomalies.see("end")

    def create_tray_image() -> Any:
        if Image is None:
            return None
        try:
            return Image.open(resource_path("pictures/icon_64x64.png")).convert("RGBA")
        except Exception:
            return None

    def restore_from_tray() -> None:
        nonlocal tray_icon
        root.after(0, lambda: (root.deiconify(), root.lift(), root.focus_force()))
        if tray_icon is not None:
            try:
                tray_icon.stop()
            except Exception:
                pass
            tray_icon = None

    def quit_application() -> None:
        nonlocal tray_icon
        if tray_icon is not None:
            try:
                tray_icon.stop()
            except Exception:
                pass
            tray_icon = None
        root.after(0, root.destroy)

    def ensure_background_monitoring_ready() -> None:
        if not monitoring_enabled.get():
            return
        if getattr(sys, "frozen", False):
            result = ensure_app_firewall_rule(sys.executable)
            if not result.get("ok"):
                append_anomaly_lines(["Regle pare-feu appli non ajoutee"])
            else:
                log_line("[OK] Regle pare-feu appliquee pour le monitoring en arriere-plan")

    def toggle_background_monitoring() -> None:
        if monitoring_enabled.get():
            ensure_background_monitoring_ready()
            log_line("[+] Monitoring reseau en arriere-plan active")
        else:
            log_line("[i] Monitoring reseau en arriere-plan desactive")
    def toggle_startup_monitoring() -> None:
        result = set_startup_monitoring_enabled(startup_enabled.get())
        if result.get("ok"):
            if startup_enabled.get():
                log_line("[OK] Demarrage auto Windows active pour le monitoring")
            else:
                log_line("[i] Demarrage auto Windows desactive")
        else:
            startup_enabled.set(not startup_enabled.get())
            messagebox.showerror("Erreur", f"Impossible de modifier le demarrage auto.\n\n{result.get('error', '')}")
    ttk.Checkbutton(rt_actions, text="Lancer avec Windows", variable=startup_enabled, command=lambda: toggle_startup_monitoring()).pack(side="left", padx=(10, 0))

    def minimize_to_tray() -> None:
        nonlocal tray_icon, tray_thread
        if tray_icon is not None:
            # Icone de tray deja active : c'est elle qui permet de rappeler la fenetre.
            root.withdraw()
            return
        if pystray is None:
            # Pas d'icone de tray disponible (pystray absent) : ne PAS masquer completement
            # (root.withdraw() rendrait la fenetre irrecuperable, sans bouton barre des taches
            # ni icone de tray). On reduit normalement a la place.
            root.iconify()
            return

        ensure_background_monitoring_ready()
        icon_image = create_tray_image()
        if icon_image is None:
            root.iconify()
            return

        menu = pystray.Menu(
            pystray.MenuItem("Ouvrir", lambda icon, item: restore_from_tray()),
            pystray.MenuItem("Quitter", lambda icon, item: quit_application()),
        )
        tray_icon = pystray.Icon("ScanSystem", icon_image, "Scan System", menu)

        def run_icon() -> None:
            try:
                tray_icon.run()
            except Exception:
                pass

        tray_thread = threading.Thread(target=run_icon, daemon=True)
        tray_thread.start()
        root.withdraw()

    def on_root_close() -> None:
        if monitoring_enabled.get():
            minimize_to_tray()
        else:
            quit_application()

    def on_window_unmap(event: Any) -> None:
        if event.widget is root and monitoring_enabled.get() and root.state() == "iconic":
            minimize_to_tray()

    realtime_busy = [False]

    def refresh_realtime() -> None:
        # collect_realtime_snapshot() inclut, toutes les 60s, deux appels Get-WinEvent via
        # PowerShell (cf. recent_task_scheduler_events/recent_service_installs) -- assez couteux
        # pour geler l'UI et faire pic le CPU si execute sur le thread principal. Lance en arriere
        # plan, avec un garde anti-chevauchement si un cycle precedent n'est pas encore termine.
        if realtime_busy[0]:
            root.after(2000, refresh_realtime)
            return
        realtime_busy[0] = True

        def worker() -> None:
            snapshot = collect_realtime_snapshot(realtime_state)

            def apply_snapshot() -> None:
                realtime_busy[0] = False
                cpu_var.set(f"CPU: {snapshot['cpu_percent']:.0f}%")
                net_var.set(
                    f"Net: D {format_rate(snapshot['download_bps'])} | U {format_rate(snapshot['upload_bps'])}"
                )
                populate_realtime(snapshot.get("connections", []))
                append_anomaly_lines(snapshot.get("anomalies", []))
                if monitoring_enabled.get() and tray_icon is not None and snapshot.get("anomalies"):
                    now_ts = time.time()
                    new_items = []
                    for item in snapshot["anomalies"]:
                        kind = anomaly_kind(item)
                        if now_ts - last_notified_ts.get(kind, 0.0) >= NOTIFY_ANOMALY_COOLDOWN_S:
                            new_items.append(item)
                            last_notified_ts[kind] = now_ts
                    if new_items:
                        try:
                            tray_icon.notify(" ; ".join(new_items[:2]), "Scan System")
                        except Exception:
                            pass
                root.after(2000, refresh_realtime)

            root.after(0, apply_snapshot)

        threading.Thread(target=worker, daemon=True).start()

    def trace_selected_ip_gui() -> None:
        items = selected_realtime_items()
        if not items:
            messagebox.showinfo("Information", "Selectionne au moins une connexion reseau.")
            return
        remote_ip = str(items[0].get("remote_ip", ""))
        if not remote_ip:
            return
        log_line(f"[~] Trace route vers {remote_ip}...")

        def worker() -> None:
            result = trace_remote_ip(remote_ip)

            def on_done() -> None:
                if result.get("ok"):
                    detail_win = tk.Toplevel(root)
                    detail_win.title(f"Trace route {remote_ip}")
                    detail_win.geometry("900x500")
                    detail_win.after_idle(lambda: set_titlebar_theme(detail_win))
                    text = tk.Text(detail_win, wrap="word", bg=box_bg, fg=fg,
                                   insertbackground=fg, highlightbackground=palette["border"])
                    text.pack(fill="both", expand=True)
                    text.insert("1.0", result.get("stdout", ""))
                    text.configure(state="disabled")
                else:
                    messagebox.showerror("Erreur", f"Trace route echouee.\n\n{result.get('stderr', '')}")

            root.after(0, on_done)

        threading.Thread(target=worker, daemon=True).start()

    def block_selected_ip_gui() -> None:
        items = selected_realtime_items()
        if not items:
            messagebox.showinfo("Information", "Selectionne au moins une connexion reseau.")
            return
        remote_ip = str(items[0].get("remote_ip", ""))
        process_name = str(items[0].get("process_name", ""))
        if not remote_ip or not is_public_ipv4(remote_ip):
            messagebox.showwarning("Blocage", "Seules les IP publiques peuvent etre bloquees ici.")
            return
        if not messagebox.askyesno(
            "Bloquer IP",
            f"Bloquer l'IP distante {remote_ip} pour la machine ?\n\nProcessus observe: {process_name or 'inconnu'}",
        ):
            return
        log_line(f"[~] Blocage firewall de {remote_ip}...")

        def worker() -> None:
            result = block_remote_ip(remote_ip)

            def on_done() -> None:
                if result.get("ok"):
                    log_line(f"[OK] IP bloquee: {remote_ip}")
                    append_anomaly_lines([f"IP bloquee manuellement: {remote_ip}"])
                else:
                    log_line(f"[ERREUR] Blocage IP {remote_ip}: {result.get('stderr', '')}")
                    messagebox.showerror("Erreur", f"Blocage IP echoue.\n\n{result.get('stderr', '')}")

            root.after(0, on_done)

        threading.Thread(target=worker, daemon=True).start()

    def get_output_dir() -> Path:
        out_dir = resolve_output_dir(output_var.get().strip() or default_output)
        output_var.set(str(out_dir))
        return out_dir

    def refresh_reports_tab() -> None:
        out_dir = get_output_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        report_list.delete(0, "end")
        files = sorted(out_dir.glob("scan_report_*.txt"), reverse=True)
        for f in files:
            report_list.insert("end", f.name)
        rep_status.set(f"{len(files)} rapport(s) dans {out_dir}")

    def open_reports_folder() -> None:
        out_dir = get_output_dir().resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(out_dir))  # type: ignore[attr-defined]
        except Exception as exc:
            messagebox.showerror("Erreur", f"Impossible d'ouvrir le dossier: {exc}")

    def open_selected_report() -> None:
        out_dir = get_output_dir()
        sel = report_list.curselection()
        if not sel:
            messagebox.showinfo("Information", "Selectionne un rapport dans la liste.")
            return
        fname = report_list.get(sel[0])
        target = out_dir / fname
        if not target.exists():
            messagebox.showerror("Erreur", "Fichier introuvable.")
            return
        try:
            os.startfile(str(target))  # type: ignore[attr-defined]
        except Exception as exc:
            messagebox.showerror("Erreur", f"Impossible d'ouvrir le rapport: {exc}")

    def refresh_defender_threats() -> None:
        def worker() -> None:
            try:
                result = defender_threat_detections()
                items = result.get("data", []) if result.get("ok") else []

                def on_success() -> None:
                    populate_threats(items)
                    log_line(f"[+] Menaces Defender rechargees: {len(items)}")

                root.after(0, on_success)
            except Exception:
                err = traceback.format_exc()
                write_crash_log(err)
                root.after(0, lambda: messagebox.showerror("Erreur", f"Impossible de rafraichir les menaces.\n\nLog: {crash_log_path()}"))

        threading.Thread(target=worker, daemon=True).start()

    def show_selected_threat_details() -> None:
        items = selected_threat_items()
        if not items:
            messagebox.showinfo("Information", "Selectionne au moins une menace.")
            return
        details = json.dumps(items, ensure_ascii=False, indent=2)
        detail_win = tk.Toplevel(root)
        detail_win.title("Details menaces Defender")
        detail_win.geometry("900x500")
        detail_win.after_idle(lambda: set_titlebar_theme(detail_win))
        text = tk.Text(detail_win, wrap="word", bg=box_bg, fg=fg,
                       insertbackground=fg, highlightbackground=palette["border"])
        text.pack(fill="both", expand=True)
        text.insert("1.0", details)
        text.configure(state="disabled")

    threat_op_running = [False]
    threat_start_ts = [0.0]

    def tick_threat_timer() -> None:
        if not threat_op_running[0]:
            return
        threat_elapsed_var.set(format_elapsed(threat_start_ts[0]))
        root.after(500, tick_threat_timer)

    def start_threat_busy(label: str) -> None:
        # Defender (Start-MpScan) ne fournit pas de pourcentage d'avancement via PowerShell --
        # barre indeterminee (animation continue) + chrono, plutot qu'une fausse jauge chiffree.
        threat_op_running[0] = True
        threat_start_ts[0] = time.time()
        threat_status_var.set(label)
        threat_elapsed_var.set("00:00")
        threat_progress_bar.start(50)
        tick_threat_timer()

    def stop_threat_busy(label: str) -> None:
        threat_op_running[0] = False
        threat_progress_bar.stop()
        threat_status_var.set(label)

    def cleanup_defender_threats() -> None:
        if not any(defender_detection_needs_attention(item) for item in threat_items):
            messagebox.showinfo("Information", "Aucune detection non resolue a nettoyer.")
            return

        prompt = (
            "Defender ne permet pas ici un nettoyage cible par menace.\n\n"
            "L'action va demander a Defender de traiter les menaces actives connues sur la machine.\n\n"
            "Continuer ?"
        )
        if not messagebox.askyesno("Nettoyage Defender", prompt):
            return
        if threat_op_running[0]:
            messagebox.showinfo("Information", "Une operation Defender est deja en cours.")
            return

        log_line("[~] Demande de nettoyage Defender en cours...")
        start_threat_busy("Nettoyage Defender en cours...")

        def worker() -> None:
            res = defender_remove_threats()

            def on_done() -> None:
                if res.get("ok"):
                    log_line("[OK] Nettoyage Defender termine")
                    stop_threat_busy(f"Nettoyage termine en {format_elapsed(threat_start_ts[0])}")
                    refresh_defender_threats()
                else:
                    log_line(f"[ERREUR] Nettoyage Defender: {res.get('error', '')}")
                    stop_threat_busy("Nettoyage Defender echoue")
                    messagebox.showerror("Erreur", f"Nettoyage Defender echoue.\n\n{res.get('error', '')}")

            root.after(0, on_done)

        threading.Thread(target=worker, daemon=True).start()

    def launch_full_scan_manual() -> None:
        if not messagebox.askyesno("Scan complet", "Lancer un scan complet Defender ?"):
            return
        if threat_op_running[0]:
            messagebox.showinfo("Information", "Une operation Defender est deja en cours.")
            return

        log_line("[~] Demande de scan complet Defender...")
        start_threat_busy("Scan complet Defender en cours (peut prendre longtemps)...")

        def worker() -> None:
            res = defender_full_scan()

            def on_done() -> None:
                if res.get("ok"):
                    log_line("[OK] Scan complet Defender termine")
                    stop_threat_busy(f"Scan complet termine en {format_elapsed(threat_start_ts[0])}")
                    refresh_defender_threats()
                else:
                    log_line(f"[ERREUR] Scan complet Defender: {res.get('error', '')}")
                    stop_threat_busy("Scan complet Defender echoue")
                    messagebox.showerror("Erreur", f"Scan complet echoue.\n\n{res.get('error', '')}")

            root.after(0, on_done)

        threading.Thread(target=worker, daemon=True).start()

    def launch_offline_scan_manual() -> None:
        prompt = (
            "Lancer un scan hors ligne Microsoft Defender ?\n\n"
            "Windows peut demander un redemarrage pour terminer cette operation."
        )
        if not messagebox.askyesno("Scan hors ligne", prompt):
            return
        if threat_op_running[0]:
            messagebox.showinfo("Information", "Une operation Defender est deja en cours.")
            return

        log_line("[~] Demande de scan hors ligne Defender...")
        start_threat_busy("Demande de scan hors ligne en cours...")

        def worker() -> None:
            res = defender_offline_scan()

            def on_done() -> None:
                if res.get("ok"):
                    log_line("[OK] Scan hors ligne Defender demande")
                    stop_threat_busy(f"Scan hors ligne demande en {format_elapsed(threat_start_ts[0])}")
                    messagebox.showinfo("Information", "La demande de scan hors ligne a ete envoyee a Defender.")
                else:
                    log_line(f"[ERREUR] Scan hors ligne Defender: {res.get('error', '')}")
                    stop_threat_busy("Scan hors ligne Defender echoue")
                    messagebox.showerror("Erreur", f"Scan hors ligne echoue.\n\n{res.get('error', '')}")

            root.after(0, on_done)

        threading.Thread(target=worker, daemon=True).start()

    audit_start_ts = [0.0]

    def format_elapsed(start_ts: float) -> str:
        mins, secs = divmod(int(time.time() - start_ts), 60)
        return f"{mins:02d}:{secs:02d}"

    def tick_audit_timer() -> None:
        if not audit_running:
            return
        audit_elapsed_var.set(format_elapsed(audit_start_ts[0]))
        root.after(500, tick_audit_timer)

    def update_audit_progress(label: str, pct: int) -> None:
        audit_progress_var.set(float(pct))
        audit_status_var.set(f"{label} ({pct}%)")

    def run_full_audit() -> None:
        nonlocal last_json_report, last_txt_report, audit_running
        if audit_running:
            messagebox.showinfo("Information", "Un audit est deja en cours.")
            return

        days = read_days()
        output_dir = get_output_dir()
        audit_running = True
        reset_audit_cancel()
        audit_button.config(state="disabled")
        stop_button.config(state="normal")
        audit_start_ts[0] = time.time()
        audit_progress_var.set(0.0)
        audit_elapsed_var.set("00:00")
        audit_status_var.set("[DEBUT AUDIT] Demarrage...")
        tick_audit_timer()
        log_line("[DEBUT AUDIT] Lancement audit complet (Defender + persistance + installations + reseau)")

        def worker() -> None:
            nonlocal last_json_report, last_txt_report, audit_running
            try:
                report = generate_report(
                    days=days,
                    do_update=True,
                    do_scan=True,
                    output_dir=output_dir,
                    progress=lambda label, pct: root.after(0, update_audit_progress, label, pct),
                )
                jpath, tpath = save_reports(report, output_dir)
                last_json_report = str(jpath)
                last_txt_report = str(tpath)
                risk = report.get("risk", {}).get("risk_score_100", 0)
                complete = audit_is_complete(report)
                tr = report.get("threat_feeds_refresh", {}).get("feeds", [])
                ok_count = sum(1 for f in tr if f.get("ok"))

                append_history_event(
                    output_dir,
                    {
                        "action": "run_audit",
                        "days": days,
                        "risk": risk,
                        "json_report": str(jpath),
                        "txt_report": str(tpath),
                        "ok": complete,
                    },
                )

                def on_success() -> None:
                    nonlocal audit_running
                    elapsed = format_elapsed(audit_start_ts[0])
                    log_line(f"[+] Rapport JSON: {jpath}")
                    log_line(f"[+] Rapport TXT : {tpath}")
                    log_line(f"[+] Score risque: {risk}/100")
                    if not complete:
                        log_line("[!] Audit incomplet : collecte, scan ou flux en echec. Verifier le JSON.")
                    log_line(f"[+] Liste de menaces mise a jour: {ok_count}/{len(tr)} flux OK")
                    log_line(f"[FIN AUDIT] Termine en {elapsed}")
                    audit_progress_var.set(100.0)
                    audit_status_var.set(f"[FIN AUDIT] {'Termine' if complete else 'Incomplet'} en {elapsed}")
                    populate_threats(report.get("defender_threat_detections", {}).get("data", []))
                    refresh_reports_tab()
                    audit_button.config(state="normal")
                    stop_button.config(state="disabled")
                    audit_running = False

                root.after(0, on_success)
            except AuditCancelled:
                def on_cancelled() -> None:
                    nonlocal audit_running
                    elapsed = format_elapsed(audit_start_ts[0])
                    log_line(
                        f"[FIN AUDIT] Annule apres {elapsed} (un scan Defender deja lance peut "
                        "continuer quelques instants en arriere-plan cote Windows)"
                    )
                    audit_status_var.set(f"[FIN AUDIT] Annule apres {elapsed}")
                    audit_button.config(state="normal")
                    stop_button.config(state="disabled")
                    audit_running = False

                root.after(0, on_cancelled)
            except Exception:
                err = traceback.format_exc()
                write_crash_log(err)

                def on_error() -> None:
                    nonlocal audit_running
                    elapsed = format_elapsed(audit_start_ts[0])
                    log_line(f"[FIN AUDIT] Echec apres {elapsed}")
                    audit_status_var.set(f"[FIN AUDIT] Echec apres {elapsed}")
                    audit_button.config(state="normal")
                    stop_button.config(state="disabled")
                    audit_running = False
                    messagebox.showerror("Erreur", f"Le scan a echoue.\n\nLog: {crash_log_path()}")

                root.after(0, on_error)

        threading.Thread(target=worker, daemon=True).start()

    def stop_full_audit() -> None:
        if not audit_running:
            return
        audit_status_var.set("[ANNULATION] Arret demande...")
        log_line("[~] Arret de l'audit demande par l'utilisateur...")
        request_audit_cancel()
        stop_button.config(state="disabled")

    audit_button = ttk.Button(audit_actions, text="Lancer audit complet", command=run_full_audit)
    audit_button.pack(side="left")
    stop_button = ttk.Button(audit_actions, text="Arreter l'audit", command=stop_full_audit, state="disabled")
    stop_button.pack(side="left", padx=8)
    ttk.Button(audit_actions, text="Ouvrir dossier rapports", command=open_reports_folder).pack(side="left", padx=8)

    ttk.Button(threat_actions, text="Rafraichir menaces", command=refresh_defender_threats).pack(side="left")
    ttk.Button(threat_actions, text="Voir details", command=show_selected_threat_details).pack(side="left", padx=8)
    ttk.Button(threat_actions, text="Nettoyer avec Defender", command=cleanup_defender_threats).pack(side="left", padx=8)
    ttk.Button(threat_actions, text="Scan complet", command=launch_full_scan_manual).pack(side="left", padx=8)
    ttk.Button(threat_actions, text="Scan hors ligne", command=launch_offline_scan_manual).pack(side="left", padx=8)

    ttk.Button(rt_actions, text="Rafraichir temps reel", command=refresh_realtime).pack(side="left")
    ttk.Button(rt_actions, text="Reduire en barre de notification", command=minimize_to_tray).pack(side="left", padx=8)
    ttk.Button(rt_actions, text="Tracer IP", command=trace_selected_ip_gui).pack(side="left", padx=8)
    ttk.Button(rt_actions, text="Bloquer IP", command=block_selected_ip_gui).pack(side="left", padx=8)

    ttk.Button(rep_top, text="Rafraichir", command=refresh_reports_tab).pack(side="left")
    ttk.Button(rep_top, text="Ouvrir rapport selectionne", command=open_selected_report).pack(side="left", padx=8)
    ttk.Button(rep_top, text="Ouvrir dossier rapports", command=open_reports_folder).pack(side="left", padx=8)

    refresh_reports_tab()
    refresh_realtime()
    if start_minimized:
        root.after(900, minimize_to_tray if monitoring_enabled.get() else root.iconify)
    log_line("[+] Interface prete (onglets Audit / Menaces / Temps reel / Rapports)")
    if last_json_report or last_txt_report:
        log_line(f"[i] Derniers rapports: {last_json_report} | {last_txt_report}")
    root.protocol("WM_DELETE_WINDOW", on_root_close)
    root.bind("<Unmap>", on_window_unmap)
    root.after_idle(lambda: set_titlebar_theme(root))
    root.after(1000, refresh_theme)
    root.mainloop()
    return 0


def main() -> int:
    if platform.system().lower() != "windows":
        print("Ce programme est concu pour Windows uniquement.")
        return 2

    args = build_arg_parser().parse_args()

    if args.gui or len(sys.argv) == 1:
        return launch_gui(start_minimized=args.start_minimized, auto_monitoring=args.monitoring_enabled)

    days = max(1, min(180, args.days))
    output_dir = resolve_output_dir(args.output)

    print("[+] Demarrage audit securite...")
    print(f"    - Fenetre d'analyse: {days} jours")
    print(f"    - Dossier rapport: {output_dir}")

    report = generate_report(
        days=days,
        do_update=not args.skip_signature_update,
        do_scan=not args.skip_quick_scan,
        output_dir=output_dir,
    )
    json_path, txt_path = save_reports(report, output_dir)

    print("[+] Audit termine")
    print(f"    - Rapport JSON: {json_path}")
    print(f"    - Rapport TXT : {txt_path}")

    risk = report.get("risk", {}).get("risk_score_100", 0)
    if not audit_is_complete(report):
        print("[!] Audit incomplet : collecte, scan ou flux en echec. Verifie le JSON avant d'interpreter le score.")
    elif isinstance(risk, int) and risk >= 60:
        print("[!] Niveau de risque eleve: isole le PC du reseau et lance un scan complet hors ligne.")
    elif isinstance(risk, int) and risk >= 30:
        print("[!] Niveau de risque modere: verifie les installations recentes et les taches/services.")
    else:
        print("[+] Aucun signal fort detecte dans cet audit, reste vigilant.")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        err = traceback.format_exc()
        write_crash_log(err)
        try:
            import tkinter as tk
            from tkinter import messagebox

            root = tk.Tk()
            root.withdraw()
            messagebox.showerror(
                "Scan System - Erreur",
                "L'application a rencontre une erreur inattendue.\n\n"
                f"Consulte ce fichier de log: {crash_log_path()}",
            )
            root.destroy()
        except Exception:
            print("Erreur fatale. Voir le log:", crash_log_path())
        raise SystemExit(1)

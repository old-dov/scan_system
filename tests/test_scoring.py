"""Tests unitaires sur la logique de scoring/matching de scanner_windows.py.

Ciblent volontairement les fonctions pures (pas d'appel PowerShell/reseau/registre) :
suspicious_score, looks_suspicious_text, build_threat_feed_ip_set, is_public_ipv4,
format_rate, parse_any_datetime, startup_fingerprint. C'est le code le plus facile a casser
silencieusement en iterant vite (aucune verification manuelle ne le couvre par construction --
un score ou un match faux ne "plante" jamais, il se contente d'etre incorrect).
"""

import datetime as dt

import pytest

import scanner_windows as sw


# ── suspicious_score ────────────────────────────────────────────────────────


def test_suspicious_score_empty_report_is_zero():
    result = sw.suspicious_score({})
    assert result["risk_score_100"] == 0
    assert result["reasons"] == []


def test_suspicious_score_defender_threats_capped_at_60():
    report = {"defender_threat_detections": {"data": [{}] * 5}}
    result = sw.suspicious_score(report)
    assert result["risk_score_100"] == 60
    assert "Detections Defender a verifier: 5" in result["reasons"][0]


def test_suspicious_score_defender_threats_uncapped():
    report = {"defender_threat_detections": {"data": [{}] * 2}}
    result = sw.suspicious_score(report)
    assert result["risk_score_100"] == 40


def test_suspicious_score_excludes_handled_defender_history():
    report = {"defender_threat_detections": {"data": [
        {"ActionSuccess": True, "CurrentThreatExecutionStatusID": 1},
        {"ActionSuccess": True, "CurrentThreatExecutionStatusID": 4},
        {"ActionSuccess": False, "CurrentThreatExecutionStatusID": 1},
        {"ActionSuccess": True, "CurrentThreatExecutionStatusID": 2},
    ]}}
    result = sw.suspicious_score(report)
    assert result["risk_score_100"] == 40
    assert result["reasons"] == ["Detections Defender a verifier: 2"]


def test_event_log_failure_is_not_an_empty_event_list(monkeypatch):
    def failure(script, timeout):
        assert "NoMatchingEventsFound" in script
        assert "-ErrorAction Stop" in script
        assert timeout == 120
        return False, "access denied"

    monkeypatch.setattr(sw, "run_powershell", failure)
    with pytest.raises(RuntimeError, match="access denied"):
        sw.recent_persistence_events(1)


def test_empty_event_logs_remain_valid(monkeypatch):
    monkeypatch.setattr(
        sw, "run_powershell", lambda *_args, **_kwargs: (True, '{"tasks":[],"services":[]}')
    )
    assert sw.recent_persistence_events(1) == ([], [])


def test_failed_event_collection_marks_audit_incomplete():
    report = {
        "parameters": {"update_signatures": False, "run_quick_scan": False},
        "defender_status": {"ok": True},
        "defender_threat_detections": {"ok": True},
        "persistence_collection": {"ok": False, "error": "access denied"},
        "threat_feeds_refresh": {"feeds": [{"ok": True}]},
    }
    assert not sw.audit_is_complete(report)


def test_msi_failure_keeps_registry_installs_and_marks_collection_failed(monkeypatch):
    monkeypatch.setattr(sw, "iter_uninstall_registry", lambda: [])

    def failure(script, timeout):
        assert "NoMatchingEventsFound" in script
        assert timeout == 120
        return False, "access denied"

    monkeypatch.setattr(sw, "run_powershell", failure)
    status = {}
    assert sw.recent_installs(1, status) == []
    assert status == {"ok": False, "error": "access denied"}


def test_no_msi_events_is_a_valid_collection(monkeypatch):
    monkeypatch.setattr(sw, "iter_uninstall_registry", lambda: [])
    monkeypatch.setattr(sw, "run_powershell", lambda *_args, **_kwargs: (True, "[]"))
    status = {}
    assert sw.recent_installs(1, status) == []
    assert status == {"ok": True}


def test_failed_defender_collection_marks_audit_incomplete():
    report = {
        "parameters": {"update_signatures": False, "run_quick_scan": False},
        "defender_status": {"ok": True},
        "defender_threat_detections": {"ok": False, "error": "access denied"},
        "threat_feeds_refresh": {"feeds": [{"ok": True}]},
    }
    assert not sw.audit_is_complete(report)


def test_suspicious_score_installs_thresholds():
    assert sw.suspicious_score({"recent_installs": [{}] * 2})["risk_score_100"] == 0
    assert sw.suspicious_score({"recent_installs": [{}] * 3})["risk_score_100"] == 10
    assert sw.suspicious_score({"recent_installs": [{}] * 6})["risk_score_100"] == 20


def test_suspicious_score_services_capped_at_15():
    report = {"recent_service_installs": [{}] * 10}
    result = sw.suspicious_score(report)
    assert result["risk_score_100"] == 15


def test_suspicious_score_services_uncapped():
    report = {"recent_service_installs": [{}] * 3}
    result = sw.suspicious_score(report)
    assert result["risk_score_100"] == 9


def test_suspicious_score_tasks_threshold():
    assert sw.suspicious_score({"recent_task_registrations": [{}] * 4})["risk_score_100"] == 0
    assert sw.suspicious_score({"recent_task_registrations": [{}] * 5})["risk_score_100"] == 10


def test_suspicious_score_network_threat_feed_match_flat_30():
    report = {
        "network_audit": {
            "connections": [
                {"threat_feed_match": True},
                {"threat_feed_match": True},
                {"threat_feed_match": False},
            ],
            "anomalies": [],
        }
    }
    result = sw.suspicious_score(report)
    # +30 fixe, peu importe le nombre de connexions en match (pas +30 par connexion).
    assert result["risk_score_100"] == 30


def test_suspicious_score_network_other_anomalies_excludes_threat_feed_wording():
    report = {
        "network_audit": {
            "connections": [],
            "anomalies": [
                "IP 1.2.3.4 presente dans une liste de blocage menace (processus: x)",
                "CPU eleve: 90%",
            ],
        }
    }
    result = sw.suspicious_score(report)
    # La ligne "liste de blocage" est deja comptee via threat_feed_match ailleurs -- ne doit
    # pas aussi compter comme anomalie reseau generique, sinon double comptage du meme signal.
    assert result["risk_score_100"] == 5
    assert "Anomalies reseau detectees: 1" in result["reasons"][0]


def test_suspicious_score_network_other_anomalies_capped_at_20():
    report = {
        "network_audit": {
            "connections": [],
            "anomalies": [f"anomalie {i}" for i in range(10)],
        }
    }
    result = sw.suspicious_score(report)
    assert result["risk_score_100"] == 20


def test_suspicious_score_overall_capped_at_100():
    report = {
        "defender_threat_detections": {"data": [{}] * 5},  # 60
        "recent_installs": [{}] * 6,  # 20
        "recent_service_installs": [{}] * 10,  # 15
        "recent_task_registrations": [{}] * 5,  # 10
        "network_audit": {
            "connections": [{"threat_feed_match": True}],  # 30
            "anomalies": [f"a{i}" for i in range(10)],  # 20
        },
    }
    # Somme brute = 60+20+15+10+30+20 = 155, doit etre ecretee a 100.
    result = sw.suspicious_score(report)
    assert result["risk_score_100"] == 100


# ── looks_suspicious_text ────────────────────────────────────────────────────


def test_looks_suspicious_text_matches_known_patterns():
    assert sw.looks_suspicious_text("powershell -enc SGVsbG8=")
    assert sw.looks_suspicious_text("POWERSHELL -ENC SGVsbG8=")  # insensible a la casse
    assert sw.looks_suspicious_text(r"C:\Users\Public\payload.exe")
    assert sw.looks_suspicious_text("rundll32.exe shell32.dll,Control_RunDLL")
    assert sw.looks_suspicious_text("schtasks /create /tn evil /tr evil.exe")


def test_looks_suspicious_text_benign_text_not_flagged():
    assert not sw.looks_suspicious_text("notepad.exe")
    assert not sw.looks_suspicious_text(r"C:\Program Files\Vendor\app.exe --start")
    assert not sw.looks_suspicious_text("")


# ── build_threat_feed_ip_set ─────────────────────────────────────────────────


def test_build_threat_feed_ip_set_prefers_ips_over_sample():
    refresh = {"feeds": [{"ips": ["1.1.1.1"], "sample": ["9.9.9.9"]}]}
    assert sw.build_threat_feed_ip_set(refresh) == {"1.1.1.1"}


def test_build_threat_feed_ip_set_falls_back_to_sample():
    refresh = {"feeds": [{"sample": ["9.9.9.9", " 8.8.8.8 "]}]}
    assert sw.build_threat_feed_ip_set(refresh) == {"9.9.9.9", "8.8.8.8"}


def test_build_threat_feed_ip_set_merges_multiple_feeds_and_dedupes():
    refresh = {
        "feeds": [
            {"ips": ["1.1.1.1", "2.2.2.2"]},
            {"ips": ["2.2.2.2", "3.3.3.3"]},
        ]
    }
    assert sw.build_threat_feed_ip_set(refresh) == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}


def test_build_threat_feed_ip_set_ignores_blank_entries():
    refresh = {"feeds": [{"ips": ["", "   ", "1.1.1.1"]}]}
    assert sw.build_threat_feed_ip_set(refresh) == {"1.1.1.1"}


def test_build_threat_feed_ip_set_empty_input():
    assert sw.build_threat_feed_ip_set({}) == set()


# ── is_public_ipv4 ───────────────────────────────────────────────────────────


def test_is_public_ipv4_true_for_real_public_address():
    assert sw.is_public_ipv4("8.8.8.8")


def test_is_public_ipv4_false_for_private_loopback_multicast_linklocal():
    assert not sw.is_public_ipv4("192.168.1.1")
    assert not sw.is_public_ipv4("10.0.0.5")
    assert not sw.is_public_ipv4("127.0.0.1")
    assert not sw.is_public_ipv4("224.0.0.1")
    assert not sw.is_public_ipv4("169.254.1.1")


def test_is_public_ipv4_false_for_ipv6_and_garbage():
    assert not sw.is_public_ipv4("2001:4860:4860::8888")
    assert not sw.is_public_ipv4("not-an-ip")
    assert not sw.is_public_ipv4("")


# ── format_rate ──────────────────────────────────────────────────────────────


def test_format_rate_units():
    assert sw.format_rate(0) == "0 bps"
    assert sw.format_rate(100) == "800 bps"
    assert sw.format_rate(125) == "1.0 Kbps"
    assert sw.format_rate(125_000) == "1.0 Mbps"
    assert sw.format_rate(125_000_000) == "1.0 Gbps"


def test_format_rate_clamps_negative_to_zero():
    assert sw.format_rate(-500) == "0 bps"


# ── parse_any_datetime ───────────────────────────────────────────────────────


def test_parse_any_datetime_iso_with_z_suffix():
    result = sw.parse_any_datetime("2026-08-25T10:00:00Z")
    assert result == dt.datetime(2026, 8, 25, 10, 0, 0, tzinfo=dt.timezone.utc)


def test_parse_any_datetime_us_format():
    result = sw.parse_any_datetime("08/25/2026 10:00:00 AM")
    assert result == dt.datetime(2026, 8, 25, 10, 0, 0)


def test_parse_any_datetime_sql_format():
    result = sw.parse_any_datetime("2026-08-25 10:00:00")
    assert result == dt.datetime(2026, 8, 25, 10, 0, 0)


def test_parse_any_datetime_powershell_event_json():
    milliseconds = 1790752330097
    expected = dt.datetime.fromtimestamp(milliseconds / 1000)
    assert sw.parse_any_datetime(f"/Date({milliseconds})/") == expected
    assert sw.parse_any_datetime(f"/Date({milliseconds}+0200)/") == expected
    assert sw.parse_any_datetime("/Date(invalid)/") is None


def test_parse_any_datetime_none_or_blank_or_garbage():
    assert sw.parse_any_datetime(None) is None
    assert sw.parse_any_datetime("") is None
    assert sw.parse_any_datetime("   ") is None
    assert sw.parse_any_datetime("pas une date") is None


# ── startup_fingerprint ──────────────────────────────────────────────────────


def test_startup_fingerprint_dedupes_case_insensitively():
    entries = [
        {"source": "HKLM", "name": "Foo", "command": "foo.exe"},
        {"source": "hklm", "name": "FOO", "command": "FOO.EXE"},
    ]
    assert len(sw.startup_fingerprint(entries)) == 1


def test_startup_fingerprint_distinguishes_different_entries():
    entries = [
        {"source": "HKLM", "name": "Foo", "command": "foo.exe"},
        {"source": "HKCU", "name": "Bar", "command": "bar.exe"},
    ]
    assert len(sw.startup_fingerprint(entries)) == 2


def test_startup_fingerprint_empty_list():
    assert sw.startup_fingerprint([]) == set()

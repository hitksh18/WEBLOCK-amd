"""Phase 2: normalization unit tests (taxonomy + determinism)."""
from datetime import datetime, timezone

from app.services.normalize import NORM_VERSION, normalize


def _norm(ttype, payload):
    return normalize(ttype, payload, datetime.now(timezone.utc), host="WS-01")


def test_4624_logon_success():
    out = _norm("auth", {"kind": "windows_security_event", "event_id": 4624,
                         "record_number": 9, "source": "Security",
                         "strings": ["a", "john.doe", "DOM"]})
    assert (out["category"], out["subtype"], out["severity_hint"]) == \
        ("AUTHENTICATION", "LOGON_SUCCESS", "info")
    assert out["attributes"]["windows_event_id"] == 4624
    assert out["actor"] == "john.doe"


def test_4625_logon_failure():
    out = _norm("auth", {"kind": "windows_security_event", "event_id": 4625,
                         "strings": []})
    assert out["subtype"] == "LOGON_FAILURE"
    assert out["severity_hint"] == "low"


def test_4634_logoff_and_4672_and_4720():
    assert _norm("auth", {"kind": "windows_security_event",
                          "event_id": 4634})["subtype"] == "LOGOFF"
    assert _norm("auth", {"kind": "windows_security_event",
                          "event_id": 4672})["subtype"] == "PRIVILEGED_LOGON"
    out = _norm("auth", {"kind": "windows_security_event", "event_id": 4720})
    assert (out["category"], out["subtype"]) == ("IDENTITY", "ACCOUNT_CREATED")


def test_process_normalization():
    out = _norm("process", {"kind": "snapshot", "processes": [
        {"pid": 1, "name": "powershell.exe"}, {"pid": 2, "name": "svchost.exe"}]})
    assert (out["category"], out["subtype"]) == ("PROCESS", "PROCESS_SNAPSHOT")
    assert out["attributes"]["process_count"] == 2
    assert "powershell.exe" in out["attributes"]["process_names"]


def test_network_normalization():
    out = _norm("network", {"kind": "snapshot", "connections": [
        {"remote": "93.184.216.34:443", "status": "ESTABLISHED"}]})
    assert out["subtype"] == "CONNECTION_ROLLUP"
    assert out["remote_addr"] == "93.184.216.34"
    assert out["remote_port"] == 443


def test_usb_normalization():
    snap = _norm("usb", {"kind": "volume_snapshot", "removable": [{"device": "E:"}]})
    assert snap["subtype"] == "VOLUME_SNAPSHOT"
    seen = _norm("usb", {"kind": "usb_device_seen", "device": {"device": "E:"}})
    assert (seen["category"], seen["subtype"], seen["severity_hint"]) == \
        ("USB", "DEVICE_CHANGE", "low")


def test_collector_error_normalization():
    out = _norm("auth", {"kind": "collector_status", "collector": "eventlog",
                         "error": "privilege missing"})
    assert (out["category"], out["subtype"]) == ("AGENT", "COLLECTOR_STATUS")
    assert "privilege" in out["attributes"]["error"]


def test_system_normalization():
    out = _norm("system", {"kind": "health", "cpu_percent": 12.5,
                           "mem_percent": 60.0})
    assert out["category"] == "SYSTEM"
    assert out["attributes"]["cpu_percent"] == 12.5


def test_deterministic():
    now = datetime.now(timezone.utc)
    payload = {"kind": "windows_security_event", "event_id": 4625,
               "strings": ["x", "intruder"]}
    a = normalize("auth", payload, now, host="H")
    b = normalize("auth", dict(payload), now, host="H")
    assert a == b
    assert NORM_VERSION == "1"

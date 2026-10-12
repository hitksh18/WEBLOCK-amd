"""Agent tests: identity, envelope, outbox, config, security, collectors."""
import json
import sys

import pytest

from weblock_agent import identity as ident
from weblock_agent.collectors import identity as c_identity
from weblock_agent.collectors import network as c_network
from weblock_agent.collectors import processes as c_process
from weblock_agent.collectors import system as c_system
from weblock_agent.collectors import usb as c_usb
from weblock_agent.collectors import windows_events as c_eventlog
from weblock_agent.config import (
    AgentConfig,
    apply_overlay,
    validate_config_dict,
)
from weblock_agent.main import backoff_delay
from weblock_agent.models.telemetry import TELEMETRY_TYPES, make_event
from weblock_agent.outbox import Outbox
from weblock_agent.security.store import (
    load_identity,
    protect_api_key,
    save_identity,
    unprotect_api_key,
)


# ---------------------------------------------------------------- identity
def test_device_info_real_fields():
    info = ident.collect_device_info()
    for key in ("hostname", "os", "ip", "mac", "fingerprint", "agent_version"):
        assert info[key], key
    assert len(info["fingerprint"]) == 32
    assert info["os"] == "Windows"  # live-Windows execution


def test_fingerprint_stable():
    assert ident.device_fingerprint("H", "M") == ident.device_fingerprint("H", "M")
    assert ident.device_fingerprint("H", "M") != ident.device_fingerprint("H", "X")


# ---------------------------------------------------------------- envelope
def test_envelope_schema():
    ev = make_event("process", {"pid": 1})
    assert set(ev) == {"event_id", "schema_version", "type", "occurred_at",
                       "source", "payload"}
    assert ev["schema_version"] == "1.0"
    assert ev["type"] in TELEMETRY_TYPES
    json.dumps(ev)


def test_envelope_rejects_bad_type():
    with pytest.raises(ValueError):
        make_event("exploit", {})


# ---------------------------------------------------------------- outbox
def test_outbox_enqueue_claim_ack(tmp_path):
    box = Outbox(str(tmp_path / "o.db"))
    assert box.enqueue(make_event("process", {"a": 1}), endpoint_id="agent-1") is True
    # Same event_id + endpoint -> duplicate, not duplicated.
    dup = make_event("process", {"a": 1})
    box.enqueue(dup, endpoint_id="agent-1")
    assert box.enqueue(dup, endpoint_id="agent-1") is False
    assert box.depth() == 2

    claimed = box.claim_for_upload(10)
    assert len(claimed) == 2
    assert box.depth() == 2  # claimed rows stay until ack
    box.ack([row_id for row_id, _ in claimed])
    assert box.depth() == 0


def test_outbox_release_retries(tmp_path):
    box = Outbox(str(tmp_path / "o.db"))
    box.enqueue(make_event("network", {}), endpoint_id="agent-1")
    claimed = box.claim_for_upload(10)
    box.release([claimed[0][0]])  # simulated failed upload
    stats = box.stats()
    assert stats["queued"]["count"] == 1
    assert stats["queued"]["max_retry"] == 1
    # Claimed again on next cycle (no loss).
    assert len(box.claim_for_upload(10)) == 1


def test_outbox_cap_and_prune(tmp_path):
    box = Outbox(str(tmp_path / "o.db"), max_rows=5)
    for _ in range(8):
        box.enqueue(make_event("system", {}), endpoint_id="a")
    assert box.depth() == 5
    assert box.prune_expired(retention_days=7) == 0


def test_outbox_survives_reopen(tmp_path):
    path = str(tmp_path / "o.db")
    Outbox(path).enqueue(make_event("usb", {"d": 1}), endpoint_id="a")
    assert Outbox(path).depth() == 1  # restart recovery


# ---------------------------------------------------------------- config
def test_config_validation():
    with pytest.raises(ValueError):
        validate_config_dict({"rm_rf": True})
    with pytest.raises(ValueError):
        validate_config_dict({"heartbeat_interval": 5})
    with pytest.raises(ValueError):
        validate_config_dict({"collectors": {"kernel_hook": True}})
    cfg = AgentConfig()
    apply_overlay(cfg, {"heartbeat_interval": 120,
                        "collectors": {"usb": False}})
    assert cfg.heartbeat_interval == 120
    assert cfg.collectors["usb"] is False
    assert cfg.collectors["process"] is True


# ---------------------------------------------------------------- backoff
def test_backoff_grows_and_caps():
    assert backoff_delay(0) < backoff_delay(3) < 310
    assert backoff_delay(100) <= 301


# ---------------------------------------------------------------- security store
def test_dpapi_roundtrip_live_windows(tmp_path):
    stored, mechanism = protect_api_key("wlk_secret123")
    assert mechanism == "dpapi"  # live Windows + pywin32
    assert "wlk_secret123" not in stored
    assert unprotect_api_key(stored) == "wlk_secret123"


def test_identity_roundtrip(tmp_path):
    save_identity(str(tmp_path), {"agent_id": "a", "api_key": "k"})
    assert load_identity(str(tmp_path))["agent_id"] == "a"
    assert load_identity(str(tmp_path / "missing")) is None


# ---------------------------------------------------------------- collectors (live Windows)
def test_collector_envelopes_live():
    groups = [c_identity.collect(), c_process.collect(), c_network.collect(),
              c_system.collect(), c_usb.collect(str(__import__("tempfile").mkdtemp()))]
    for events in groups:
        assert isinstance(events, list) and events
        for e in events:
            assert e["schema_version"] == "1.0"
            assert e["type"] in TELEMETRY_TYPES
            json.dumps(e)


def test_process_snapshot_fields_live():
    procs = c_process.collect()[0]["payload"]["processes"]
    assert procs
    assert {"pid", "ppid", "name", "exe", "cmdline"} <= set(procs[0])


def test_eventlog_live_windows(tmp_path):
    events = c_eventlog.collect(str(tmp_path))
    assert isinstance(events, list)  # may be empty on quiet lab machine
    for e in events:
        assert e["type"] == "auth"


def test_eventlog_unavailable_path(monkeypatch, tmp_path):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "win32evtlog":
            raise ImportError("mocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    events = c_eventlog.collect(str(tmp_path))
    assert len(events) == 1
    assert events[0]["payload"]["kind"] == "collector_status"
    assert "error" in events[0]["payload"]


def test_service_module_importable():
    import weblock_agent.service as svc
    assert svc.SERVICE_NAME == "WebLockAgent"


def test_no_verify_flag_absent_by_default():
    cfg = AgentConfig()
    assert cfg.verify_tls is True

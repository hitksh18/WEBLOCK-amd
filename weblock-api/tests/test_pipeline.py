"""Phase 2: pipeline integration — persistence, idempotency, states,
dispatcher, detection persistence, login adapter."""
import uuid
from datetime import datetime, timezone

from tests.conftest import auth_header, login
from tests.test_endpoints import _agent_header, _enroll, _mint


def _ev(**overrides):
    base = {"event_id": str(uuid.uuid4()), "schema_version": "1.0",
            "type": "process", "occurred_at": datetime.now(timezone.utc).isoformat(),
            "source": "agent", "payload": {"kind": "snapshot", "processes": []}}
    base.update(overrides)
    return base


def _setup(client, org_a):
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    return _enroll(client, _mint(client, admin_token))


def _post(client, body, events):
    return client.post("/v1/telemetry/batch",
                       json={"agent_id": body["agent_id"], "events": events},
                       headers=_agent_header(body["api_key"]))


def test_raw_preserved_and_normalized(client, org_a, db):
    from app.db.models import SecurityEvent, TelemetryEvent
    body = _setup(client, org_a)
    raw_payload = {"kind": "windows_security_event", "event_id": 4625,
                   "record_number": 42, "source": "Security", "strings": []}
    resp = _post(client, body, [_ev(type="auth", payload=raw_payload)])
    assert resp.json()["accepted"] == 1

    raw = db.query(TelemetryEvent).filter(
        TelemetryEvent.endpoint_id == body["endpoint_id"]).first()
    assert raw.payload == raw_payload  # untouched
    assert raw.processing_status == "PROCESSED"
    assert raw.event_category == "AUTHENTICATION"
    assert raw.normalization_version == "1"
    assert raw.normalized_at is not None

    sec = db.query(SecurityEvent).filter(
        SecurityEvent.telemetry_ref == raw.id).first()
    assert sec is not None
    assert (sec.category, sec.subtype) == ("AUTHENTICATION", "LOGON_FAILURE")
    assert sec.status == "PROCESSED"
    assert sec.processed_at is not None


def test_idempotent_replay_no_dup_normalized_or_detection(client, org_a, db):
    from app.db.models import Detection, SecurityEvent, TelemetryEvent
    from app.services.detection import TestMarkerRule, dispatch_event
    body = _setup(client, org_a)
    event = _ev(type="auth", payload={"kind": "session_snapshot", "user": "bob",
                                      "test_marker": True})
    # inject marker into attributes path: session_snapshot has no attributes slot;
    # use usb_device_seen which keeps device dict? Instead mark via network remotes?
    # Simplest: raw payload attribute passthrough is tested at unit level; here
    # replay the same batch twice and assert single raw + single normalized.
    r1 = _post(client, body, [event])
    r2 = _post(client, body, [event])
    assert r1.json()["accepted"] == 1
    assert r2.json()["duplicates"] == 1
    assert db.query(TelemetryEvent).count() == 1
    assert db.query(SecurityEvent).count() == 1

    sec = db.query(SecurityEvent).first()
    sec.attributes = {"test_marker": True}
    db.commit()
    n1 = dispatch_event(db, sec, extra_rules=[TestMarkerRule()])
    n2 = dispatch_event(db, sec, extra_rules=[TestMarkerRule()])
    db.commit()
    assert n1 == 1 and n2 == 0  # detection idempotent
    assert db.query(Detection).count() == 1
    det = db.query(Detection).first()
    assert det.rule_id == "TEST-MARKER"
    assert det.primary_event_id == sec.id
    assert "[TEST]" in det.title


def test_disabled_rule_skipped(client, org_a, db):
    from app.db.models import Detection, DetectionRule, SecurityEvent
    from app.services.detection import TestMarkerRule, dispatch_event
    body = _setup(client, org_a)
    _post(client, body, [_ev()])
    sec = db.query(SecurityEvent).first()
    sec.attributes = {"test_marker": True}
    db.add(DetectionRule(org_id=None, rule_id="TEST-MARKER", name="t",
                         enabled=False, severity="info"))
    db.commit()
    assert dispatch_event(db, sec, extra_rules=[TestMarkerRule()]) == 0
    assert db.query(Detection).count() == 0


def test_failed_processing_and_reprocess(client, org_a, db, monkeypatch):
    from app.db.models import Endpoint, SecurityEvent, TelemetryEvent
    import app.services.ingest as ingest
    body = _setup(client, org_a)
    monkeypatch.setattr(ingest, "normalize",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    resp = _post(client, body, [_ev()])
    assert resp.json()["accepted"] == 1  # raw kept, never 500
    raw = db.query(TelemetryEvent).first()
    assert raw.processing_status == "FAILED"
    assert "boom" in raw.processing_error
    assert db.query(SecurityEvent).count() == 0

    # Controlled retry: reset raw row, re-run normalize+dispatch.
    monkeypatch.undo()
    raw.processing_status = "RECEIVED"
    raw.processing_error = ""
    db.commit()
    endpoint = db.query(Endpoint).filter(
        Endpoint.id == body["endpoint_id"]).first()
    n, _d = ingest.normalize_and_dispatch(db, endpoint, [raw])
    db.commit()
    assert n == 1
    assert db.query(SecurityEvent).count() == 1

    # reprocess_failed resets FAILED security events (none here -> 0).
    from app.services.detection import reprocess_failed
    assert reprocess_failed(db, org_id=999999) == 0

    sec = db.query(SecurityEvent).first()
    sec.status = "FAILED"
    sec.error = "x"
    db.commit()
    assert reprocess_failed(db, org_id=sec.org_id) == 1
    assert db.query(SecurityEvent).first().status == "NORMALIZED"


def test_login_adapter_mapping(client, org_a, db):
    from app.db.models import SecurityEvent
    from app.services.login_adapter import auth_event_to_login_input
    body = _setup(client, org_a)
    _post(client, body, [_ev(type="auth", payload={
        "kind": "windows_security_event", "event_id": 4624, "strings": []})])
    sec = db.query(SecurityEvent).first()
    mapped = auth_event_to_login_input(sec)
    assert mapped is not None
    assert mapped["subtype"] == "LOGON_SUCCESS"
    assert mapped["source_event_id"] == sec.id
    # Non-auth events map to None (no fake conversion).
    sec.category = "PROCESS"
    assert auth_event_to_login_input(sec) is None

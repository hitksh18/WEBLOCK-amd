"""Phase 7: hash-chain tests — valid, tamper, breaks, gaps, bounds, isolation."""
import uuid
from datetime import datetime, timedelta, timezone

from app.db.models import TelemetryEvent
from app.services.chain_verify import verify_telemetry_chain
from app.services.ingest import HASH_CANONICAL_V1, assign_chain
from tests.conftest import auth_header, login
from tests.test_endpoints import _enroll, _mint


def _mk_ep(db, org_id, name="WS-CHAIN"):
    from app.db.models import Endpoint
    ep = Endpoint(org_id=org_id, agent_id=f"agent-{uuid.uuid4().hex[:8]}",
                  name=name, hostname=name, status="healthy")
    db.add(ep)
    db.flush()
    return ep


def _mk_raw(db, org_id, endpoint_id, occurred, payload=None, event_id=None):
    row = TelemetryEvent(
        org_id=org_id, endpoint_id=endpoint_id,
        event_id=event_id or str(uuid.uuid4()), type="process",
        occurred_at=occurred, payload=payload or {"n": 1},
        event_hash="PENDING", hash_algorithm=HASH_CANONICAL_V1)
    # Compute the real v2 digest like ingest does.
    from app.services.ingest import canonical_hash_v2
    row.event_hash = canonical_hash_v2(
        row.event_id, "1.0", "process", occurred, "agent", row.payload)
    db.add(row)
    db.flush()
    return row


def _chain(db, org_id, ep_id, n=5, base=None):
    from app.db.models import Endpoint
    base = base or datetime.now(timezone.utc)
    rows = [_mk_raw(db, org_id, ep_id, base - timedelta(minutes=n - i),
                    payload={"n": i}) for i in range(n)]
    db.commit()
    assign_chain(db, db.query(Endpoint).filter(Endpoint.id == ep_id).first())
    db.commit()
    return rows


def test_valid_chain(db, org_a):
    ep = _mk_ep(db, org_a["org"].id)
    _chain(db, org_a["org"].id, ep.id, n=5)
    out = verify_telemetry_chain(db, org_id=org_a["org"].id,
                                 endpoint_id=ep.id)
    assert out["valid"] is True
    assert out["events_checked"] == 5
    assert out["violations"] == []
    assert out["algorithm"] == "SHA-256"


def test_modified_payload_detected(db, org_a):
    ep = _mk_ep(db, org_a["org"].id)
    rows = _chain(db, org_a["org"].id, ep.id, n=3)
    rows[1].payload = {"n": 999}
    db.commit()
    out = verify_telemetry_chain(db, org_id=org_a["org"].id,
                                 endpoint_id=ep.id)
    assert out["valid"] is False
    kinds = {v["type"] for v in out["violations"]}
    assert "PAYLOAD_HASH_MISMATCH" in kinds


def test_modified_hash_and_broken_prev(db, org_a):
    ep = _mk_ep(db, org_a["org"].id)
    rows = _chain(db, org_a["org"].id, ep.id, n=3)
    rows[1].event_hash = "0" * 64
    db.commit()
    out = verify_telemetry_chain(db, org_id=org_a["org"].id,
                                 endpoint_id=ep.id)
    kinds = {v["type"] for v in out["violations"]}
    assert "PAYLOAD_HASH_MISMATCH" in kinds  # recompute differs
    assert "PREV_LINK_BREAK" in kinds  # next row's prev no longer matches


def test_missing_event_gap_detected(db, org_a):
    ep = _mk_ep(db, org_a["org"].id)
    rows = _chain(db, org_a["org"].id, ep.id, n=4)
    db.delete(rows[1])
    db.commit()
    out = verify_telemetry_chain(db, org_id=org_a["org"].id,
                                 endpoint_id=ep.id)
    kinds = {v["type"] for v in out["violations"]}
    assert "PREV_LINK_BREAK" in kinds or "SEQUENCE_GAP" in kinds


def test_equal_timestamps_deterministic(db, org_a):
    from app.db.models import Endpoint
    ep = _mk_ep(db, org_a["org"].id)
    same = datetime.now(timezone.utc)
    rows = [_mk_raw(db, org_a["org"].id, ep.id, same) for _ in range(3)]
    db.commit()
    assign_chain(db, db.query(Endpoint).filter(Endpoint.id == ep.id).first())
    db.commit()
    seqs = sorted(r.chain_seq for r in
                  db.query(TelemetryEvent).filter(
                      TelemetryEvent.endpoint_id == ep.id).all())
    assert seqs == [1, 2, 3]
    out = verify_telemetry_chain(db, org_id=org_a["org"].id,
                                 endpoint_id=ep.id)
    assert out["valid"] is True


def test_bounded_partial_and_empty(db, org_a):
    ep = _mk_ep(db, org_a["org"].id)
    base = datetime.now(timezone.utc)
    _chain(db, org_a["org"].id, ep.id, n=4, base=base)
    out = verify_telemetry_chain(
        db, org_id=org_a["org"].id, endpoint_id=ep.id,
        start=base - timedelta(minutes=2), end=base)
    assert out["events_checked"] == 2  # partial range is bounded
    empty = verify_telemetry_chain(
        db, org_id=org_a["org"].id, endpoint_id=ep.id,
        start=base + timedelta(hours=1), end=base + timedelta(hours=2))
    assert empty["events_checked"] == 0 and empty["valid"] is True


def test_org_and_endpoint_isolation(db, org_a, org_b):
    ep_a = _mk_ep(db, org_a["org"].id)
    _chain(db, org_a["org"].id, ep_a.id, n=2)
    ep_b = _mk_ep(db, org_b["org"].id)
    _chain(db, org_b["org"].id, ep_b.id, n=2)
    import pytest
    with pytest.raises(LookupError):
        verify_telemetry_chain(db, org_id=org_b["org"].id, endpoint_id=ep_a.id)
    out = verify_telemetry_chain(db, org_id=org_a["org"].id,
                                 endpoint_id=ep_a.id)
    assert out["events_checked"] == 2  # no cross-endpoint bleed


def test_legacy_rows_linkage_only(db, org_a):
    ep = _mk_ep(db, org_a["org"].id)
    rows = _chain(db, org_a["org"].id, ep.id, n=2)
    rows[0].hash_algorithm = "sha256-received-v1"
    rows[0].event_hash = "legacy-digest"
    db.commit()
    out = verify_telemetry_chain(db, org_id=org_a["org"].id,
                                 endpoint_id=ep.id)
    assert out["legacy_rows"] == 1
    # Linkage still checked (prev of row 2 vs legacy digest) — honest scope.


def test_chain_api_endpoint(client, org_a):
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    body = _enroll(client, _mint(client, admin_token))
    h = auth_header(admin_token)
    viewer = login(client, "viewer@a.weblock.io")["access_token"]
    # Viewer cannot run verification (write-gated), admin can.
    assert client.post(
        f"/v1/endpoints/{body['endpoint_id']}/integrity/verify", json={},
        headers=auth_header(viewer)).status_code == 403
    resp = client.post(
        f"/v1/endpoints/{body['endpoint_id']}/integrity/verify", json={},
        headers=h)
    assert resp.status_code == 200
    assert resp.json()["endpoint_id"] == body["endpoint_id"]
    bad = client.post(
        f"/v1/endpoints/{body['endpoint_id']}/integrity/verify",
        json={"start": "not-a-date"}, headers=h)
    assert bad.status_code == 422

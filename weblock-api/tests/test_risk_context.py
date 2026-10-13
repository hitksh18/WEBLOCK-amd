"""Phase 5: contextual risk tests — canonical example, edges, API, isolation."""
import uuid
from datetime import datetime, timedelta, timezone

from app.db.models import (
    CorrelationCluster,
    CorrelationMember,
    Detection,
    RiskSnapshot,
)
from app.services.risk import compute_endpoint_risk, severity_of
from tests.conftest import auth_header, login
from tests.test_endpoints import _enroll, _mint


def _t(minutes_ago=0, base=None):
    base = base or datetime.now(timezone.utc)
    return base - timedelta(minutes=minutes_ago)


def _mk_ep(db, org_id, name="WS-RISK"):
    from app.db.models import Endpoint
    ep = Endpoint(org_id=org_id, agent_id=f"agent-{uuid.uuid4().hex[:8]}",
                  name=name, hostname=name, status="healthy")
    db.add(ep)
    db.flush()
    return ep


def _mk_det(db, org_id, endpoint_id, rule_id, occurred, severity="medium",
            actor="alice"):
    from app.db.models import SecurityEvent, TelemetryEvent
    raw = TelemetryEvent(org_id=org_id, endpoint_id=endpoint_id,
                         event_id=str(uuid.uuid4()), type="auth",
                         occurred_at=occurred, payload={}, event_hash="x")
    db.add(raw)
    db.flush()
    sec = SecurityEvent(org_id=org_id, endpoint_id=endpoint_id,
                        telemetry_ref=raw.id, event_id=str(uuid.uuid4()),
                        category="AUTHENTICATION", subtype="X",
                        occurred_at=occurred, actor=actor, attributes={})
    db.add(sec)
    db.flush()
    det = Detection(org_id=org_id, endpoint_id=endpoint_id, rule_id=rule_id,
                    rule_version="1", severity=severity, confidence=0.8,
                    status="open", title=f"{rule_id} t", explanation="e",
                    primary_event_id=sec.id, related_event_ids=[])
    db.add(det)
    db.flush()
    return det


def _mk_cluster(db, org_id, endpoint_id, det_ids, confidence=80):
    key = f"test:{endpoint_id}:{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)
    cluster = CorrelationCluster(
        org_id=org_id, endpoint_id=endpoint_id, correlation_key=key,
        first_seen=now - timedelta(minutes=10), last_seen=now,
        status="open", confidence=confidence, severity="high",
        detection_count=len(det_ids), distinct_family_count=3,
        families=["AUTHENTICATION", "NETWORK", "PROCESS"],
        primary_detection_id=det_ids[0] if det_ids else None,
        explanation="test cluster")
    db.add(cluster)
    db.flush()
    for did in det_ids:
        db.add(CorrelationMember(cluster_id=cluster.id, detection_id=did))
    db.flush()
    return cluster


def _canonical(db, org_id):
    """AUTH-01 HIGH x2 + PROC-01 HIGH + NET-01 MED + open cluster conf 80."""
    ep = _mk_ep(db, org_id)
    now = datetime.now(timezone.utc)
    d1 = _mk_det(db, org_id, ep.id, "AUTH-01", _t(12, now), severity="high")
    d2 = _mk_det(db, org_id, ep.id, "AUTH-01", _t(9, now), severity="high")
    d3 = _mk_det(db, org_id, ep.id, "PROC-01", _t(6, now), severity="high")
    d4 = _mk_det(db, org_id, ep.id, "NET-01", _t(5, now), severity="medium")
    _mk_cluster(db, org_id, ep.id, [d1.id, d3.id, d4.id], confidence=80)
    db.commit()
    return ep


def test_canonical_86_critical(db, org_a):
    ep = _canonical(db, org_a["org"].id)
    result = compute_endpoint_risk(db, org_id=org_a["org"].id, endpoint_id=ep.id)
    assert result.score == 86, result.factors
    assert result.severity == "critical"
    assert [f["points"] for f in result.factors] == [32, 18, 10, 10, 7, 5, 4]
    assert "86" in result.explanation
    assert "WS-RISK" in result.explanation
    assert "attacker" not in result.explanation.lower()
    assert set(result.inputs["families"]) == {"AUTHENTICATION", "NETWORK",
                                              "PROCESS"}
    assert result.inputs["rule_counts"]["AUTH-01"] == 2


def test_empty_endpoint_zero_low(db, org_a):
    ep = _mk_ep(db, org_a["org"].id)
    db.commit()
    result = compute_endpoint_risk(db, org_id=org_a["org"].id, endpoint_id=ep.id)
    assert result.score == 0
    assert result.severity == "low"
    assert result.factors == []
    assert "no qualifying" in result.explanation


def test_single_low_detection(db, org_a):
    ep = _mk_ep(db, org_a["org"].id)
    _mk_det(db, org_a["org"].id, ep.id, "USB-01", _t(5), severity="low")
    db.commit()
    result = compute_endpoint_risk(db, org_id=org_a["org"].id, endpoint_id=ep.id)
    # families 1 -> 0; prior 1 -> 3; recency 5min -> 10; novel (first seen) -> 4
    assert result.score == 17
    assert result.severity == "low"


def test_false_positive_excluded(db, org_a):
    ep = _mk_ep(db, org_a["org"].id)
    _mk_det(db, org_a["org"].id, ep.id, "AUTH-01", _t(5), severity="high")
    fp = _mk_det(db, org_a["org"].id, ep.id, "PROC-01", _t(4), severity="high")
    fp.status = "false_positive"
    db.commit()
    result = compute_endpoint_risk(db, org_id=org_a["org"].id, endpoint_id=ep.id)
    assert result.inputs["rule_counts"] == {"AUTH-01": 1}
    assert all("PROC-01" not in f["label"] or "families" in f["label"]
               for f in result.factors)


def test_severity_bands():
    assert severity_of(0) == "low"
    assert severity_of(29) == "low"
    assert severity_of(30) == "medium"
    assert severity_of(59) == "medium"
    assert severity_of(60) == "high"
    assert severity_of(79) == "high"
    assert severity_of(80) == "critical"
    assert severity_of(100) == "critical"


def test_clamp_at_100(db, org_a):
    ep = _mk_ep(db, org_a["org"].id)
    now = datetime.now(timezone.utc)
    for i in range(10):
        _mk_det(db, org_a["org"].id, ep.id, "AUTH-01", _t(i, now),
                severity="high")
    c1 = _mk_cluster(db, org_a["org"].id, ep.id, [], confidence=100)
    c2 = _mk_cluster(db, org_a["org"].id, ep.id, [], confidence=95)
    db.commit()
    result = compute_endpoint_risk(db, org_id=org_a["org"].id, endpoint_id=ep.id)
    assert result.score <= 100
    assert result.severity == "critical"


def test_unknown_endpoint_raises(db, org_a):
    import pytest
    with pytest.raises(LookupError):
        compute_endpoint_risk(db, org_id=org_a["org"].id, endpoint_id=999999)


# ------------------------------------------------------------------- API
def test_risk_api_snapshot_and_history(client, org_a):
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    body = _enroll(client, _mint(client, admin_token))
    h = auth_header(admin_token)

    r1 = client.get(f"/v1/endpoints/{body['endpoint_id']}/risk", headers=h)
    assert r1.status_code == 200, r1.text
    assert r1.json()["score"] == 0  # fresh endpoint, no detections
    assert r1.json()["snapshot_written"] is True

    r2 = client.get(f"/v1/endpoints/{body['endpoint_id']}/risk", headers=h)
    assert r2.json()["snapshot_written"] is False  # unchanged: no new row

    r3 = client.get(f"/v1/endpoints/{body['endpoint_id']}/risk",
                    params={"force_snapshot": True}, headers=h)
    assert r3.json()["snapshot_written"] is True

    hist = client.get(f"/v1/endpoints/{body['endpoint_id']}/risk/history",
                      headers=h).json()
    assert hist["total"] == 2
    assert hist["snapshots"][0]["score"] == 0

    assert client.get("/v1/endpoints/999999/risk", headers=h).status_code == 404


def test_risk_api_live_detection_moves_score(client, org_a):
    import uuid as uuid_mod
    from datetime import datetime, timezone
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    body = _enroll(client, _mint(client, admin_token))
    h = auth_header(admin_token)
    key_h = {"Authorization": f"Bearer {body['api_key']}"}
    now = datetime.now(timezone.utc).isoformat()
    events = [{
        "event_id": str(uuid_mod.uuid4()), "schema_version": "1.0",
        "type": "usb",
        "occurred_at": now, "source": "agent",
        "payload": {"kind": "usb_device_seen", "device": {"device": "E:"}}}]
    resp = client.post("/v1/telemetry/batch",
                       json={"agent_id": body["agent_id"], "events": events},
                       headers=key_h)
    assert resp.json()["accepted"] == 1
    risk = client.get(f"/v1/endpoints/{body['endpoint_id']}/risk",
                      headers=h).json()
    assert risk["score"] > 0
    assert any("usb" in f["label"].lower() or "famil" in f["label"].lower()
               or "activit" in f["label"] for f in risk["factors"])


def test_risk_isolation(client, org_a, org_b):
    admin_a = login(client, "admin@a.weblock.io")["access_token"]
    body_a = _enroll(client, _mint(client, admin_a))
    admin_b = login(client, "admin@b.weblock.io")["access_token"]
    body_b = _enroll(client, _mint(client, admin_b))
    # Org B cannot read org A's endpoint risk.
    assert client.get(f"/v1/endpoints/{body_a['endpoint_id']}/risk",
                      headers=auth_header(admin_b)).status_code == 404
    assert client.get(f"/v1/endpoints/{body_a['endpoint_id']}/risk/history",
                      headers=auth_header(admin_b)).status_code == 404
    # Org B endpoint unaffected by org A activity.
    r = client.get(f"/v1/endpoints/{body_b['endpoint_id']}/risk",
                   headers=auth_header(admin_b)).json()
    assert r["score"] == 0

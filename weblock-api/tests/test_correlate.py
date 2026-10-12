"""Phase 4: correlation engine tests.

Helpers build detections directly (security event + detection row) for
deterministic time control, plus HTTP end-to-end for the pipeline path.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.db.models import CorrelationCluster, CorrelationMember, Detection
from app.services.correlate import (
    RULE_FAMILY,
    cluster_severity,
    correlation_score,
    process_detection,
)
from tests.conftest import auth_header, login
from tests.test_endpoints import _enroll, _mint


@pytest.fixture()
def endpoint(db, org_a):
    from app.db.models import Endpoint
    ep = Endpoint(org_id=org_a["org"].id, agent_id="agent-corr-1",
                  name="WS-CORR", hostname="WS-CORR", status="healthy")
    db.add(ep)
    db.flush()
    return ep


def _det(db, org_id, endpoint_id, rule_id, occurred, severity="medium",
         actor="alice", status="open"):
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
                    status=status, title=f"{rule_id} t", explanation="e",
                    primary_event_id=sec.id, related_event_ids=[])
    db.add(det)
    db.flush()
    return det


def _t(minutes_ago=0):
    return datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)


# ---------------------------------------------------------------- threshold
def test_isolated_detection_no_cluster(db, org_a, endpoint):
    d = _det(db, org_a["org"].id, endpoint.id, "USB-01", _t(5), severity="low")
    db.commit()
    assert process_detection(db, d) is None
    assert db.query(CorrelationCluster).count() == 0


def test_same_family_only_no_cluster(db, org_a, endpoint):
    d1 = _det(db, org_a["org"].id, endpoint.id, "AUTH-01", _t(10))
    d2 = _det(db, org_a["org"].id, endpoint.id, "AUTH-01", _t(5))
    db.commit()
    assert process_detection(db, d1) is None
    assert process_detection(db, d2) is None
    assert db.query(CorrelationCluster).count() == 0


def test_two_families_form_cluster(db, org_a, endpoint):
    d1 = _det(db, org_a["org"].id, endpoint.id, "AUTH-01", _t(11))
    d2 = _det(db, org_a["org"].id, endpoint.id, "PROC-01", _t(5),
              severity="high")
    db.commit()
    # Window is bidirectional (backfill-safe): the first processed detection
    # already sees its in-window partner.
    cluster = process_detection(db, d1)
    assert cluster is not None
    assert process_detection(db, d2).id == cluster.id
    assert cluster.detection_count == 2
    assert cluster.distinct_family_count == 2
    assert sorted(cluster.families) == ["AUTHENTICATION", "PROCESS"]
    assert cluster.severity == "high"
    assert cluster.confidence == 20 + 15 + 15 + 10 + 5  # fam+sev+prox+actor
    assert "2 detections" in cluster.explanation
    assert "endpoint" in cluster.explanation
    assert "attacker" not in cluster.explanation.lower()
    assert cluster.primary_detection_id == d1.id
    assert cluster.first_seen <= cluster.last_seen


def test_three_families_stronger(db, org_a, endpoint):
    # Created incrementally so each step observes genuine growth.
    d1 = _det(db, org_a["org"].id, endpoint.id, "AUTH-01", _t(20))
    db.commit()
    assert process_detection(db, d1) is None  # truly alone
    d2 = _det(db, org_a["org"].id, endpoint.id, "PROC-01", _t(12),
              severity="high")
    db.commit()
    c2 = process_detection(db, d2)
    assert c2 is not None and c2.detection_count == 2
    assert c2.confidence == 20 + 15 + 15 + 10 + 5  # span 8min, one actor
    c2_score = int(c2.confidence)  # snapshot: c2/c3 alias the same row later
    d3 = _det(db, org_a["org"].id, endpoint.id, "NET-01", _t(4))
    db.commit()
    c3 = process_detection(db, d3)
    assert c3 is not None and c3.id == c2.id  # appended, not duplicated
    assert c3.detection_count == 3
    assert c3.distinct_family_count == 3
    assert c3.confidence == 20 + 30 + 15 + 5 + 5  # span 16min, one actor
    assert int(c3.confidence) > c2_score
    assert c3.severity == "critical"  # 3 families + HIGH


def test_outside_window_new_cluster(db, org_a, endpoint):
    d1 = _det(db, org_a["org"].id, endpoint.id, "AUTH-01", _t(120))
    d2 = _det(db, org_a["org"].id, endpoint.id, "PROC-01", _t(115),
              severity="high")
    d3 = _det(db, org_a["org"].id, endpoint.id, "AUTH-01", _t(5))
    d4 = _det(db, org_a["org"].id, endpoint.id, "PROC-01", _t(1),
              severity="high")
    db.commit()
    process_detection(db, d1)
    old_cluster = process_detection(db, d2)
    process_detection(db, d3)
    new_cluster = process_detection(db, d4)
    assert old_cluster is not None and new_cluster is not None
    assert old_cluster.id != new_cluster.id


def test_window_boundary(db, org_a, endpoint):
    d1 = _det(db, org_a["org"].id, endpoint.id, "AUTH-01", _t(31))
    d2 = _det(db, org_a["org"].id, endpoint.id, "PROC-01", _t(0),
              severity="high")
    db.commit()
    process_detection(db, d1)
    assert process_detection(db, d2, window=1800) is None  # 31 min > 30 min
    assert db.query(CorrelationCluster).count() == 0


def test_repeated_same_rule_appends(db, org_a, endpoint):
    d1 = _det(db, org_a["org"].id, endpoint.id, "AUTH-01", _t(9))
    db.commit()
    assert process_detection(db, d1) is None  # alone so far
    d2 = _det(db, org_a["org"].id, endpoint.id, "PROC-01", _t(6),
              severity="high")
    d3 = _det(db, org_a["org"].id, endpoint.id, "AUTH-01", _t(3))
    d4 = _det(db, org_a["org"].id, endpoint.id, "AUTH-01", _t(1))
    db.commit()
    c = process_detection(db, d2)
    assert c is not None
    assert process_detection(db, d3).id == c.id
    assert process_detection(db, d4).id == c.id
    assert db.query(CorrelationCluster).count() == 1
    assert db.query(CorrelationMember).count() == 4


def test_replay_idempotent(db, org_a, endpoint):
    d1 = _det(db, org_a["org"].id, endpoint.id, "AUTH-01", _t(9))
    d2 = _det(db, org_a["org"].id, endpoint.id, "PROC-01", _t(6),
              severity="high")
    db.commit()
    process_detection(db, d1)
    c1 = process_detection(db, d2)
    c2 = process_detection(db, d2)  # replay
    c3 = process_detection(db, d1)  # replay
    assert c1.id == c2.id == c3.id
    assert c1.detection_count == 2
    assert db.query(CorrelationMember).count() == 2


# ------------------------------------------------------------------ formulas
def test_score_formula_spots():
    assert correlation_score({"A"}, ["low"], 60, set(), 1800) == \
        20 + 0 + 5 + 10 + 0
    assert correlation_score({"A", "B"}, ["high"], 300, {"u"}, 1800) == \
        20 + 15 + 15 + 10 + 5
    assert correlation_score({"A", "B"}, ["medium"], 2000, set(), 1800) == \
        20 + 15 + 10 + 0 + 0  # >10min but inside window
    assert correlation_score({"A", "B", "C", "D", "E"}, ["critical"], 100,
                             {"u"}, 1800) == 100  # 115 clamped
    assert correlation_score({"A", "B", "C", "D"}, ["low"], 5000, set(),
                             1800) == 20 + 45 + 5 + 0 + 0


def test_severity_table():
    assert cluster_severity({"A"}, ["low"]) == "low"
    assert cluster_severity({"A", "B"}, ["medium", "low"]) == "medium"
    assert cluster_severity({"A", "B"}, ["high", "low"]) == "high"
    assert cluster_severity({"A", "B", "C"}, ["high", "medium"]) == "critical"
    assert cluster_severity({"A", "B", "C"}, ["medium"]) == "medium"


def test_rule_family_map_complete():
    assert set(RULE_FAMILY) >= {"AUTH-01", "AUTH-02", "DEV-01", "PROC-01",
                                "PROC-02", "NET-01", "SYS-01", "USB-01"}
    assert RULE_FAMILY["PROC-01"] == RULE_FAMILY["PROC-02"] == "PROCESS"


# ---------------------------------------------------------------- lifecycle
def test_close_and_expire(db, org_a, endpoint):
    from app.services.correlate import close_cluster, expire_stale
    d1 = _det(db, org_a["org"].id, endpoint.id, "AUTH-01", _t(200))
    db.commit()
    assert process_detection(db, d1, window=1800) is None
    d2 = _det(db, org_a["org"].id, endpoint.id, "PROC-01", _t(195),
              severity="high")
    db.commit()
    c = process_detection(db, d2, window=1800)
    assert c is not None and c.status == "open"
    close_cluster(db, org_id=org_a["org"].id, cluster_id=c.id, actor_id=None)
    assert db.query(CorrelationCluster).first().status == "closed"
    # Closed cluster: new detection starts a FRESH cluster, not append.
    d3 = _det(db, org_a["org"].id, endpoint.id, "NET-01", _t(190))
    db.commit()
    c2 = process_detection(db, d3, window=3600)
    assert c2 is not None and c2.id != c.id
    # Expire: backdate an open cluster beyond 2 windows.
    c2.last_seen = datetime.now(timezone.utc) - timedelta(hours=3)
    db.commit()
    assert expire_stale(db, org_id=org_a["org"].id, window=1800,
                        actor_id=None) == 1
    assert db.query(CorrelationCluster).filter(
        CorrelationCluster.id == c2.id).first().status == "expired"


# --------------------------------------------------------------------- API
def _http_setup(client, org_a):
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    return admin_token, _enroll(client, _mint(client, admin_token))


def _batch(client, body, events):
    import uuid
    from datetime import datetime, timezone
    wire = []
    for e in events:
        wire.append({"event_id": str(uuid.uuid4()), "schema_version": "1.0",
                     "type": e[0],
                     "occurred_at": datetime.now(timezone.utc).isoformat(),
                     "source": "agent", "payload": e[1]})
    resp = client.post("/v1/telemetry/batch",
                       json={"agent_id": body["agent_id"], "events": wire},
                       headers={"Authorization": f"Bearer {body['api_key']}"})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_correlation_api_end_to_end(client, org_a):
    admin_token, body = _http_setup(client, org_a)
    h = auth_header(admin_token)
    # AUTH family + USB family via pipeline (DEV-01 may also fire: DEVICE).
    _batch(client, body, [
        ("auth", {"kind": "windows_security_event", "event_id": 4625,
                  "record_number": 1, "source": "Security",
                  "strings": ["x", "corr-user"]}),
        ("usb", {"kind": "usb_device_seen", "device": {"device": "E:"}}),
    ])
    clusters = client.get("/v1/correlations", headers=h).json()
    assert clusters["total"] >= 1
    cl = clusters["clusters"][0]
    assert cl["detection_count"] >= 2
    assert cl["distinct_family_count"] >= 2
    assert "Observed sequence" in cl["explanation"]

    detail = client.get(f"/v1/correlations/{cl['id']}", headers=h).json()
    assert detail["id"] == cl["id"]
    occ = [t["occurred_at"] for t in detail["timeline"]]
    assert occ == sorted(occ)  # chronological
    for entry in detail["timeline"]:
        assert entry["detection_id"] and entry["security_event_id"] is not None
        assert entry["telemetry_ref"] is not None

    filt = client.get("/v1/correlations",
                      params={"endpoint_id": body["endpoint_id"]}, headers=h).json()
    assert filt["total"] >= 1
    sev = client.get("/v1/correlations",
                     params={"severity": cl["severity"]}, headers=h).json()
    assert sev["total"] >= 1

    close = client.post(f"/v1/correlations/{cl['id']}/close", headers=h)
    assert close.json()["status"] == "closed"
    viewer = login(client, "viewer@a.weblock.io")["access_token"]
    assert client.get("/v1/correlations",
                      headers=auth_header(viewer)).status_code == 200
    assert client.post(f"/v1/correlations/{cl['id']}/close",
                       headers=auth_header(viewer)).status_code == 403


def test_correlation_org_isolation(client, org_a, org_b):
    admin_a, body_a = _http_setup(client, org_a)
    _batch(client, body_a, [
        ("auth", {"kind": "windows_security_event", "event_id": 4625,
                  "record_number": 1, "source": "Security",
                  "strings": ["x", "iso-user"]}),
        ("usb", {"kind": "usb_device_seen", "device": {"device": "E:"}}),
    ])
    admin_b = login(client, "admin@b.weblock.io")["access_token"]
    assert client.get("/v1/correlations",
                      headers=auth_header(admin_b)).json()["total"] == 0
    assert client.get("/v1/correlations/1",
                      headers=auth_header(admin_b)).status_code == 404

"""Phase 6: incident engine — auto/manual creation, idempotency, detail."""
import uuid
from datetime import datetime, timezone

from app.db.models import Incident
from app.services.incidents import maybe_create_incident, next_incident_key
from tests.conftest import auth_header, login
from tests.test_endpoints import _enroll, _mint


def _setup(client, org_a):
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    return admin_token, _enroll(client, _mint(client, admin_token))


def _batch(client, body, events):
    from datetime import datetime, timezone
    wire = [{"event_id": str(uuid.uuid4()), "schema_version": "1.0",
             "type": e[0],
             "occurred_at": datetime.now(timezone.utc).isoformat(),
             "source": "agent:fixture", "payload": e[1]} for e in events]
    resp = client.post("/v1/telemetry/batch",
                       json={"agent_id": body["agent_id"], "events": wire},
                       headers={"Authorization": f"Bearer {body['api_key']}"})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _bruteforce_events(n=5):
    events = []
    for i in range(n):
        events.append(("auth", {"kind": "windows_security_event",
                                "event_id": 4625, "record_number": 3000 + i,
                                "source": "Security",
                                "strings": ["x", "TEST-p6-user"]}))
    events.append(("process", {"kind": "snapshot", "processes": [
        {"pid": 9301, "ppid": 1, "name": "powershell.exe",
         "cmdline": "powershell -EncodedCommand QUJD", "username": "",
         "create_time": 0}]}))
    events.append(("network", {"kind": "snapshot", "connections": [
        {"proto": "tcp", "local": "10.0.0.9:51234",
         "remote": "8.8.8.8:4444", "status": "ESTABLISHED",
         "pid": 9301, "process": "powershell.exe"}]}))
    return events


def test_auto_incident_on_qualifying_cluster(client, org_a, db):
    admin_token, body = _setup(client, org_a)
    h = auth_header(admin_token)
    _batch(client, body, _bruteforce_events())
    incidents = client.get("/v1/incidents", headers=h).json()
    assert len(incidents) == 1, incidents
    inc = incidents[0]
    assert inc["incident_key"].startswith("INC-")
    assert inc["severity"] == "critical"
    assert inc["status"] == "open"
    assert inc["risk_score"] >= 60
    assert inc["correlation_id"] is not None
    assert "powershell" in inc["title"].lower() or "threat" in inc["title"].lower()

    detail = client.get(f"/v1/incidents/{inc['id']}", headers=h).json()
    assert detail["correlation"] is not None
    assert detail["correlation"]["id"] == inc["correlation_id"]
    assert len(detail["correlation"]["detections"]) >= 3
    rules = {d["rule_id"] for d in detail["correlation"]["detections"]}
    assert {"AUTH-01", "PROC-01", "NET-01"} <= rules
    assert detail["risk"] is not None
    assert detail["risk"]["score"] == inc["risk_score"]
    assert detail["risk"]["factors"]
    # Login-compat blocks stay null-free for cluster incidents.
    assert detail["user_id"] is None
    assert detail["event"] is None


def test_no_incident_below_threshold(client, org_a):
    admin_token, body = _setup(client, org_a)
    h = auth_header(admin_token)
    _batch(client, body, [("usb", {"kind": "usb_device_seen",
                                   "device": {"device": "E:"}})])
    assert client.get("/v1/incidents", headers=h).json() == []
    assert client.get("/v1/correlations", headers=h).json()["total"] == 0


def test_idempotent_reprocess_no_dup_incident(client, org_a, db):
    from app.services.correlate import process_detection
    from app.db.models import Detection
    admin_token, body = _setup(client, org_a)
    h = auth_header(admin_token)
    _batch(client, body, _bruteforce_events())
    first = client.get("/v1/incidents", headers=h).json()
    assert len(first) == 1
    # Reprocess every detection: no new incident, no new cluster members.
    for det in db.query(Detection).all():
        process_detection(db, det)
    db.commit()
    second = client.get("/v1/incidents", headers=h).json()
    assert len(second) == 1
    assert second[0]["id"] == first[0]["id"]


def test_manual_create_and_idempotent(client, org_a):
    admin_token, body = _setup(client, org_a)
    h = auth_header(admin_token)
    # Medium-severity USB cluster path: single USB detection makes no cluster,
    # so build a medium cluster via AUTH-02? Simpler: low-threshold manual on
    # any open cluster — create one via two-family medium chain.
    _batch(client, body, [
        ("auth", {"kind": "windows_security_event", "event_id": 4625,
                  "record_number": 4001, "source": "Security",
                  "strings": ["x", "m-user"]}),
        ("usb", {"kind": "usb_device_seen", "device": {"device": "E:"}}),
    ])
    clusters = client.get("/v1/correlations", headers=h).json()
    assert clusters["total"] >= 1
    cid = clusters["clusters"][0]["id"]
    # Auto gate needs HIGH+; this cluster is medium/low -> no auto incident.
    assert client.get("/v1/incidents", headers=h).json() == []
    r1 = client.post(f"/v1/correlations/{cid}/incident", headers=h)
    assert r1.status_code == 200, r1.text
    r2 = client.post(f"/v1/correlations/{cid}/incident", headers=h)
    assert r2.json()["id"] == r1.json()["id"]  # idempotent
    assert len(client.get("/v1/incidents", headers=h).json()) == 1
    # Viewer forbidden, closed cluster -> 409.
    viewer = login(client, "viewer@a.weblock.io")["access_token"]
    assert client.post(f"/v1/correlations/{cid}/incident",
                       headers=auth_header(viewer)).status_code == 403
    assert client.post("/v1/correlations/999999/incident",
                       headers=h).status_code == 404


def test_incident_key_sequence_and_filters(client, org_a):
    admin_token, body = _setup(client, org_a)
    h = auth_header(admin_token)
    _batch(client, body, _bruteforce_events())
    _batch(client, body, [("usb", {"kind": "usb_device_seen",
                                   "device": {"device": "E:"}})])
    incidents = client.get("/v1/incidents", headers=h).json()
    assert len(incidents) == 1
    crit = client.get("/v1/incidents", params={"severity": "critical"},
                      headers=h).json()
    assert len(crit) == 1
    by_ep = client.get("/v1/incidents",
                       params={"endpoint_id": body["endpoint_id"]},
                       headers=h).json()
    assert len(by_ep) == 1
    assert client.get("/v1/incidents", params={"severity": "low"},
                      headers=h).json() == []


def test_incident_isolation(client, org_a, org_b):
    admin_a, body_a = _setup(client, org_a)
    _batch(client, body_a, _bruteforce_events())
    admin_b = login(client, "admin@b.weblock.io")["access_token"]
    assert client.get("/v1/incidents",
                      headers=auth_header(admin_b)).json() == []
    inc_id = client.get("/v1/incidents",
                        headers=auth_header(admin_a)).json()[0]["id"]
    assert client.get(f"/v1/incidents/{inc_id}",
                      headers=auth_header(admin_b)).status_code == 404


def test_next_incident_key_format(db, org_a):
    k1 = next_incident_key(db, org_a["org"].id)
    assert k1.startswith("INC-")
    assert len(k1.split("-")) == 3


def test_maybe_create_closed_cluster_returns_none(db, org_a):
    from app.db.models import CorrelationCluster, Endpoint
    ep = Endpoint(org_id=org_a["org"].id, agent_id="agent-p6x", name="X")
    db.add(ep)
    db.flush()
    now = datetime.now(timezone.utc)
    cluster = CorrelationCluster(
        org_id=org_a["org"].id, endpoint_id=ep.id, correlation_key="t:x",
        first_seen=now, last_seen=now, status="closed", confidence=90,
        severity="critical", detection_count=2, distinct_family_count=2,
        families=["AUTHENTICATION", "PROCESS"], explanation="t")
    db.add(cluster)
    db.commit()
    assert maybe_create_incident(db, cluster) is None
    assert db.query(Incident).count() == 0


def test_incident_syncs_when_cluster_grows(client, org_a, db):
    from app.db.models import CorrelationMember, Detection
    admin_token, body = _setup(client, org_a)
    h = auth_header(admin_token)
    # First wave: AUTH-01 + PROC-01 only (2 families -> cluster, incident).
    wave1 = _bruteforce_events()
    wave1 = [e for e in wave1 if e[0] == "auth"][:5] + \
        [e for e in wave1 if e[0] == "process"]
    _batch(client, body, wave1)
    first = client.get("/v1/incidents", headers=h).json()
    assert len(first) == 1
    title_before = first[0]["title"]
    assert "NET-01" not in title_before
    # Second wave: NET-01 appends to the same cluster -> same incident, richer.
    _batch(client, body, [("network", {"kind": "snapshot", "connections": [
        {"proto": "tcp", "local": "10.0.0.9:51234", "remote": "8.8.8.8:4444",
         "status": "ESTABLISHED", "pid": 1, "process": "x"}]})])
    second = client.get("/v1/incidents", headers=h).json()
    assert len(second) == 1  # still exactly one incident
    assert second[0]["id"] == first[0]["id"]
    assert "NET-01" in second[0]["title"]
    detail = client.get(f"/v1/incidents/{first[0]['id']}", headers=h).json()
    assert len(detail["correlation"]["detections"]) >= 3

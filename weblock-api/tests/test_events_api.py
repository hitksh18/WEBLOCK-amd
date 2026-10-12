"""Phase 2: event query + timeline APIs (filters, pagination, isolation)."""
import uuid
from datetime import datetime, timedelta, timezone

from tests.conftest import auth_header, login
from tests.test_endpoints import _enroll, _mint
from tests.test_pipeline import _ev, _post


def _setup(client, org_a):
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    return _enroll(client, _mint(client, admin_token))


def _seed_mixed(client, body):
    now = datetime.now(timezone.utc)
    events = [
        _ev(type="auth", payload={"kind": "windows_security_event",
                                  "event_id": 4624, "strings": []},
            occurred_at=(now - timedelta(minutes=30)).isoformat()),
        _ev(type="auth", payload={"kind": "windows_security_event",
                                  "event_id": 4625, "strings": []},
            occurred_at=(now - timedelta(minutes=20)).isoformat()),
        _ev(type="process", payload={"kind": "snapshot",
                                     "processes": [{"name": "powershell.exe"}]},
            occurred_at=(now - timedelta(minutes=10)).isoformat()),
        _ev(type="network", payload={"kind": "snapshot", "connections": []},
            occurred_at=now.isoformat()),
    ]
    resp = _post(client, body, events)
    assert resp.json()["accepted"] == 4
    return events


def test_query_filters_and_pagination(client, org_a):
    body = _setup(client, org_a)
    _seed_mixed(client, body)
    admin = login(client, "admin@a.weblock.io")["access_token"]
    h = auth_header(admin)

    all_resp = client.get("/v1/events", headers=h).json()
    assert all_resp["total"] == 4

    auth_only = client.get("/v1/events", params={"category": "AUTHENTICATION"},
                           headers=h).json()
    assert auth_only["total"] == 2

    fail = client.get("/v1/events", params={"event_type": "LOGON_FAILURE"},
                      headers=h).json()
    assert fail["total"] == 1

    page = client.get("/v1/events", params={"limit": 2, "offset": 0,
                                            "order": "asc"}, headers=h).json()
    assert len(page["events"]) == 2
    page2 = client.get("/v1/events", params={"limit": 2, "offset": 2,
                                             "order": "asc"}, headers=h).json()
    assert len(page2["events"]) == 2
    assert page["events"][0]["id"] != page2["events"][0]["id"]

    search = client.get("/v1/events", params={"search": "powershell"},
                        headers=h).json()
    assert search["total"] == 1


def test_timeline_chronological(client, org_a):
    body = _setup(client, org_a)
    _seed_mixed(client, body)
    admin = login(client, "admin@a.weblock.io")["access_token"]
    tl = client.get(f"/v1/endpoints/{body['endpoint_id']}/events",
                    headers=auth_header(admin)).json()
    assert tl["total"] == 4
    subtypes = [e["subtype"] for e in tl["events"]]
    assert subtypes == ["LOGON_SUCCESS", "LOGON_FAILURE", "PROCESS_SNAPSHOT",
                        "CONNECTION_ROLLUP"]
    cat = client.get(f"/v1/endpoints/{body['endpoint_id']}/events",
                     params={"category": "PROCESS"},
                     headers=auth_header(admin)).json()
    assert cat["total"] == 1


def test_cross_org_event_access_rejected(client, org_a, org_b):
    body = _setup(client, org_a)
    _seed_mixed(client, body)
    admin_b = login(client, "admin@b.weblock.io")["access_token"]
    h_b = auth_header(admin_b)
    assert client.get("/v1/events", headers=h_b).json()["total"] == 0
    assert client.get(f"/v1/endpoints/{body['endpoint_id']}/events",
                      headers=h_b).status_code == 404
    assert client.get("/v1/detections", headers=h_b).json()["total"] == 0


def test_detections_list_api(client, org_a, db):
    from app.db.models import SecurityEvent
    from app.services.detection import TestMarkerRule, dispatch_event
    body = _setup(client, org_a)
    _post(client, body, [_ev()])
    sec = db.query(SecurityEvent).first()
    sec.attributes = {"test_marker": True}
    db.commit()
    assert dispatch_event(db, sec, extra_rules=[TestMarkerRule()]) == 1
    db.commit()
    admin = login(client, "admin@a.weblock.io")["access_token"]
    out = client.get("/v1/detections", headers=auth_header(admin)).json()
    assert out["total"] == 1
    assert out["detections"][0]["rule_id"] == "TEST-MARKER"
    by_rule = client.get("/v1/detections", params={"rule_id": "TEST-MARKER"},
                         headers=auth_header(admin)).json()
    assert by_rule["total"] == 1

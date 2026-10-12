"""Phase 1 server tests: telemetry batch ingestion."""
import uuid
from datetime import datetime, timezone

from tests.conftest import auth_header, login
from tests.test_endpoints import _agent_header, _enroll, _mint


def _ev(**overrides):
    base = {
        "event_id": str(uuid.uuid4()),
        "schema_version": "1.0",
        "type": "process",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "source": "agent",
        "payload": {"pid": 4, "name": "System"},
    }
    base.update(overrides)
    return base


def _setup(client, org_a):
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    body = _enroll(client, _mint(client, admin_token))
    return body


def test_batch_accept_and_persist(client, org_a, db):
    from app.db.models import TelemetryEvent
    body = _setup(client, org_a)
    events = [_ev(), _ev(type="network", payload={"remote": "10.0.0.1:443"})]
    resp = client.post("/v1/telemetry/batch",
                       json={"agent_id": body["agent_id"], "events": events},
                       headers=_agent_header(body["api_key"]))
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"accepted": 2, "duplicates": 0, "rejected": []}
    assert db.query(TelemetryEvent).filter(
        TelemetryEvent.endpoint_id == body["endpoint_id"]).count() == 2


def test_batch_duplicates_not_duplicated(client, org_a, db):
    from app.db.models import TelemetryEvent
    body = _setup(client, org_a)
    events = [_ev()]
    first = client.post("/v1/telemetry/batch",
                        json={"agent_id": body["agent_id"], "events": events},
                        headers=_agent_header(body["api_key"]))
    assert first.json()["accepted"] == 1
    second = client.post("/v1/telemetry/batch",
                         json={"agent_id": body["agent_id"], "events": events},
                         headers=_agent_header(body["api_key"]))
    assert second.json() == {"accepted": 0, "duplicates": 1, "rejected": []}
    assert db.query(TelemetryEvent).count() == 1


def test_batch_malformed_event_rejected_not_500(client, org_a):
    body = _setup(client, org_a)
    events = [_ev(), {"event_id": "bad!! id", "type": "process"},
              _ev(type="nope")]
    resp = client.post("/v1/telemetry/batch",
                       json={"agent_id": body["agent_id"], "events": events},
                       headers=_agent_header(body["api_key"]))
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["accepted"] == 1
    assert len(out["rejected"]) == 2


def test_batch_cross_endpoint_rejected(client, org_a):
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    a = _enroll(client, _mint(client, admin_token), hostname="WS-A")
    b = _enroll(client, _mint(client, admin_token), hostname="WS-B")
    resp = client.post("/v1/telemetry/batch",
                       json={"agent_id": a["agent_id"], "events": [_ev()]},
                       headers=_agent_header(b["api_key"]))
    assert resp.status_code == 403


def test_batch_cross_org_rejected(client, org_a, org_b):
    admin_b = login(client, "admin@b.weblock.io")["access_token"]
    b = _enroll(client, _mint(client, admin_b), hostname="WS-B")
    # Org A analyst listing must not contain org B endpoint (isolation).
    analyst_a = login(client, "analyst@a.weblock.io")["access_token"]
    listing = client.get("/v1/endpoints", headers=auth_header(analyst_a))
    assert all(e["agent_id"] != b["agent_id"] for e in listing.json())
    # And org B key cannot submit as org A agent_id.
    admin_a = login(client, "admin@a.weblock.io")["access_token"]
    from tests.test_endpoints import _enroll as enroll_a, _mint as mint_a
    a = enroll_a(client, mint_a(client, admin_a), hostname="WS-A")
    resp = client.post("/v1/telemetry/batch",
                       json={"agent_id": a["agent_id"], "events": [_ev()]},
                       headers=_agent_header(b["api_key"]))
    assert resp.status_code == 403


def test_batch_size_limit(client, org_a):
    body = _setup(client, org_a)
    events = [_ev() for _ in range(501)]
    resp = client.post("/v1/telemetry/batch",
                       json={"agent_id": body["agent_id"], "events": events},
                       headers=_agent_header(body["api_key"]))
    assert resp.status_code == 413


def test_batch_unauthorized_no_key(client, org_a):
    resp = client.post("/v1/telemetry/batch",
                       json={"agent_id": "agent-x", "events": [_ev()]})
    assert resp.status_code in (401, 403)


def test_batch_future_timestamp_rejected(client, org_a):
    body = _setup(client, org_a)
    future = datetime.now(timezone.utc).isoformat().replace("+00:00", "")
    from datetime import timedelta
    far = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    resp = client.post("/v1/telemetry/batch",
                       json={"agent_id": body["agent_id"],
                             "events": [_ev(occurred_at=far)]},
                       headers=_agent_header(body["api_key"]))
    assert resp.json()["rejected"] and resp.json()["accepted"] == 0

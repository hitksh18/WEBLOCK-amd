"""Phase 8: authz + policy + simulation + idempotency + lifecycle."""
import uuid
from datetime import datetime, timezone

from tests.conftest import auth_header, login
from tests.test_endpoints import _enroll, _mint


def _setup(client, org_a):
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    body = _enroll(client, _mint(client, admin_token))
    return admin_token, body


def _incident(client, admin_token, body):
    """Two-family cluster via fixtures -> auto incident (may be None if gates
    fail); fallback to manual creation. Returns incident dict."""
    from datetime import datetime, timezone
    wire = []
    for i in range(5):
        wire.append({"event_id": str(uuid.uuid4()), "schema_version": "1.0",
                     "type": "auth",
                     "occurred_at": datetime.now(timezone.utc).isoformat(),
                     "source": "agent",
                     "payload": {"kind": "windows_security_event",
                                 "event_id": 4625, "record_number": 9000 + i,
                                 "source": "Security",
                                 "strings": ["x", "TEST-p8-user"]}})
    wire.append({"event_id": str(uuid.uuid4()), "schema_version": "1.0",
                 "type": "process",
                 "occurred_at": datetime.now(timezone.utc).isoformat(),
                 "source": "agent",
                 "payload": {"kind": "snapshot", "processes": [
                     {"pid": 9501, "ppid": 1, "name": "powershell.exe",
                      "cmdline": "powershell -EncodedCommand QUJD",
                      "username": "", "create_time": 0}]}})
    resp = client.post("/v1/telemetry/batch",
                       json={"agent_id": body["agent_id"], "events": wire},
                       headers={"Authorization": f"Bearer {body['api_key']}"})
    assert resp.status_code == 200, resp.text
    h = auth_header(admin_token)
    incidents = client.get("/v1/incidents", headers=h).json()
    assert len(incidents) >= 1, incidents
    return incidents[0]


def _fresh_heartbeat(client, body):
    """Heartbeat with capabilities so LIVE policy sees a fresh endpoint."""
    resp = client.post(
        f"/v1/endpoints/{body['endpoint_id']}/heartbeat",
        json={"hostname": "WS-X", "agent_version": "1.1.0",
              "capabilities": {
                  "isolate_endpoint": True, "restore_isolation": True,
                  "terminate_process": True,
                  "block_network_destination": True,
                  "disable_session": False, "collect_evidence": True,
                  "response_protocol": "1"}},
        headers={"Authorization": f"Bearer {body['api_key']}"})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _req(client, token, inc_id, action, target=None, mode="SIMULATION",
         endpoint_id=None):
    params = f"?endpoint_id={endpoint_id}" if endpoint_id else ""
    return client.post(
        f"/v1/incidents/{inc_id}/response-actions{params}",
        json={"action_type": action, "target": target or {},
              "reason": "test", "execution_mode": mode},
        headers=auth_header(token))


def test_rbac_matrix(client, org_a, org_b):
    admin_token, body = _setup(client, org_a)
    inc = _incident(client, admin_token, body)
    analyst = login(client, "analyst@a.weblock.io")["access_token"]
    viewer = login(client, "viewer@a.weblock.io")["access_token"]

    # Viewer: read ok, request denied (role guard -> 403).
    assert client.get(f"/v1/incidents/{inc['id']}/response-actions",
                      headers=auth_header(viewer)).status_code == 200
    assert _req(client, viewer, inc["id"], "ISOLATE_ENDPOINT",
                endpoint_id=body["endpoint_id"]).status_code == 403
    # Analyst: simulation allowed.
    r = _req(client, analyst, inc["id"], "TERMINATE_PROCESS",
             {"pid": 1234}, endpoint_id=body["endpoint_id"])
    assert r.status_code == 200, r.text
    assert r.json()["execution_mode"] == "SIMULATION"
    # Cross-org: org B admin cannot see org A incident/actions.
    admin_b = login(client, "admin@b.weblock.io")["access_token"]
    assert client.get(f"/v1/incidents/{inc['id']}/response-actions",
                      headers=auth_header(admin_b)).status_code == 404
    assert _req(client, admin_b, inc["id"], "ISOLATE_ENDPOINT",
                endpoint_id=body["endpoint_id"]).status_code == 404


def test_investigator_live_restricted(client, org_a, db):
    from app.db.models import User
    from app.core.security import hash_password
    admin_token, body = _setup(client, org_a)
    _fresh_heartbeat(client, body)
    inc = _incident(client, admin_token, body)
    # Create investigator user.
    org_id = body["org_id"] if "org_id" in body else None
    inv = User(org_id=db.query(User).filter(
        User.email == "admin@a.weblock.io").first().org_id,
        email="inv@a.weblock.io", password_hash=hash_password("Password123!"),
        role="investigator")
    db.add(inv)
    db.commit()
    inv_token = login(client, "inv@a.weblock.io")["access_token"]
    # LIVE destructive denied by policy...
    r = _req(client, inv_token, inc["id"], "TERMINATE_PROCESS", {"pid": 42},
             mode="LIVE", endpoint_id=body["endpoint_id"])
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "POLICY_DENIED"
    # ...but LIVE collect allowed (queued, command dispatched).
    r2 = _req(client, inv_token, inc["id"], "COLLECT_EVIDENCE",
              {"collection_type": "PROCESS_LIST"}, mode="LIVE",
              endpoint_id=body["endpoint_id"])
    assert r2.json()["status"] == "QUEUED", r2.text


def test_policy_denied_cases(client, org_a):
    admin_token, body = _setup(client, org_a)
    _fresh_heartbeat(client, body)
    inc = _incident(client, admin_token, body)
    h = auth_header(admin_token)
    # Bad target.
    r = _req(client, admin_token, inc["id"], "TERMINATE_PROCESS",
             {"pid": -5}, endpoint_id=body["endpoint_id"])
    assert r.status_code == 422
    # Unknown action.
    r = _req(client, admin_token, inc["id"], "FORMAT_C_DRIVE",
             endpoint_id=body["endpoint_id"])
    assert r.status_code == 422
    # Block loopback rejected.
    r = _req(client, admin_token, inc["id"], "BLOCK_NETWORK_DESTINATION",
             {"ip": "127.0.0.1"}, endpoint_id=body["endpoint_id"])
    assert r.status_code == 422
    # Bad IP rejected.
    r = _req(client, admin_token, inc["id"], "BLOCK_NETWORK_DESTINATION",
             {"ip": "999.1.1.1"}, endpoint_id=body["endpoint_id"])
    assert r.status_code == 422
    # Wrong incident -> 404; wrong endpoint -> 404.
    assert _req(client, admin_token, 999999, "ISOLATE_ENDPOINT",
                endpoint_id=body["endpoint_id"]).status_code == 404
    assert _req(client, admin_token, inc["id"], "ISOLATE_ENDPOINT",
                endpoint_id=999999).status_code == 404


def test_simulation_record_and_audit(client, org_a, db):
    from app.db.models import AgentCommand, AuditLog
    admin_token, body = _setup(client, org_a)
    inc = _incident(client, admin_token, body)
    r = _req(client, admin_token, inc["id"], "TERMINATE_PROCESS",
             {"pid": 4321, "name": "evil.exe"},
             endpoint_id=body["endpoint_id"])
    assert r.status_code == 200
    out = r.json()
    assert out["status"] == "SUCCEEDED"
    assert out["execution_mode"] == "SIMULATION"
    assert out["result"]["simulated"] is True
    assert out["result"]["executed_on_endpoint"] is False
    # No command row for simulations.
    assert db.query(AgentCommand).count() == 0
    # Audits exist, no secrets/targets dumped beyond typed target.
    audits = db.query(AuditLog).filter(
        AuditLog.action.like("response.%")).all()
    actions = {a.action for a in audits}
    assert "response.requested" in actions
    assert "response.succeeded" in actions
    for a in audits:
        assert "wlk_" not in str(a.meta_data)


def test_live_queued_and_idempotent_replay(client, org_a, db):
    from app.db.models import ResponseAction
    admin_token, body = _setup(client, org_a)
    _fresh_heartbeat(client, body)
    inc = _incident(client, admin_token, body)
    r1 = _req(client, admin_token, inc["id"], "COLLECT_EVIDENCE",
              {"collection_type": "SYSTEM_INFO"}, mode="LIVE",
              endpoint_id=body["endpoint_id"])
    assert r1.json()["status"] == "QUEUED", r1.text
    r2 = _req(client, admin_token, inc["id"], "COLLECT_EVIDENCE",
              {"collection_type": "SYSTEM_INFO"}, mode="LIVE",
              endpoint_id=body["endpoint_id"])
    assert r2.json()["id"] == r1.json()["id"]  # idempotent replay
    assert db.query(ResponseAction).count() == 1


def test_offline_endpoint_denied_live(client, org_a):
    admin_token, body = _setup(client, org_a)
    # No heartbeat with capabilities -> stale/unknown -> deny.
    inc = _incident(client, admin_token, body)
    r = _req(client, admin_token, inc["id"], "COLLECT_EVIDENCE",
             {"collection_type": "SYSTEM_INFO"}, mode="LIVE",
             endpoint_id=body["endpoint_id"])
    assert r.json()["status"] == "POLICY_DENIED"
    codes = [c["code"] for c in r.json()["policy_decision"]["checks"]
             if not c["ok"]]
    assert codes  # at least one failing check cited


def test_cancel_and_retry(client, org_a):
    admin_token, body = _setup(client, org_a)
    _fresh_heartbeat(client, body)
    inc = _incident(client, admin_token, body)
    r = _req(client, admin_token, inc["id"], "COLLECT_EVIDENCE",
             {"collection_type": "SYSTEM_INFO"}, mode="LIVE",
             endpoint_id=body["endpoint_id"])
    aid = r.json()["id"]
    h = auth_header(admin_token)
    c = client.post(f"/v1/response-actions/{aid}/cancel", headers=h)
    assert c.json()["status"] == "CANCELLED"
    # Cannot retry a cancelled action.
    assert client.post(f"/v1/response-actions/{aid}/retry",
                       headers=h).status_code == 422
    # Retry budget: fail it manually then retry.
    r2 = _req(client, admin_token, inc["id"], "TERMINATE_PROCESS",
              {"pid": 777}, mode="LIVE", endpoint_id=body["endpoint_id"])
    aid2 = r2.json()["id"]
    # Force FAILED via direct result post with unknown command? Instead drive
    # the agent loop below in protocol tests; here assert cancel-after-terminal
    # is rejected.
    client.post(f"/v1/response-actions/{aid2}/cancel", headers=h)
    assert client.post(f"/v1/response-actions/{aid2}/cancel",
                       headers=h).status_code == 422


def test_timeline_includes_response(client, org_a):
    admin_token, body = _setup(client, org_a)
    inc = _incident(client, admin_token, body)
    h = auth_header(admin_token)
    _req(client, admin_token, inc["id"], "ISOLATE_ENDPOINT",
         endpoint_id=body["endpoint_id"])
    tl = client.get(f"/v1/incidents/{inc['id']}/timeline", headers=h).json()
    kinds = [t["kind"] for t in tl["timeline"]]
    assert "response" in kinds
    assert any("RESPONSE_" in t["title"] for t in tl["timeline"]
               if t["kind"] == "response")

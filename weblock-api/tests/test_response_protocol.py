"""Phase 8: agent protocol — pull, execute (safe), result, evidence link."""
import uuid
from datetime import datetime, timezone

from app.db.models import Evidence
from tests.conftest import auth_header, login
from tests.test_endpoints import _enroll, _mint
from tests.test_response import _fresh_heartbeat, _incident, _req, _setup


def test_agent_pull_execute_report_collect(client, org_a, db):
    admin_token, body = _setup(client, org_a)
    _fresh_heartbeat(client, body)
    inc = _incident(client, admin_token, body)
    h = auth_header(admin_token)
    key_h = {"Authorization": f"Bearer {body['api_key']}"}

    r = _req(client, admin_token, inc["id"], "COLLECT_EVIDENCE",
             {"collection_type": "SYSTEM_INFO"}, mode="LIVE",
             endpoint_id=body["endpoint_id"])
    assert r.json()["status"] == "QUEUED"
    aid = r.json()["id"]

    # Agent pulls pending commands.
    pending = client.get(
        f"/v1/endpoints/{body['endpoint_id']}/commands/pending",
        headers=key_h).json()
    assert len(pending["commands"]) == 1
    cmd = pending["commands"][0]
    assert cmd["action_type"] == "COLLECT_EVIDENCE"
    assert cmd["target"] == {"collection_type": "SYSTEM_INFO"}

    # Agent reports a fabricated-but-well-formed result (protocol check).
    res = client.post(
        f"/v1/endpoints/{body['endpoint_id']}/commands/{cmd['command_id']}/result",
        json={"status": "SUCCEEDED",
              "result": {"collected": 2, "queued": 2,
                         "collection_type": "SYSTEM_INFO"}},
        headers=key_h)
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "SUCCEEDED"

    # Phase 7 evidence linked to the action + incident.
    rows = db.query(Evidence).filter(
        Evidence.source_type == "RESPONSE_RESULT").all()
    assert len(rows) == 1
    assert rows[0].incident_id == inc["id"]
    assert rows[0].integrity_status in ("UNVERIFIED", "VERIFIED")

    # Duplicate result delivery is idempotent.
    res2 = client.post(
        f"/v1/endpoints/{body['endpoint_id']}/commands/{cmd['command_id']}/result",
        json={"status": "SUCCEEDED", "result": {}},
        headers=key_h)
    assert res2.json()["status"] == "SUCCEEDED"
    assert db.query(Evidence).filter(
        Evidence.source_type == "RESPONSE_RESULT").count() == 1

    # Heartbeat peek does not consume: dedicated pull still lists nothing
    # new (already RESULT_RECEIVED), heartbeat shows no pending.
    hb = client.post(
        f"/v1/endpoints/{body['endpoint_id']}/heartbeat",
        json={"hostname": "WS-X"},
        headers=key_h).json()
    assert hb["pending_commands"] == []

    # Timeline shows the response lifecycle.
    tl = client.get(f"/v1/incidents/{inc['id']}/timeline", headers=h).json()
    titles = [t["title"] for t in tl["timeline"] if t["kind"] == "response"]
    assert any("REQUESTED" in t for t in titles)
    assert any("SUCCEEDED" in t for t in titles)


def test_command_security_rejections(client, org_a):
    admin_token, body = _setup(client, org_a)
    _fresh_heartbeat(client, body)
    inc = _incident(client, admin_token, body)
    key_h = {"Authorization": f"Bearer {body['api_key']}"}
    # Unknown command.
    assert client.post(
        f"/v1/endpoints/{body['endpoint_id']}/commands/deadbeef/result",
        json={"status": "SUCCEEDED", "result": {}},
        headers=key_h).status_code == 404
    # Wrong endpoint path.
    assert client.post("/v1/endpoints/999999/commands/x/result",
                       json={"status": "SUCCEEDED", "result": {}},
                       headers=key_h).status_code == 403
    # Bad result status.
    r = _req(client, admin_token, inc["id"], "COLLECT_EVIDENCE",
             {"collection_type": "SYSTEM_INFO"}, mode="LIVE",
             endpoint_id=body["endpoint_id"])
    pending = client.get(
        f"/v1/endpoints/{body['endpoint_id']}/commands/pending",
        headers=key_h).json()
    cmd = pending["commands"][0]
    bad = client.post(
        f"/v1/endpoints/{body['endpoint_id']}/commands/{cmd['command_id']}/result",
        json={"status": "MAYBE", "result": {}}, headers=key_h)
    assert bad.status_code == 422
    # Oversized result rejected.
    big = client.post(
        f"/v1/endpoints/{body['endpoint_id']}/commands/{cmd['command_id']}/result",
        json={"status": "FAILED", "result": {"blob": "x" * 20000}},
        headers=key_h)
    assert big.status_code == 422


def test_retry_after_failure(client, org_a, db):
    from app.db.models import AgentCommand
    admin_token, body = _setup(client, org_a)
    _fresh_heartbeat(client, body)
    inc = _incident(client, admin_token, body)
    h = auth_header(admin_token)
    key_h = {"Authorization": f"Bearer {body['api_key']}"}
    r = _req(client, admin_token, inc["id"], "TERMINATE_PROCESS",
             {"pid": 4242}, mode="LIVE", endpoint_id=body["endpoint_id"])
    aid = r.json()["id"]
    pending = client.get(
        f"/v1/endpoints/{body['endpoint_id']}/commands/pending",
        headers=key_h).json()
    cmd = pending["commands"][0]
    fail = client.post(
        f"/v1/endpoints/{body['endpoint_id']}/commands/{cmd['command_id']}/result",
        json={"status": "FAILED", "result": {},
              "error_code": "ACCESS_DENIED"}, headers=key_h)
    assert fail.json()["status"] == "FAILED"
    retry = client.post(f"/v1/response-actions/{aid}/retry", headers=h)
    assert retry.status_code == 200, retry.text
    assert retry.json()["attempt"] == 1
    assert db.query(AgentCommand).filter(
        AgentCommand.response_action_id == aid).count() == 2

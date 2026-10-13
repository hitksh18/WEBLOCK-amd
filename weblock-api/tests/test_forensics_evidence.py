"""Phase 7: evidence, custody, snapshots — collection, RBAC, isolation."""
import uuid

from app.db.models import AuditLog, CustodyRecord, Evidence
from app.services.evidence import (
    add_custody,
    collect_evidence,
    create_snapshot,
    verify_custody_chain,
    verify_evidence,
)
from tests.conftest import auth_header, login
from tests.test_endpoints import _enroll, _mint


def _telemetry_id(client, body):
    from datetime import datetime, timezone
    resp = client.post("/v1/telemetry/batch", json={
        "agent_id": body["agent_id"], "events": [{
            "event_id": str(uuid.uuid4()), "schema_version": "1.0",
            "type": "usb",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "source": "agent",
            "payload": {"kind": "volume_snapshot", "removable": []}}]},
        headers={"Authorization": f"Bearer {body['api_key']}"})
    assert resp.json()["accepted"] == 1
    from app.db.models import TelemetryEvent
    return resp


def test_collect_verify_custody_lifecycle(db, org_a):
    from app.db.models import Endpoint, TelemetryEvent
    ep = Endpoint(org_id=org_a["org"].id, agent_id="agent-ev-1", name="E")
    db.add(ep)
    db.flush()
    raw = TelemetryEvent(org_id=org_a["org"].id, endpoint_id=ep.id,
                         event_id=str(uuid.uuid4()), type="usb",
                         occurred_at=__import__("datetime").datetime.now(
                             __import__("datetime").timezone.utc),
                         payload={}, event_hash="x")
    db.add(raw)
    db.flush()
    db.commit()

    ev = collect_evidence(db, org_id=org_a["org"].id,
                          source_type="TELEMETRY_EVENT", source_id=raw.id,
                          actor_user_id=org_a["admin"].id,
                          description="lab collection")
    db.commit()
    assert ev.sha256 and len(ev.sha256) == 64
    assert ev.integrity_status == "UNVERIFIED"

    recs = db.query(CustodyRecord).filter(
        CustodyRecord.evidence_id == ev.id).all()
    assert [r.action for r in recs] == ["COLLECTED", "STORED"]
    assert recs[0].prev_hash == "GENESIS"
    assert recs[1].prev_hash == recs[0].record_hash

    row, ok = verify_evidence(db, org_id=org_a["org"].id, evidence_id=ev.id,
                              actor_user_id=org_a["admin"].id)
    db.commit()
    assert ok is True and row.integrity_status == "VERIFIED"

    valid, problems = verify_custody_chain(db, ev.id)
    assert valid is True and problems == []

    # Tamper with content -> TAMPERED.
    ev.content = {"source_type": "TELEMETRY_EVENT", "source_id": raw.id,
                  "reference": {"forged": True}}
    db.commit()
    row2, ok2 = verify_evidence(db, org_id=org_a["org"].id, evidence_id=ev.id)
    assert ok2 is False and row2.integrity_status == "TAMPERED"


def test_custody_invalid_action_rejected(db, org_a):
    import pytest
    from app.db.models import Endpoint
    ep = Endpoint(org_id=org_a["org"].id, agent_id="agent-ev-2", name="E")
    db.add(ep)
    db.flush()
    ev = Evidence(org_id=org_a["org"].id, source="t", content={},
                  sha256="x", source_type="LOGIN")
    db.add(ev)
    db.flush()
    with pytest.raises(ValueError):
        add_custody(db, org_id=org_a["org"].id, evidence_id=ev.id,
                    action="SHREDDED", actor_user_id=None)


def test_snapshot_and_audit_hygiene(client, org_a, org_b, db):
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    body = _enroll(client, _mint(client, admin_token))
    h = auth_header(admin_token)
    # Make an incident via USB? No auto-incident for LOW single. Use manual:
    # create a 2-family cluster first.
    from datetime import datetime, timezone
    wire = []
    for kind, etype, payload in [
        ("auth", "auth", {"kind": "windows_security_event", "event_id": 4625,
                          "record_number": 1, "source": "S",
                          "strings": ["x", "snap-user"]}),
        ("usb", "usb", {"kind": "usb_device_seen",
                        "device": {"device": "E:"}}),
    ]:
        wire.append({"event_id": str(uuid.uuid4()), "schema_version": "1.0",
                     "type": etype,
                     "occurred_at": datetime.now(timezone.utc).isoformat(),
                     "source": "agent", "payload": payload})
    client.post("/v1/telemetry/batch",
                json={"agent_id": body["agent_id"], "events": wire},
                headers={"Authorization": f"Bearer {body['api_key']}"})
    clusters = client.get("/v1/correlations", headers=h).json()
    assert clusters["total"] >= 1
    cid = clusters["clusters"][0]["id"]
    inc = client.post(f"/v1/correlations/{cid}/incident", headers=h).json()

    snap = client.post(f"/v1/incidents/{inc['id']}/snapshot", headers=h)
    assert snap.status_code == 200, snap.text
    assert snap.json()["evidence_ids"]
    assert len(snap.json()["snapshot_hash"]) == 64

    ev_list = client.get(f"/v1/incidents/{inc['id']}/evidence",
                         headers=h).json()
    assert ev_list["total"] >= 3
    first_id = ev_list["evidence"][0]["id"]

    # Viewed + verified are audited WITHOUT payloads.
    client.get(f"/v1/evidence/{first_id}", headers=h)
    client.post(f"/v1/evidence/{first_id}/verify", headers=h)
    audits = db.query(AuditLog).filter(
        AuditLog.action.in_(["evidence.viewed", "evidence.verified",
                             "evidence.snapshot_created"])).all()
    assert len(audits) >= 3
    for audit in audits:
        blob = str(audit.meta_data)
        assert "removable" not in blob and "cmdline" not in blob
        assert "password" not in blob.lower()

    # Custody chain for one item is hash-valid.
    custody = client.get(f"/v1/evidence/{first_id}/custody", headers=h).json()
    assert custody["chain_valid"] is True
    assert [r["action"] for r in custody["records"][:2]] == \
        ["COLLECTED", "STORED"]

    # RBAC: viewer reads but cannot collect/snapshot/verify.
    viewer = login(client, "viewer@a.weblock.io")["access_token"]
    vh = auth_header(viewer)
    assert client.get(f"/v1/evidence/{first_id}", headers=vh).status_code == 200
    assert client.post(f"/v1/incidents/{inc['id']}/evidence/collect",
                       json={"source_type": "INCIDENT", "source_id": inc["id"]},
                       headers=vh).status_code == 403
    assert client.post(f"/v1/incidents/{inc['id']}/snapshot",
                       headers=vh).status_code == 403
    assert client.post(f"/v1/evidence/{first_id}/verify",
                       headers=vh).status_code == 403

    # Isolation: org B sees nothing.
    admin_b = login(client, "admin@b.weblock.io")["access_token"]
    assert client.get(f"/v1/evidence/{first_id}",
                      headers=auth_header(admin_b)).status_code == 404

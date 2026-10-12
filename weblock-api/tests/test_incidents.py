"""Incidents / evidence / audit / org isolation."""
import hashlib
import json

from tests.conftest import auth_header, login


def _intruder(client, token, email="employee@a.weblock.io"):
    resp = client.post(
        "/v1/analyze-login",
        json={
            "user_email": email,
            "ip_address": "185.22.44.10",
            "mac_address": "FF:FF:FF:FF:FF:FF",
            "device_fingerprint": "fp-evil",
            "geo_location": "UnknownLand",
        },
        headers=auth_header(token),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_incident_created_with_severity_and_evidence(client, org_a, db):
    from app.db.models import Evidence, Incident
    token = login(client, "analyst@a.weblock.io")["access_token"]
    out = _intruder(client, token)
    assert out["classification"] == "Intruder"
    inc = db.query(Incident).filter(
        Incident.id == out["incident_id"]).first()
    assert inc is not None
    assert inc.severity == "high"
    assert inc.status == "open"
    assert inc.incident_key == out["incident_key"]
    assert inc.risk_score == out["risk_score"]

    ev = db.query(Evidence).filter(
        Evidence.incident_id == inc.id).first()
    assert ev is not None
    recomputed = hashlib.sha256(
        json.dumps(ev.content, sort_keys=True, default=str).encode()).hexdigest()
    assert ev.sha256 == recomputed
    assert len(ev.sha256) == 64


def test_incident_status_flow(client, org_a):
    analyst = login(client, "analyst@a.weblock.io")["access_token"]
    out = _intruder(client, analyst)
    resp = client.post(
        f"/v1/incidents/{out['incident_id']}/status",
        json={"status": "investigating"},
        headers=auth_header(analyst),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "investigating"
    bad = client.post(
        f"/v1/incidents/{out['incident_id']}/status",
        json={"status": "hacked"},
        headers=auth_header(analyst),
    )
    assert bad.status_code == 422


def test_org_isolation_incidents(client, org_a, org_b):
    analyst_a = login(client, "analyst@a.weblock.io")["access_token"]
    out = _intruder(client, analyst_a)
    admin_b = login(client, "admin@b.weblock.io")["access_token"]
    # Org B admin must NOT see Org A's incident.
    resp = client.get(f"/v1/incidents/{out['incident_id']}",
                      headers=auth_header(admin_b))
    assert resp.status_code == 404
    listing = client.get("/v1/incidents", headers=auth_header(admin_b))
    assert listing.status_code == 200
    assert listing.json() == []


def test_cross_org_analyze_rejected(client, org_a, org_b):
    analyst_a = login(client, "analyst@a.weblock.io")["access_token"]
    # Org A analyst tries to analyze Org B's admin by id -> 404 (not in org).
    resp = client.post(
        "/v1/analyze-login",
        json={"user_id": org_b["admin"].id, "ip_address": "10.0.0.5"},
        headers=auth_header(analyst_a),
    )
    assert resp.status_code == 404


def test_audit_logged(client, org_a, db):
    from app.db.models import AuditLog
    token = login(client, "admin@a.weblock.io")["access_token"]
    _intruder(client, token)
    actions = {r.action for r in db.query(AuditLog).filter(
        AuditLog.org_id == org_a["org"].id).all()}
    assert "auth.login" in actions
    assert "incident.created" in actions
    assert "login.analyzed" in actions

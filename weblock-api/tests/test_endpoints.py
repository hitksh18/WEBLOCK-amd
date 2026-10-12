"""Phase 1 server tests: enrollment, heartbeat, config, revocation."""
from tests.conftest import auth_header, login


def _mint(client, admin_token, label="lab-pc"):
    resp = client.post("/v1/admin/enrollment-tokens", json={"label": label},
                       headers=auth_header(admin_token))
    assert resp.status_code == 200, resp.text
    return resp.json()["enroll_token"]


def _enroll(client, token, hostname="WS-LAB-01"):
    resp = client.post("/v1/endpoints/enroll", json={
        "enroll_token": token,
        "device": {"hostname": hostname, "os": "Windows",
                   "ip": "10.0.0.21", "mac": "AA:BB:CC:DD:EE:99",
                   "fingerprint": "fp-lab-01", "agent_version": "1.0.0"},
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["api_key"].startswith("wlk_")
    # api_key must NOT appear in listing/detail afterwards.
    return body


def _agent_header(key):
    return {"Authorization": f"Bearer {key}"}


def test_enroll_and_heartbeat_path_param(client, org_a):
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    body = _enroll(client, _mint(client, admin_token))

    hb = client.post(f"/v1/endpoints/{body['endpoint_id']}/heartbeat",
                     json={"hostname": "WS-LAB-01", "agent_version": "1.0.0",
                           "queue_depth": 0},
                     headers=_agent_header(body["api_key"]))
    assert hb.status_code == 200, hb.text
    assert hb.json()["last_seen"]

    listing = client.get("/v1/endpoints", headers=auth_header(admin_token))
    assert listing.status_code == 200
    row = next(e for e in listing.json() if e["agent_id"] == body["agent_id"])
    assert row["presence"] == "healthy"
    assert "api_key" not in str(row)


def test_enroll_reuse_rejected(client, org_a):
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    token = _mint(client, admin_token)
    _enroll(client, token)
    again = client.post("/v1/endpoints/enroll",
                        json={"enroll_token": token, "device": {}})
    assert again.status_code == 401


def test_enroll_invalid_token_rejected(client, org_a):
    resp = client.post("/v1/endpoints/enroll",
                       json={"enroll_token": "wle_deadbeef", "device": {}})
    assert resp.status_code == 401


def test_enroll_expired_token_rejected(client, org_a, db):
    from datetime import datetime, timedelta, timezone
    from app.db.models import EnrollmentToken
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    token = _mint(client, admin_token)
    import hashlib
    row = db.query(EnrollmentToken).filter(
        EnrollmentToken.token_hash == hashlib.sha256(token.encode()).hexdigest()
    ).first()
    row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()
    resp = client.post("/v1/endpoints/enroll",
                       json={"enroll_token": token, "device": {}})
    assert resp.status_code == 401


def test_heartbeat_wrong_endpoint_id_rejected(client, org_a):
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    body = _enroll(client, _mint(client, admin_token))
    resp = client.post("/v1/endpoints/999999/heartbeat", json={},
                       headers=_agent_header(body["api_key"]))
    assert resp.status_code == 403


def test_revoked_endpoint_rejected(client, org_a):
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    body = _enroll(client, _mint(client, admin_token))
    rev = client.post(f"/v1/admin/endpoints/{body['endpoint_id']}/revoke",
                      headers=auth_header(admin_token))
    assert rev.status_code == 200
    hb = client.post(f"/v1/endpoints/{body['endpoint_id']}/heartbeat", json={},
                     headers=_agent_header(body["api_key"]))
    assert hb.status_code == 401


def test_agent_config_roundtrip(client, org_a):
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    body = _enroll(client, _mint(client, admin_token))
    cfg = client.get(f"/v1/endpoints/{body['endpoint_id']}/config",
                     headers=_agent_header(body["api_key"]))
    assert cfg.status_code == 200
    assert cfg.json()["heartbeat_interval"] == 60
    put = client.put(f"/v1/admin/endpoints/{body['endpoint_id']}/config",
                     json={"config": {"heartbeat_interval": 120}},
                     headers=auth_header(admin_token))
    assert put.status_code == 200, put.text
    assert put.json()["heartbeat_interval"] == 120
    bad = client.put(f"/v1/admin/endpoints/{body['endpoint_id']}/config",
                     json={"config": {"rm_rf": True}},
                     headers=auth_header(admin_token))
    assert bad.status_code == 422


def test_non_admin_cannot_mint_or_revoke(client, org_a):
    viewer = login(client, "viewer@a.weblock.io")["access_token"]
    assert client.post("/v1/admin/enrollment-tokens", json={},
                       headers=auth_header(viewer)).status_code == 403
    assert client.post("/v1/admin/endpoints/1/revoke",
                       headers=auth_header(viewer)).status_code == 403

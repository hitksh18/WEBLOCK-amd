"""Authentication: login / refresh / logout / RBAC."""
from tests.conftest import auth_header, login


def test_login_success(client, org_a):
    data = login(client, "admin@a.weblock.io")
    assert data["token_type"] == "bearer"
    assert data["role"] == "admin"
    assert data["org_id"] == org_a["org"].id
    assert data["access_token"] and data["refresh_token"]


def test_login_invalid_password(client, org_a):
    resp = client.post("/v1/auth/login",
                       json={"email": "admin@a.weblock.io", "password": "wrong"})
    assert resp.status_code == 401


def test_login_unknown_user(client, org_a):
    resp = client.post("/v1/auth/login",
                       json={"email": "ghost@a.weblock.io", "password": "Password123!"})
    assert resp.status_code == 401


def test_blocked_user_cannot_login(client, org_a, db):
    org_a["viewer"].is_blocked = True
    db.commit()
    resp = client.post("/v1/auth/login",
                       json={"email": "viewer@a.weblock.io", "password": "Password123!"})
    assert resp.status_code == 403


def test_refresh_rotation_and_reuse_rejected(client, org_a):
    data = login(client, "admin@a.weblock.io")
    r1 = client.post("/v1/auth/refresh",
                     json={"refresh_token": data["refresh_token"]})
    assert r1.status_code == 200, r1.text
    new_tokens = r1.json()
    assert new_tokens["access_token"] != data["access_token"]
    # Old refresh token was rotated -> revoked.
    r2 = client.post("/v1/auth/refresh",
                     json={"refresh_token": data["refresh_token"]})
    assert r2.status_code == 401


def test_logout_revokes_refresh(client, org_a):
    data = login(client, "admin@a.weblock.io")
    headers = auth_header(data["access_token"])
    resp = client.post("/v1/auth/logout",
                       json={"refresh_token": data["refresh_token"]},
                       headers=headers)
    assert resp.status_code == 200
    r2 = client.post("/v1/auth/refresh",
                     json={"refresh_token": data["refresh_token"]})
    assert r2.status_code == 401


def test_expired_token_rejected(client, org_a):
    headers = auth_header("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.invalid")
    resp = client.get("/v1/admin/metrics", headers=headers)
    assert resp.status_code == 401


def test_viewer_cannot_access_admin(client, org_a):
    data = login(client, "viewer@a.weblock.io")
    resp = client.get("/v1/admin/metrics", headers=auth_header(data["access_token"]))
    assert resp.status_code == 403


def test_admin_can_access_metrics(client, org_a):
    data = login(client, "admin@a.weblock.io")
    resp = client.get("/v1/admin/metrics", headers=auth_header(data["access_token"]))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["org_id"] == org_a["org"].id


def test_rate_limiting(client, org_a):
    from app.core.config import settings
    old = settings.LOGIN_RATE_LIMIT_MAX_ATTEMPTS
    settings.LOGIN_RATE_LIMIT_MAX_ATTEMPTS = 3
    try:
        for _ in range(3):
            client.post("/v1/auth/login",
                        json={"email": "analyst@a.weblock.io", "password": "bad"})
        resp = client.post("/v1/auth/login",
                           json={"email": "analyst@a.weblock.io", "password": "bad"})
        assert resp.status_code == 429, resp.text
    finally:
        settings.LOGIN_RATE_LIMIT_MAX_ATTEMPTS = old

"""Risk engine: genuine / suspicious / intruder / history-based."""
from tests.conftest import auth_header, login

BASELINE = {
    "ip_address": "10.1.2.3",
    "mac_address": "AA:BB:CC:DD:EE:01",
    "device_fingerprint": "fp-baseline-1",
    "geo_location": "India",
}


def _analyze(client, token, **overrides):
    payload = dict(BASELINE)
    payload.update(overrides)
    payload["user_email"] = "employee@a.weblock.io"
    resp = client.post("/v1/analyze-login", json=payload,
                       headers=auth_header(token))
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_genuine_login(client, org_a):
    token = login(client, "analyst@a.weblock.io")["access_token"]
    out = _analyze(client, token)
    assert out["classification"] == "Genuine"
    assert out["risk_score"] < 30
    assert out["incident_id"] is None


def test_suspicious_login_new_device_and_ip(client, org_a):
    token = login(client, "analyst@a.weblock.io")["access_token"]
    # Seed one baseline event first so deltas trigger (new IP/device/geo).
    _analyze(client, token)
    out = _analyze(
        client, token,
        ip_address="10.9.9.9",
        mac_address="AA:BB:CC:DD:EE:01",  # registered -> no device penalty
        device_fingerprint="fp-unknown-9",
        geo_location="India",
    )
    # new IP (+15) + new device (+15) = 30 -> Suspicious (threshold 75).
    assert out["classification"] == "Suspicious", out
    assert out["incident_id"] is not None
    assert out["incident_key"].startswith("INC-")


def test_intruder_login_disallowed_country(client, org_a):
    token = login(client, "analyst@a.weblock.io")["access_token"]
    out = _analyze(
        client, token,
        ip_address="185.22.44.10",
        mac_address="FF:FF:FF:FF:FF:FF",
        device_fingerprint="fp-evil",
        geo_location="UnknownLand",
    )
    # 40 (country) + 20 (mismatch) + 35 (device) + 30 (IP range*) ...
    # *strict? test_day allows 0.0.0.0/0 so no IP-range penalty; still >=75.
    assert out["classification"] == "Intruder", out
    assert out["risk_score"] >= 75


def test_history_frequency_raises_risk(client, org_a):
    token = login(client, "analyst@a.weblock.io")["access_token"]
    for _ in range(4):
        _analyze(client, token)
    out = _analyze(client, token)  # 5th: high-frequency factor present
    assert "High login frequency detected." in out["factors"], out


def test_policy_violation_unregistered_device(client, org_a, db):
    from app.db.models import OrgPolicy
    # Switch employee to strict role: 10.0.0.0/8 only, 08:00-20:00.
    pol = db.query(OrgPolicy).filter(
        OrgPolicy.org_id == org_a["org"].id).first()
    overrides = dict(pol.user_overrides or {})
    overrides[str(org_a["employee"].id)] = {"role": "strict_day"}
    pol.user_overrides = dict(overrides)
    db.commit()
    token = login(client, "analyst@a.weblock.io")["access_token"]
    out = _analyze(
        client, token,
        ip_address="203.0.113.9",  # outside 10/8 -> +30
        mac_address="00:11:22:33:44:55",  # unregistered -> +35
    )
    assert out["risk_score"] >= 65, out
    assert any("IP outside allowed range" in f for f in out["factors"])

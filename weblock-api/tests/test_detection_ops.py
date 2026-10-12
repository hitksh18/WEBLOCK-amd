"""Phase 3: detection ops — lifecycle, admin RBAC, overrides, isolation."""
import uuid
from datetime import datetime, timezone

from tests.conftest import auth_header, login
from tests.test_endpoints import _enroll, _mint


def _setup(client, org_a):
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    return admin_token, _enroll(client, _mint(client, admin_token))


def _auth_event(client, body, payload, etype="auth"):
    from datetime import datetime, timezone
    resp = client.post("/v1/telemetry/batch", json={
        "agent_id": body["agent_id"], "events": [{
            "event_id": str(uuid.uuid4()), "schema_version": "1.0",
            "type": etype,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "source": "agent", "payload": payload}]},
        headers={"Authorization": f"Bearer {body['api_key']}"})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_usb_detection_end_to_end_and_status_lifecycle(client, org_a, db):
    admin_token, body = _setup(client, org_a)
    out = _auth_event(client, body, {"kind": "usb_device_seen",
                                     "device": {"device": "E:"}}, etype="usb")
    assert out["accepted"] == 1
    h = auth_header(admin_token)
    dets = client.get("/v1/detections", params={"rule_id": "USB-01"},
                      headers=h).json()
    # USB-01 plus DEV-01? DEV-01 is AUTH-only; usb batch has no auth events.
    usb = [d for d in dets["detections"] if d["rule_id"] == "USB-01"]
    assert len(usb) == 1, dets
    det = usb[0]
    assert det["severity"] == "low"
    assert det["status"] == "open"
    assert "E:" in det["explanation"]
    assert det["primary_event_id"]
    assert det["mitre"] == []

    # Lifecycle: acknowledge -> resolve; bad value -> 422.
    r1 = client.post(f"/v1/detections/{det['id']}/status",
                     json={"status": "acknowledged"}, headers=h)
    assert r1.json()["status"] == "acknowledged"
    r2 = client.post(f"/v1/detections/{det['id']}/status",
                     json={"status": "resolved"}, headers=h)
    assert r2.json()["status"] == "resolved"
    bad = client.post(f"/v1/detections/{det['id']}/status",
                      json={"status": "deleted"}, headers=h)
    assert bad.status_code == 422
    # Viewer cannot transition.
    viewer = login(client, "viewer@a.weblock.io")["access_token"]
    assert client.post(f"/v1/detections/{det['id']}/status",
                       json={"status": "open"},
                       headers=auth_header(viewer)).status_code == 403


def test_auth01_end_to_end_bruteforce(client, org_a):
    admin_token, body = _setup(client, org_a)
    for _ in range(5):
        _auth_event(client, body, {"kind": "windows_security_event",
                                   "event_id": 4625, "record_number": 1,
                                   "source": "Security",
                                   "strings": ["x", "victim"]})
    h = auth_header(admin_token)
    dets = client.get("/v1/detections", params={"rule_id": "AUTH-01"},
                      headers=h).json()
    assert dets["total"] == 1, dets
    det = dets["detections"][0]
    assert det["severity"] == "high"
    assert "5 failed logons" in det["explanation"]
    assert det["mitre"] == ["T1110"]
    assert len(det["related_event_ids"]) == 4
    # 6th failure inside window: suppressed, still 1.
    _auth_event(client, body, {"kind": "windows_security_event",
                               "event_id": 4625, "record_number": 2,
                               "source": "Security", "strings": ["x", "victim"]})
    dets2 = client.get("/v1/detections", params={"rule_id": "AUTH-01"},
                       headers=h).json()
    assert dets2["total"] == 1


def test_rule_disable_and_severity_override(client, org_a):
    admin_token, body = _setup(client, org_a)
    h = auth_header(admin_token)
    # Disable USB-01 for this org: no detection.
    put = client.put("/v1/admin/rules/USB-01", json={"enabled": False}, headers=h)
    assert put.status_code == 200
    _auth_event(client, body, {"kind": "usb_device_seen",
                               "device": {"device": "F:"}}, etype="usb")
    assert client.get("/v1/detections", params={"rule_id": "USB-01"},
                      headers=h).json()["total"] == 0
    # Re-enable with severity override: detection carries override.
    client.put("/v1/admin/rules/USB-01",
               json={"enabled": True, "severity": "medium"}, headers=h)
    _auth_event(client, body, {"kind": "usb_device_seen",
                               "device": {"device": "G:"}}, etype="usb")
    dets = client.get("/v1/detections", params={"rule_id": "USB-01"},
                      headers=h).json()
    assert dets["total"] == 1
    assert dets["detections"][0]["severity"] == "medium"


def test_rule_admin_rbac_and_validation(client, org_a):
    admin_token, body = _setup(client, org_a)
    viewer = login(client, "viewer@a.weblock.io")["access_token"]
    vh = auth_header(viewer)
    # Viewer can read rules...
    assert client.get("/v1/rules", headers=vh).status_code == 200
    # ...but not modify them.
    assert client.put("/v1/admin/rules/USB-01", json={"enabled": False},
                      headers=vh).status_code == 403
    h = auth_header(admin_token)
    assert client.put("/v1/admin/rules/NOPE", json={},
                      headers=h).status_code == 404
    assert client.put("/v1/admin/rules/USB-01", json={"severity": "extreme"},
                      headers=h).status_code == 422
    assert client.put("/v1/admin/rules/AUTH-01",
                      json={"params": {"threshold": "many"}},
                      headers=h).status_code == 422
    assert client.put("/v1/admin/rules/AUTH-01",
                      json={"params": {"rm_rf": True}},
                      headers=h).status_code == 422


def test_rule_override_is_org_scoped(client, org_a, org_b):
    admin_a = login(client, "admin@a.weblock.io")["access_token"]
    admin_b = login(client, "admin@b.weblock.io")["access_token"]
    client.put("/v1/admin/rules/USB-01", json={"enabled": False},
               headers=auth_header(admin_a))
    rules_b = client.get("/v1/rules",
                         headers=auth_header(admin_b)).json()
    usb_b = next(r for r in rules_b if r["rule_id"] == "USB-01")
    assert usb_b["scope"] in ("global", "code-default")
    assert usb_b["enabled"] is True  # org A override does not leak


def test_test_marker_never_seeded(client, org_a):
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    rules = client.get("/v1/rules",
                       headers=auth_header(admin_token)).json()
    assert "TEST-MARKER" not in [r["rule_id"] for r in rules]

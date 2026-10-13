"""Phase 7: timeline + reports — ordering, sections, hashes, RBAC."""
import uuid
from datetime import datetime, timezone

from tests.conftest import auth_header, login
from tests.test_endpoints import _enroll, _mint


def _incident_via_fixtures(client, body, tag="TEST-P7"):
    wire = []
    for i in range(5):
        wire.append({"event_id": f"{tag}-{uuid.uuid4()}",
                     "schema_version": "1.0", "type": "auth",
                     "occurred_at": datetime.now(timezone.utc).isoformat(),
                     "source": "agent",
                     "payload": {"kind": "windows_security_event",
                                 "event_id": 4625, "record_number": i,
                                 "source": "Security",
                                 "strings": ["x", "TEST-p7-user"]}})
    wire.append({"event_id": f"{tag}-{uuid.uuid4()}",
                 "schema_version": "1.0", "type": "process",
                 "occurred_at": datetime.now(timezone.utc).isoformat(),
                 "source": "agent",
                 "payload": {"kind": "snapshot", "processes": [
                     {"pid": 9701, "ppid": 1, "name": "powershell.exe",
                      "cmdline": "powershell -EncodedCommand QUJD",
                      "username": "", "create_time": 0}]}})
    resp = client.post("/v1/telemetry/batch",
                       json={"agent_id": body["agent_id"], "events": wire},
                       headers={"Authorization": f"Bearer {body['api_key']}"})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _setup_incident(client, org_a):
    admin_token = login(client, "admin@a.weblock.io")["access_token"]
    body = _enroll(client, _mint(client, admin_token))
    h = auth_header(admin_token)
    _incident_via_fixtures(client, body)
    incidents = client.get("/v1/incidents", headers=h).json()
    assert len(incidents) == 1, incidents
    return admin_token, body, h, incidents[0]


def test_timeline_chronological_and_sourced(client, org_a, org_b):
    admin_token, body, h, inc = _setup_incident(client, org_a)
    tl = client.get(f"/v1/incidents/{inc['id']}/timeline",
                    params={"limit": 100}, headers=h).json()
    assert tl["total"] > 5
    stamps = [t["timestamp"] for t in tl["timeline"]]
    assert stamps == sorted(stamps)
    kinds = {t["kind"] for t in tl["timeline"]}
    assert {"telemetry", "security_event", "detection", "incident",
            "risk"} <= kinds
    for item in tl["timeline"]:
        assert item["title"] and item["refs"]
    # Pagination slices deterministically.
    p1 = client.get(f"/v1/incidents/{inc['id']}/timeline",
                    params={"limit": 3, "offset": 0}, headers=h).json()
    p2 = client.get(f"/v1/incidents/{inc['id']}/timeline",
                    params={"limit": 3, "offset": 3}, headers=h).json()
    assert len(p1["timeline"]) == 3 and len(p2["timeline"]) == 3
    assert p1["timeline"][0] != p2["timeline"][0]
    # Isolation.
    admin_b = login(client, "admin@b.weblock.io")["access_token"]
    assert client.get(f"/v1/incidents/{inc['id']}/timeline",
                      headers=auth_header(admin_b)).status_code == 404


def test_report_json_sections_and_hash(client, org_a):
    from app.db.models import ForensicReport
    admin_token, body, h, inc = _setup_incident(client, org_a)
    exp = client.post(f"/v1/incidents/{inc['id']}/report/export",
                      json={"format": "json"}, headers=h)
    assert exp.status_code == 200, exp.text
    meta = exp.json()
    assert len(meta["sha256"]) == 64
    assert meta["version"] == 1

    got = client.get(f"/v1/incidents/{inc['id']}/report", headers=h).json()
    content = got["content"]
    for section in ("incident", "endpoint", "risk", "correlation",
                    "timeline", "evidence_inventory", "integrity", "mitre",
                    "limitations", "generated_by", "generated_at"):
        assert section in content, section
    assert content["incident"]["incident_key"] == inc["incident_key"]
    assert len(content["timeline"]) > 5
    assert "AUTH-01" in str(content["timeline"])
    assert "no legal-admissibility claim" in content["report"].lower()

    verify = client.post(f"/v1/reports/{meta['id']}/verify", headers=h).json()
    assert verify["valid"] is True

    # Second export = immutable new version, never overwrite.
    exp2 = client.post(f"/v1/incidents/{inc['id']}/report/export",
                       json={"format": "json"}, headers=h).json()
    assert exp2["version"] == 2
    assert exp2["sha256"] != meta["sha256"]  # generated_at differs


def test_report_pdf_content_and_download(client, org_a, org_b, tmp_path,
                                           monkeypatch):
    import app.services.reports as reports_mod
    monkeypatch.setattr(reports_mod, "REPORTS_DIR", str(tmp_path))
    admin_token, body, h, inc = _setup_incident(client, org_a)
    exp = client.post(f"/v1/incidents/{inc['id']}/report/export",
                      json={"format": "pdf"}, headers=h)
    assert exp.status_code == 200, exp.text
    meta = exp.json()
    assert meta["size_bytes"] > 1000

    dl = client.get(f"/v1/reports/{meta['id']}/download", headers=h)
    assert dl.status_code == 200
    assert dl.headers["content-type"] == "application/pdf"
    assert dl.content[:5] == b"%PDF-"
    import io
    from pypdf import PdfReader
    text = "\n".join(page.extract_text() or ""
                     for page in PdfReader(io.BytesIO(dl.content)).pages)
    assert inc["incident_key"] in text
    assert "Timeline" in text
    assert "Evidence inventory" in text

    verify = client.post(f"/v1/reports/{meta['id']}/verify", headers=h).json()
    assert verify["valid"] is True

    # RBAC + isolation.
    viewer = login(client, "viewer@a.weblock.io")["access_token"]
    assert client.post(f"/v1/incidents/{inc['id']}/report/export",
                       json={"format": "json"},
                       headers=auth_header(viewer)).status_code == 403
    assert client.get(f"/v1/incidents/{inc['id']}/report",
                      headers=auth_header(viewer)).status_code == 200
    admin_b = login(client, "admin@b.weblock.io")["access_token"]
    assert client.get(f"/v1/reports/{meta['id']}/download",
                      headers=auth_header(admin_b)).status_code == 404

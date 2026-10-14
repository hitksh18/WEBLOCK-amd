"""Phase 9: provider matrix, validation, persistence, boundary, security."""
import json
import uuid
from datetime import datetime, timezone

from app.db.models import AIAnalysis
from app.services.ai_analysis import request_analysis, validate_analysis
from app.services.ai_providers import MockProvider
from tests.conftest import auth_header, login
from tests.test_ai_context import _incident_with_chain
from tests.test_endpoints import _enroll, _mint


def _good_script(det_id=1, evd_id=1, corr_id=1):
    return {
        "assessment": "Multiple failed logons preceded encoded PowerShell.",
        "confidence": {"level": "MEDIUM", "reason": "two rule families agree"},
        "observed_facts": [
            {"statement": "AUTH-01 fired", "references": [f"DET-{det_id}"]}],
        "inferences": [
            {"statement": "May indicate credential abuse", "confidence": "LOW",
             "references": [f"DET-{det_id}"]}],
        "recommendations": [
            {"action": "COLLECT_EVIDENCE", "reason": "preserve process state",
             "references": [f"DET-{det_id}"], "urgency": "MEDIUM",
             "requires_human_approval": True}],
        "unknowns": [{"statement": "Actor identity unconfirmed",
                      "why_unknown": "no identity binding"}],
        "mitre_assessment": [{"technique": "T1059.001", "observed": True,
                              "reason": "PROC-01 mapping"}],
        "limitations": ["advisory only"],
    }


def test_mock_success_end_to_end(client, org_a, db, monkeypatch):
    import app.services.ai_analysis as analysis_mod
    from app.core.config import settings
    monkeypatch.setattr(settings, "AI_MIN_REFRESH_SECONDS", 0)
    admin_token, body, h, inc = _incident_with_chain(client, org_a)
    dets = client.get(f"/v1/incidents/{inc['id']}", headers=h).json()
    corr_dets = dets["correlation"]["detections"]
    script = _good_script(det_id=corr_dets[0]["id"])
    mock = MockProvider(script=script)
    monkeypatch.setattr(analysis_mod, "default_provider", lambda: mock)
    resp = client.post(f"/v1/incidents/{inc['id']}/ai-analysis", headers=h)
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["status"] == "SUCCEEDED"
    assert out["validation_status"] == "VALID"
    assert out["version"] == 1
    assert out["context_hash"]
    analysis = out["analysis"]
    assert analysis["confidence"] == "MEDIUM"
    assert analysis["observed_facts"][0]["references"] == \
        [f"DET-{corr_dets[0]['id']}"]
    assert analysis["recommendations"][0]["requires_human_approval"] is True
    # No response command created by the AI path.
    from app.db.models import AgentCommand, ResponseAction
    assert db.query(ResponseAction).count() == 0
    assert db.query(AgentCommand).count() == 0
    # Timeline + audit recorded.
    tl = client.get(f"/v1/incidents/{inc['id']}/timeline", headers=h).json()
    assert any(t["kind"] == "ai" for t in tl["timeline"])
    # Refresh creates immutable v2.
    resp2 = client.post(f"/v1/incidents/{inc['id']}/ai-analysis", headers=h)
    assert resp2.json()["version"] == 2
    listing = client.get(f"/v1/incidents/{inc['id']}/ai-analyses",
                         headers=h).json()
    assert listing["total"] == 2
    one = client.get(f"/v1/ai-analyses/{out['id']}", headers=h).json()
    assert one["version"] == 1  # v1 untouched


def test_unavailable_provider_honest(client, org_a, db, monkeypatch):
    from app.db.models import Incident
    import app.services.ai_analysis as analysis_mod
    admin_token, body, h, inc = _incident_with_chain(client, org_a)
    monkeypatch.setattr(analysis_mod, "default_provider",
                        lambda: MockProvider(fail="unavailable"))
    # Force availability check through real settings path by patching enabled?
    # Mock unavailable short-circuits: row must be AI_UNAVAILABLE, no analysis.
    resp = client.post(f"/v1/incidents/{inc['id']}/ai-analysis", headers=h)
    out = resp.json()
    assert out["status"] == "AI_UNAVAILABLE"
    assert out["analysis"] == {}
    assert out["error_code"] == "AI_UNAVAILABLE"


def test_no_provider_configured_returns_unavailable(client, org_a):
    admin_token, body, h, inc = _incident_with_chain(client, org_a)
    # Default env has no key and AI disabled -> honest unavailable.
    resp = client.post(f"/v1/incidents/{inc['id']}/ai-analysis", headers=h)
    out = resp.json()
    assert out["status"] == "AI_UNAVAILABLE", out


def test_provider_failures(client, org_a, db, monkeypatch):
    import app.services.ai_analysis as analysis_mod
    from app.core.config import settings
    monkeypatch.setattr(settings, "AI_MIN_REFRESH_SECONDS", 0)
    admin_token, body, h, inc = _incident_with_chain(client, org_a)
    for fail, code in (("timeout", "TIMEOUT"), ("malformed", "MALFORMED_OUTPUT")):
        monkeypatch.setattr(analysis_mod, "default_provider",
                            lambda fail=fail: MockProvider(fail=fail))
        out = client.post(f"/v1/incidents/{inc['id']}/ai-analysis",
                          headers=h).json()
        assert out["status"] == "FAILED", (fail, out)
        assert out["error_code"] == code, out
    monkeypatch.setattr(analysis_mod, "default_provider",
                        lambda: MockProvider(fail="oversized"))
    out = client.post(f"/v1/incidents/{inc['id']}/ai-analysis",
                      headers=h).json()
    assert out["error_code"] == "OUTPUT_TOO_LARGE", out


def test_hallucinated_reference_rejected(client, org_a, db, monkeypatch):
    import app.services.ai_analysis as analysis_mod
    admin_token, body, h, inc = _incident_with_chain(client, org_a)
    script = _good_script(det_id=999999)
    script["recommendations"][0]["references"] = ["EVD-999999"]
    script["recommendations"][0]["action"] = "ISOLATE_ENDPOINT"
    monkeypatch.setattr(analysis_mod, "default_provider",
                        lambda: MockProvider(script=script))
    out = client.post(f"/v1/incidents/{inc['id']}/ai-analysis",
                      headers=h).json()
    assert out["status"] == "VALIDATION_FAILED", out
    assert "999999" in out["error_message"]
    # Nothing canonical stored.
    assert out["analysis"] == {}


def test_unsupported_action_rejected(client, org_a, db, monkeypatch):
    import app.services.ai_analysis as analysis_mod
    from app.db.models import Incident
    admin_token, body, h, inc = _incident_with_chain(client, org_a)
    incident = db.query(Incident).filter(Incident.id == inc["id"]).first()
    from app.services.ai_context import build_incident_context
    det_id = build_incident_context(
        db, incident)["detections"][0]["id"]
    script = _good_script(det_id=det_id)
    script["recommendations"][0]["action"] = "FORMAT_C_DRIVE"
    monkeypatch.setattr(analysis_mod, "default_provider",
                        lambda: MockProvider(script=script))
    out = client.post(f"/v1/incidents/{inc['id']}/ai-analysis",
                      headers=h).json()
    assert out["status"] == "VALIDATION_FAILED"
    assert "FORMAT_C_DRIVE" in out["error_message"]


def test_cross_org_reference_rejected(db, org_a, org_b):
    from app.db.models import Incident
    from app.services.ai_analysis import validate_analysis
    incident = db.query(Incident).filter(
        Incident.org_id == org_a["org"].id).first()
    # No incident in org_a DB slice? Build minimal via fixtures is heavy;
    # validate reference logic directly with a stub incident row.
    if incident is None:
        from app.db.models import Endpoint
        ep = Endpoint(org_id=org_a["org"].id, agent_id="agent-x9", name="X")
        db.add(ep)
        db.flush()
        incident = Incident(org_id=org_a["org"].id, incident_key="INC-T",
                            title="t", severity="low", risk_score=1,
                            endpoint_id=ep.id)
        db.add(incident)
        db.flush()
    other_det = db.query(
        __import__("app.db.models", fromlist=["Detection"]).Detection).filter(
        __import__("app.db.models", fromlist=["Detection"]).Detection.org_id
        == org_b["org"].id).first()
    script = _good_script(det_id=1)
    if other_det is not None:
        script["observed_facts"][0]["references"] = [f"DET-{other_det.id}"]
        canonical, problems = validate_analysis(
            db, org_a["org"].id, incident, script)
        assert canonical is None
        assert any("invalid reference" in p for p in problems)


def test_rate_limits(client, org_a, db, monkeypatch):
    from app.core.config import settings
    import app.services.ai_analysis as analysis_mod
    admin_token, body, h, inc = _incident_with_chain(client, org_a)
    dets = client.get(f"/v1/incidents/{inc['id']}", headers=h).json()
    script = _good_script(
        det_id=dets["correlation"]["detections"][0]["id"])
    monkeypatch.setattr(analysis_mod, "default_provider",
                        lambda: MockProvider(script=script))
    old_min, old_max = settings.AI_MIN_REFRESH_SECONDS, \
        settings.AI_MAX_ANALYSES_PER_INCIDENT
    settings.AI_MIN_REFRESH_SECONDS = 3600
    settings.AI_MAX_ANALYSES_PER_INCIDENT = 5
    try:
        assert client.post(f"/v1/incidents/{inc['id']}/ai-analysis",
                           headers=h).json()["status"] == "SUCCEEDED"
        second = client.post(f"/v1/incidents/{inc['id']}/ai-analysis",
                             headers=h).json()
        assert second["status"] == "FAILED"
        assert second["error_code"] == "REFRESH_TOO_SOON"
    finally:
        settings.AI_MIN_REFRESH_SECONDS = old_min
        settings.AI_MAX_ANALYSES_PER_INCIDENT = old_max


def test_no_secrets_in_analysis_or_audit(client, org_a, db, monkeypatch):
    import app.services.ai_analysis as analysis_mod
    from app.db.models import AuditLog
    admin_token, body, h, inc = _incident_with_chain(client, org_a)
    dets = client.get(f"/v1/incidents/{inc['id']}", headers=h).json()
    script = _good_script(
        det_id=dets["correlation"]["detections"][0]["id"])
    mock = MockProvider(script=script)
    monkeypatch.setattr(analysis_mod, "default_provider", lambda: mock)
    # Provider saw bounded context; nothing secret in audit rows.
    client.post(f"/v1/incidents/{inc['id']}/ai-analysis", headers=h)
    for audit in db.query(AuditLog).filter(
            AuditLog.action.like("ai.%")).all():
        blob = json.dumps(audit.meta_data or {})
        assert "wlk_" not in blob and "API_KEY" not in blob
        assert "password" not in blob.lower()
    sent = mock.calls[0]["user"]
    assert "wlk_" not in sent and "password_hash" not in sent
    assert len(sent.encode()) <= 12000

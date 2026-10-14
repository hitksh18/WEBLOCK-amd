"""AI analysis orchestration: prompt -> provider -> strict validate ->
reference-check -> versioned persist. No response execution path exists here
by construction (recommendations are data rows, never dispatched).
"""
import hashlib
import json
import logging
import re
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import (
    AIAnalysis,
    AuditLog,
    CorrelationCluster,
    Detection,
    Evidence,
    Incident,
    ResponseAction,
    SecurityEvent,
    TelemetryEvent,
)
from app.services.ai_context import (
    SYSTEM_PROMPT,
    USER_PROMPT_TEMPLATE,
    build_incident_context,
)
from app.services.ai_providers import (
    AIProvider,
    OUTPUT_VERSION,
    PROMPT_VERSION,
    default_provider,
)
logger = logging.getLogger("weblock.ai_analysis")

ALLOWED_ACTIONS = ("ISOLATE_ENDPOINT", "TERMINATE_PROCESS",
                   "BLOCK_NETWORK_DESTINATION", "COLLECT_EVIDENCE",
                   "RESTORE_ISOLATION", "DISABLE_SESSION")
ALLOWED_CONFIDENCE = ("LOW", "MEDIUM", "HIGH")
MAX_OUTPUT_BYTES = 8000  # hard cap; settings.AI_MAX_OUTPUT_BYTES enforced too
REF_RE = re.compile(r"^(INC|DET|EVT|EVD|CORR|RESP)-(.+)$")


def _audit(db: Session, *, org_id: int, actor_id: int | None, action: str,
           incident: Incident, analysis_id: int | None = None,
           extra: dict | None = None) -> None:
    meta = {"incident_id": incident.id,
            "incident_key": incident.incident_key}
    if analysis_id is not None:
        meta["analysis_id"] = analysis_id
    if extra:
        meta.update(extra)
    db.add(AuditLog(org_id=org_id, actor_id=actor_id, action=action,
                    target=f"ai-analysis:{analysis_id}" if analysis_id
                    else f"incident:{incident.incident_key}",
                    meta_data=meta))


def _check_references(db: Session, org_id: int, incident: Incident,
                      refs: list) -> tuple[list[str], list[str]]:
    """Return (valid, invalid). Every ID must exist in-org. No exceptions."""
    valid, invalid = [], []
    if not isinstance(refs, list):
        return [], ["<non-list references>"]
    seen = set()
    for ref in refs:
        if not isinstance(ref, str) or ref in seen:
            if isinstance(ref, str):
                seen.add(ref)
            continue
        seen.add(ref)
        match = REF_RE.match(ref.strip())
        if not match:
            invalid.append(ref)
            continue
        kind, ident = match.groups()
        try:
            if kind == "INC":
                ok = db.query(Incident).filter(
                    Incident.id == int(ident),
                    Incident.org_id == org_id).first() is not None
            elif kind == "DET":
                ok = db.query(Detection).filter(
                    Detection.id == int(ident),
                    Detection.org_id == org_id).first() is not None
            elif kind == "EVT":
                ok = db.query(SecurityEvent).filter(
                    (SecurityEvent.event_id == ident)
                    | (SecurityEvent.id == int(ident)
                       if ident.isdigit() else False),
                    SecurityEvent.org_id == org_id).first() is not None
            elif kind == "EVD":
                ok = db.query(Evidence).filter(
                    Evidence.id == int(ident),
                    Evidence.org_id == org_id).first() is not None
            elif kind == "CORR":
                ok = db.query(CorrelationCluster).filter(
                    CorrelationCluster.id == int(ident),
                    CorrelationCluster.org_id == org_id).first() is not None
            elif kind == "RESP":
                ok = db.query(ResponseAction).filter(
                    ResponseAction.id == int(ident),
                    ResponseAction.org_id == org_id).first() is not None
            else:
                ok = False
        except (ValueError, TypeError):
            ok = False
        (valid if ok else invalid).append(ref)
    return valid, invalid


def _sanitize_text(value: str, limit: int = 2000) -> str:
    # AI output is untrusted: strip HTML tags, cap length, no raw markup stored.
    text = re.sub(r"<[^>]*>", "", value if isinstance(value, str) else "")
    return text[:limit]


def validate_analysis(db: Session, org_id: int, incident: Incident,
                      payload: dict) -> tuple[dict | None, list[str]]:
    """Strict-validate provider output. Returns (canonical, problems)."""
    problems: list[str] = []
    if not isinstance(payload, dict):
        return None, ["output is not a JSON object"]
    required = ("assessment", "confidence", "observed_facts", "inferences",
                "recommendations", "unknowns")
    for key in required:
        if key not in payload:
            problems.append(f"missing required field: {key}")
    if problems:
        return None, problems

    confidence = payload.get("confidence")
    if isinstance(confidence, dict):
        level = confidence.get("level", "")
        confidence_reason = _sanitize_text(confidence.get("reason", ""), 500)
    elif isinstance(confidence, str):
        level, confidence_reason = confidence, ""
    else:
        level, confidence_reason = "", ""
    if level not in ALLOWED_CONFIDENCE:
        problems.append("confidence must be LOW/MEDIUM/HIGH")

    def entries(key: str, kinds: tuple[str, ...]) -> list[dict]:
        items = payload.get(key)
        if not isinstance(items, list):
            problems.append(f"{key} must be a list")
            return []
        out = []
        for item in items[:50]:
            if not isinstance(item, dict):
                problems.append(f"{key} item must be an object")
                continue
            entry = {"statement": _sanitize_text(item.get("statement", ""))}
            if "references" in kinds:
                refs = item.get("references", [])
                valid, invalid = _check_references(db, org_id, incident, refs)
                entry["references"] = valid
                for bad in invalid:
                    problems.append(f"invalid reference in {key}: {bad}")
            if "confidence" in kinds:
                if item.get("confidence") not in ALLOWED_CONFIDENCE:
                    problems.append(f"bad confidence in {key}")
                entry["confidence"] = item.get("confidence")
            if "action" in kinds:
                if item.get("action") not in ALLOWED_ACTIONS:
                    problems.append(
                        f"unsupported recommended action: {item.get('action')}")
                entry["action"] = item.get("action")
                entry["reason"] = _sanitize_text(item.get("reason", ""), 1000)
                entry["urgency"] = item.get("urgency") \
                    if item.get("urgency") in ALLOWED_CONFIDENCE else "MEDIUM"
                entry["requires_human_approval"] = True
            if "why_unknown" in kinds:
                entry["why_unknown"] = _sanitize_text(
                    item.get("why_unknown", ""), 500)
            out.append(entry)
        return out

    observed = entries("observed_facts", ("references",))
    inferences = entries("inferences", ("references", "confidence"))
    recommendations = entries("recommendations", ("references", "action"))
    unknowns = entries("unknowns", ("why_unknown",))

    mitre = []
    for item in payload.get("mitre_assessment", [])[:20]:
        if not isinstance(item, dict):
            continue
        technique = str(item.get("technique", ""))[:32]
        if not re.match(r"^T\d{4}(\.\d{3})?$", technique):
            problems.append(f"bad technique id: {technique}")
            continue
        mitre.append({"technique": technique,
                      "observed": bool(item.get("observed", False)),
                      "reason": _sanitize_text(item.get("reason", ""), 500)})
    limitations = [_sanitize_text(x, 500) for x in
                   payload.get("limitations", [])[:20]
                   if isinstance(x, str)]

    if problems:
        return None, problems
    return {
        "assessment": _sanitize_text(payload.get("assessment", "")),
        "confidence": level, "confidence_reason": confidence_reason,
        "observed_facts": observed, "inferences": inferences,
        "recommendations": recommendations, "unknowns": unknowns,
        "mitre_assessment": mitre, "limitations": limitations,
        "output_version": OUTPUT_VERSION,
    }, []


def _limits_ok(db: Session, incident: Incident,
               exclude_id: int | None = None) -> tuple[bool, str]:
    from app.db.models import AIAnalysis as AIModel
    q = db.query(AIModel).filter(AIModel.incident_id == incident.id)
    if exclude_id is not None:
        q = q.filter(AIModel.id != exclude_id)
    if q.count() >= settings.AI_MAX_ANALYSES_PER_INCIDENT:
        return False, "ANALYSIS_QUOTA_EXCEEDED"
    latest = q.order_by(AIModel.id.desc()).first()
    if latest is not None and latest.created_at is not None:
        from app.core.timeutil import as_utc
        age = (datetime.now(timezone.utc) - as_utc(latest.created_at)
               ).total_seconds()
        if age < settings.AI_MIN_REFRESH_SECONDS:
            return False, "REFRESH_TOO_SOON"
    return True, ""


def request_analysis(db: Session, *, incident: Incident, user,
                     provider: AIProvider | None = None) -> AIAnalysis:
    """Create versioned analysis row through the full pipeline. Commits."""
    org_id = incident.org_id
    version = db.query(AIAnalysis).filter(
        AIAnalysis.incident_id == incident.id).count() + 1
    row = AIAnalysis(org_id=org_id, incident_id=incident.id,
                     version=version, status="REQUESTED",
                     created_by=user.id if user else None,
                     prompt_version=PROMPT_VERSION,
                     output_version=OUTPUT_VERSION)
    db.add(row)
    db.flush()
    _audit(db, org_id=org_id, actor_id=user.id if user else None,
           action="ai.requested", incident=incident, analysis_id=row.id,
           extra={"version": version})
    db.commit()

    ok, reason = _limits_ok(db, incident, exclude_id=row.id)
    if not ok:
        row.status = "FAILED"
        row.error_code = reason
        row.validation_status = "NOT_RUN"
        _audit(db, org_id=org_id, actor_id=user.id if user else None,
               action="ai.failed", incident=incident, analysis_id=row.id,
               extra={"error": reason})
        db.commit()
        return row

    prov = provider or default_provider()
    available, why = prov.available()
    if not available:
        row.status = "AI_UNAVAILABLE"
        row.provider = getattr(prov, "name", "?")
        row.error_code = "AI_UNAVAILABLE"
        row.error_message = why[:1000]
        row.validation_status = "NOT_RUN"
        _audit(db, org_id=org_id, actor_id=user.id if user else None,
               action="ai.unavailable", incident=incident, analysis_id=row.id,
               extra={"reason": why[:200]})
        db.commit()
        return row

    row.status = "RUNNING"
    row.provider = prov.name
    row.model = getattr(prov, "model", "")
    db.commit()
    try:
        context = build_incident_context(
            db, incident, max_input_bytes=settings.AI_MAX_INPUT_BYTES)
    except ValueError as exc:
        row.status = "FAILED"
        row.error_code = "CONTEXT_TOO_LARGE"
        row.error_message = str(exc)[:1000]
        db.commit()
        return row
    row.context_hash = context["context_hash"]
    user_prompt = USER_PROMPT_TEMPLATE.format(
        context_json=json.dumps(context, default=str)[:settings.AI_MAX_INPUT_BYTES],
        incident_key=incident.incident_key)
    result = prov.analyze(system=SYSTEM_PROMPT,
                          user=user_prompt,
                          timeout_seconds=settings.AI_TIMEOUT_SECONDS)

    if not result.ok:
        row.status = "FAILED"
        row.error_code = result.error_code or "PROVIDER_ERROR"
        row.error_message = result.error_message[:1000]
        _audit(db, org_id=org_id, actor_id=user.id if user else None,
               action="ai.failed", incident=incident, analysis_id=row.id,
               extra={"error": row.error_code})
        db.commit()
        return row
    if len(result.text.encode()) > settings.AI_MAX_OUTPUT_BYTES:
        row.status = "FAILED"
        row.error_code = "OUTPUT_TOO_LARGE"
        _audit(db, org_id=org_id, actor_id=user.id if user else None,
               action="ai.failed", incident=incident, analysis_id=row.id,
               extra={"error": "OUTPUT_TOO_LARGE"})
        db.commit()
        return row
    try:
        payload = json.loads(result.text)
    except ValueError:
        row.status = "FAILED"
        row.error_code = "MALFORMED_OUTPUT"
        _audit(db, org_id=org_id, actor_id=user.id if user else None,
               action="ai.failed", incident=incident, analysis_id=row.id,
               extra={"error": "MALFORMED_OUTPUT"})
        db.commit()
        return row

    canonical, problems = validate_analysis(db, org_id, incident, payload)
    if canonical is None:
        row.status = "VALIDATION_FAILED"
        row.validation_status = "INVALID"
        row.error_code = "VALIDATION_FAILED"
        row.error_message = "; ".join(problems)[:1000]
        _audit(db, org_id=org_id, actor_id=user.id if user else None,
               action="ai.validation_failed", incident=incident,
               analysis_id=row.id, extra={"problems": problems[:10]})
        db.commit()
        return row

    row.analysis = canonical
    row.status = "SUCCEEDED"
    row.validation_status = "VALID"
    row.completed_at = datetime.now(timezone.utc)
    _audit(db, org_id=org_id, actor_id=user.id if user else None,
           action="ai.completed", incident=incident, analysis_id=row.id,
           extra={"provider": row.provider, "model": row.model})
    db.commit()
    return row

"""Incident endpoints (analyst/investigator/admin; viewer read-only).

Two incident origins share one table:
- Phase 0 login-incidents (user_id/event_id set, correlation_id NULL).
- Phase 6 correlation-incidents (correlation_id set, enriched detail).
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user, require_role
from app.db.database import get_db
from app.db.models import (
    CorrelationCluster,
    CorrelationMember,
    Detection,
    Evidence,
    Incident,
    LoginEvent,
    RiskAssessment,
    RiskSnapshot,
    SecurityEvent,
    User,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])

MAX_LIMIT = 200


@router.get("")
def list_incidents(status: str | None = None,
                   severity: str | None = None,
                   endpoint_id: int | None = None,
                   limit: int = Query(default=100, ge=1, le=MAX_LIMIT),
                   offset: int = Query(default=0, ge=0),
                   db: Session = Depends(get_db),
                   current_user: User = Depends(get_current_user)):
    # NOTE: bare-array shape is the Phase 0 contract (kept for compatibility).
    q = db.query(Incident).filter(Incident.org_id == current_user.org_id)
    if status:
        q = q.filter(Incident.status == status)
    if severity:
        q = q.filter(Incident.severity == severity)
    if endpoint_id is not None:
        q = q.filter(Incident.endpoint_id == endpoint_id)
    rows = q.order_by(Incident.id.desc()).offset(offset).limit(limit).all()
    return [
        {"id": r.id, "incident_key": r.incident_key, "title": r.title,
         "severity": r.severity, "risk_score": r.risk_score, "status": r.status,
         "user_id": r.user_id, "endpoint_id": r.endpoint_id,
         "correlation_id": r.correlation_id,
         "created_at": r.created_at.isoformat() if r.created_at else None}
        for r in rows
    ]


def _correlation_block(db: Session, inc: Incident) -> dict | None:
    if inc.correlation_id is None:
        return None
    cluster = db.query(CorrelationCluster).filter(
        CorrelationCluster.id == inc.correlation_id).first()
    if cluster is None:
        return {"id": inc.correlation_id, "missing": True}
    member_ids = [m.detection_id for m in
                  db.query(CorrelationMember)
                  .filter(CorrelationMember.cluster_id == cluster.id).all()]
    dets = db.query(Detection).filter(Detection.id.in_(member_ids)).all() \
        if member_ids else []
    out_dets = []
    for det in sorted(dets, key=lambda d: d.id):
        sec = db.query(SecurityEvent).filter(
            SecurityEvent.id == det.primary_event_id).first()
        out_dets.append({
            "id": det.id, "rule_id": det.rule_id, "severity": det.severity,
            "confidence": det.confidence, "status": det.status,
            "title": det.title, "explanation": det.explanation,
            "mitre": (det.meta_data or {}).get("mitre", []),
            "occurred_at": sec.occurred_at.isoformat()
            if sec and sec.occurred_at else None,
            "event_id": sec.event_id if sec else None,
            "security_event_id": sec.id if sec else None,
            "actor": sec.actor if sec else "",
        })
    return {
        "id": cluster.id, "status": cluster.status,
        "severity": cluster.severity, "confidence": cluster.confidence,
        "families": cluster.families,
        "first_seen": cluster.first_seen.isoformat() if cluster.first_seen else None,
        "last_seen": cluster.last_seen.isoformat() if cluster.last_seen else None,
        "explanation": cluster.explanation,
        "detections": out_dets,
    }


def _risk_block(db: Session, inc: Incident) -> dict | None:
    snap = None
    if inc.risk_snapshot_id is not None:
        snap = db.query(RiskSnapshot).filter(
            RiskSnapshot.id == inc.risk_snapshot_id).first()
    if snap is None and inc.endpoint_id is not None:
        snap = (
            db.query(RiskSnapshot)
            .filter(RiskSnapshot.org_id == inc.org_id,
                    RiskSnapshot.endpoint_id == inc.endpoint_id)
            .order_by(RiskSnapshot.id.desc())
            .first()
        )
    if snap is None:
        return None
    return {"id": snap.id, "score": snap.score, "severity": snap.severity,
            "factors": snap.factors,
            "created_at": snap.created_at.isoformat() if snap.created_at else None}


@router.get("/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db),
                 current_user: User = Depends(get_current_user)):
    inc = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.org_id == current_user.org_id)
        .first()
    )
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    evidence = (
        db.query(Evidence).filter(Evidence.incident_id == inc.id).all()
    )
    event = db.query(LoginEvent).filter(LoginEvent.id == inc.event_id).first() if inc.event_id else None
    assessment = (
        db.query(RiskAssessment).filter(RiskAssessment.event_id == inc.event_id).first()
        if inc.event_id else None
    )
    return {
        "id": inc.id, "incident_key": inc.incident_key, "title": inc.title,
        "severity": inc.severity, "risk_score": inc.risk_score, "status": inc.status,
        "user_id": inc.user_id, "endpoint_id": inc.endpoint_id,
        "correlation_id": inc.correlation_id, "summary": inc.summary,
        "event": {"id": event.id, "ip_address": event.ip_address,
                  "classification": event.classification} if event else None,
        "assessment": {"explanation": assessment.explanation,
                       "factors": (assessment.factors or {}).get("factors", [])} if assessment else None,
        "evidence": [{"id": e.id, "sha256": e.sha256, "source": e.source,
                      "collected_at": e.collected_at.isoformat() if e.collected_at else None} for e in evidence],
        "correlation": _correlation_block(db, inc),
        "risk": _risk_block(db, inc),
    }


@router.post("/{incident_id}/status")
def set_status(incident_id: int, payload: dict, db: Session = Depends(get_db),
               current_user: User = Depends(
                   require_role("admin", "analyst", "investigator"))):
    allowed = {"open", "investigating", "contained", "resolved", "closed"}
    new_status = (payload.get("status") or "").lower()
    if new_status not in allowed:
        raise HTTPException(status_code=422, detail="Invalid status")
    inc = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.org_id == current_user.org_id)
        .first()
    )
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    from app.db.models import AuditLog
    inc.status = new_status
    db.add(AuditLog(org_id=current_user.org_id, actor_id=current_user.id,
                    action="incident.status_changed", target=inc.incident_key,
                    meta_data={"status": new_status}))
    db.commit()
    return {"id": inc.id, "status": inc.status}

"""Incident read endpoints (analyst/investigator/admin; viewer read-only)."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user, require_role
from app.db.database import get_db
from app.db.models import Evidence, Incident, LoginEvent, RiskAssessment, User

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("")
def list_incidents(status: str | None = None, db: Session = Depends(get_db),
                   current_user: User = Depends(get_current_user)):
    q = db.query(Incident).filter(Incident.org_id == current_user.org_id)
    if status:
        q = q.filter(Incident.status == status)
    rows = q.order_by(Incident.id.desc()).limit(100).all()
    return [
        {"id": r.id, "incident_key": r.incident_key, "title": r.title,
         "severity": r.severity, "risk_score": r.risk_score, "status": r.status,
         "user_id": r.user_id, "created_at": r.created_at.isoformat() if r.created_at else None}
        for r in rows
    ]


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
        "user_id": inc.user_id, "summary": inc.summary,
        "event": {"id": event.id, "ip_address": event.ip_address,
                  "classification": event.classification} if event else None,
        "assessment": {"explanation": assessment.explanation,
                       "factors": (assessment.factors or {}).get("factors", [])} if assessment else None,
        "evidence": [{"id": e.id, "sha256": e.sha256, "source": e.source,
                      "collected_at": e.collected_at.isoformat() if e.collected_at else None} for e in evidence],
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

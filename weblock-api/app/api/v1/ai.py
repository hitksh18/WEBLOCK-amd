"""Phase 9 AI analyst APIs (org-scoped).

- POST /v1/incidents/{id}/ai-analysis  (admin/analyst/investigator)
- GET  /v1/incidents/{id}/ai-analyses  (any role, read-only)
- GET  /v1/ai-analyses/{id}            (any role)
- POST /v1/ai-analyses/{id}/refresh    (admin/analyst/investigator)
- GET  /v1/incidents/{id}/ai-context   (any role; no secrets, bounded)

No endpoint here can execute response actions — recommendations are data.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.dependencies import get_current_user, require_role
from app.db.database import get_db
from app.db.models import AIAnalysis, Incident, User
from app.services.ai_context import build_incident_context

router = APIRouter(tags=["ai"])
MAX_LIMIT = 200
ai_write = require_role("admin", "analyst", "investigator")


def _incident_or_404(db: Session, org_id: int, incident_id: int) -> Incident:
    incident = db.query(Incident).filter(
        Incident.id == incident_id, Incident.org_id == org_id).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


def _analysis_out(row: AIAnalysis) -> dict:
    return {
        "id": row.id, "incident_id": row.incident_id, "version": row.version,
        "provider": row.provider, "model": row.model,
        "prompt_version": row.prompt_version,
        "output_version": row.output_version,
        "context_hash": row.context_hash, "status": row.status,
        "validation_status": row.validation_status,
        "error_code": row.error_code, "error_message": row.error_message,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "completed_at": row.completed_at.isoformat()
        if row.completed_at else None,
        "analysis": row.analysis,
    }


@router.post("/incidents/{incident_id}/ai-analysis")
def create_analysis(
    incident_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(ai_write),
):
    from app.services.ai_analysis import request_analysis
    incident = _incident_or_404(db, current_user.org_id, incident_id)
    row = request_analysis(db, incident=incident, user=current_user)
    return _analysis_out(row)


@router.get("/incidents/{incident_id}/ai-analyses")
def list_analyses(
    incident_id: int,
    limit: int = Query(default=20, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _incident_or_404(db, current_user.org_id, incident_id)
    q = db.query(AIAnalysis).filter(
        AIAnalysis.org_id == current_user.org_id,
        AIAnalysis.incident_id == incident_id)
    total = q.count()
    rows = q.order_by(AIAnalysis.version.desc()).offset(offset).limit(limit).all()
    return {"total": total, "analyses": [_analysis_out(r) for r in rows]}


@router.get("/ai-analyses/{analysis_id}")
def get_analysis(
    analysis_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    row = db.query(AIAnalysis).filter(
        AIAnalysis.id == analysis_id,
        AIAnalysis.org_id == current_user.org_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return _analysis_out(row)


@router.post("/ai-analyses/{analysis_id}/refresh")
def refresh_analysis(
    analysis_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(ai_write),
):
    from app.services.ai_analysis import request_analysis
    row = db.query(AIAnalysis).filter(
        AIAnalysis.id == analysis_id,
        AIAnalysis.org_id == current_user.org_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    incident = _incident_or_404(db, current_user.org_id, row.incident_id)
    new_row = request_analysis(db, incident=incident, user=current_user)
    return _analysis_out(new_row)


@router.get("/incidents/{incident_id}/ai-context")
def ai_context_preview(
    incident_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    incident = _incident_or_404(db, current_user.org_id, incident_id)
    try:
        context = build_incident_context(
            db, incident, max_input_bytes=settings.AI_MAX_INPUT_BYTES)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return context

"""Contextual risk APIs (org-scoped, read-only + history).

- GET /v1/endpoints/{id}/risk[?force_snapshot=true]
- GET /v1/endpoints/{id}/risk/history
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import Endpoint, RiskSnapshot, User
from app.services.risk import snapshot_endpoint_risk

router = APIRouter(tags=["risk"])

MAX_LIMIT = 200


def _result_out(result, written: bool) -> dict:
    return {
        "score": result.score,
        "severity": result.severity,
        "factors": result.factors,
        "explanation": result.explanation,
        "inputs": result.inputs,
        "snapshot_written": written,
    }


@router.get("/endpoints/{endpoint_id}/risk")
def endpoint_risk(
    endpoint_id: int,
    force_snapshot: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    endpoint = (
        db.query(Endpoint)
        .filter(Endpoint.id == endpoint_id,
                Endpoint.org_id == current_user.org_id)
        .first()
    )
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    result, written = snapshot_endpoint_risk(
        db, org_id=current_user.org_id, endpoint_id=endpoint_id,
        lookback_hours=settings.RISK_LOOKBACK_HOURS, force=force_snapshot)
    return {"endpoint_id": endpoint_id, **_result_out(result, written)}


@router.get("/endpoints/{endpoint_id}/risk/history")
def risk_history(
    endpoint_id: int,
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    endpoint = (
        db.query(Endpoint)
        .filter(Endpoint.id == endpoint_id,
                Endpoint.org_id == current_user.org_id)
        .first()
    )
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    q = (
        db.query(RiskSnapshot)
        .filter(RiskSnapshot.org_id == current_user.org_id,
                RiskSnapshot.endpoint_id == endpoint_id)
        .order_by(RiskSnapshot.id.desc())
    )
    total = q.count()
    rows = q.offset(offset).limit(limit).all()
    return {"endpoint_id": endpoint_id, "total": total, "snapshots": [
        {"id": s.id, "score": s.score, "severity": s.severity,
         "factors": s.factors, "inputs": s.inputs,
         "created_at": s.created_at.isoformat() if s.created_at else None}
        for s in rows]}

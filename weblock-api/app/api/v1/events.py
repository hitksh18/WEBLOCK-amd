"""Event query + endpoint timeline + detection listing (org-scoped).

Powers future Threats / Investigate / Forensics / AI views. Every query is
filtered by the caller's org_id; pagination is capped.
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import Detection, Endpoint, SecurityEvent, User

router = APIRouter(tags=["events"])

MAX_LIMIT = 200


def _event_out(e: SecurityEvent) -> dict:
    return {
        "id": e.id,
        "event_id": e.event_id,
        "endpoint_id": e.endpoint_id,
        "category": e.category,
        "subtype": e.subtype,
        "severity_hint": e.severity_hint,
        "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None,
        "received_at": e.received_at.isoformat() if e.received_at else None,
        "processed_at": e.processed_at.isoformat() if e.processed_at else None,
        "actor": e.actor,
        "host": e.host,
        "proc_name": e.proc_name,
        "remote_addr": e.remote_addr,
        "status": e.status,
        "telemetry_ref": e.telemetry_ref,
    }


def _apply_filters(q, model, *, endpoint_id=None, category=None,
                   event_type=None, severity=None, actor=None,
                   since=None, until=None, search=None):
    if endpoint_id is not None:
        q = q.filter(model.endpoint_id == endpoint_id)
    if category is not None:
        q = q.filter(model.category == category)
    if event_type is not None:
        q = q.filter(model.subtype == event_type)
    if severity is not None:
        q = q.filter(model.severity_hint == severity)
    if actor is not None:
        q = q.filter(model.actor.ilike(f"%{actor}%"))
    if since is not None:
        q = q.filter(model.occurred_at >= since)
    if until is not None:
        q = q.filter(model.occurred_at <= until)
    if search is not None:
        like = f"%{search}%"
        q = q.filter((model.proc_name.ilike(like))
                     | (model.remote_addr.ilike(like))
                     | (model.actor.ilike(like)))
    return q


@router.get("/events")
def query_events(
    endpoint_id: int | None = None,
    category: str | None = None,
    event_type: str | None = None,
    severity: str | None = None,
    actor: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    search: str | None = Query(default=None, max_length=128),
    order: str = "desc",
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = db.query(SecurityEvent).filter(SecurityEvent.org_id == current_user.org_id)
    q = _apply_filters(q, SecurityEvent, endpoint_id=endpoint_id, category=category,
                       event_type=event_type, severity=severity, actor=actor,
                       since=since, until=until, search=search)
    total = q.count()
    q = q.order_by(SecurityEvent.occurred_at.asc() if order == "asc"
                   else SecurityEvent.occurred_at.desc())
    rows = q.offset(offset).limit(limit).all()
    return {"total": total, "limit": limit, "offset": offset,
            "events": [_event_out(e) for e in rows]}


@router.get("/endpoints/{endpoint_id}/events")
def endpoint_timeline(
    endpoint_id: int,
    category: str | None = None,
    event_type: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    order: str = "asc",
    limit: int = Query(default=100, ge=1, le=MAX_LIMIT),
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
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    q = db.query(SecurityEvent).filter(
        SecurityEvent.org_id == current_user.org_id,
        SecurityEvent.endpoint_id == endpoint_id)
    q = _apply_filters(q, SecurityEvent, category=category, event_type=event_type,
                       since=since, until=until)
    total = q.count()
    q = q.order_by(SecurityEvent.occurred_at.asc() if order == "asc"
                   else SecurityEvent.occurred_at.desc())
    rows = q.offset(offset).limit(limit).all()
    return {"endpoint_id": endpoint_id, "agent_id": endpoint.agent_id,
            "total": total, "events": [_event_out(e) for e in rows]}


@router.get("/detections")
def list_detections(
    endpoint_id: int | None = None,
    rule_id: str | None = None,
    status: str | None = None,
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = db.query(Detection).filter(Detection.org_id == current_user.org_id)
    if endpoint_id is not None:
        q = q.filter(Detection.endpoint_id == endpoint_id)
    if rule_id is not None:
        q = q.filter(Detection.rule_id == rule_id)
    if status is not None:
        q = q.filter(Detection.status == status)
    total = q.count()
    rows = q.order_by(Detection.id.desc()).offset(offset).limit(limit).all()
    return {"total": total, "detections": [
        {"id": d.id, "rule_id": d.rule_id, "rule_version": d.rule_version,
         "severity": d.severity, "confidence": d.confidence, "status": d.status,
         "title": d.title, "explanation": d.explanation,
         "endpoint_id": d.endpoint_id, "primary_event_id": d.primary_event_id,
         "related_event_ids": d.related_event_ids,
         "detected_at": d.detected_at.isoformat() if d.detected_at else None}
        for d in rows]}

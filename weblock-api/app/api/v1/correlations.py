"""Correlation APIs (org-scoped).

- GET /v1/correlations (endpoint/severity/status/family/time filters)
- GET /v1/correlations/{id} (metadata + ordered timeline + references)
- POST /v1/correlations/{id}/close (analyst+; audited)
- POST /v1/admin/correlations/expire (admin; marks stale open clusters expired)
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user, require_role
from app.db.database import get_db
from app.db.models import (
    CorrelationCluster,
    CorrelationMember,
    Detection,
    SecurityEvent,
    User,
)

router = APIRouter(tags=["correlations"])

MAX_LIMIT = 200


def _cluster_out(cluster: CorrelationCluster) -> dict:
    return {
        "id": cluster.id,
        "correlation_key": cluster.correlation_key,
        "endpoint_id": cluster.endpoint_id,
        "status": cluster.status,
        "severity": cluster.severity,
        "confidence": cluster.confidence,
        "detection_count": cluster.detection_count,
        "distinct_family_count": cluster.distinct_family_count,
        "families": cluster.families,
        "primary_detection_id": cluster.primary_detection_id,
        "first_seen": cluster.first_seen.isoformat() if cluster.first_seen else None,
        "last_seen": cluster.last_seen.isoformat() if cluster.last_seen else None,
        "explanation": cluster.explanation,
    }


@router.get("/correlations")
def list_correlations(
    endpoint_id: int | None = None,
    severity: str | None = None,
    status: str | None = None,
    family: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = db.query(CorrelationCluster).filter(
        CorrelationCluster.org_id == current_user.org_id)
    if endpoint_id is not None:
        q = q.filter(CorrelationCluster.endpoint_id == endpoint_id)
    if severity is not None:
        q = q.filter(CorrelationCluster.severity == severity)
    if status is not None:
        q = q.filter(CorrelationCluster.status == status)
    if since is not None:
        q = q.filter(CorrelationCluster.last_seen >= since)
    if until is not None:
        q = q.filter(CorrelationCluster.first_seen <= until)
    if family is not None:
        # families is JSONB array; containment via ? operator.
        q = q.filter(CorrelationCluster.families.op("?")(family))
    total = q.count()
    rows = q.order_by(CorrelationCluster.last_seen.desc()
                      ).offset(offset).limit(limit).all()
    return {"total": total, "limit": limit, "offset": offset,
            "clusters": [_cluster_out(c) for c in rows]}


def _timeline(db: Session, cluster: CorrelationCluster) -> list[dict]:
    member_ids = [m.detection_id for m in
                  db.query(CorrelationMember)
                  .filter(CorrelationMember.cluster_id == cluster.id).all()]
    dets = db.query(Detection).filter(Detection.id.in_(member_ids)).all() \
        if member_ids else []
    entries = []
    for det in dets:
        sec = db.query(SecurityEvent).filter(
            SecurityEvent.id == det.primary_event_id).first()
        occurred = sec.occurred_at.isoformat() if sec and sec.occurred_at else None
        entries.append({
            "detected_at_order": occurred or det.detected_at.isoformat()
            if det.detected_at else "",
            "detection_id": det.id,
            "rule_id": det.rule_id,
            "severity": det.severity,
            "title": det.title,
            "occurred_at": occurred,
            "event_id": sec.event_id if sec else None,
            "security_event_id": sec.id if sec else None,
            "telemetry_ref": sec.telemetry_ref if sec else None,
            "actor": sec.actor if sec else "",
        })
    entries.sort(key=lambda e: e["detected_at_order"])
    return entries


@router.get("/correlations/{cluster_id}")
def get_correlation(cluster_id: int, db: Session = Depends(get_db),
                    current_user: User = Depends(get_current_user)):
    cluster = (
        db.query(CorrelationCluster)
        .filter(CorrelationCluster.id == cluster_id,
                CorrelationCluster.org_id == current_user.org_id)
        .first()
    )
    if cluster is None:
        raise HTTPException(status_code=404, detail="Cluster not found")
    return {**_cluster_out(cluster), "timeline": _timeline(db, cluster)}


@router.post("/correlations/{cluster_id}/close")
def close_correlation(
    cluster_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "analyst",
                                              "investigator")),
):
    from app.services.correlate import close_cluster
    try:
        cluster = close_cluster(db, org_id=current_user.org_id,
                                cluster_id=cluster_id,
                                actor_id=current_user.id)
    except LookupError:
        raise HTTPException(status_code=404, detail="Cluster not found")
    return {"id": cluster.id, "status": cluster.status}


@router.post("/correlations/{cluster_id}/incident")
def incident_from_correlation(
    cluster_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "analyst",
                                              "investigator")),
):
    """Analyst-judgment incident from any open cluster (thresholds bypassed,
    idempotent per cluster)."""
    from app.services.incidents import maybe_create_incident
    cluster = (
        db.query(CorrelationCluster)
        .filter(CorrelationCluster.id == cluster_id,
                CorrelationCluster.org_id == current_user.org_id)
        .first()
    )
    if cluster is None:
        raise HTTPException(status_code=404, detail="Cluster not found")
    incident = maybe_create_incident(db, cluster, manual=True,
                                     actor_id=current_user.id)
    db.commit()
    if incident is None:
        raise HTTPException(status_code=409,
                            detail="Cluster is not open for incidents")
    return {"id": incident.id, "incident_key": incident.incident_key,
            "status": incident.status}


@router.post("/admin/correlations/expire")
def expire_correlations(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    from app.core.config import settings
    from app.services.correlate import expire_stale
    count = expire_stale(db, org_id=current_user.org_id,
                         window=settings.CORRELATION_WINDOW_SECONDS,
                         actor_id=current_user.id)
    return {"expired": count}

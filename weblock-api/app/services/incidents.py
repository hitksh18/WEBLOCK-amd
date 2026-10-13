"""Phase 6 incident engine: clusters -> incidents.

Auto-trigger: an OPEN cluster with severity high/critical whose endpoint's
live contextual risk >= INCIDENT_MIN_RISK gets exactly one non-closed
incident (partial unique index + app-level check = idempotent, race-safe).
Analysts may also create manually from any open cluster (judgment call,
thresholds bypassed, still idempotent per cluster).

user_id stays NULL on cluster-incidents: no user<->endpoint binding exists
yet (documented Phase 4/5 limitation) — incidents cite endpoint + actor
strings from member detections instead of fabricating a user row.
"""
import logging
from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models import (
    AuditLog,
    CorrelationCluster,
    CorrelationMember,
    Detection,
    Endpoint,
    Incident,
    SecurityEvent,
)

logger = logging.getLogger("weblock.incidents")

AUTO_SEVERITIES = ("high", "critical")
CLOSED = "closed"


def next_incident_key(db: Session, org_id: int) -> str:
    year = datetime.now(timezone.utc).year
    count = db.query(Incident).filter(Incident.org_id == org_id).count() + 1
    return f"INC-{year}-{count:04d}"


def open_incident_for_cluster(db: Session, org_id: int,
                              cluster_id: int) -> Incident | None:
    return (
        db.query(Incident)
        .filter(Incident.org_id == org_id,
                Incident.correlation_id == cluster_id,
                Incident.status != CLOSED)
        .order_by(Incident.id.desc())
        .first()
    )


def _member_details(db: Session, cluster_id: int) -> tuple[list[Detection], str]:
    member_ids = [m.detection_id for m in
                  db.query(CorrelationMember)
                  .filter(CorrelationMember.cluster_id == cluster_id).all()]
    dets = db.query(Detection).filter(Detection.id.in_(member_ids)).all() \
        if member_ids else []
    actors = sorted({(db.query(SecurityEvent.actor).filter(
        SecurityEvent.id == d.primary_event_id).scalar() or "")
        for d in dets} - {""})
    return dets, ", ".join(actors)


def _render(host: str, cluster: CorrelationCluster, rules: list[str],
            actors: str, result) -> tuple[str, str]:
    title = (f"Correlated threat on {host}: {' + '.join(rules) if rules else 'suspicious behavior'} "
             f"[{cluster.severity.upper()}, risk {result.score}]")
    summary = (
        f"{cluster.explanation} "
        f"Endpoint contextual risk {result.score} ({result.severity.upper()}): "
        f"{result.explanation}"
    )
    if actors:
        summary += f" Observed actors: {actors}."
    return title, summary


def _refresh_from_cluster(db: Session, incident: Incident,
                          cluster: CorrelationCluster, result,
                          snapshot_id: int | None) -> None:
    endpoint = db.query(Endpoint).filter(
        Endpoint.id == cluster.endpoint_id).first()
    host = endpoint.hostname if endpoint and endpoint.hostname else \
        f"endpoint-{cluster.endpoint_id}"
    dets, actors = _member_details(db, cluster.id)
    rules = sorted({d.rule_id for d in dets})
    title, summary = _render(host, cluster, rules, actors, result)
    incident.title = title[:500]
    incident.summary = summary
    incident.severity = cluster.severity
    incident.risk_score = result.score
    incident.risk_snapshot_id = snapshot_id
    db.flush()


def maybe_create_incident(db: Session, cluster: CorrelationCluster,
                          *, manual: bool = False,
                          actor_id: int | None = None,
                          min_risk: int = 60) -> Incident | None:
    """Create (or return existing) incident for an open cluster."""
    if cluster.status != "open":
        return None
    existing = open_incident_for_cluster(db, cluster.org_id, cluster.id)

    from app.services.risk import snapshot_endpoint_risk
    result, snapshot_written = snapshot_endpoint_risk(
        db, org_id=cluster.org_id, endpoint_id=cluster.endpoint_id)
    # Latest snapshot row for the reference (the call above just wrote one
    # when the score changed; otherwise fetch the current latest).
    from app.db.models import RiskSnapshot
    snapshot = (
        db.query(RiskSnapshot)
        .filter(RiskSnapshot.org_id == cluster.org_id,
                RiskSnapshot.endpoint_id == cluster.endpoint_id)
        .order_by(RiskSnapshot.id.desc())
        .first()
    )
    _ = snapshot_written

    if existing is not None:
        # Cluster grew since creation: refresh title/summary/risk so the
        # incident tracks current evidence (silent sync; only creation and
        # status changes are audited).
        _refresh_from_cluster(db, existing, cluster, result,
                              snapshot.id if snapshot else None)
        return existing

    if not manual:
        if cluster.severity not in AUTO_SEVERITIES:
            return None
        if result.score < min_risk:
            return None

    endpoint = db.query(Endpoint).filter(
        Endpoint.id == cluster.endpoint_id).first()
    host = endpoint.hostname if endpoint and endpoint.hostname else \
        f"endpoint-{cluster.endpoint_id}"
    dets, actors = _member_details(db, cluster.id)
    rules = sorted({d.rule_id for d in dets})
    title, summary = _render(host, cluster, rules, actors, result)
    incident = Incident(
        org_id=cluster.org_id,
        incident_key=next_incident_key(db, cluster.org_id),
        title=title[:500],
        severity=cluster.severity,
        risk_score=result.score,
        status="open",
        endpoint_id=cluster.endpoint_id,
        user_id=None,
        summary=summary,
        correlation_id=cluster.id,
        risk_snapshot_id=snapshot.id if snapshot else None,
    )
    db.add(incident)
    try:
        # Savepoint: a lost race rolls back only this insert, never the
        # caller's batch transaction.
        with db.begin_nested():
            db.flush()
    except IntegrityError:
        winner = open_incident_for_cluster(db, cluster.org_id, cluster.id)
        logger.info("incident race lost for cluster %s; using %s",
                    cluster.id, winner.incident_key if winner else None)
        return winner
    db.add(AuditLog(org_id=cluster.org_id, actor_id=actor_id,
                    action="incident.created", target=incident.incident_key,
                    meta_data={"correlation_id": cluster.id,
                               "manual": manual,
                               "risk_score": result.score}))
    db.flush()
    logger.info("incident %s from cluster %s (manual=%s)",
                incident.incident_key, cluster.id, manual)
    return incident


def hook_after_correlation(db: Session, cluster: CorrelationCluster | None,
                           *, actor_id: int | None = None,
                           min_risk: int = 60) -> Incident | None:
    """Dispatch-hook entry: never raises into the detection pipeline."""
    if cluster is None:
        return None
    try:
        return maybe_create_incident(db, cluster, actor_id=actor_id,
                                     min_risk=min_risk)
    except Exception:
        logger.exception("incident hook failed for cluster %s", cluster.id)
        return None

"""Phase 4 correlation engine: related detections -> threat clusters.

Trigger: process_detection(db, detection) runs after each persisted detection
(hooked from dispatch, same transaction). No background queue yet.

Compatibility: a detection joins the newest OPEN cluster on the same
org+endpoint whose span overlaps the detection time within the window.
Otherwise, if >=1 other in-window detection with a DISTINCT rule family
exists, a new cluster is created containing the whole in-window set.
Isolated detections (no distinct-family partner) create nothing.

Score (0-100, deterministic, NOT ML):
    20 base
  + 15 per distinct family beyond the first (max +60, i.e. 4 extra families)
  + max-severity weight (info 0 / low 5 / medium 10 / high 15 / critical 20)
  + temporal proximity (span <= 10 min: +10; <= window: +5; else +0)
  + actor consistency (+5 when exactly one non-empty actor across members)
Severity (deterministic table):
    >=3 families and any HIGH+  -> CRITICAL
    any HIGH                    -> HIGH
    any MEDIUM                  -> MEDIUM
    else                        -> LOW
Wording rule: "observed sequence", never "attacker did X".
"""
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.timeutil import as_utc
from app.db.models import (
    AuditLog,
    CorrelationCluster,
    CorrelationMember,
    Detection,
    SecurityEvent,
)

logger = logging.getLogger("weblock.correlate")

RULE_FAMILY = {
    "AUTH-01": "AUTHENTICATION",
    "AUTH-02": "AUTHENTICATION",
    "DEV-01": "DEVICE",
    "PROC-01": "PROCESS",
    "PROC-02": "PROCESS",
    "NET-01": "NETWORK",
    "SYS-01": "SYSTEM",
    "USB-01": "USB",
    "TEST-MARKER": "TEST",
}

SEVERITY_WEIGHT = {"info": 0, "low": 5, "medium": 10, "high": 15, "critical": 20}
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

MIN_DETECTIONS = 2
MIN_FAMILIES = 2
MEMBER_CAP = 100


def family_of(detection: Detection) -> str:
    return RULE_FAMILY.get(detection.rule_id, "UNKNOWN")


def correlation_score(families: set[str], severities: list[str],
                      span_seconds: float, actors: set[str],
                      window: int) -> int:
    score = 20
    score += 15 * max(0, min(len(families) - 1, 4))
    score += max([SEVERITY_WEIGHT.get(s, 0) for s in severities] + [0])
    score += 10 if span_seconds <= 600 else (5 if span_seconds <= window else 0)
    if len(actors) == 1:
        score += 5
    return min(100, score)


def cluster_severity(families: set[str], severities: list[str]) -> str:
    rank = max([SEVERITY_RANK.get(s, 0) for s in severities] + [0])
    if len(families) >= 3 and rank >= SEVERITY_RANK["high"]:
        return "critical"
    if rank >= SEVERITY_RANK["high"]:
        return "high"
    if rank >= SEVERITY_RANK["medium"]:
        return "medium"
    return "low"


def build_explanation(endpoint_label: str, ordered: list[Detection],
                      families: set[str], span_seconds: float,
                      window: int) -> str:
    minutes = max(1, int(span_seconds // 60))
    seq = " -> ".join(f"{d.rule_id}" for d in ordered)
    fams = ", ".join(sorted(families)).lower()
    text = (f"{len(ordered)} detections from {len(families)} rule families "
            f"({fams}) were observed on endpoint '{endpoint_label}' within "
            f"{minutes} minute(s) (window {window // 60} min). "
            f"Observed sequence: {seq}.")
    fams_up = {f.upper() for f in families}
    if {"PROCESS", "NETWORK"} <= fams_up:
        text += (" Process activity and an external connection were observed "
                 "on the same endpoint within the window.")
    if {"AUTHENTICATION", "PROCESS"} <= fams_up:
        text += (" Authentication anomalies were followed by suspicious "
                 "process activity on the same endpoint.")
    return text


def _detection_time(db: Session, det: Detection) -> datetime:
    sec = db.query(SecurityEvent).filter(
        SecurityEvent.id == det.primary_event_id).first()
    if sec is not None and sec.occurred_at is not None:
        return as_utc(sec.occurred_at)
    detected = det.detected_at
    return as_utc(detected) if detected is not None else datetime.now(timezone.utc)


def _recompute(db: Session, cluster: CorrelationCluster,
               window: int, endpoint_label: str) -> None:
    member_ids = [m.detection_id for m in
                  db.query(CorrelationMember)
                  .filter(CorrelationMember.cluster_id == cluster.id)
                  .order_by(CorrelationMember.id).all()]
    dets = db.query(Detection).filter(Detection.id.in_(member_ids)).all()
    if not dets:
        return
    times = sorted(_detection_time(db, d) for d in dets)
    fams = {family_of(d) for d in dets}
    sevs = [d.severity for d in dets]
    actors = {a for a in
              {(db.query(SecurityEvent.actor).filter(
                  SecurityEvent.id == d.primary_event_id).scalar() or "")
               for d in dets} if a}
    span = (times[-1] - times[0]).total_seconds()
    ordered = sorted(dets, key=lambda d: _detection_time(db, d))
    cluster.first_seen = times[0]
    cluster.last_seen = times[-1]
    cluster.detection_count = len(dets)
    cluster.distinct_family_count = len(fams)
    cluster.families = sorted(fams)
    cluster.primary_detection_id = ordered[0].id
    cluster.confidence = correlation_score(fams, sevs, span, actors, window)
    cluster.severity = cluster_severity(fams, sevs)
    cluster.explanation = build_explanation(endpoint_label, ordered, fams,
                                            span, window)


def process_detection(db: Session, detection: Detection,
                      window: int = 1800) -> CorrelationCluster | None:
    """Correlate one persisted detection. Idempotent. Returns cluster or None."""
    det_time = _detection_time(db, detection)

    # 1. Already a member of an open cluster? No-op (idempotent replay).
    existing = (
        db.query(CorrelationCluster)
        .join(CorrelationMember,
              CorrelationMember.cluster_id == CorrelationCluster.id)
        .filter(CorrelationMember.detection_id == detection.id,
                CorrelationCluster.status == "open")
        .first()
    )
    if existing is not None:
        return existing

    # 2. Newest compatible open cluster on this endpoint?
    lo, hi = det_time - timedelta(seconds=window), det_time + timedelta(seconds=window)
    candidate = (
        db.query(CorrelationCluster)
        .filter(CorrelationCluster.org_id == detection.org_id,
                CorrelationCluster.endpoint_id == detection.endpoint_id,
                CorrelationCluster.status == "open",
                CorrelationCluster.first_seen <= hi,
                CorrelationCluster.last_seen >= lo)
        .order_by(CorrelationCluster.last_seen.desc())
        .first()
    )
    if candidate is not None:
        db.add(CorrelationMember(cluster_id=candidate.id,
                                 detection_id=detection.id))
        db.flush()
        from app.db.models import Endpoint
        ep = db.query(Endpoint).filter(
            Endpoint.id == detection.endpoint_id).first()
        _recompute(db, candidate, window, ep.hostname if ep else "")
        db.flush()
        logger.info("correlation append cluster=%s detection=%s",
                    candidate.id, detection.id)
        return candidate

    # 3. Partner search: other in-window detections, distinct family required.
    others = (
        db.query(Detection)
        .join(SecurityEvent, SecurityEvent.id == Detection.primary_event_id)
        .filter(Detection.org_id == detection.org_id,
                Detection.endpoint_id == detection.endpoint_id,
                Detection.id != detection.id,
                Detection.status != "false_positive",
                SecurityEvent.occurred_at >= lo,
                SecurityEvent.occurred_at <= hi)
        .order_by(Detection.id)
        .limit(MEMBER_CAP)
        .all()
    )
    my_family = family_of(detection)
    partners = [o for o in others if family_of(o) != my_family]
    if not partners:
        return None  # isolated detection: no cluster (spec threshold)

    members = sorted([detection, *others], key=lambda d: d.id)[:MEMBER_CAP]
    # Deterministic per trigger: same trigger reprocessing converges to the
    # same key. Key conflicts (closed-cluster reprocessing) resolve by
    # converging members into the existing row — never a duplicate cluster.
    # Savepoint only: a full rollback would nuke the caller's transaction.
    key = f"{detection.endpoint_id}:{detection.id}"
    try:
        with db.begin_nested():
            cluster = CorrelationCluster(
                org_id=detection.org_id, endpoint_id=detection.endpoint_id,
                correlation_key=key, first_seen=det_time, last_seen=det_time,
                status="open")
            db.add(cluster)
            db.flush()
            for member in members:
                db.add(CorrelationMember(cluster_id=cluster.id,
                                         detection_id=member.id))
            db.flush()
    except Exception:
        # Lost race / reprocessing after close: converge into existing row.
        cluster = (
            db.query(CorrelationCluster)
            .filter(CorrelationCluster.org_id == detection.org_id,
                    CorrelationCluster.correlation_key == key)
            .first()
        )
        if cluster is None:
            raise
        have = {m.detection_id for m in db.query(CorrelationMember).filter(
            CorrelationMember.cluster_id == cluster.id).all()}
        for member in members:
            if member.id not in have:
                db.add(CorrelationMember(cluster_id=cluster.id,
                                         detection_id=member.id))
        db.flush()
    from app.db.models import Endpoint
    ep = db.query(Endpoint).filter(Endpoint.id == detection.endpoint_id).first()
    _recompute(db, cluster, window, ep.hostname if ep else "")
    db.flush()
    logger.info("correlation created cluster=%s members=%d",
                cluster.id, len(members))
    return cluster


def close_cluster(db: Session, *, org_id: int, cluster_id: int,
                  actor_id: int | None) -> CorrelationCluster:
    cluster = (
        db.query(CorrelationCluster)
        .filter(CorrelationCluster.id == cluster_id,
                CorrelationCluster.org_id == org_id)
        .first()
    )
    if cluster is None:
        raise LookupError("Cluster not found")
    cluster.status = "closed"
    db.add(AuditLog(org_id=org_id, actor_id=actor_id,
                    action="correlation.closed", target=f"cluster:{cluster.id}"))
    db.commit()
    return cluster


def expire_stale(db: Session, *, org_id: int, window: int,
                 actor_id: int | None) -> int:
    """Mark open clusters untouched for >2 windows as expired. Returns count."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=2 * window)
    stale = (
        db.query(CorrelationCluster)
        .filter(CorrelationCluster.org_id == org_id,
                CorrelationCluster.status == "open",
                CorrelationCluster.last_seen < cutoff)
        .all()
    )
    for cluster in stale:
        cluster.status = "expired"
        db.add(AuditLog(org_id=org_id, actor_id=actor_id,
                        action="correlation.expired",
                        target=f"cluster:{cluster.id}"))
    db.commit()
    return len(stale)

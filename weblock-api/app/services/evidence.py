"""Forensic evidence collection, integrity, chain of custody, snapshots.

Evidence rows REFERENCE source records (telemetry/security/detection/
correlation/incident/login) plus a content hash — payloads are never copied.
Supported source types mirror data the agent/server actually produce.
"""
import hashlib
import json
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.db.models import (
    AuditLog,
    CorrelationCluster,
    CustodyRecord,
    Detection,
    Evidence,
    EvidenceSnapshot,
    Incident,
    SecurityEvent,
    TelemetryEvent,
)

logger = logging.getLogger("weblock.evidence")

SOURCE_TYPES = ("TELEMETRY_EVENT", "SECURITY_EVENT", "DETECTION", "CORRELATION",
                "INCIDENT", "LOGIN")
CUSTODY_ACTIONS = ("COLLECTED", "STORED", "VIEWED", "VERIFIED", "EXPORTED",
                   "UPDATED_METADATA")


def _canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=str)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def resolve_source(db: Session, org_id: int, source_type: str,
                   source_id: int) -> tuple[dict, datetime | None]:
    """Return (summary_ref, occurred_at) or raise LookupError. Org-scoped."""
    if source_type == "TELEMETRY_EVENT":
        row = db.query(TelemetryEvent).filter(
            TelemetryEvent.id == source_id,
            TelemetryEvent.org_id == org_id).first()
        if not row:
            raise LookupError("Telemetry event not found")
        return ({"event_id": row.event_id, "type": row.type,
                 "endpoint_id": row.endpoint_id,
                 "event_hash": row.event_hash,
                 "occurred_at": row.occurred_at.isoformat()
                 if row.occurred_at else None}, row.occurred_at)
    if source_type == "SECURITY_EVENT":
        row = db.query(SecurityEvent).filter(
            SecurityEvent.id == source_id,
            SecurityEvent.org_id == org_id).first()
        if not row:
            raise LookupError("Security event not found")
        return ({"event_id": row.event_id, "category": row.category,
                 "subtype": row.subtype, "endpoint_id": row.endpoint_id,
                 "actor": row.actor,
                 "occurred_at": row.occurred_at.isoformat()
                 if row.occurred_at else None}, row.occurred_at)
    if source_type == "DETECTION":
        row = db.query(Detection).filter(
            Detection.id == source_id, Detection.org_id == org_id).first()
        if not row:
            raise LookupError("Detection not found")
        return ({"rule_id": row.rule_id, "severity": row.severity,
                 "title": row.title, "endpoint_id": row.endpoint_id,
                 "primary_event_id": row.primary_event_id,
                 "detected_at": row.detected_at.isoformat()
                 if row.detected_at else None}, row.detected_at)
    if source_type == "CORRELATION":
        row = db.query(CorrelationCluster).filter(
            CorrelationCluster.id == source_id,
            CorrelationCluster.org_id == org_id).first()
        if not row:
            raise LookupError("Correlation cluster not found")
        return ({"severity": row.severity, "confidence": row.confidence,
                 "families": row.families, "endpoint_id": row.endpoint_id,
                 "first_seen": row.first_seen.isoformat()
                 if row.first_seen else None}, row.last_seen)
    if source_type == "INCIDENT":
        row = db.query(Incident).filter(
            Incident.id == source_id, Incident.org_id == org_id).first()
        if not row:
            raise LookupError("Incident not found")
        return ({"incident_key": row.incident_key, "severity": row.severity,
                 "status": row.status, "endpoint_id": row.endpoint_id,
                 "created_at": row.created_at.isoformat()
                 if row.created_at else None}, row.created_at)
    if source_type == "LOGIN":
        from app.db.models import LoginEvent
        row = db.query(LoginEvent).filter(
            LoginEvent.id == source_id, LoginEvent.org_id == org_id).first()
        if not row:
            raise LookupError("Login event not found")
        return ({"classification": row.classification,
                 "ip_address": row.ip_address,
                 "created_at": row.created_at.isoformat()
                 if row.created_at else None}, row.created_at)
    raise ValueError(f"Unsupported source_type: {source_type}")


def add_custody(db: Session, *, org_id: int, evidence_id: int, action: str,
                actor_user_id: int | None, reason: str = "",
                meta: dict | None = None) -> CustodyRecord:
    if action not in CUSTODY_ACTIONS:
        raise ValueError(f"Invalid custody action: {action}")
    last = (
        db.query(CustodyRecord)
        .filter(CustodyRecord.evidence_id == evidence_id)
        .order_by(CustodyRecord.id.desc())
        .first()
    )
    prev = last.record_hash if last else "GENESIS"
    # created_at is set explicitly (not server_default) so the hashed instant
    # and the stored instant are identical — required for verification.
    stamp = datetime.now(timezone.utc)
    digest = _sha(prev + _canonical({
        "action": action, "evidence_id": evidence_id,
        "actor": actor_user_id, "at": stamp.isoformat(), "reason": reason or ""}))
    record = CustodyRecord(
        org_id=org_id, evidence_id=evidence_id, action=action,
        actor_user_id=actor_user_id, created_at=stamp,
        reason=(reason or "")[:500],
        meta_data=meta or {}, prev_hash=prev, record_hash=digest)
    db.add(record)
    db.flush()
    return record


def verify_custody_chain(db: Session, evidence_id: int) -> tuple[bool, list]:
    records = (
        db.query(CustodyRecord)
        .filter(CustodyRecord.evidence_id == evidence_id)
        .order_by(CustodyRecord.id.asc())
        .all()
    )
    problems: list[dict] = []
    prev = "GENESIS"
    for rec in records:
        if rec.prev_hash != prev:
            problems.append({"record_id": rec.id, "type": "CUSTODY_LINK_BREAK"})
        instant = rec.created_at.astimezone(timezone.utc).isoformat() \
            if rec.created_at else ""
        recomputed = _sha(prev + _canonical({
            "action": rec.action, "evidence_id": rec.evidence_id,
            "actor": rec.actor_user_id, "at": instant,
            "reason": rec.reason or ""}))
        if recomputed != rec.record_hash:
            problems.append({"record_id": rec.id, "type": "CUSTODY_HASH_MISMATCH"})
        prev = rec.record_hash
    return (not problems, problems)


def _audit(db: Session, *, org_id: int, actor_id: int | None, action: str,
           target: str, meta: dict | None = None) -> None:
    db.add(AuditLog(org_id=org_id, actor_id=actor_id, action=action,
                    target=target, meta_data=meta or {}))


def collect_evidence(db: Session, *, org_id: int, source_type: str,
                     source_id: int, incident_id: int | None = None,
                     correlation_id: int | None = None,
                     actor_user_id: int | None = None,
                     actor_name: str = "weblock-server",
                     description: str = "") -> Evidence:
    if source_type not in SOURCE_TYPES:
        raise ValueError(f"Unsupported source_type: {source_type}")
    summary, _occurred = resolve_source(db, org_id, source_type, source_id)
    if incident_id is not None:
        incident = db.query(Incident).filter(
            Incident.id == incident_id, Incident.org_id == org_id).first()
        if incident is None:
            raise LookupError("Incident not found")
    content = {"source_type": source_type, "source_id": source_id,
               "reference": summary}
    digest = _sha(_canonical(content))
    row = Evidence(
        org_id=org_id, incident_id=incident_id, correlation_id=correlation_id,
        source=source_type.lower(), source_type=source_type,
        source_id=source_id, content=content, sha256=digest,
        collector="weblock-server", collected_by=actor_name,
        chain_of_custody={"collected_by": actor_name},
        integrity_status="UNVERIFIED", description=(description or "")[:2000],
        meta={})
    db.add(row)
    db.flush()
    add_custody(db, org_id=org_id, evidence_id=row.id, action="COLLECTED",
                actor_user_id=actor_user_id,
                meta={"source_type": source_type, "source_id": source_id})
    add_custody(db, org_id=org_id, evidence_id=row.id, action="STORED",
                actor_user_id=actor_user_id)
    _audit(db, org_id=org_id, actor_id=actor_user_id,
           action="evidence.collected", target=f"evidence:{row.id}",
           meta={"source_type": source_type, "source_id": source_id,
                 "incident_id": incident_id})
    db.flush()
    return row


def verify_evidence(db: Session, *, org_id: int, evidence_id: int,
                    actor_user_id: int | None = None) -> tuple[Evidence, bool]:
    row = db.query(Evidence).filter(
        Evidence.id == evidence_id, Evidence.org_id == org_id).first()
    if row is None:
        raise LookupError("Evidence not found")
    recomputed = _sha(_canonical(row.content or {}))
    ok = recomputed == row.sha256
    # Cross-check the live source record still matches the reference.
    source_ok = True
    try:
        summary, _ = resolve_source(db, org_id, row.source_type,
                                    row.source_id or -1)
        source_ok = summary == (row.content or {}).get("reference")
    except (LookupError, ValueError):
        source_ok = False  # source deleted/retained: reference frozen, flagged
    row.integrity_status = "VERIFIED" if (ok and source_ok) else "TAMPERED"
    add_custody(db, org_id=org_id, evidence_id=row.id, action="VERIFIED",
                actor_user_id=actor_user_id,
                meta={"content_match": ok, "source_match": source_ok})
    _audit(db, org_id=org_id, actor_id=actor_user_id,
           action="evidence.verified", target=f"evidence:{row.id}",
           meta={"content_match": ok, "source_match": source_ok})
    db.flush()
    return row, (ok and source_ok)


def create_snapshot(db: Session, *, org_id: int, incident_id: int,
                    actor_user_id: int | None = None) -> EvidenceSnapshot:
    """Snapshot an incident's reference graph (immutable refs + hash).

    Includes: existing evidence rows for the incident, plus reference
    evidence auto-collected for the correlation, member detections, and the
    incident itself (deduped by source). Bounded by cluster membership.
    """
    incident = db.query(Incident).filter(
        Incident.id == incident_id, Incident.org_id == org_id).first()
    if incident is None:
        raise LookupError("Incident not found")

    wanted: list[tuple[str, int, int | None]] = []  # (type, id, correlation)
    if incident.correlation_id is not None:
        wanted.append(("CORRELATION", incident.correlation_id,
                       incident.correlation_id))
        from app.db.models import CorrelationMember
        member_ids = [m.detection_id for m in
                      db.query(CorrelationMember)
                      .filter(CorrelationMember.cluster_id ==
                              incident.correlation_id).all()]
        for det in db.query(Detection).filter(
                Detection.id.in_(member_ids)).all() if member_ids else []:
            wanted.append(("DETECTION", det.id, incident.correlation_id))
            sec = db.query(SecurityEvent).filter(
                SecurityEvent.id == det.primary_event_id).first()
            if sec is not None:
                wanted.append(("SECURITY_EVENT", sec.id, incident.correlation_id))
                raw = db.query(TelemetryEvent).filter(
                    TelemetryEvent.id == sec.telemetry_ref).first()
                if raw is not None:
                    wanted.append(("TELEMETRY_EVENT", raw.id,
                                   incident.correlation_id))
    wanted.append(("INCIDENT", incident.id, incident.correlation_id))

    collected: list[int] = []
    have = {(e.source_type, e.source_id) for e in
            db.query(Evidence)
            .filter(Evidence.org_id == org_id,
                    Evidence.incident_id == incident_id).all()}
    for source_type, source_id, corr in wanted:
        if (source_type, source_id) in have:
            continue
        try:
            row = collect_evidence(
                db, org_id=org_id, source_type=source_type,
                source_id=source_id, incident_id=incident_id,
                correlation_id=corr, actor_user_id=actor_user_id)
        except (LookupError, ValueError):
            continue  # source retained/deleted mid-snapshot: skip, don't fail
        collected.append(row.id)
        have.add((source_type, source_id))

    all_ids = sorted({e.id for e in db.query(Evidence).filter(
        Evidence.org_id == org_id,
        Evidence.incident_id == incident_id).all()} | set(collected))
    if len(all_ids) > 500:
        raise ValueError("Snapshot too large (>500 evidence items)")
    digest = _sha(_canonical({"incident_id": incident_id, "evidence": all_ids}))
    snap = EvidenceSnapshot(org_id=org_id, incident_id=incident_id,
                            created_by=actor_user_id, evidence_ids=all_ids,
                            snapshot_hash=digest)
    db.add(snap)
    db.flush()
    _audit(db, org_id=org_id, actor_id=actor_user_id,
           action="evidence.snapshot_created",
           target=f"incident:{incident.incident_key}",
           meta={"snapshot_id": snap.id, "evidence_count": len(all_ids)})
    db.flush()
    return snap

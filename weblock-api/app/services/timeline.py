"""Deterministic forensic timeline for an incident.

Sources (all real rows, nothing invented): member security events + their
raw telemetry, member detections, the correlation cluster, endpoint risk
snapshots near the incident, incident audit lifecycle rows, custody actions
on the incident's evidence. Ordered by (timestamp, kind_rank, id).
"""
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.timeutil import as_utc
from app.db.models import (
    AuditLog,
    CorrelationCluster,
    CorrelationMember,
    CustodyRecord,
    Detection,
    Evidence,
    Incident,
    RiskSnapshot,
    SecurityEvent,
    TelemetryEvent,
)

logger = logging.getLogger("weblock.timeline")

KIND_RANK = {
    "telemetry": 10,
    "security_event": 20,
    "detection": 30,
    "correlation": 40,
    "risk": 50,
    "incident": 60,
    "response": 65,
    "evidence": 70,
    "custody": 80,
}
MAX_ITEMS = 500


def _iso(value) -> str | None:
    if value is None:
        return None
    try:
        return as_utc(value).isoformat()
    except Exception:
        return str(value)


def build_incident_timeline(db: Session, incident: Incident,
                            limit: int = MAX_ITEMS) -> list[dict]:
    items: list[dict] = []

    def add(ts, kind: str, title: str, ref_id: int | None = None,
            severity: str | None = None, refs: dict | None = None):
        if ts is None:
            return
        items.append({
            "timestamp": _iso(ts),
            "_sort_ts": as_utc(ts).timestamp(),
            "kind": kind,
            "kind_rank": KIND_RANK.get(kind, 99),
            "title": title,
            "severity": severity,
            "ref_id": ref_id,
            "refs": refs or {},
        })

    # Member security events + raw telemetry + detections.
    member_ids: list[int] = []
    cluster = None
    if incident.correlation_id is not None:
        cluster = db.query(CorrelationCluster).filter(
            CorrelationCluster.id == incident.correlation_id).first()
        member_ids = [m.detection_id for m in
                      db.query(CorrelationMember)
                      .filter(CorrelationMember.cluster_id ==
                              incident.correlation_id).all()]
    dets = db.query(Detection).filter(Detection.id.in_(member_ids)).all() \
        if member_ids else []
    for det in dets:
        sec = db.query(SecurityEvent).filter(
            SecurityEvent.id == det.primary_event_id).first()
        if sec is not None:
            raw = db.query(TelemetryEvent).filter(
                TelemetryEvent.id == sec.telemetry_ref).first()
            if raw is not None:
                add(raw.occurred_at, "telemetry",
                    f"{raw.type.upper()} telemetry {raw.event_id[:8]}",
                    ref_id=raw.id,
                    refs={"telemetry_id": raw.id, "event_id": raw.event_id})
            add(sec.occurred_at, "security_event",
                f"{sec.category} {sec.subtype}"
                + (f" by {sec.actor}" if sec.actor else ""),
                ref_id=sec.id, severity=sec.severity_hint,
                refs={"security_event_id": sec.id,
                      "telemetry_ref": sec.telemetry_ref})
        add(det.detected_at, "detection",
            f"{det.rule_id}: {det.title}", ref_id=det.id,
            severity=det.severity,
            refs={"detection_id": det.id,
                  "primary_event_id": det.primary_event_id})
    if cluster is not None:
        add(cluster.first_seen, "correlation",
            f"Correlation opened ({cluster.distinct_family_count} families, "
            f"confidence {cluster.confidence})", ref_id=cluster.id,
            severity=cluster.severity,
            refs={"cluster_id": cluster.id})

    # Risk snapshots for the endpoint near the incident (±6h of creation).
    if incident.endpoint_id is not None and incident.created_at is not None:
        created = as_utc(incident.created_at)
        snaps = (
            db.query(RiskSnapshot)
            .filter(RiskSnapshot.endpoint_id == incident.endpoint_id,
                    RiskSnapshot.created_at >= created - timedelta(hours=6),
                    RiskSnapshot.created_at <= created + timedelta(hours=6))
            .order_by(RiskSnapshot.id.asc())
            .limit(20)
            .all()
        )
        for snap in snaps:
            add(snap.created_at, "risk",
                f"Risk assessment {snap.score} {snap.severity.upper()}",
                ref_id=snap.id, severity=snap.severity,
                refs={"risk_snapshot_id": snap.id})

    # Incident lifecycle from audit trail + creation row.
    add(incident.created_at, "incident",
        f"Incident {incident.incident_key} created ({incident.severity.upper()}, "
        f"risk {incident.risk_score})", ref_id=incident.id,
        severity=incident.severity,
        refs={"incident_id": incident.id})
    for audit in (
        db.query(AuditLog)
        .filter(AuditLog.org_id == incident.org_id,
                AuditLog.action == "incident.status_changed",
                AuditLog.target == incident.incident_key)
        .order_by(AuditLog.id.asc())
        .limit(50)
        .all()
    ):
        add(audit.created_at, "incident",
            f"Incident status -> {(audit.meta_data or {}).get('status', '?')}",
            ref_id=incident.id,
            refs={"incident_id": incident.id, "audit_id": audit.id})

    # Response lifecycle (Phase 8): audit rows carry incident_id in metadata.
    for audit in (
        db.query(AuditLog)
        .filter(AuditLog.org_id == incident.org_id,
                AuditLog.action.like("response.%"))
        .order_by(AuditLog.id.asc())
        .limit(200)
        .all()
    ):
        meta = audit.meta_data or {}
        if meta.get("incident_id") != incident.id:
            continue
        label = audit.action.replace("response.", "RESPONSE_").upper()
        add(audit.created_at, "response",
            f"{label} {meta.get('action_type', '')} "
            f"(action #{meta.get('action_id')})".strip(),
            ref_id=meta.get("action_id"),
            severity=None,
            refs={"incident_id": incident.id,
                  "response_action_id": meta.get("action_id"),
                  "audit_id": audit.id})

    # Evidence + custody for this incident.
    ev_rows = (
        db.query(Evidence)
        .filter(Evidence.org_id == incident.org_id,
                Evidence.incident_id == incident.id)
        .order_by(Evidence.id.asc())
        .limit(200)
        .all()
    )
    for ev in ev_rows:
        add(ev.collected_at, "evidence",
            f"Evidence #{ev.id} collected ({ev.source_type})", ref_id=ev.id,
            refs={"evidence_id": ev.id})
    if ev_rows:
        for rec in (
            db.query(CustodyRecord)
            .filter(CustodyRecord.evidence_id.in_([e.id for e in ev_rows]))
            .order_by(CustodyRecord.id.asc())
            .limit(200)
            .all()
        ):
            add(rec.created_at, "custody",
                f"Custody {rec.action} on evidence #{rec.evidence_id}",
                ref_id=rec.id,
                refs={"evidence_id": rec.evidence_id,
                      "custody_id": rec.id})

    # Legacy login-incident single event (no correlation graph).
    if incident.event_id is not None and not member_ids:
        from app.db.models import LoginEvent
        event = db.query(LoginEvent).filter(
            LoginEvent.id == incident.event_id).first()
        if event is not None:
            add(event.created_at, "security_event",
                f"LOGIN {event.classification} from {event.ip_address}",
                ref_id=event.id, refs={"login_event_id": event.id})

    items.sort(key=lambda i: (i["_sort_ts"], i["kind_rank"], i["ref_id"] or 0))
    for item in items:
        del item["_sort_ts"]
    return items[:limit]

"""Telemetry hash-chain verification (read-only cryptographic integrity).

Scope: one organization + one endpoint, ordered by (chain_seq, id).
- sha256-received-v1 rows (pre-Phase-7): payload bytes not recomputable
  server-side -> linkage + sequence only (status LEGACY per row).
- sha256-canonical-v1 rows: full recompute from stored fields.
Detects: modified payload/hash, broken prev linkage, sequence gaps
(deleted rows; retention deletions also surface as gaps — documented),
out-of-order linkage. Cannot detect: deletion of trailing rows, or gaps
hidden by retention (stated limits, not silent).
"""
import logging
from datetime import datetime

from sqlalchemy.orm import Session

from app.core.timeutil import as_utc
from app.db.models import TelemetryEvent
from app.services.ingest import HASH_CANONICAL_V1, canonical_hash_v2

logger = logging.getLogger("weblock.forensics")

MAX_VERIFY_ROWS = 5000


def _recompute(row: TelemetryEvent) -> tuple[str | None, str]:
    """Return (digest_or_None, status): VERIFIED / TAMPERED / LEGACY."""
    if row.hash_algorithm != HASH_CANONICAL_V1:
        return None, "LEGACY"
    digest = canonical_hash_v2(
        row.event_id, row.schema_version or "1.0", row.type,
        as_utc(row.occurred_at), row.source or "agent", row.payload or {})
    return digest, ("VERIFIED" if digest == row.event_hash else "TAMPERED")


def verify_telemetry_chain(db: Session, *, org_id: int, endpoint_id: int,
                           start=None, end=None,
                           limit: int = MAX_VERIFY_ROWS) -> dict:
    from app.db.models import Endpoint
    endpoint = db.query(Endpoint).filter(
        Endpoint.id == endpoint_id, Endpoint.org_id == org_id).first()
    if endpoint is None:
        raise LookupError("Endpoint not found")

    q = db.query(TelemetryEvent).filter(
        TelemetryEvent.org_id == org_id,
        TelemetryEvent.endpoint_id == endpoint_id)
    if start is not None:
        q = q.filter(TelemetryEvent.occurred_at >= start)
    if end is not None:
        q = q.filter(TelemetryEvent.occurred_at <= end)
    rows = q.order_by(TelemetryEvent.chain_seq.asc(),
                      TelemetryEvent.id.asc()).limit(limit + 1).all()
    truncated = len(rows) > limit
    rows = rows[:limit]

    violations: list[dict] = []
    legacy = 0
    prev = None
    if rows:
        # Boundary continuity: predecessor just outside the range, if any.
        first = rows[0]
        if first.chain_seq is not None and first.chain_seq > 1:
            pred = (
                db.query(TelemetryEvent)
                .filter(TelemetryEvent.endpoint_id == endpoint_id,
                        TelemetryEvent.chain_seq == first.chain_seq - 1)
                .first()
            )
            if pred is None:
                violations.append({
                    "event_id": first.event_id, "row_id": first.id,
                    "type": "CHAIN_START_GAP",
                    "detail": f"chain_seq starts at {first.chain_seq} with no "
                              f"predecessor row in scope (deleted or out of range)",
                    "occurred_at": first.occurred_at.isoformat()
                    if first.occurred_at else None,
                    "severity": "medium"})
            else:
                prev = pred
        elif first.prev_hash:
            violations.append({
                "event_id": first.event_id, "row_id": first.id,
                "type": "CHAIN_START_MISMATCH",
                "detail": "first in-scope row links to a predecessor that is "
                          "not the chain genesis",
                "occurred_at": first.occurred_at.isoformat()
                if first.occurred_at else None,
                "severity": "low"})

    for row in rows:
        digest, status = _recompute(row)
        if status == "LEGACY":
            legacy += 1
        elif status == "TAMPERED":
            violations.append({
                "event_id": row.event_id, "row_id": row.id,
                "type": "PAYLOAD_HASH_MISMATCH",
                "detail": "recomputed SHA-256 differs from stored event_hash "
                          "(payload or metadata modified after ingest)",
                "expected": row.event_hash, "actual": digest,
                "occurred_at": row.occurred_at.isoformat()
                if row.occurred_at else None,
                "severity": "high"})
        if prev is not None and row.prev_hash != prev.event_hash:
            violations.append({
                "event_id": row.event_id, "row_id": row.id,
                "type": "PREV_LINK_BREAK",
                "detail": "prev_hash does not match previous row event_hash "
                          "(reorder, insertion, or modification)",
                "expected": prev.event_hash, "actual": row.prev_hash,
                "occurred_at": row.occurred_at.isoformat()
                if row.occurred_at else None,
                "severity": "high"})
        if (prev is not None and row.chain_seq is not None
                and prev.chain_seq is not None
                and row.chain_seq != prev.chain_seq + 1):
            violations.append({
                "event_id": row.event_id, "row_id": row.id,
                "type": "SEQUENCE_GAP",
                "detail": f"chain_seq jumps {prev.chain_seq} -> {row.chain_seq} "
                          f"(deleted/retained rows in between)",
                "occurred_at": row.occurred_at.isoformat()
                if row.occurred_at else None,
                "severity": "medium"})
        prev = row

    return {
        "valid": not violations,
        "org_id": org_id,
        "endpoint_id": endpoint_id,
        "events_checked": len(rows),
        "truncated": truncated,
        "legacy_rows": legacy,
        "first_event": rows[0].event_id if rows else None,
        "last_event": rows[-1].event_id if rows else None,
        "algorithm": "SHA-256",
        "scope": "organization+endpoint, ordered by (chain_seq, id)",
        "violations": violations,
        "verified_at": datetime.now().astimezone().isoformat(),
    }

"""POST /v1/telemetry/batch — agent telemetry ingestion.

Pipeline (Phase 1 scope): authenticate endpoint -> validate envelope ->
enforce limits -> per-event validate -> canonical hash -> dedup insert ->
ack. Detection/correlation land in Phase 3/4 (tables are ready for them).

Guards:
- body agent_id must equal the authenticated endpoint (no cross-submit)
- revoked endpoints rejected in agent_auth
- 500 events / 256KB per event caps (-> 413)
- per-event failures reported in `rejected`, envelope failures -> 4xx
- heartbeats/audits NOT written per batch (noise); enroll/revoke audited
"""
import hashlib
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.agent_auth import get_current_endpoint
from app.db.database import get_db
from app.db.models import Endpoint, TelemetryEvent
from app.schemas.telemetry import (
    MAX_BATCH_EVENTS,
    MAX_EVENT_PAYLOAD_BYTES,
    TelemetryBatchOut,
)

logger = logging.getLogger("weblock.telemetry")
router = APIRouter(tags=["telemetry"])

MAX_BODY_BYTES = 2 * 1024 * 1024


def _canonical_hash(event: dict) -> str:
    return hashlib.sha256(
        json.dumps(event, sort_keys=True, separators=(",", ":"),
                   default=str).encode()
    ).hexdigest()


@router.post("/telemetry/batch", response_model=TelemetryBatchOut)
async def ingest_batch(request: Request, db: Session = Depends(get_db),
                       endpoint: Endpoint = Depends(get_current_endpoint)):
    raw_body = await request.body()
    if len(raw_body) > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Batch body too large")
    try:
        envelope = json.loads(raw_body)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    if not isinstance(envelope, dict) or envelope.get("agent_id") != endpoint.agent_id:
        # Covers missing agent_id AND cross-endpoint submission.
        raise HTTPException(
            status_code=403, detail="agent_id must match authenticated endpoint")
    events = envelope.get("events")
    if not isinstance(events, list) or not events:
        raise HTTPException(status_code=422, detail="events must be a non-empty list")
    if len(events) > MAX_BATCH_EVENTS:
        raise HTTPException(
            status_code=413, detail=f"Too many events (max {MAX_BATCH_EVENTS})")

    from app.schemas.telemetry import TelemetryEventIn  # local: fail fast, clear err

    accepted = 0
    duplicates = 0
    rejected: list[dict] = []
    rows: list[dict] = []
    seen_in_batch: set[str] = set()
    for raw in events:
        if not isinstance(raw, dict):
            rejected.append({"event_id": None, "reason": "event must be an object"})
            continue
        try:
            ev = TelemetryEventIn.model_validate(raw)
        except Exception as exc:
            rejected.append({"event_id": raw.get("event_id"),
                             "reason": f"validation: {exc.errors()[0]['msg']}"
                             if hasattr(exc, "errors") else "validation failed"})
            continue
        payload_bytes = len(json.dumps(ev.payload, default=str).encode())
        if payload_bytes > MAX_EVENT_PAYLOAD_BYTES:
            rejected.append({"event_id": ev.event_id, "reason": "payload too large"})
            continue
        if ev.event_id in seen_in_batch:
            duplicates += 1
            continue
        seen_in_batch.add(ev.event_id)
        rows.append({
            "org_id": endpoint.org_id,
            "endpoint_id": endpoint.id,
            "event_id": ev.event_id,
            "schema_version": ev.schema_version,
            "type": ev.type,
            "source": ev.source,
            "occurred_at": ev.occurred_at,
            "payload": ev.payload,
            "event_hash": _canonical_hash(raw),
        })

    if rows:
        stmt = pg_insert(TelemetryEvent).values(rows).on_conflict_do_nothing(
            constraint="uq_telemetry_endpoint_event")
        # RETURNING id tells us which rows were actually inserted.
        stmt = stmt.returning(TelemetryEvent.id)
        inserted = db.execute(stmt).scalars().all()
        accepted = len(inserted)
        duplicates += len(rows) - accepted
        endpoint.last_seen = datetime.now(timezone.utc)
        db.commit()
        logger.info("telemetry batch endpoint=%s accepted=%d dup=%d rej=%d",
                    endpoint.agent_id, accepted, duplicates, len(rejected))

    return TelemetryBatchOut(accepted=accepted, duplicates=duplicates,
                             rejected=rejected)

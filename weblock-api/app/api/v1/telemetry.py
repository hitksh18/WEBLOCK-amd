"""POST /v1/telemetry/batch — agent telemetry ingestion.

Pipeline (Phase 2): RECEIVE -> AUTHENTICATE -> VALIDATE -> DEDUPLICATE
  -> PERSIST RAW -> NORMALIZE -> CLASSIFY -> DETECTION HOOK -> STATUS
(stages implemented in app/services/ingest.py; this route is RECEIVE +
envelope guards). Response contract unchanged from Phase 1:
{accepted, duplicates, rejected}.

Guards:
- body agent_id must equal the authenticated endpoint (no cross-submit)
- revoked endpoints rejected in agent_auth
- 500 events / 2MB body / 256KB per-event caps (-> 413)
- per-event failures reported in `rejected`, envelope failures -> 4xx
- heartbeats/audits NOT written per batch (noise); enroll/revoke audited
"""
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.agent_auth import get_current_endpoint
from app.db.database import get_db
from app.db.models import Endpoint
from app.schemas.telemetry import MAX_BATCH_EVENTS, TelemetryBatchOut
from app.services.ingest import normalize_and_dispatch, persist_raw

logger = logging.getLogger("weblock.telemetry")
router = APIRouter(tags=["telemetry"])

MAX_BODY_BYTES = 2 * 1024 * 1024


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

    inserted, duplicates, rejected = persist_raw(db, endpoint, events)
    accepted = len(inserted)
    if inserted:
        _normalized, _detections = normalize_and_dispatch(db, endpoint, inserted)
        endpoint.last_seen = datetime.now(timezone.utc)
    db.commit()
    logger.info("telemetry batch endpoint=%s accepted=%d dup=%d rej=%d",
                endpoint.agent_id, accepted, duplicates, len(rejected))
    return TelemetryBatchOut(accepted=accepted, duplicates=duplicates,
                             rejected=rejected)

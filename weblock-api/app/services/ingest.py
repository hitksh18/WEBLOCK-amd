"""Telemetry ingestion pipeline (Phase 2 structure).

RECEIVE -> AUTHENTICATE -> VALIDATE -> DEDUPLICATE -> PERSIST RAW
  -> NORMALIZE -> CLASSIFY -> DETECTION HOOK -> STATUS

The route (api/v1/telemetry.py) handles RECEIVE envelope checks + limits;
everything below runs here in ONE transaction per batch (bulk statements,
no per-event connections). Raw payloads are never mutated; processing
metadata lives in dedicated columns.
"""
import hashlib
import json
import logging
from datetime import datetime, timezone

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.timeutil import as_utc
from app.db.models import Endpoint, SecurityEvent, TelemetryEvent
from app.schemas.telemetry import MAX_EVENT_PAYLOAD_BYTES, TelemetryEventIn
from app.services.detection import dispatch_event
from app.services.normalize import NORM_VERSION, normalize

logger = logging.getLogger("weblock.ingest")

HASH_RECEIVED_V1 = "sha256-received-v1"
HASH_CANONICAL_V1 = "sha256-canonical-v1"


def canonical_hash(event: dict) -> str:
    """Legacy v1: SHA-256 over as-received envelope bytes.

    Contract preserved: existing rows keep this form (linkage-verifiable
    only — the original occurred_at string is not recoverable server-side).
    """
    return hashlib.sha256(
        json.dumps(event, sort_keys=True, separators=(",", ":"),
                   default=str).encode()
    ).hexdigest()


def canonical_envelope(event_id: str, schema_version: str, type_: str,
                       occurred_at, source: str, payload: dict) -> dict:
    """Server-canonical envelope (v2): occurred_at normalized to UTC ISO."""
    return {
        "event_id": event_id,
        "occurred_at": as_utc(occurred_at).isoformat(),
        "payload": payload,
        "schema_version": schema_version,
        "source": source,
        "type": type_,
    }


def canonical_hash_v2(event_id: str, schema_version: str, type_: str,
                      occurred_at, source: str, payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(canonical_envelope(event_id, schema_version, type_,
                                      occurred_at, source, payload),
                   sort_keys=True, separators=(",", ":"),
                   default=str).encode()
    ).hexdigest()


def validate_event(raw: object) -> TelemetryEventIn | str:
    """Return parsed event or human-readable rejection reason."""
    if not isinstance(raw, dict):
        return "event must be an object"
    try:
        return TelemetryEventIn.model_validate(raw)
    except Exception as exc:
        if hasattr(exc, "errors"):
            try:
                return f"validation: {exc.errors()[0]['msg']}"
            except (IndexError, KeyError):
                pass
        return "validation failed"


def persist_raw(db: Session, endpoint: Endpoint,
                raws: list[dict]) -> tuple[list[TelemetryEvent], int, list[dict]]:
    """Dedup + bulk insert raw rows. Returns (inserted_rows, dup_count, rejected)."""
    rejected: list[dict] = []
    candidates: list[dict] = []
    seen: set[str] = set()
    dup = 0
    for raw in raws:
        parsed = validate_event(raw)
        if isinstance(parsed, str):
            rejected.append({"event_id": raw.get("event_id")
                             if isinstance(raw, dict) else None,
                             "reason": parsed})
            continue
        if len(json.dumps(parsed.payload, default=str).encode()) > MAX_EVENT_PAYLOAD_BYTES:
            rejected.append({"event_id": parsed.event_id,
                             "reason": "payload too large"})
            continue
        if parsed.event_id in seen:
            dup += 1
            continue
        seen.add(parsed.event_id)
        candidates.append({"parsed": parsed, "raw": raw})

    rows = [{
        "org_id": endpoint.org_id,
        "endpoint_id": endpoint.id,
        "event_id": c["parsed"].event_id,
        "schema_version": c["parsed"].schema_version,
        "type": c["parsed"].type,
        "source": c["parsed"].source,
        "occurred_at": as_utc(c["parsed"].occurred_at),
        "payload": c["parsed"].payload,
        "event_hash": canonical_hash_v2(
            c["parsed"].event_id, c["parsed"].schema_version, c["parsed"].type,
            c["parsed"].occurred_at, c["parsed"].source, c["parsed"].payload),
        "hash_algorithm": HASH_CANONICAL_V1,
        "processing_status": "RECEIVED",
    } for c in candidates]

    inserted: list[TelemetryEvent] = []
    if rows:
        stmt = (pg_insert(TelemetryEvent).values(rows)
                .on_conflict_do_nothing(constraint="uq_telemetry_endpoint_event")
                .returning(TelemetryEvent))
        inserted = list(db.execute(stmt).scalars().all())
        dup += len(rows) - len(inserted)
    # Always run: converges chain links for retried batches whose rows already
    # exist but are still unchained. Touches only chain_seq-NULL rows.
    assign_chain(db, endpoint)
    return inserted, dup, rejected


def assign_chain(db: Session, endpoint: Endpoint) -> int:
    """Link all unchained rows for the endpoint in (occurred_at, id) order.

    Idempotent: only rows with chain_seq NULL are linked, continuing from the
    current max (hash, seq). Late/backfilled rows take the next sequence —
    the chain reflects ingest order within equal timestamps (documented).
    Returns number of rows linked.
    """
    from sqlalchemy import func as sa_func
    top = (
        db.query(TelemetryEvent.event_hash, TelemetryEvent.chain_seq)
        .filter(TelemetryEvent.endpoint_id == endpoint.id,
                TelemetryEvent.chain_seq.is_not(None))
        .order_by(TelemetryEvent.chain_seq.desc())
        .first()
    )
    last_hash, last_seq = (top[0], top[1]) if top else (None, 0)
    pending = (
        db.query(TelemetryEvent)
        .filter(TelemetryEvent.endpoint_id == endpoint.id,
                TelemetryEvent.chain_seq.is_(None))
        .order_by(TelemetryEvent.occurred_at.asc(), TelemetryEvent.id.asc())
        .all()
    )
    for row in pending:
        last_seq += 1
        row.prev_hash = last_hash
        row.chain_seq = last_seq
        last_hash = row.event_hash
    db.flush()
    return len(pending)


def normalize_and_dispatch(db: Session, endpoint: Endpoint,
                           raws: list[TelemetryEvent]) -> tuple[int, int]:
    """Normalize inserted rows, persist security_events, run dispatcher.

    Returns (normalized_count, detection_count). Idempotent: security_events
    has UNIQUE(telemetry_ref); replays insert nothing and dispatch nothing new
    (detections unique on rule+version+primary event).
    """
    normalized = 0
    detections = 0
    host = endpoint.hostname or ""
    sec_rows: list[dict] = []
    for raw in raws:
        try:
            fields = normalize(raw.type, raw.payload or {},
                               as_utc(raw.occurred_at), host=host)
        except Exception as exc:
            raw.processing_status = "FAILED"
            raw.processing_error = str(exc)[:500]
            continue
        sec_rows.append({
            "org_id": raw.org_id,
            "endpoint_id": raw.endpoint_id,
            "telemetry_ref": raw.id,
            "event_id": raw.event_id,
            "occurred_at": as_utc(raw.occurred_at),
            **{k: v for k, v in fields.items() if k != "occurred_at"},
            "norm_version": NORM_VERSION,
            "status": "NORMALIZED",
        })
    if sec_rows:
        stmt = (pg_insert(SecurityEvent).values(sec_rows)
                .on_conflict_do_nothing(index_elements=["telemetry_ref"])
                .returning(SecurityEvent))
        fresh = list(db.execute(stmt).scalars().all())
        normalized = len(fresh)
        now = datetime.now(timezone.utc)
        for event in fresh:
            # Mark raw row processed-state.
            raw_row = next((r for r in raws if r.id == event.telemetry_ref), None)
            if raw_row is not None:
                raw_row.processing_status = "NORMALIZED"
                raw_row.normalization_version = NORM_VERSION
                raw_row.event_category = event.category
                raw_row.normalized_at = now
            try:
                detections += dispatch_event(db, event)
                event.status = "PROCESSED"
                event.processed_at = now
                if raw_row is not None:
                    raw_row.processing_status = "PROCESSED"
            except Exception as exc:
                logger.exception("dispatch failed event=%s", event.id)
                event.status = "FAILED"
                event.error = str(exc)[:500]
                if raw_row is not None:
                    raw_row.processing_status = "FAILED"
                    raw_row.processing_error = str(exc)[:500]
    return normalized, detections

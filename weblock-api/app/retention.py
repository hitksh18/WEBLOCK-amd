"""Retention maintenance (manual/scheduled, never automatic).

Deletes telemetry_events older than --days (cascades to security_events and
detections via FK). Evidence, incidents, audit logs are NEVER touched.

Usage (from weblock-api/):
    python -m app.retention --days 90            # dry run (default)
    python -m app.retention --days 90 --apply    # actually delete
"""
import argparse
from datetime import datetime, timedelta, timezone

from app.db.database import SessionLocal
from app.db.models import TelemetryEvent

RETAINED_TABLES = ("evidence", "incidents", "audit_logs")


def plan_retention(days: int) -> tuple[int, str]:
    """Return (row_count, cutoff_iso) without deleting."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    db = SessionLocal()
    try:
        count = db.query(TelemetryEvent).filter(
            TelemetryEvent.occurred_at < cutoff).count()
        return count, cutoff.isoformat()
    finally:
        db.close()


def apply_retention(days: int, batch: int = 1000) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    db = SessionLocal()
    total = 0
    try:
        while True:
            ids = [r[0] for r in db.query(TelemetryEvent.id).filter(
                TelemetryEvent.occurred_at < cutoff).limit(batch).all()]
            if not ids:
                break
            db.query(TelemetryEvent).filter(TelemetryEvent.id.in_(ids)) \
                .delete(synchronize_session=False)
            db.commit()
            total += len(ids)
        return total
    finally:
        db.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="WebLock telemetry retention")
    ap.add_argument("--days", type=int, default=90)
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    if args.days < 7:
        raise SystemExit("Refusing retention < 7 days (forensic safety).")
    if args.apply:
        deleted = apply_retention(args.days)
        print(f"deleted {deleted} telemetry events older than {args.days}d "
              f"(evidence/incidents/audit untouched)")
    else:
        count, cutoff = plan_retention(args.days)
        print(f"DRY RUN: {count} telemetry events older than {args.days}d "
              f"(cutoff {cutoff}) would be deleted")

"""Timezone helpers: Postgres returns tz-aware datetimes, SQLite naive.

NEVER use dt.replace(tzinfo=utc) on an already-aware value — it relabels
without converting. Use as_utc() everywhere.
"""
from datetime import datetime, timezone


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)

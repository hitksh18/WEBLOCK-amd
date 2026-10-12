"""Windows Security event-log collector (4624/4625/4634/...).

Bookmark file tracks the last record number so each cycle ships only new
events. Returns a status event (error field) — NEVER fabricated logons —
when the log is unavailable. Import of win32evtlog is lazy so unit tests
can run on any platform with mocks.
"""
import logging
import os
from datetime import datetime, timezone

from weblock_agent.models.telemetry import make_event

logger = logging.getLogger("weblock-agent.collectors.eventlog")

INTERESTING = {4624: "logon", 4625: "logon_failed", 4634: "logoff",
               4647: "logoff", 4672: "special_privileges", 4720: "account_created"}


def _bookmark_path(workdir: str) -> str:
    return os.path.join(workdir, "eventlog.bookmark")


def read_bookmark(workdir: str) -> int:
    try:
        with open(_bookmark_path(workdir), encoding="utf-8") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return 0


def write_bookmark(workdir: str, record_number: int) -> None:
    try:
        with open(_bookmark_path(workdir), "w", encoding="utf-8") as f:
            f.write(str(record_number))
    except OSError:
        logger.warning("cannot persist eventlog bookmark")


def collect(workdir: str, max_events: int = 100) -> list[dict]:
    try:
        import win32evtlog
    except ImportError:
        return [make_event("auth", {
            "kind": "collector_status", "collector": "eventlog",
            "error": "pywin32 unavailable on this platform",
        }, source="agent:eventlog")]
    events: list[dict] = []
    last_seen = read_bookmark(workdir)
    newest = last_seen
    try:
        hand = win32evtlog.OpenEventLog(None, "Security")
        try:
            flags = (win32evtlog.EVENTLOG_BACKWARDS_READ
                     | win32evtlog.EVENTLOG_SEQUENTIAL_READ)
            while len(events) < max_events:
                records = win32evtlog.ReadEventLog(hand, flags, 0)
                if not records:
                    break
                for rec in records:
                    newest = max(newest, rec.RecordNumber)
                    if rec.RecordNumber <= last_seen:
                        continue
                    eid = rec.EventID & 0xFFFF
                    if eid not in INTERESTING:
                        continue
                    occurred = (rec.TimeGenerated.isoformat()
                                if hasattr(rec.TimeGenerated, "isoformat")
                                else datetime.now(timezone.utc).isoformat())
                    events.append({
                        "event_id": f"evtlog-{rec.RecordNumber}",
                        "schema_version": "1.0",
                        "type": "auth",
                        "occurred_at": occurred,
                        "source": "agent:eventlog",
                        "payload": {
                            "kind": "windows_security_event",
                            "event_id": eid,
                            "action": INTERESTING[eid],
                            "record_number": rec.RecordNumber,
                            "source": rec.SourceName,
                            "strings": list(rec.StringInserts or [])[:12],
                        },
                    })
                if records[-1].RecordNumber <= last_seen:
                    break
        finally:
            win32evtlog.CloseEventLog(hand)
    except Exception as exc:
        logger.exception("security log read failed")
        return [make_event("auth", {
            "kind": "collector_status", "collector": "eventlog",
            "error": str(exc)[:200],
        }, source="agent:eventlog")]
    if newest:
        write_bookmark(workdir, newest)
    return events

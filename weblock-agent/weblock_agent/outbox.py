"""SQLite outbox: per-event durable queue with retry bookkeeping.

Schema: id, event_id (agent UUID), endpoint_id, type, occurred_at,
payload JSON, status (queued|sending|acked|failed), retry_count,
created_at, last_attempt.

- enqueue: INSERT OR IGNORE on (endpoint_id, event_id) -> natural dedup
- claim_for_upload: atomically mark N oldest queued/failed-due rows `sending`
- ack: delete by row id (server accepted)
- release: sending -> queued + retry_count++ + last_attempt (server/retry fail)
- prune: delete acked... (acked rows are deleted at ack time); enforce caps:
  drop oldest rows beyond max_rows, delete rows older than retention_days.
"""
import json
import logging
import sqlite3
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger("weblock-agent.outbox")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    endpoint_id TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    retry_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    last_attempt TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_outbox_endpoint_event
    ON outbox(endpoint_id, event_id);
CREATE INDEX IF NOT EXISTS idx_outbox_status_id ON outbox(status, id);
"""


class Outbox:
    def __init__(self, path: str, max_rows: int = 50000):
        self._path = path
        self._lock = threading.Lock()
        self._max_rows = max_rows
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def enqueue(self, event: dict, endpoint_id: str = "") -> bool:
        """Insert one envelope. Returns False when duplicate (already queued)."""
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """INSERT OR IGNORE INTO outbox
                   (event_id, endpoint_id, type, occurred_at, payload,
                    status, retry_count, created_at)
                   VALUES (?, ?, ?, ?, ?, 'queued', 0, ?)""",
                (event["event_id"], endpoint_id, event.get("type", ""),
                 event.get("occurred_at", self._now()),
                 json.dumps(event), self._now()),
            )
            self._enforce_caps(conn)
            return cur.rowcount == 1

    def enqueue_many(self, events: list[dict], endpoint_id: str = "") -> int:
        added = 0
        with self._lock, self._connect() as conn:
            for event in events:
                cur = conn.execute(
                    """INSERT OR IGNORE INTO outbox
                       (event_id, endpoint_id, type, occurred_at, payload,
                        status, retry_count, created_at)
                       VALUES (?, ?, ?, ?, ?, 'queued', 0, ?)""",
                    (event["event_id"], endpoint_id, event.get("type", ""),
                     event.get("occurred_at", self._now()),
                     json.dumps(event), self._now()),
                )
                added += cur.rowcount
            self._enforce_caps(conn)
        return added

    def claim_for_upload(self, limit: int) -> list[tuple[int, dict]]:
        """Atomically take oldest queued/due rows; returns [(row_id, event)]."""
        now = self._now()
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """SELECT id, payload FROM outbox
                   WHERE status IN ('queued','failed') ORDER BY id LIMIT ?""",
                (limit,),
            ).fetchall()
            ids = [r[0] for r in rows]
            if ids:
                conn.execute(
                    f"""UPDATE outbox SET status='sending', last_attempt=?
                        WHERE id IN ({','.join('?' * len(ids))})""",
                    [now, *ids],
                )
        return [(r[0], json.loads(r[1])) for r in rows]

    def ack(self, row_ids: list[int]) -> None:
        if not row_ids:
            return
        with self._lock, self._connect() as conn:
            conn.execute(
                f"DELETE FROM outbox WHERE id IN ({','.join('?' * len(row_ids))})",
                row_ids,
            )

    def release(self, row_ids: list[int]) -> None:
        """Sending -> queued with backoff bookkeeping after a failed attempt."""
        if not row_ids:
            return
        with self._lock, self._connect() as conn:
            conn.execute(
                f"""UPDATE outbox SET status='queued',
                        retry_count=retry_count+1, last_attempt=?
                    WHERE id IN ({','.join('?' * len(row_ids))})""",
                [self._now(), *row_ids],
            )

    def depth(self) -> int:
        with self._connect() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM outbox WHERE status != 'acked'").fetchone()[0]

    def stats(self) -> dict:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*), MAX(retry_count) FROM outbox GROUP BY status"
            ).fetchall()
        return {s: {"count": c, "max_retry": m} for s, c, m in rows}

    def prune_expired(self, retention_days: int) -> int:
        cutoff_ms = int((time.time() - retention_days * 86400) * 1000)
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM outbox WHERE CAST(strftime('%s', created_at) AS INT)"
                " < CAST(? AS INT)",
                (cutoff_ms // 1000,),
            )
            return cur.rowcount

    def _enforce_caps(self, conn: sqlite3.Connection) -> None:
        total = conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]
        if total > self._max_rows:
            conn.execute(
                """DELETE FROM outbox WHERE id IN (
                       SELECT id FROM outbox ORDER BY id LIMIT ?)""",
                (total - self._max_rows,),
            )
            logger.warning("outbox cap hit (%d); dropped oldest rows", self._max_rows)

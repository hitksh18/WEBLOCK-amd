"""Durable executed-command ledger (SQLite, same outbox file).

Bounds: keeps the 1000 most recent command_ids. Survives restarts —
idempotency never relies on memory alone.
"""
import logging
import sqlite3
import threading
from datetime import datetime, timezone

logger = logging.getLogger("weblock-agent.ledger")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS processed_commands (
    command_id TEXT PRIMARY KEY,
    action_type TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL DEFAULT '{}',
    processed_at TEXT NOT NULL
);
"""

MAX_LEDGER_ROWS = 1000


class CommandLedger:
    def __init__(self, db_path: str):
        self._path = db_path
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def seen(self, command_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT status, result FROM processed_commands WHERE command_id=?",
                (command_id,)).fetchone()
        if row:
            return {"status": row[0], "result": row[1]}
        return None

    def record(self, command_id: str, action_type: str,
               status: str, result: str = "{}") -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO processed_commands
                   (command_id, action_type, status, result, processed_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (command_id, action_type, status, result,
                 datetime.now(timezone.utc).isoformat()))
            conn.execute(
                """DELETE FROM processed_commands WHERE command_id NOT IN (
                       SELECT command_id FROM processed_commands
                       ORDER BY processed_at DESC LIMIT ?)""",
                (MAX_LEDGER_ROWS,))

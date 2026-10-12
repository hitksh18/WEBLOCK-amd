"""Identity collector: active user session snapshot."""
import getpass
import socket
from datetime import datetime, timezone

from weblock_agent.models.telemetry import make_event


def collect() -> list[dict]:
    try:
        user = getpass.getuser()
    except OSError:
        user = "unknown"
    return [make_event("auth", {
        "kind": "session_snapshot",
        "user": user,
        "host": socket.gethostname(),
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }, source="agent:identity")]

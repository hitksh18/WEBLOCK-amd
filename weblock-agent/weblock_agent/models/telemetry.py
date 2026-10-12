"""Versioned telemetry envelope (mirrors server schema_version 1.0).

{
  "event_id": uuid4,
  "schema_version": "1.0",
  "type": auth|process|network|system|usb|heartbeat,
  "occurred_at": UTC ISO-8601,
  "source": "agent[:collector]",
  "payload": {...}
}
"""
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from weblock_agent import SCHEMA_VERSION

TELEMETRY_TYPES = ("auth", "process", "network", "system", "usb", "heartbeat")


@dataclass
class TelemetryEvent:
    type: str
    payload: dict
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: str = SCHEMA_VERSION
    occurred_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "agent"

    def __post_init__(self) -> None:
        if self.type not in TELEMETRY_TYPES:
            raise ValueError(f"Unknown telemetry type: {self.type}")
        # Fail fast on non-serializable payloads (server would 422 them).
        json.dumps(self.payload)

    def to_dict(self) -> dict:
        return asdict(self)


def make_event(event_type: str, payload: dict, source: str = "agent") -> dict:
    return TelemetryEvent(type=event_type, payload=payload, source=source).to_dict()

"""Telemetry + endpoint Pydantic contracts (schema_version 1.0)."""
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

SCHEMA_VERSION = "1.0"
TELEMETRY_TYPES = ("auth", "process", "network", "system", "usb", "heartbeat")
TelemetryType = Literal["auth", "process", "network", "system", "usb", "heartbeat"]
MAX_BATCH_EVENTS = 500
MAX_EVENT_PAYLOAD_BYTES = 256 * 1024


class TelemetryEventIn(BaseModel):
    event_id: str = Field(min_length=8, max_length=64)
    schema_version: Literal["1.0"] = "1.0"
    type: TelemetryType
    occurred_at: datetime
    source: str = Field(default="agent", max_length=64)
    payload: dict = Field(default_factory=dict)

    @field_validator("event_id")
    @classmethod
    def _event_id_format(cls, v: str) -> str:
        # Accept UUIDs (agent-generated) or opaque stable IDs.
        try:
            UUID(v)
            return v
        except ValueError:
            if all(c.isalnum() or c in "-_:" for c in v):
                return v
            raise ValueError("event_id must be UUID or [A-Za-z0-9-_:] string")

    @field_validator("occurred_at")
    @classmethod
    def _occurred_at_sane(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware ISO-8601")
        now = datetime.now(timezone.utc)
        if (v - now).total_seconds() > 300:
            raise ValueError("occurred_at is more than 5 minutes in the future")
        if (now - v).total_seconds() > 366 * 86400:
            raise ValueError("occurred_at is unreasonably old")
        return v


class TelemetryBatchIn(BaseModel):
    agent_id: str = Field(min_length=1, max_length=255)
    events: list[TelemetryEventIn] = Field(min_length=1, max_length=MAX_BATCH_EVENTS)


class TelemetryBatchOut(BaseModel):
    accepted: int
    duplicates: int
    rejected: list[dict] = []


class EnrollIn(BaseModel):
    enroll_token: str = Field(min_length=8, max_length=128)
    device: dict = Field(default_factory=dict)


class HeartbeatIn(BaseModel):
    agent_version: str | None = Field(default=None, max_length=50)
    hostname: str | None = Field(default=None, max_length=255)
    os: str | None = Field(default=None, max_length=100)
    os_version: str | None = Field(default=None, max_length=100)
    ip: str | None = Field(default=None, max_length=45)
    queue_depth: int = Field(default=0, ge=0)
    collectors: dict = Field(default_factory=dict)
    # Phase 8: agent-advertised response capabilities + isolation state.
    capabilities: dict = Field(default_factory=dict)
    isolation_active: bool | None = None


DEFAULT_AGENT_CONFIG: dict = {
    "heartbeat_interval": 60,
    "batch_interval": 60,
    "collectors": {
        "identity": True,
        "process": True,
        "network": True,
        "eventlog": True,
        "system": True,
        "usb": True,
    },
    "log_level": "INFO",
    "retention_days": 7,
    "max_batch_events": MAX_BATCH_EVENTS,
}

CONFIG_MUTABLE_KEYS = set(DEFAULT_AGENT_CONFIG)


def merge_config(overrides: dict | None) -> dict:
    merged = {k: (dict(v) if isinstance(v, dict) else v)
              for k, v in DEFAULT_AGENT_CONFIG.items()}
    for key, value in (overrides or {}).items():
        if key not in CONFIG_MUTABLE_KEYS:
            raise ValueError(f"Unknown config key: {key}")
        if key == "collectors":
            if not isinstance(value, dict):
                raise ValueError("collectors must be an object")
            for ck, cv in value.items():
                if ck not in merged["collectors"]:
                    raise ValueError(f"Unknown collector: {ck}")
                if not isinstance(cv, bool):
                    raise ValueError(f"Collector flag must be bool: {ck}")
            merged["collectors"].update(value)
        else:
            merged[key] = value
    hb = merged["heartbeat_interval"]
    bi = merged["batch_interval"]
    if not isinstance(hb, int) or not 10 <= hb <= 3600:
        raise ValueError("heartbeat_interval must be int in [10, 3600]")
    if not isinstance(bi, int) or not 10 <= bi <= 3600:
        raise ValueError("batch_interval must be int in [10, 3600]")
    if merged["log_level"] not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        raise ValueError("log_level must be DEBUG/INFO/WARNING/ERROR")
    rd = merged["retention_days"]
    if not isinstance(rd, int) or not 1 <= rd <= 90:
        raise ValueError("retention_days must be int in [1, 90]")
    return merged

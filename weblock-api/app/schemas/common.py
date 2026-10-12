"""Pydantic v2 schemas with strict validation. Malformed telemetry is rejected."""
import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field, field_validator

Role = Literal["admin", "analyst", "investigator", "viewer"]
Severity = Literal["low", "medium", "high", "critical"]
IncidentStatus = Literal["open", "investigating", "contained", "resolved", "closed"]
Classification = Literal["Genuine", "Suspicious", "Intruder"]

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    role: str
    org_id: int


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=10)


class LogoutRequest(BaseModel):
    refresh_token: str = Field(min_length=10)


class AnalyzeLoginRequest(BaseModel):
    """Phase 0 compatibility adapter. user_id resolved server-side via email."""

    user_email: EmailStr | None = None
    user_id: int | None = None
    ip_address: str
    mac_address: str | None = None
    device_fingerprint: str | None = Field(default=None, max_length=1024)
    geo_location: str | None = Field(default=None, max_length=100)

    @field_validator("ip_address")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        import ipaddress

        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {v}") from exc
        return v

    @field_validator("mac_address")
    @classmethod
    def _valid_mac(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not _MAC_RE.match(v):
            raise ValueError(f"Invalid MAC address: {v}")
        return v.upper()

    def resolve_user_id(self, db_user_id: int | None = None) -> int:
        if self.user_id is not None:
            return self.user_id
        if db_user_id is not None:
            return db_user_id
        raise ValueError("user_id or user_email required")


class AnalyzeLoginResponse(BaseModel):
    event_id: int
    incident_id: int | None = None
    incident_key: str | None = None
    risk_score: int
    classification: Classification
    confidence: float
    explanation: str
    factors: list[str] = []


class IncidentOut(BaseModel):
    id: int
    incident_key: str
    title: str
    severity: Severity
    risk_score: int
    status: IncidentStatus
    user_id: int | None
    endpoint_id: int | None
    summary: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class HealthOut(BaseModel):
    application: str
    version: str
    environment: str
    database: str
    database_latency_ms: float | None = None


class AuditLogOut(BaseModel):
    id: int
    action: str
    actor_id: int | None
    target: str | None
    meta_data: dict[str, Any] | None = None
    created_at: datetime

    model_config = {"from_attributes": True}

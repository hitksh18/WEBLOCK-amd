"""WebLock Phase 0 SQLAlchemy 2.x models.

Conventions:
- Every organization-owned table has org_id (org isolation).
- Enums stored as VARCHAR with CHECK-friendly values; validated in Pydantic too.
- Evidence carries sha256 + chain-of-custody JSONB for future forensic chaining.
- endpoints table exists (nullable FK from incidents) so Phase 1 telemetry has
  a place to land; no agent code writes to it in Phase 0.
"""
from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    users: Mapped[list["User"]] = relationship(back_populates="org")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("org_id", "email", name="uq_users_org_email"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    # admin | analyst | investigator | viewer
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="viewer")
    is_blocked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    baseline_ip: Mapped[str | None] = mapped_column(String(45))
    baseline_mac: Mapped[str | None] = mapped_column(String(50))
    baseline_fingerprint: Mapped[str | None] = mapped_column(Text)
    baseline_country: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    org: Mapped["Organization"] = relationship(back_populates="users")


class Endpoint(Base):
    """Phase 0: enrollment-ready stub. No agent writes here yet."""

    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    hostname: Mapped[str | None] = mapped_column(String(255))
    os_name: Mapped[str | None] = mapped_column(String(100))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    mac_address: Mapped[str | None] = mapped_column(String(50))
    fingerprint: Mapped[str | None] = mapped_column(Text)
    agent_version: Mapped[str | None] = mapped_column(String(50))
    # healthy | degraded | isolated | offline | revoked
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="healthy")
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    name: Mapped[str] = mapped_column(String(255), default="")
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # Phase 8: agent-advertised response capabilities (see AGENT_CAPABILITIES).
    capabilities: Mapped[dict] = mapped_column(JSON, nullable=False,
                                               default=dict)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class OrgPolicy(Base):
    """DB-backed successor of abc_corp_policy.json. One row per org."""

    __tablename__ = "org_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    allowed_countries: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    risk_threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=75)
    roles: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    user_overrides: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class LoginEvent(Base):
    __tablename__ = "login_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ip_address: Mapped[str | None] = mapped_column(String(45))
    mac_address: Mapped[str | None] = mapped_column(String(50))
    device_fingerprint: Mapped[str | None] = mapped_column(Text)
    geo_location: Mapped[str | None] = mapped_column(Text)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Genuine | Suspicious | Intruder
    classification: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_id: Mapped[int] = mapped_column(
        ForeignKey("login_events.id", ondelete="CASCADE"), nullable=False, index=True
    )
    anomaly_score: Mapped[float] = mapped_column(nullable=False, default=0.0)
    model_confidence: Mapped[float] = mapped_column(nullable=False, default=1.0)
    explanation: Mapped[str | None] = mapped_column(Text)
    model_version: Mapped[str] = mapped_column(String(50), default="v4-policy-engine")
    factors: Mapped[dict | None] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint("org_id", "incident_key", name="uq_incidents_org_key"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    incident_key: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    # low | medium | high | critical
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # open | investigating | contained | resolved | closed
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    endpoint_id: Mapped[int | None] = mapped_column(
        ForeignKey("endpoints.id", ondelete="SET NULL")
    )
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    event_id: Mapped[int | None] = mapped_column(
        ForeignKey("login_events.id", ondelete="SET NULL")
    )
    # Phase 6: incident-from-correlation linkage (nullable; legacy
    # login-incidents use user_id/event_id instead and keep working).
    correlation_id: Mapped[int | None] = mapped_column(
        ForeignKey("correlation_clusters.id", ondelete="SET NULL"), index=True
    )
    risk_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("risk_snapshots.id", ondelete="SET NULL")
    )
    summary: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Phase 7: nullable — reference evidence may exist without an incident.
    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    source: Mapped[str] = mapped_column(String(100), nullable=False, default="login")
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    content: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    collector: Mapped[str] = mapped_column(String(255), default="weblock-server")
    chain_of_custody: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # Phase 7 forensic extension (legacy rows: source_type LOGIN).
    correlation_id: Mapped[int | None] = mapped_column(
        ForeignKey("correlation_clusters.id", ondelete="SET NULL")
    )
    source_type: Mapped[str] = mapped_column(String(32), default="LOGIN", index=True)
    source_id: Mapped[int | None] = mapped_column(Integer, index=True)
    collected_by: Mapped[str] = mapped_column(String(255), default="weblock-server")
    integrity_status: Mapped[str] = mapped_column(
        String(16), default="UNVERIFIED", index=True)  # UNVERIFIED|VERIFIED|TAMPERED
    description: Mapped[str] = mapped_column(Text, default="")
    meta: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class CustodyRecord(Base):
    """Hash-chained chain-of-custody entry (engineering audit trail).

    record_hash = sha256(prev_hash + canonical(action|evidence|actor|ts|reason)).
    Actions are CHECK-constrained; no legal-admissibility claim.
    """

    __tablename__ = "custody_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_id: Mapped[int] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action: Mapped[str] = mapped_column(String(24), nullable=False)
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    reason: Mapped[str] = mapped_column(String(500), default="")
    meta_data: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), default="GENESIS")
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class EvidenceSnapshot(Base):
    """Immutable incident evidence snapshot (references + hash, no blobs)."""

    __tablename__ = "evidence_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    evidence_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    snapshot_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class ForensicReport(Base):
    """Versioned forensic report (immutable versions, hashed bytes)."""

    __tablename__ = "forensic_reports"
    __table_args__ = (
        UniqueConstraint("incident_id", "version",
                         name="uq_reports_incident_version"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    format: Mapped[str] = mapped_column(String(16), nullable=False)  # json|pdf
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    generated_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    file_path: Mapped[str] = mapped_column(String(500), default="")
    content: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class AIAnalysis(Base):
    """Versioned AI analyst output (immutable per version).

    The canonical analysis is the VALIDATED structured payload; raw provider
    text is never stored. History rows are never updated.
    """

    __tablename__ = "ai_analyses"
    __table_args__ = (
        UniqueConstraint("incident_id", "version",
                         name="uq_ai_incident_version"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    provider: Mapped[str] = mapped_column(String(64), default="")
    model: Mapped[str] = mapped_column(String(128), default="")
    prompt_version: Mapped[str] = mapped_column(String(16), default="1")
    output_version: Mapped[str] = mapped_column(String(16), default="1")
    context_hash: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(24), default="REQUESTED",
                                        index=True)
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    analysis: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    validation_status: Mapped[str] = mapped_column(String(24), default="PENDING")
    error_code: Mapped[str] = mapped_column(String(64), default="")
    error_message: Mapped[str] = mapped_column(String(1000), default="")


class ResponseAction(Base):
    """Policy-gated response request (one row per request/attempt-chain).

    Terminal statuses (FAILED/EXPIRED/CANCELLED/POLICY_DENIED) free the
    idempotency key for a fresh request; non-terminal rows collide safely.
    """

    __tablename__ = "response_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    endpoint_id: Mapped[int] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    requested_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    target: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    reason: Mapped[str] = mapped_column(String(1000), default="")
    execution_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="REQUESTED", index=True)
    policy_decision: Mapped[dict] = mapped_column(JSON, nullable=False,
                                                  default=dict)
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    result: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    error_code: Mapped[str] = mapped_column(String(64), default="")
    error_message: Mapped[str] = mapped_column(String(1000), default="")
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AgentCommand(Base):
    """One dispatchable command for a response action attempt."""

    __tablename__ = "agent_commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    response_action_id: Mapped[int] = mapped_column(
        ForeignKey("response_actions.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    command_id: Mapped[str] = mapped_column(String(64), nullable=False,
                                            unique=True, index=True)
    endpoint_id: Mapped[int] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    execution_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="PENDING", index=True)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    result: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    start_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="active")


class RefreshToken(Base):
    """Hashed refresh-token store so logout revokes."""

    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="SET NULL"), index=True
    )
    actor_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    target: Mapped[str | None] = mapped_column(String(255))
    meta_data: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )


class EnrollmentToken(Base):
    """Single-use enrollment secret (only sha256 stored)."""

    __tablename__ = "enrollment_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    label: Mapped[str] = mapped_column(String(255), default="")
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AgentCredential(Base):
    """Persistent endpoint API key (only sha256 stored, shown once)."""

    __tablename__ = "agent_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True,
    )
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class TelemetryEvent(Base):
    """Versioned agent telemetry. Dedup key: (endpoint_id, event_id)."""

    __tablename__ = "telemetry_events"
    __table_args__ = (
        UniqueConstraint("endpoint_id", "event_id",
                         name="uq_telemetry_endpoint_event"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    endpoint_id: Mapped[int] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), default="agent")
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Phase 7 chain metadata. event_hash contract unchanged:
    #  'sha256-received-v1' = as-received bytes (linkage-verifiable only);
    #  'sha256-canonical-v1' = server-canonical form (fully recomputable).
    prev_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    chain_seq: Mapped[int | None] = mapped_column(BigInteger, index=True)
    hash_algorithm: Mapped[str] = mapped_column(String(32),
                                                default="sha256-received-v1")
    # Phase 2 processing metadata — raw payload is NEVER mutated.
    processing_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="RECEIVED",
        index=True)  # RECEIVED|NORMALIZED|PROCESSED|FAILED
    normalization_version: Mapped[str | None] = mapped_column(String(16))
    event_category: Mapped[str] = mapped_column(String(32), default="")
    processing_error: Mapped[str] = mapped_column(Text, default="")
    normalized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SecurityEvent(Base):
    """Normalized security event — stable contract for detection/correlation.

    Structured columns cover what rules query; event-specific detail stays in
    `attributes`; the full raw envelope stays in telemetry_events (FK).
    """

    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    endpoint_id: Mapped[int] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    telemetry_ref: Mapped[int] = mapped_column(
        ForeignKey("telemetry_events.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True,
    )
    event_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    subtype: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity_hint: Mapped[str] = mapped_column(String(16), default="info")
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    actor: Mapped[str] = mapped_column(String(255), default="")
    host: Mapped[str] = mapped_column(String(255), default="")
    proc_name: Mapped[str] = mapped_column(String(255), default="")
    proc_pid: Mapped[int | None] = mapped_column(Integer)
    proc_exe: Mapped[str] = mapped_column(Text, default="")
    remote_addr: Mapped[str] = mapped_column(String(255), default="")
    remote_port: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), default="NORMALIZED", index=True)
    error: Mapped[str] = mapped_column(Text, default="")
    norm_version: Mapped[str] = mapped_column(String(16), default="1")
    attributes: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class DetectionRule(Base):
    """DB-backed rule config. org_id NULL = global. Phase 3 adds real rules."""

    __tablename__ = "detection_rules"
    __table_args__ = (
        UniqueConstraint("org_id", "rule_id", name="uq_rules_org_rule"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    category: Mapped[str] = mapped_column(String(32), default="")
    version: Mapped[str] = mapped_column(String(16), default="1")
    params: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    mitre: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Detection(Base):
    """A rule match. References security_events; never copies raw payloads."""

    __tablename__ = "detections"
    __table_args__ = (
        UniqueConstraint("org_id", "rule_id", "rule_version", "primary_event_id",
                         name="uq_detections_idempotency"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    endpoint_id: Mapped[int] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule_version: Mapped[str] = mapped_column(String(16), default="1")
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(nullable=False, default=0.0)
    status: Mapped[str] = mapped_column(String(24), default="open", index=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, default="")
    primary_event_id: Mapped[int] = mapped_column(
        ForeignKey("security_events.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    related_event_ids: Mapped[list] = mapped_column(JSON, nullable=False,
                                                    default=list)
    meta_data: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )


class CorrelationCluster(Base):
    """A group of related detections (multi-stage behavior candidate).

    Member detections live in correlation_members; payloads are never copied
    here. Phase 6 consumes clusters to decide on incidents.
    """

    __tablename__ = "correlation_clusters"
    __table_args__ = (
        UniqueConstraint("org_id", "correlation_key",
                         name="uq_clusters_org_key"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    endpoint_id: Mapped[int] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    correlation_key: Mapped[str] = mapped_column(String(128), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    severity: Mapped[str] = mapped_column(String(16), default="low")
    detection_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    distinct_family_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0)
    families: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    primary_detection_id: Mapped[int | None] = mapped_column(
        ForeignKey("detections.id", ondelete="SET NULL")
    )
    explanation: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class CorrelationMember(Base):
    __tablename__ = "correlation_members"
    __table_args__ = (
        UniqueConstraint("cluster_id", "detection_id",
                         name="uq_members_cluster_detection"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cluster_id: Mapped[int] = mapped_column(
        ForeignKey("correlation_clusters.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    detection_id: Mapped[int] = mapped_column(
        ForeignKey("detections.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class RiskSnapshot(Base):
    """Point-in-time contextual risk for an endpoint (append-only history).

    Snapshots are written when the score changes (or on forced recompute),
    so polling the risk API does not spam rows. Phase 6 reads these.
    """

    __tablename__ = "risk_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    endpoint_id: Mapped[int] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    factors: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    inputs: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

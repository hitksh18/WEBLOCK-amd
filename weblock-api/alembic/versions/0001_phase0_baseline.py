"""Phase 0 baseline: organizations, users, endpoints, org_policies,
login_events, risk_assessments, incidents, evidence, sessions,
refresh_tokens, audit_logs.

Revision ID: 0001_phase0_baseline
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_phase0_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(255), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("email", sa.String(255), nullable=False, index=True),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("role", sa.String(50), nullable=False,
                  server_default="viewer"),
        sa.Column("is_blocked", sa.Boolean(), nullable=False,
                  server_default=sa.false()),
        sa.Column("baseline_ip", sa.String(45)),
        sa.Column("baseline_mac", sa.String(50)),
        sa.Column("baseline_fingerprint", sa.Text()),
        sa.Column("baseline_country", sa.String(100)),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("org_id", "email", name="uq_users_org_email"),
    )
    op.create_table(
        "endpoints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("agent_id", sa.String(255), nullable=False, unique=True),
        sa.Column("hostname", sa.String(255)),
        sa.Column("os_name", sa.String(100)),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("mac_address", sa.String(50)),
        sa.Column("fingerprint", sa.Text()),
        sa.Column("agent_version", sa.String(50)),
        sa.Column("status", sa.String(50), nullable=False,
                  server_default="healthy"),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_heartbeat", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "org_policies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, unique=True, index=True),
        sa.Column("allowed_countries", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="[]"),
        sa.Column("risk_threshold", sa.Integer(), nullable=False,
                  server_default="75"),
        sa.Column("roles", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="{}"),
        sa.Column("user_overrides", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="{}"),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now()),
    )
    op.create_table(
        "login_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("user_id", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("mac_address", sa.String(50)),
        sa.Column("device_fingerprint", sa.Text()),
        sa.Column("geo_location", sa.Text()),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("classification", sa.String(50), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False, index=True),
    )
    op.create_table(
        "risk_assessments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("event_id", sa.Integer(),
                  sa.ForeignKey("login_events.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("anomaly_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("model_confidence", sa.Float(), nullable=False, server_default="1"),
        sa.Column("explanation", sa.Text()),
        sa.Column("model_version", sa.String(50),
                  server_default="v4-policy-engine"),
        sa.Column("factors", postgresql.JSONB(astext_type=sa.Text()),
                  server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("incident_key", sa.String(50), nullable=False, index=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("endpoint_id", sa.Integer(),
                  sa.ForeignKey("endpoints.id", ondelete="SET NULL")),
        sa.Column("user_id", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("event_id", sa.Integer(),
                  sa.ForeignKey("login_events.id", ondelete="SET NULL")),
        sa.Column("summary", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now()),
        sa.UniqueConstraint("org_id", "incident_key", name="uq_incidents_org_key"),
    )
    op.create_table(
        "evidence",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("incident_id", sa.Integer(),
                  sa.ForeignKey("incidents.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("source", sa.String(100), nullable=False, server_default="login"),
        sa.Column("collected_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("content", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="{}"),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("collector", sa.String(255), server_default="weblock-server"),
        sa.Column("chain_of_custody", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="{}"),
    )
    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("user_id", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("start_time", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("end_time", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(50), nullable=False, server_default="active"),
    )
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="SET NULL"),
                  index=True),
        sa.Column("actor_id", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("action", sa.String(100), nullable=False, index=True),
        sa.Column("target", sa.String(255)),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()),
                  server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False, index=True),
    )


def downgrade() -> None:
    for table in ("audit_logs", "refresh_tokens", "sessions", "evidence",
                  "incidents", "risk_assessments", "login_events",
                  "org_policies", "endpoints", "users", "organizations"):
        op.drop_table(table)

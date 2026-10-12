"""Phase 1: endpoint enrollment, agent credentials, telemetry events.

- enrollment_tokens: single-use bootstrap secrets (sha256 only)
- agent_credentials: persistent endpoint API keys (sha256 only)
- telemetry_events: versioned agent telemetry, dedup on (endpoint, event_id)
- endpoints: rename last_heartbeat -> last_seen, add name + config JSONB

Revision ID: 0002_phase1_endpoints_telemetry
Revises: 0001_phase0_baseline
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002_phase1_endpoints_telemetry"
down_revision = "0001_phase0_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "enrollment_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("label", sa.String(255), server_default=""),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "agent_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("endpoint_id", sa.Integer(),
                  sa.ForeignKey("endpoints.id", ondelete="CASCADE"),
                  nullable=False, unique=True, index=True),
        sa.Column("key_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("revoked", sa.Boolean(), nullable=False,
                  server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "telemetry_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("endpoint_id", sa.Integer(),
                  sa.ForeignKey("endpoints.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("event_id", sa.String(64), nullable=False),
        sa.Column("schema_version", sa.String(16), nullable=False,
                  server_default="1.0"),
        sa.Column("type", sa.String(32), nullable=False, index=True),
        sa.Column("source", sa.String(64), nullable=False, server_default="agent"),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False,
                  index=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="{}"),
        sa.Column("event_hash", sa.String(64), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("endpoint_id", "event_id",
                            name="uq_telemetry_endpoint_event"),
    )
    op.alter_column("endpoints", "last_heartbeat", new_column_name="last_seen")
    op.add_column("endpoints",
                  sa.Column("name", sa.String(255), server_default=""))
    op.add_column("endpoints",
                  sa.Column("config", postgresql.JSONB(astext_type=sa.Text()),
                            nullable=False, server_default="{}"))


def downgrade() -> None:
    op.drop_column("endpoints", "config")
    op.drop_column("endpoints", "name")
    op.alter_column("endpoints", "last_seen", new_column_name="last_heartbeat")
    op.drop_table("telemetry_events")
    op.drop_table("agent_credentials")
    op.drop_table("enrollment_tokens")

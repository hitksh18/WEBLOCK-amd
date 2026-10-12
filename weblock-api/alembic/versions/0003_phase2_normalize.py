"""Phase 2: normalized security events + detection foundation.

- telemetry_events: processing metadata (status/version/category/error/at)
  — raw payload NEVER mutated.
- security_events: stable normalized contract for detection/correlation.
- detection_rules: DB-backed rule configs (global org_id NULL + per-org).
- detections: rule matches referencing security_events (no payload copies).

Revision ID: 0003_phase2_normalization_detection
Revises: 0002_phase1_endpoints_telemetry
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003_phase2_normalize"
down_revision = "0002_phase1_endpoints_telemetry"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("telemetry_events",
                  sa.Column("processing_status", sa.String(16),
                            nullable=False, server_default="RECEIVED"))
    op.add_column("telemetry_events",
                  sa.Column("normalization_version", sa.String(16),
                            server_default="1"))
    op.add_column("telemetry_events",
                  sa.Column("event_category", sa.String(32),
                            server_default=""))
    op.add_column("telemetry_events",
                  sa.Column("processing_error", sa.Text(), server_default=""))
    op.add_column("telemetry_events",
                  sa.Column("normalized_at", sa.DateTime(timezone=True)))

    op.create_table(
        "security_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("endpoint_id", sa.Integer(),
                  sa.ForeignKey("endpoints.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("telemetry_ref", sa.Integer(),
                  sa.ForeignKey("telemetry_events.id", ondelete="CASCADE"),
                  nullable=False, unique=True, index=True),
        sa.Column("event_id", sa.String(64), nullable=False, index=True),
        sa.Column("category", sa.String(32), nullable=False, index=True),
        sa.Column("subtype", sa.String(64), nullable=False, index=True),
        sa.Column("severity_hint", sa.String(16), nullable=False,
                  server_default="info"),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False,
                  index=True),
        sa.Column("received_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True)),
        sa.Column("actor", sa.String(255), server_default=""),
        sa.Column("host", sa.String(255), server_default=""),
        sa.Column("proc_name", sa.String(255), server_default=""),
        sa.Column("proc_pid", sa.Integer()),
        sa.Column("proc_exe", sa.Text(), server_default=""),
        sa.Column("remote_addr", sa.String(255), server_default=""),
        sa.Column("remote_port", sa.Integer()),
        sa.Column("status", sa.String(16), nullable=False,
                  server_default="NORMALIZED", index=True),
        sa.Column("error", sa.Text(), server_default=""),
        sa.Column("norm_version", sa.String(16), nullable=False,
                  server_default="1"),
        sa.Column("attributes", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="{}"),
    )
    op.create_index("ix_security_org_endpoint_occurred", "security_events",
                    ["org_id", "endpoint_id", "occurred_at"])
    op.create_index("ix_security_org_category_occurred", "security_events",
                    ["org_id", "category", "occurred_at"])

    op.create_table(
        "detection_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  index=True),  # NULL = global rule
        sa.Column("rule_id", sa.String(64), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), server_default=""),
        sa.Column("enabled", sa.Boolean(), nullable=False,
                  server_default=sa.true()),
        sa.Column("severity", sa.String(16), nullable=False,
                  server_default="medium"),
        sa.Column("category", sa.String(32), server_default=""),
        sa.Column("version", sa.String(16), nullable=False, server_default="1"),
        sa.Column("params", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="{}"),
        sa.Column("mitre", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now()),
        sa.UniqueConstraint("org_id", "rule_id", name="uq_rules_org_rule"),
    )
    op.create_table(
        "detections",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("endpoint_id", sa.Integer(),
                  sa.ForeignKey("endpoints.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("rule_id", sa.String(64), nullable=False, index=True),
        sa.Column("rule_version", sa.String(16), nullable=False,
                  server_default="1"),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(24), nullable=False,
                  server_default="open", index=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("explanation", sa.Text(), server_default=""),
        sa.Column("primary_event_id", sa.Integer(),
                  sa.ForeignKey("security_events.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("related_event_ids", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="[]"),
        sa.Column("meta_data", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="{}"),
        sa.Column("detected_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False, index=True),
        sa.UniqueConstraint("org_id", "rule_id", "rule_version",
                            "primary_event_id",
                            name="uq_detections_idempotency"),
    )


def downgrade() -> None:
    op.drop_table("detections")
    op.drop_table("detection_rules")
    op.drop_index("ix_security_org_category_occurred", "security_events")
    op.drop_index("ix_security_org_endpoint_occurred", "security_events")
    op.drop_table("security_events")
    for col in ("normalized_at", "processing_error", "event_category",
                "normalization_version", "processing_status"):
        op.drop_column("telemetry_events", col)

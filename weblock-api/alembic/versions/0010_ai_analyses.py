"""Phase 9: AI analyses persistence (versioned, immutable history).

Revision ID: 0010_ai_analyses
Revises: 0009_response
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0010_ai_analyses"
down_revision = "0009_response"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_analyses",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("incident_id", sa.Integer(),
                  sa.ForeignKey("incidents.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False,
                  server_default=""),
        sa.Column("model", sa.String(128), nullable=False, server_default=""),
        sa.Column("prompt_version", sa.String(16), nullable=False,
                  server_default="1"),
        sa.Column("output_version", sa.String(16), nullable=False,
                  server_default="1"),
        sa.Column("context_hash", sa.String(64), nullable=False,
                  server_default=""),
        sa.Column("status", sa.String(24), nullable=False,
                  server_default="REQUESTED", index=True),
        sa.Column("created_by", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("analysis", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="{}"),
        sa.Column("validation_status", sa.String(24), nullable=False,
                  server_default="PENDING"),
        sa.Column("error_code", sa.String(64), server_default=""),
        sa.Column("error_message", sa.String(1000), server_default=""),
        sa.CheckConstraint(
            "status IN ('REQUESTED','RUNNING','SUCCEEDED','FAILED',"
            "'AI_UNAVAILABLE','VALIDATION_FAILED')",
            name="ck_ai_status"),
        sa.UniqueConstraint("incident_id", "version",
                            name="uq_ai_incident_version"),
    )


def downgrade() -> None:
    op.drop_table("ai_analyses")

"""Phase 5: contextual risk snapshots (append-only history).

Revision ID: 0006_contextual_risk
Revises: 0005_correlation
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0006_contextual_risk"
down_revision = "0005_correlation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "risk_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("endpoint_id", sa.Integer(),
                  sa.ForeignKey("endpoints.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False, index=True),
        sa.Column("factors", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="[]"),
        sa.Column("inputs", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False, index=True),
    )
    op.create_index("ix_risk_org_endpoint_created", "risk_snapshots",
                    ["org_id", "endpoint_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_risk_org_endpoint_created", "risk_snapshots")
    op.drop_table("risk_snapshots")

"""Phase 4: correlation clusters + members (no payload duplication).

Revision ID: 0005_correlation
Revises: 0004_fix_detections_meta
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005_correlation"
down_revision = "0004_fix_detections_meta"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "correlation_clusters",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("endpoint_id", sa.Integer(),
                  sa.ForeignKey("endpoints.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("correlation_key", sa.String(128), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False,
                  index=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False,
                  index=True),
        sa.Column("status", sa.String(16), nullable=False,
                  server_default="open", index=True),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("severity", sa.String(16), nullable=False,
                  server_default="low"),
        sa.Column("detection_count", sa.Integer(), nullable=False,
                  server_default="0"),
        sa.Column("distinct_family_count", sa.Integer(), nullable=False,
                  server_default="0"),
        sa.Column("families", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="[]"),
        sa.Column("primary_detection_id", sa.Integer(),
                  sa.ForeignKey("detections.id", ondelete="SET NULL")),
        sa.Column("explanation", sa.Text(), server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now()),
        sa.UniqueConstraint("org_id", "correlation_key",
                            name="uq_clusters_org_key"),
    )
    op.create_table(
        "correlation_members",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cluster_id", sa.Integer(),
                  sa.ForeignKey("correlation_clusters.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("detection_id", sa.Integer(),
                  sa.ForeignKey("detections.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("added_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("cluster_id", "detection_id",
                            name="uq_members_cluster_detection"),
    )


def downgrade() -> None:
    op.drop_table("correlation_members")
    op.drop_table("correlation_clusters")

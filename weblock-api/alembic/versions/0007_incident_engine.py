"""Phase 6: incident engine columns on the Phase 0 incidents table.

- correlation_id: the cluster this incident responds to (nullable so
  legacy login-incidents keep working).
- risk_snapshot_id: the risk snapshot cited at creation (nullable).
- Partial unique index: one non-closed incident per cluster (race-safe
  idempotency; re-incident allowed after closure).

Revision ID: 0007_incident_engine
Revises: 0006_contextual_risk
"""
import sqlalchemy as sa
from alembic import op

revision = "0007_incident_engine"
down_revision = "0006_contextual_risk"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("incidents",
                  sa.Column("correlation_id", sa.Integer(),
                            sa.ForeignKey("correlation_clusters.id",
                                          ondelete="SET NULL"),
                            index=True))
    op.add_column("incidents",
                  sa.Column("risk_snapshot_id", sa.Integer(),
                            sa.ForeignKey("risk_snapshots.id",
                                          ondelete="SET NULL")))
    op.create_index(
        "uq_incidents_open_correlation", "incidents",
        ["org_id", "correlation_id"], unique=True,
        postgresql_where=sa.text("status <> 'closed' AND correlation_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_incidents_open_correlation", "incidents")
    op.drop_column("incidents", "risk_snapshot_id")
    op.drop_column("incidents", "correlation_id")

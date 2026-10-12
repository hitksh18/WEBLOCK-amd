"""Fix detections metadata column name (meta_data -> metadata, matches model).

Revision ID: 0004_fix_detections_meta
Revises: 0003_phase2_normalize
"""
import sqlalchemy as sa
from alembic import op

revision = "0004_fix_detections_meta"
down_revision = "0003_phase2_normalize"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("detections", "meta_data", new_column_name="metadata")


def downgrade() -> None:
    op.alter_column("detections", "metadata", new_column_name="meta_data")

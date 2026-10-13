"""Phase 7: forensic hash chain + evidence/custody/snapshot/report tables.

- telemetry_events: prev_hash, chain_seq, hash_algorithm. Backfill builds
  per-endpoint chains ordered by (occurred_at, id); pre-existing rows keep
  algorithm 'sha256-received-v1' (as-received bytes, linkage-verifiable
  only), new rows use 'sha256-canonical-v1' (server-canonical, fully
  recomputable). This transition is explicit, not silent.
- evidence: incident_id nullable; + correlation_id, source_type, source_id,
  collected_by, integrity_status, description, meta. Legacy rows mapped to
  source_type LOGIN.
- custody_records: hash-chained CoC actions (CHECK-constrained).
- evidence_snapshots, forensic_reports: immutable versioned artifacts.

Revision ID: 0008_forensics
Revises: 0007_incident_engine
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0008_forensics"
down_revision = "0007_incident_engine"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("telemetry_events",
                  sa.Column("prev_hash", sa.String(64)))
    op.add_column("telemetry_events",
                  sa.Column("chain_seq", sa.BigInteger(), index=True))
    op.add_column("telemetry_events",
                  sa.Column("hash_algorithm", sa.String(32),
                            nullable=False, server_default="sha256-received-v1"))
    op.create_index("uq_telemetry_endpoint_seq", "telemetry_events",
                      ["endpoint_id", "chain_seq"], unique=True,
                      postgresql_where=sa.text("chain_seq IS NOT NULL"))

    # Backfill per-endpoint chains over existing rows.
    op.execute(sa.text("""
        WITH ranked AS (
            SELECT id, endpoint_id, event_hash,
                   ROW_NUMBER() OVER (
                       PARTITION BY endpoint_id ORDER BY occurred_at, id) AS seq,
                   LAG(event_hash) OVER (
                       PARTITION BY endpoint_id ORDER BY occurred_at, id) AS prev
            FROM telemetry_events
        )
        UPDATE telemetry_events t
        SET chain_seq = r.seq, prev_hash = r.prev
        FROM ranked r WHERE t.id = r.id
    """))

    op.alter_column("evidence", "incident_id",
                    existing_type=sa.Integer(), nullable=True)
    op.add_column("evidence",
                  sa.Column("correlation_id", sa.Integer(),
                            sa.ForeignKey("correlation_clusters.id",
                                          ondelete="SET NULL")))
    op.add_column("evidence",
                  sa.Column("source_type", sa.String(32),
                            nullable=False, server_default="LOGIN"))
    op.add_column("evidence",
                  sa.Column("source_id", sa.Integer()))
    op.add_column("evidence",
                  sa.Column("collected_by", sa.String(255),
                            server_default="weblock-server"))
    op.add_column("evidence",
                  sa.Column("integrity_status", sa.String(16),
                            nullable=False, server_default="UNVERIFIED"))
    op.add_column("evidence",
                  sa.Column("description", sa.Text(), server_default=""))
    op.add_column("evidence",
                  sa.Column("meta", postgresql.JSONB(astext_type=sa.Text()),
                            nullable=False, server_default="{}"))
    op.create_index("ix_evidence_incident", "evidence", ["incident_id"])
    op.create_index("ix_evidence_source", "evidence",
                    ["source_type", "source_id"])

    op.create_table(
        "custody_records",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("evidence_id", sa.Integer(),
                  sa.ForeignKey("evidence.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("action", sa.String(24), nullable=False),
        sa.Column("actor_user_id", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False, index=True),
        sa.Column("reason", sa.String(500), server_default=""),
        sa.Column("meta_data", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="{}"),
        sa.Column("prev_hash", sa.String(64), nullable=False,
                  server_default="GENESIS"),
        sa.Column("record_hash", sa.String(64), nullable=False),
        sa.CheckConstraint(
            "action IN ('COLLECTED','STORED','VIEWED','VERIFIED','EXPORTED',"
            "'UPDATED_METADATA')",
            name="ck_custody_action"),
    )
    op.create_table(
        "evidence_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("incident_id", sa.Integer(),
                  sa.ForeignKey("incidents.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("created_by", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("evidence_ids", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="[]"),
        sa.Column("snapshot_hash", sa.String(64), nullable=False),
    )
    op.create_table(
        "forensic_reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("incident_id", sa.Integer(),
                  sa.ForeignKey("incidents.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("format", sa.String(16), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("generated_by", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("generated_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("file_path", sa.String(500), server_default=""),
        sa.Column("content", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="{}"),
        sa.UniqueConstraint("incident_id", "version",
                            name="uq_reports_incident_version"),
    )


def downgrade() -> None:
    op.drop_table("forensic_reports")
    op.drop_table("evidence_snapshots")
    op.drop_table("custody_records")
    op.drop_index("ix_evidence_source", "evidence")
    op.drop_index("ix_evidence_incident", "evidence")
    for col in ("meta", "description", "integrity_status", "collected_by",
                "source_id", "source_type", "correlation_id"):
        op.drop_column("evidence", col)
    op.alter_column("evidence", "incident_id",
                    existing_type=sa.Integer(), nullable=False)
    op.drop_index("uq_telemetry_endpoint_seq", "telemetry_events")
    for col in ("hash_algorithm", "chain_seq", "prev_hash"):
        op.drop_column("telemetry_events", col)

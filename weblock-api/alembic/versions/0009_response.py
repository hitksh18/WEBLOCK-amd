"""Phase 8: response actions + agent commands + endpoint capabilities.

- response_actions: policy-gated requests (unique idempotency key per org
  while non-terminal; CHECK-constrained type/mode/status).
- agent_commands: dispatch/execution rows per attempt (unique command_id).
- endpoints.capabilities: agent-advertised support map.

Revision ID: 0009_response
Revises: 0008_forensics
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0009_response"
down_revision = "0008_forensics"
branch_labels = None
depends_on = None

ACTION_TYPES = ("ISOLATE_ENDPOINT", "RESTORE_ISOLATION",
                "TERMINATE_PROCESS", "BLOCK_NETWORK_DESTINATION",
                "UNBLOCK_NETWORK_DESTINATION", "DISABLE_SESSION",
                "COLLECT_EVIDENCE")
MODES = ("SIMULATION", "LIVE")
ACTION_STATUSES = ("REQUESTED", "POLICY_DENIED", "QUEUED", "ACCEPTED",
                   "EXECUTING", "SUCCEEDED", "FAILED", "EXPIRED", "CANCELLED")
CMD_STATUSES = ("PENDING", "DELIVERED", "ACKED", "RESULT_RECEIVED", "EXPIRED")


def upgrade() -> None:
    op.add_column("endpoints",
                  sa.Column("capabilities",
                            postgresql.JSONB(astext_type=sa.Text()),
                            nullable=False, server_default="{}"))
    op.create_table(
        "response_actions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("incident_id", sa.Integer(),
                  sa.ForeignKey("incidents.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("endpoint_id", sa.Integer(),
                  sa.ForeignKey("endpoints.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("action_type", sa.String(32), nullable=False, index=True),
        sa.Column("requested_by", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("target", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="{}"),
        sa.Column("reason", sa.String(1000), server_default=""),
        sa.Column("execution_mode", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False,
                  server_default="REQUESTED", index=True),
        sa.Column("policy_decision", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="{}"),
        sa.Column("idempotency_key", sa.String(64), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False,
                  server_default="3"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="{}"),
        sa.Column("error_code", sa.String(64), server_default=""),
        sa.Column("error_message", sa.String(1000), server_default=""),
        sa.Column("requested_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now()),
        sa.CheckConstraint(
            "action_type IN ('ISOLATE_ENDPOINT','RESTORE_ISOLATION',"
            "'TERMINATE_PROCESS','BLOCK_NETWORK_DESTINATION',"
            "'UNBLOCK_NETWORK_DESTINATION','DISABLE_SESSION',"
            "'COLLECT_EVIDENCE')",
            name="ck_response_action_type"),
        sa.CheckConstraint("execution_mode IN ('SIMULATION','LIVE')",
                           name="ck_response_mode"),
        sa.CheckConstraint(
            "status IN ('REQUESTED','POLICY_DENIED','QUEUED','ACCEPTED',"
            "'EXECUTING','SUCCEEDED','FAILED','EXPIRED','CANCELLED')",
            name="ck_response_status"),
    )
    op.create_index(
        "uq_response_idempotency", "response_actions",
        ["org_id", "idempotency_key"], unique=True,
        postgresql_where=sa.text(
            "status NOT IN ('FAILED','EXPIRED','CANCELLED','POLICY_DENIED')"),
    )
    op.create_table(
        "agent_commands",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("response_action_id", sa.Integer(),
                  sa.ForeignKey("response_actions.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("command_id", sa.String(64), nullable=False, unique=True,
                  index=True),
        sa.Column("endpoint_id", sa.Integer(),
                  sa.ForeignKey("endpoints.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("action_type", sa.String(32), nullable=False),
        sa.Column("target", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="{}"),
        sa.Column("execution_mode", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False,
                  server_default="PENDING", index=True),
        sa.Column("issued_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="{}"),
        sa.CheckConstraint(
            "status IN ('PENDING','DELIVERED','ACKED','RESULT_RECEIVED',"
            "'EXPIRED')",
            name="ck_command_status"),
    )


def downgrade() -> None:
    op.drop_table("agent_commands")
    op.drop_index("uq_response_idempotency", "response_actions")
    op.drop_table("response_actions")
    op.drop_column("endpoints", "capabilities")

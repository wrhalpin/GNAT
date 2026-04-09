"""Add agent_sessions and agent_actions tables (Phase 4D).

Postgres-backed agent memory and audit trail.  All agent actions
pass through AgentGovernor which writes here for complete auditability.

Revision ID: 0006
Revises: 0005
Create Date: 2026-04-08 00:00:06.000000

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_sessions",
        sa.Column("session_id",  sa.String(36),  primary_key=True),
        sa.Column("agent_id",    sa.String(128), nullable=False, index=True),
        sa.Column("created_at",  sa.DateTime(timezone=True), nullable=False),
        sa.Column("context_id",  sa.String(36),  nullable=True),  # FK to execution_log.context_id
        sa.Column("state_json",  sa.Text,        nullable=True),
    )

    op.create_table(
        "agent_actions",
        sa.Column("action_id",    sa.String(36),  primary_key=True),
        sa.Column("agent_id",     sa.String(128), nullable=False, index=True),
        sa.Column("session_id",   sa.String(36),  nullable=True),  # FK to agent_sessions
        sa.Column("action_type",  sa.String(64),  nullable=False),
        sa.Column("target_ref",   sa.String(256), nullable=True),
        sa.Column("impact_level", sa.String(16),  nullable=False, server_default="low"),  # low/medium/high/critical
        sa.Column("approved_by",  sa.String(128), nullable=True),
        sa.Column("executed_at",  sa.DateTime(timezone=True), nullable=True),
        sa.Column("result_json",  sa.Text,        nullable=True),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status",       sa.String(32),  nullable=False, server_default="pending"),  # pending/approved/rejected/executed
    )
    op.create_index("ix_agent_actions_agent_status", "agent_actions", ["agent_id", "status"])


def downgrade() -> None:
    op.drop_index("ix_agent_actions_agent_status", "agent_actions")
    op.drop_table("agent_actions")
    op.drop_table("agent_sessions")

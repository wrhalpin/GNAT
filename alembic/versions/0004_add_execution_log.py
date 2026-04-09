"""Add execution_log table (Phase 4A).

Append-only audit log for all GNAT operations.  Every pipeline run,
enrichment call, connector request, and agent action writes one row.

Revision ID: 0004
Revises: 0003
Create Date: 2026-04-08 00:00:04.000000

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "execution_log",
        sa.Column("context_id",       sa.String(36),  primary_key=True),
        sa.Column("initiated_by",     sa.String(128), nullable=False),
        sa.Column("domain",           sa.String(32),  nullable=False, index=True),
        sa.Column("trust_level",      sa.String(32),  nullable=False, index=True),
        sa.Column("policy_set",       sa.String(64),  nullable=False, server_default="default"),
        sa.Column("workspace_id",     sa.String(256), nullable=False),
        sa.Column("created_at",       sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("parent_context_id", sa.String(36), nullable=True),
        sa.Column("is_replay",        sa.Boolean,     nullable=False, server_default="0"),
        sa.Column("event_type",       sa.String(64),  nullable=True),  # "security_event", "replay_event", etc.
        sa.Column("notes",            sa.Text,        nullable=True),
    )
    op.create_index(
        "ix_execution_log_workspace_domain",
        "execution_log",
        ["workspace_id", "domain"],
    )


def downgrade() -> None:
    op.drop_index("ix_execution_log_workspace_domain", "execution_log")
    op.drop_table("execution_log")

"""Add workflow_runs table.

Stores workflow execution history for the autonomous investigation pipeline.

Revision ID: 0009
Revises: 0008
Create Date: 2026-04-09 00:00:09.000000

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "workflow_runs",
        sa.Column("run_id",           sa.String(36),              primary_key=True),
        sa.Column("workflow_name",    sa.String(128),             nullable=False),
        sa.Column("status",           sa.String(32),              nullable=False),
        sa.Column("context_json",     sa.Text,                    nullable=False, server_default="{}"),
        sa.Column("steps_completed",  sa.Text,                    nullable=False, server_default="[]"),
        sa.Column("steps_failed",     sa.Text,                    nullable=False, server_default="[]"),
        sa.Column("errors",           sa.Text,                    nullable=False, server_default="[]"),
        sa.Column("elapsed_seconds",  sa.Float,                   nullable=False, server_default="0"),
        sa.Column("investigation_id", sa.String(128),             nullable=True),
        sa.Column("created_at",       sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at",       sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_workflow_runs_name",    "workflow_runs", ["workflow_name"])
    op.create_index("ix_workflow_runs_status",  "workflow_runs", ["status"])
    op.create_index("ix_workflow_runs_inv_id",  "workflow_runs", ["investigation_id"])
    op.create_index("ix_workflow_runs_created", "workflow_runs", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_workflow_runs_created", "workflow_runs")
    op.drop_index("ix_workflow_runs_inv_id",  "workflow_runs")
    op.drop_index("ix_workflow_runs_status",  "workflow_runs")
    op.drop_index("ix_workflow_runs_name",    "workflow_runs")
    op.drop_table("workflow_runs")

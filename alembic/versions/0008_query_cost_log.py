"""Add query_cost_log table (Phase 4E).

Tracks per-connector query cost for capacity planning and budget enforcement.

Revision ID: 0008
Revises: 0007
Create Date: 2026-04-08 00:00:08.000000

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "query_cost_log",
        sa.Column("id",           sa.Integer,     primary_key=True, autoincrement=True),
        sa.Column("connector_id", sa.String(128), nullable=False, index=True),
        sa.Column("cost_units",   sa.Integer,     nullable=False),
        sa.Column("context_id",   sa.String(36),  nullable=True),  # FK to execution_log
        sa.Column("operation",    sa.String(64),  nullable=True),   # "bulk_pull", "lookup", "search"
        sa.Column("timestamp",    sa.DateTime(timezone=True), nullable=False, index=True),
    )
    op.create_index(
        "ix_query_cost_connector_ts",
        "query_cost_log",
        ["connector_id", "timestamp"],
    )


def downgrade() -> None:
    op.drop_index("ix_query_cost_connector_ts", "query_cost_log")
    op.drop_table("query_cost_log")

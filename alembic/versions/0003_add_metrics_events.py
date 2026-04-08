"""Add metrics_events table (Phase 3D).

Persistent backing store for analyst metrics events.

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-08 00:00:02.000000

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "metrics_events",
        sa.Column("id",          sa.Integer,     primary_key=True, autoincrement=True),
        sa.Column("metric_type", sa.String(64),  nullable=False, index=True),
        sa.Column("value",       sa.Float,       nullable=False),
        sa.Column("labels_json", sa.Text,        nullable=True),
        sa.Column("timestamp",   sa.DateTime(timezone=True), nullable=False, index=True),
    )
    op.create_index("ix_metrics_events_type_ts", "metrics_events", ["metric_type", "timestamp"])


def downgrade() -> None:
    op.drop_index("ix_metrics_events_type_ts", "metrics_events")
    op.drop_table("metrics_events")

"""Add lineage_events table (Phase 3C).

Append-only event log for data provenance and traceability.

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-08 00:00:01.000000

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "lineage_events",
        sa.Column("id",           sa.String(36),  primary_key=True),
        sa.Column("event_type",   sa.String(32),  nullable=False, index=True),
        sa.Column("object_id",    sa.String(256), nullable=False, index=True),
        sa.Column("object_type",  sa.String(64),  nullable=False),
        sa.Column("actor",        sa.String(256), nullable=False),
        sa.Column("source",       sa.String(256), nullable=False),
        sa.Column("metadata_json", sa.Text,       nullable=True),
        sa.Column("timestamp",    sa.DateTime(timezone=True), nullable=False, index=True),
    )
    op.create_index("ix_lineage_events_object_id_ts", "lineage_events", ["object_id", "timestamp"])


def downgrade() -> None:
    op.drop_index("ix_lineage_events_object_id_ts", "lineage_events")
    op.drop_table("lineage_events")

"""Add idempotency_key to workspace_objects (Phase 4B).

Enables safe pipeline replay: re-ingesting the same STIX object produces
a single stored row with a logged replay_event rather than a duplicate.

Revision ID: 0005
Revises: 0004
Create Date: 2026-04-08 00:00:05.000000

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("workspace_objects") as batch_op:
        batch_op.add_column(
            sa.Column(
                "idempotency_key",
                sa.String(255),
                nullable=True,
                unique=False,
            )
        )
    op.create_index(
        "ix_workspace_objects_idempotency",
        "workspace_objects",
        ["idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_workspace_objects_idempotency", "workspace_objects")
    with op.batch_alter_table("workspace_objects") as batch_op:
        batch_op.drop_column("idempotency_key")

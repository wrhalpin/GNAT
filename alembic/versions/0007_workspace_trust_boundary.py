"""Add trust_boundary and allowed_connector_refs to workspaces (Phase 4E).

Enables workspace isolation: connectors whose TRUST_LEVEL is below the
workspace's trust_boundary are rejected at instantiation time.

Revision ID: 0007
Revises: 0006
Create Date: 2026-04-08 00:00:07.000000

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("workspaces") as batch_op:
        batch_op.add_column(
            sa.Column(
                "trust_boundary",
                sa.String(32),
                nullable=False,
                server_default="semi_trusted",
            )
        )
        batch_op.add_column(
            sa.Column(
                "allowed_connector_refs",
                sa.Text,  # JSON array of connector class names; NULL = all allowed
                nullable=True,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("workspaces") as batch_op:
        batch_op.drop_column("allowed_connector_refs")
        batch_op.drop_column("trust_boundary")

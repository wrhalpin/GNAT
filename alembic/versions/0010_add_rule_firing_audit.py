"""Add rule_firing_audit table

Revision ID: 0010
Revises: 0009
Create Date: 2026-04-19
"""

import sqlalchemy as sa

from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rule_firing_audit",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("investigation_id", sa.String(255), nullable=False),
        sa.Column("hypothesis_id", sa.String(255), nullable=False),
        sa.Column("workspace_id", sa.Integer, nullable=False),
        sa.Column("rule_name", sa.Text, nullable=False),
        sa.Column("rule_source_file", sa.Text, nullable=False),
        sa.Column("rule_git_sha", sa.String(40), nullable=True),
        sa.Column(
            "fired_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("decision", sa.JSON, nullable=False),
        sa.Column(
            "applied",
            sa.Boolean,
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("engine_version", sa.String(32), nullable=False),
    )
    op.create_index(
        "idx_rfa_hypothesis",
        "rule_firing_audit",
        ["hypothesis_id"],
    )
    op.create_index(
        "idx_rfa_rule_time",
        "rule_firing_audit",
        ["rule_name", "fired_at"],
    )
    op.create_index(
        "idx_rfa_investigation",
        "rule_firing_audit",
        ["investigation_id", "fired_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_rfa_investigation", table_name="rule_firing_audit")
    op.drop_index("idx_rfa_rule_time", table_name="rule_firing_audit")
    op.drop_index("idx_rfa_hypothesis", table_name="rule_firing_audit")
    op.drop_table("rule_firing_audit")

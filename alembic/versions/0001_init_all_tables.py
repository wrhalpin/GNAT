"""Init all GNAT tables.

Creates the six core GNAT tables in a single initial migration:
- investigations
- reports
- workspaces
- workspace_objects
- enrichment_log
- context_globals

Revision ID: 0001
Revises: (none — first migration)
Create Date: 2026-04-08 00:00:00.000000

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers
revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── investigations ──────────────────────────────────────────────────────
    op.create_table(
        "investigations",
        sa.Column("id",                 sa.String(36),  primary_key=True),
        sa.Column("title",              sa.String(512), nullable=False, index=True),
        sa.Column("status",             sa.String(32),  nullable=False, index=True, default="open"),
        sa.Column("classification",     sa.String(32),  nullable=False, default="amber"),
        sa.Column("created_by",         sa.String(256), nullable=False, index=True),
        sa.Column("tags_csv",           sa.Text,        nullable=True,  default=""),
        sa.Column("investigation_json", sa.Text,        nullable=False),
        sa.Column("created_at",         sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("updated_at",         sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_deleted",         sa.Boolean,     nullable=False, default=False),
    )

    # ── reports ─────────────────────────────────────────────────────────────
    op.create_table(
        "reports",
        sa.Column("id",                 sa.String(36),  primary_key=True),
        sa.Column("title",              sa.String(512), nullable=False, index=True),
        sa.Column("report_type",        sa.String(64),  nullable=False, index=True),
        sa.Column("status",             sa.String(32),  nullable=False, index=True, default="draft"),
        sa.Column("classification",     sa.String(32),  nullable=False, default="amber"),
        sa.Column("authors_csv",        sa.Text,        nullable=True,  default=""),
        sa.Column("tags_csv",           sa.Text,        nullable=True,  default=""),
        sa.Column("linked_investigation", sa.String(36), nullable=True, index=True),
        sa.Column("stix_report_ref",    sa.String(256), nullable=True),
        sa.Column("parent_report_id",   sa.String(36),  nullable=True),
        sa.Column("version",            sa.Integer,     nullable=False, default=1),
        sa.Column("report_json",        sa.Text,        nullable=False),
        sa.Column("published_at",       sa.DateTime(timezone=True), nullable=True, index=True),
        sa.Column("created_at",         sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("updated_at",         sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_deleted",         sa.Boolean,     nullable=False, default=False),
    )

    # ── workspaces ──────────────────────────────────────────────────────────
    op.create_table(
        "workspaces",
        sa.Column("id",           sa.String(36),  primary_key=True),
        sa.Column("name",         sa.String(256), nullable=False, index=True),
        sa.Column("description",  sa.Text,        nullable=True),
        sa.Column("owner",        sa.String(256), nullable=True, index=True),
        sa.Column("tags",         sa.Text,        nullable=True),
        sa.Column("created_at",   sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("updated_at",   sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_success", sa.DateTime(timezone=True), nullable=True),
    )

    # ── workspace_objects ───────────────────────────────────────────────────
    op.create_table(
        "workspace_objects",
        sa.Column("id",           sa.String(64),  primary_key=True),   # stix_id
        sa.Column("workspace_id", sa.String(36),  nullable=False, index=True),
        sa.Column("stix_type",    sa.String(64),  nullable=False, index=True),
        sa.Column("stix_json",    sa.Text,        nullable=False),
        sa.Column("source",       sa.String(256), nullable=True),
        sa.Column("is_dirty",     sa.Boolean,     nullable=False, default=True),
        sa.Column("created_at",   sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at",   sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
    )

    # ── enrichment_log ──────────────────────────────────────────────────────
    op.create_table(
        "enrichment_log",
        sa.Column("id",              sa.Integer,    primary_key=True, autoincrement=True),
        sa.Column("workspace_id",    sa.String(36), nullable=False, index=True),
        sa.Column("stix_id",         sa.String(64), nullable=False, index=True),
        sa.Column("source_platform", sa.String(64), nullable=False),
        sa.Column("enrichment_json", sa.Text,       nullable=False),
        sa.Column("strategy",        sa.String(32), nullable=True),
        sa.Column("created_at",      sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
    )

    # ── context_globals ─────────────────────────────────────────────────────
    op.create_table(
        "context_globals",
        sa.Column("id",          sa.String(36),  primary_key=True),
        sa.Column("name",        sa.String(256), nullable=False, unique=True, index=True),
        sa.Column("description", sa.Text,        nullable=True),
        sa.Column("config_json", sa.Text,        nullable=True),
        sa.Column("created_at",  sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at",  sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("context_globals")
    op.drop_table("enrichment_log")
    op.drop_table("workspace_objects")
    op.drop_table("workspaces")
    op.drop_table("reports")
    op.drop_table("investigations")

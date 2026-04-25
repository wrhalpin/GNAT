# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Pydantic v2 schema for rule firing audit records."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RuleAuditEntrySchema(BaseModel):
    """A single rule firing audit record."""

    model_config = ConfigDict(from_attributes=True)

    id: int | None = Field(
        default=None,
        description="Audit record ID.",
    )
    investigation_id: str = Field(
        default="",
        description="ID of the investigation this firing relates to.",
    )
    hypothesis_id: str = Field(
        default="",
        description="ID of the hypothesis this firing relates to.",
    )
    workspace_id: int = Field(
        default=0,
        description="Workspace ID.",
    )
    rule_name: str = Field(
        description="Name of the rule that fired.",
    )
    rule_source_file: str = Field(
        default="",
        description="Path to the rule source file.",
    )
    rule_git_sha: str | None = Field(
        default=None,
        description="Git commit SHA of the rule source file at firing time.",
    )
    fired_at: str = Field(
        description="ISO 8601 timestamp of the firing.",
    )
    decision: dict[str, Any] = Field(
        default_factory=dict,
        description="Serialised decision payload (action, reason, target_status, key, value).",
    )
    applied: bool = Field(
        default=False,
        description="Whether the decision has been applied.",
    )
    applied_at: str | None = Field(
        default=None,
        description="ISO 8601 timestamp when the decision was applied.",
    )
    error_message: str | None = Field(
        default=None,
        description="Error message if application failed.",
    )
    engine_version: str = Field(
        default="1.0.0",
        description="Version of the rule engine that produced this firing.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> RuleAuditEntrySchema:
        """Hydrate from a domain audit record dict."""
        if isinstance(obj, dict):
            return cls.model_validate(obj)
        return cls.model_validate(obj, from_attributes=True)

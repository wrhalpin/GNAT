# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Pydantic v2 schema for an engine-agnostic rule representation."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RuleSchema(BaseModel):
    """Engine-agnostic representation of a rule definition."""

    model_config = ConfigDict(from_attributes=True)

    name: str = Field(
        description="Unique rule name.",
    )
    source_file: str = Field(
        default="",
        description="Path to the rule source file.",
    )
    engine: str = Field(
        default="",
        description="Rule engine type (hy, yaml, prolog).",
    )
    description: str = Field(
        default="",
        description="Human-readable rule description.",
    )
    enabled: bool = Field(
        default=True,
        description="Whether the rule is active.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary rule metadata.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> RuleSchema:
        """Hydrate from a domain rule object."""
        return cls.model_validate(obj, from_attributes=True)

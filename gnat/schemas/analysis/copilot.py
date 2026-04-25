# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Pydantic v2 schemas for copilot gap detection and report drafting."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class GapRecommendationSchema(BaseModel):
    """A single detected evidence gap with remediation guidance."""

    model_config = ConfigDict(from_attributes=True)

    description: str = Field(
        description="What is missing.",
    )
    severity: Literal["critical", "high", "medium", "low"] = Field(
        description="How important this gap is to address.",
    )
    suggested_action: str = Field(
        description="Concrete analyst action to close the gap.",
    )
    rule_id: str = Field(
        description="Identifier of the rule that triggered this gap.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> GapRecommendationSchema:
        """Hydrate from a domain GapRecommendation dataclass."""
        return cls.model_validate(obj, from_attributes=True)


class DraftResultSchema(BaseModel):
    """The output of a drafting assistant call."""

    model_config = ConfigDict(from_attributes=True)

    executive_summary: str = Field(
        description="Drafted executive summary text (markdown).",
    )
    key_findings_narrative: str = Field(
        description="Drafted key-findings narrative (markdown).",
    )
    model: str = Field(
        default="",
        description="LLM model identifier used.",
    )
    prompt_tokens: int = Field(
        default=0,
        description="Approximate prompt token count.",
    )
    completion_tokens: int = Field(
        default=0,
        description="Approximate completion token count.",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Any warnings generated during drafting.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> DraftResultSchema:
        """Hydrate from a domain DraftResult dataclass."""
        return cls.model_validate(obj, from_attributes=True)

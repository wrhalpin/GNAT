# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Pydantic v2 schema for the ConfidenceScore composite model."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ConfidenceScoreSchema(BaseModel):
    """Composite confidence combining the NATO Admiralty Scale with STIX numeric confidence."""

    model_config = ConfigDict(from_attributes=True)

    source_reliability: Literal["A", "B", "C", "D", "E", "F"] = Field(
        description="Admiralty Scale source reliability grade (A-F).",
    )
    information_credibility: Literal[1, 2, 3, 4, 5, 6] = Field(
        description="Admiralty Scale information credibility grade (1-6).",
    )
    stix_confidence: int = Field(
        ge=0,
        le=100,
        description="STIX 2.1 numeric confidence in range 0-100.",
    )
    rationale: str | None = Field(
        default=None,
        description="Human-readable explanation for the assigned confidence level.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> ConfidenceScoreSchema:
        """Hydrate from a domain ConfidenceScore dataclass."""
        return cls.model_validate(obj, from_attributes=True)

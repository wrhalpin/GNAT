# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Pydantic v2 schema for the investigative graph context."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class GraphContextSchema(BaseModel):
    """A mutable sub-graph assembled by GraphQuery operations."""

    model_config = ConfigDict(from_attributes=True)

    nodes: dict[str, Any] = Field(
        default_factory=dict,
        description="Mapping of node_id to EvidenceNode.",
    )
    edges: list[Any] = Field(
        default_factory=list,
        description="EvidenceEdge objects connecting nodes in this context.",
    )
    seed_ids: list[str] = Field(
        default_factory=list,
        description="Node IDs that seeded this context.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> GraphContextSchema:
        """Hydrate from a domain GraphContext dataclass."""
        return cls.model_validate(obj, from_attributes=True)

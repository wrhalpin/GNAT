# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Pydantic v2 schemas for the Investigation object model."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from gnat.schemas.analysis.confidence import ConfidenceScoreSchema
from gnat.schemas.analysis.tlp import TLPLevelSchema


class InvestigationScopeSchema(BaseModel):
    """Temporal and thematic scope constraints for an Investigation."""

    model_config = ConfigDict(from_attributes=True)

    date_range_start: datetime | None = Field(
        default=None,
        description="Earliest activity date of interest.",
    )
    date_range_end: datetime | None = Field(
        default=None,
        description="Latest activity date of interest.",
    )
    target_sectors: list[str] = Field(
        default_factory=list,
        description="Industry verticals in scope.",
    )
    target_geographies: list[str] = Field(
        default_factory=list,
        description="Country codes or region names in scope.",
    )
    ioc_types: list[str] = Field(
        default_factory=list,
        description="STIX indicator types in scope.",
    )
    keywords: list[str] = Field(
        default_factory=list,
        description="Free-text keywords used during automated seed expansion.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> InvestigationScopeSchema:
        """Hydrate from a domain InvestigationScope dataclass."""
        return cls.model_validate(obj, from_attributes=True)


class HypothesisSchema(BaseModel):
    """A falsifiable analytical statement attached to an Investigation."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(
        description="UUID for this hypothesis.",
    )
    statement: str = Field(
        description="The falsifiable claim.",
    )
    confidence: ConfidenceScoreSchema | None = Field(
        default=None,
        description="Current confidence in the hypothesis.",
    )
    status: Literal["open", "supported", "refuted", "inconclusive"] = Field(
        default="open",
        description="Evaluation status of the hypothesis.",
    )
    supporting_evidence: list[str] = Field(
        default_factory=list,
        description="Artifact IDs that support this hypothesis.",
    )
    refuting_evidence: list[str] = Field(
        default_factory=list,
        description="Artifact IDs that contradict this hypothesis.",
    )
    created_at: datetime = Field(
        description="Creation timestamp.",
    )
    updated_at: datetime = Field(
        description="Last update timestamp.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> HypothesisSchema:
        """Hydrate from a domain Hypothesis dataclass."""
        return cls.model_validate(obj, from_attributes=True)


class AnalystNoteSchema(BaseModel):
    """A freeform markdown note attached to an Investigation."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(
        description="UUID for this note.",
    )
    content: str = Field(
        description="Markdown-formatted note body.",
    )
    author: str = Field(
        description="Analyst identifier (username or email).",
    )
    created_at: datetime = Field(
        description="Creation timestamp.",
    )
    linked_artifacts: list[str] = Field(
        default_factory=list,
        description="Optional artifact IDs this note annotates.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> AnalystNoteSchema:
        """Hydrate from a domain AnalystNote dataclass."""
        return cls.model_validate(obj, from_attributes=True)


class InvestigationTaskSchema(BaseModel):
    """An actionable task within an Investigation."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(
        description="UUID for this task.",
    )
    title: str = Field(
        description="Short task description.",
    )
    description: str = Field(
        default="",
        description="Detailed task body (markdown).",
    )
    status: Literal["todo", "in_progress", "done", "blocked"] = Field(
        default="todo",
        description="Current kanban state.",
    )
    priority: Literal["low", "medium", "high", "critical"] = Field(
        default="medium",
        description="Task urgency.",
    )
    assigned_to: str | None = Field(
        default=None,
        description="Analyst identifier.",
    )
    due_date: datetime | None = Field(
        default=None,
        description="Target completion date.",
    )
    created_at: datetime = Field(
        description="Creation timestamp.",
    )
    updated_at: datetime = Field(
        description="Last update timestamp.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> InvestigationTaskSchema:
        """Hydrate from a domain InvestigationTask dataclass."""
        return cls.model_validate(obj, from_attributes=True)


class InvestigationSchema(BaseModel):
    """The top-level analyst workspace for a security investigation."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(
        description="UUID for this investigation.",
    )
    title: str = Field(
        description="Short descriptive title.",
    )
    description: str = Field(
        default="",
        description="Markdown-formatted investigation description and background.",
    )
    status: Literal["open", "in_progress", "review", "closed"] = Field(
        default="open",
        description="Current lifecycle state.",
    )
    classification: TLPLevelSchema = Field(
        default=TLPLevelSchema.AMBER,
        description="TLP classification for this investigation.",
    )
    created_by: str = Field(
        description="Analyst who created this investigation.",
    )
    assigned_to: list[str] = Field(
        default_factory=list,
        description="Analysts currently assigned to this investigation.",
    )
    scope: InvestigationScopeSchema = Field(
        default_factory=InvestigationScopeSchema,
        description="Temporal and thematic scope constraints.",
    )
    hypothesis: list[HypothesisSchema] = Field(
        default_factory=list,
        description="Analytical hypotheses under evaluation.",
    )
    notes: list[AnalystNoteSchema] = Field(
        default_factory=list,
        description="Freeform markdown notes.",
    )
    tasks: list[InvestigationTaskSchema] = Field(
        default_factory=list,
        description="Actionable tasks.",
    )
    indicators: list[str] = Field(
        default_factory=list,
        description="Normalized indicator IDs linked to this investigation.",
    )
    observables: list[str] = Field(
        default_factory=list,
        description="Observable IDs linked to this investigation.",
    )
    threat_actors: list[str] = Field(
        default_factory=list,
        description="STIX ThreatActor IDs linked to this investigation.",
    )
    campaigns: list[str] = Field(
        default_factory=list,
        description="STIX Campaign IDs linked to this investigation.",
    )
    reports: list[str] = Field(
        default_factory=list,
        description="Report IDs produced from this investigation.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Free-text tags for search and filtering.",
    )
    source_connectors: list[str] = Field(
        default_factory=list,
        description="Platform names that contributed data.",
    )
    stix_bundle_ref: str | None = Field(
        default=None,
        description="STIX bundle ID if this investigation has been exported.",
    )
    created_at: datetime = Field(
        description="Creation timestamp.",
    )
    updated_at: datetime = Field(
        description="Last update timestamp.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> InvestigationSchema:
        """Hydrate from a domain Investigation dataclass."""
        return cls.model_validate(obj, from_attributes=True)

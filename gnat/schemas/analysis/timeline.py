# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Pydantic v2 schema for timeline events."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from gnat.schemas.analysis.confidence import ConfidenceScoreSchema


class TimelineEventSchema(BaseModel):
    """A single event on an investigation or campaign timeline."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(
        description="UUID for this event.",
    )
    timestamp: datetime = Field(
        description="Event timestamp (UTC).",
    )
    title: str = Field(
        description="Short event description.",
    )
    event_type: Literal[
        "indicator_first_seen",
        "indicator_last_seen",
        "attack_phase",
        "victim_identified",
        "incident_opened",
        "incident_closed",
        "investigation_opened",
        "investigation_closed",
        "analyst_note",
        "task_completed",
        "report_published",
        "alert",
        "observable",
        "other",
    ] = Field(
        default="other",
        description="Classification of the event origin and significance.",
    )
    precision: Literal["exact", "hour", "day", "month", "year"] = Field(
        default="exact",
        description="How precise the timestamp is.",
    )
    description: str = Field(
        default="",
        description="Detailed markdown description.",
    )
    linked_artifacts: list[str] = Field(
        default_factory=list,
        description="Artifact IDs related to this event.",
    )
    source: str = Field(
        default="",
        description="Platform or analyst that generated this event.",
    )
    confidence: ConfidenceScoreSchema | None = Field(
        default=None,
        description="Confidence in this event's timing or attribution.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> TimelineEventSchema:
        """Hydrate from a domain TimelineEvent dataclass."""
        return cls.model_validate(obj, from_attributes=True)

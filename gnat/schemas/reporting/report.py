# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Pydantic v2 schemas for the Report object model."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from gnat.schemas.analysis.confidence import ConfidenceScoreSchema
from gnat.schemas.analysis.tlp import TLPLevelSchema


class EvidenceLinkSchema(BaseModel):
    """A statement-to-artifact binding supporting (or contradicting) a Finding."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(
        description="UUID for this evidence link.",
    )
    statement: str = Field(
        description="The claim this artifact supports, contradicts, or contextualises.",
    )
    artifact_type: str = Field(
        description="STIX object type of the linked artifact.",
    )
    artifact_id: str = Field(
        description="STIX ID or platform-specific ID of the artifact.",
    )
    artifact_source: str = Field(
        description="Platform name that contributed this artifact.",
    )
    link_type: Literal["supports", "contradicts", "contextualizes"] = Field(
        default="supports",
        description="How the artifact relates to the statement.",
    )
    confidence: ConfidenceScoreSchema | None = Field(
        default=None,
        description="Confidence for this specific evidence link.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> EvidenceLinkSchema:
        """Hydrate from a domain EvidenceLink dataclass."""
        return cls.model_validate(obj, from_attributes=True)


class FindingSchema(BaseModel):
    """A key analytical finding within a Report."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(
        description="UUID for this finding.",
    )
    statement: str = Field(
        description="The analytical conclusion.",
    )
    confidence: ConfidenceScoreSchema | None = Field(
        default=None,
        description="Confidence in this finding.",
    )
    supporting_evidence: list[str] = Field(
        default_factory=list,
        description="IDs of EvidenceLink objects that support this finding.",
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="ATT&CK technique IDs relevant to this finding.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> FindingSchema:
        """Hydrate from a domain Finding dataclass."""
        return cls.model_validate(obj, from_attributes=True)


class AttributionSchema(BaseModel):
    """Threat actor attribution for a Report."""

    model_config = ConfigDict(from_attributes=True)

    threat_actor_name: str = Field(
        description="Display name of the attributed threat actor.",
    )
    confidence: ConfidenceScoreSchema = Field(
        description="Attribution confidence.",
    )
    rationale: str = Field(
        description="Explanation of the attribution basis.",
    )
    threat_actor_id: str | None = Field(
        default=None,
        description="STIX ThreatActor SDO ID.",
    )
    mitre_group_id: str | None = Field(
        default=None,
        description="MITRE ATT&CK group ID.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> AttributionSchema:
        """Hydrate from a domain Attribution dataclass."""
        return cls.model_validate(obj, from_attributes=True)


class ReportSectionSchema(BaseModel):
    """A titled section of report body content."""

    model_config = ConfigDict(from_attributes=True)

    title: str = Field(
        description="Section heading.",
    )
    content: str = Field(
        default="",
        description="Markdown-formatted section body.",
    )
    order: int = Field(
        default=0,
        description="Display order (lower = earlier in document).",
    )

    @classmethod
    def from_domain(cls, obj: object) -> ReportSectionSchema:
        """Hydrate from a domain ReportSection dataclass."""
        return cls.model_validate(obj, from_attributes=True)


class ChangelogEntrySchema(BaseModel):
    """A version history entry for a Report."""

    model_config = ConfigDict(from_attributes=True)

    version: int = Field(
        description="Report version number.",
    )
    changed_by: str = Field(
        description="Analyst who made this change.",
    )
    summary: str = Field(
        description="Short description of what changed.",
    )
    changed_at: datetime = Field(
        description="Timestamp of the change.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> ChangelogEntrySchema:
        """Hydrate from a domain ChangelogEntry dataclass."""
        return cls.model_validate(obj, from_attributes=True)


class ReportSchema(BaseModel):
    """A structured intelligence product."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(
        description="UUID for this report.",
    )
    title: str = Field(
        description="Report title.",
    )
    report_type: Literal[
        "incident_report",
        "threat_actor_profile",
        "campaign_analysis",
        "daily_brief",
        "vulnerability_advisory",
        "finished_intelligence",
    ] = Field(
        description="Category of intelligence product.",
    )
    status: Literal["draft", "review", "approved", "published", "archived"] = Field(
        default="draft",
        description="Current lifecycle state.",
    )
    classification: TLPLevelSchema = Field(
        default=TLPLevelSchema.AMBER,
        description="TLP classification.",
    )
    authors: list[str] = Field(
        default_factory=list,
        description="Analyst identifiers.",
    )
    reviewers: list[str] = Field(
        default_factory=list,
        description="Reviewer identifiers.",
    )
    executive_summary: str = Field(
        default="",
        description="Markdown-formatted executive summary.",
    )
    key_findings: list[FindingSchema] = Field(
        default_factory=list,
        description="Key analytical conclusions.",
    )
    body_sections: list[ReportSectionSchema] = Field(
        default_factory=list,
        description="Full report body, ordered by section.order.",
    )
    recommendations: list[str] = Field(
        default_factory=list,
        description="Action recommendations.",
    )
    attribution: AttributionSchema | None = Field(
        default=None,
        description="Threat actor attribution, if applicable.",
    )
    overall_confidence: ConfidenceScoreSchema | None = Field(
        default=None,
        description="Overall report confidence.",
    )
    evidence_links: list[EvidenceLinkSchema] = Field(
        default_factory=list,
        description="Statement-to-artifact bindings.",
    )
    linked_investigation: str | None = Field(
        default=None,
        description="ID of the Investigation this report was produced from.",
    )
    version: int = Field(
        default=1,
        description="Report version number.",
    )
    changelog: list[ChangelogEntrySchema] = Field(
        default_factory=list,
        description="Version history.",
    )
    parent_report_id: str | None = Field(
        default=None,
        description="ID of the previous published version.",
    )
    distribution_list: list[str] = Field(
        default_factory=list,
        description="Recipients for dissemination.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Free-text tags.",
    )
    stix_report_ref: str | None = Field(
        default=None,
        description="STIX Report SDO ID, set when the report is published.",
    )
    stix_bundle_json: str | None = Field(
        default=None,
        description="JSON-serialised STIX bundle, set when the report is published.",
    )
    published_at: datetime | None = Field(
        default=None,
        description="Publication timestamp.",
    )
    created_at: datetime = Field(
        description="Creation timestamp.",
    )
    updated_at: datetime = Field(
        description="Last update timestamp.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> ReportSchema:
        """Hydrate from a domain Report dataclass."""
        return cls.model_validate(obj, from_attributes=True)

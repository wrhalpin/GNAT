# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Pydantic v2 schemas for the evidence graph model."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from gnat.schemas.investigations.seed import SeedSchema


class EvidenceNodeSchema(BaseModel):
    """A normalised record from any connected platform."""

    model_config = ConfigDict(from_attributes=True)

    node_id: str = Field(
        description="Stable deduplication key: '{platform}::{node_type}::{source_id}'.",
    )
    node_type: Literal[
        "incident",
        "observable",
        "asset",
        "identity",
        "finding",
        "task",
        "decision",
        "artifact",
        "timeline_event",
    ] = Field(
        description="Normalised record category regardless of source platform.",
    )
    platform: str = Field(
        description="Source connector name.",
    )
    source_id: str = Field(
        description="Native platform identifier.",
    )
    stix: dict[str, Any] = Field(
        default_factory=dict,
        description="Normalised STIX 2.1 SDO built from the native record.",
    )
    raw: dict[str, Any] = Field(
        default_factory=dict,
        description="Unmodified platform API response.",
    )
    ioc_values: list[str] = Field(
        default_factory=list,
        description="Extracted indicator values (IPs, domains, hashes, URLs).",
    )
    hostnames: list[str] = Field(
        default_factory=list,
        description="Extracted hostnames / asset names.",
    )
    usernames: list[str] = Field(
        default_factory=list,
        description="Extracted usernames / identity references.",
    )
    campaign_labels: list[str] = Field(
        default_factory=list,
        description="Campaign or actor labels found in tags, names, or custom fields.",
    )
    ticket_refs: list[str] = Field(
        default_factory=list,
        description="External ticket references (Jira, ServiceNow, etc.).",
    )
    infrastructure_roles: list[str] = Field(
        default_factory=list,
        description="Infrastructure classification roles.",
    )
    time_window: tuple[str, str] | None = Field(
        default=None,
        description="Earliest and latest timestamps found in the record.",
    )
    origin: str = Field(
        default="gnat",
        description="Which tool produced this node.",
    )
    investigation_id: str | None = Field(
        default=None,
        description="x_gnat_investigation_id from the source STIX object.",
    )
    investigation_origin: str | None = Field(
        default=None,
        description="x_gnat_investigation_origin from the source STIX object.",
    )
    investigation_link_type: str | None = Field(
        default=None,
        description="x_gnat_investigation_link_type (confirmed, inferred, or suggested).",
    )

    @classmethod
    def from_domain(cls, obj: object) -> EvidenceNodeSchema:
        """Hydrate from a domain EvidenceNode dataclass."""
        return cls.model_validate(obj, from_attributes=True)


class EvidenceEdgeSchema(BaseModel):
    """A directed relationship between two EvidenceNode objects."""

    model_config = ConfigDict(from_attributes=True)

    source_id: str = Field(
        description="node_id of the source node.",
    )
    target_id: str = Field(
        description="node_id of the target node.",
    )
    relationship_type: str = Field(
        description="Relationship verb (e.g. 'part-of', 'same-ioc', 'related-to').",
    )
    confidence: float = Field(
        default=1.0,
        description="0-1 confidence score.",
    )
    source_platform: str = Field(
        default="",
        description="Which platform produced this edge.",
    )
    reasoning: str = Field(
        default="",
        description="Human-readable justification.",
    )
    link_type: str = Field(
        default="inferred",
        description="Cross-tool link type: confirmed, inferred, or suggested.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> EvidenceEdgeSchema:
        """Hydrate from a domain EvidenceEdge dataclass."""
        return cls.model_validate(obj, from_attributes=True)


class EvidenceGraphSchema(BaseModel):
    """Container for the full evidence graph produced by InvestigationBuilder."""

    model_config = ConfigDict(from_attributes=True)

    title: str = Field(
        description="Human-readable investigation title.",
    )
    seeds: list[SeedSchema] = Field(
        default_factory=list,
        description="The seeds that started this investigation.",
    )
    nodes: dict[str, EvidenceNodeSchema] = Field(
        default_factory=dict,
        description="Mapping of node_id to EvidenceNode.",
    )
    edges: list[EvidenceEdgeSchema] = Field(
        default_factory=list,
        description="All structural and correlation edges.",
    )
    by_ioc: dict[str, list[str]] = Field(
        default_factory=dict,
        description="IOC value correlation index.",
    )
    by_hostname: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Hostname correlation index.",
    )
    by_username: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Username correlation index.",
    )
    by_campaign: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Campaign label correlation index.",
    )
    by_ticket: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Ticket reference correlation index.",
    )
    by_infra_role: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Infrastructure role correlation index.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> EvidenceGraphSchema:
        """Hydrate from a domain EvidenceGraph dataclass."""
        return cls.model_validate(obj, from_attributes=True)

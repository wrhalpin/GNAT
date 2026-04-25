# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Pydantic v2 enum schemas for report lifecycle states."""

from enum import Enum


class ReportTypeEnum(str, Enum):
    """Intelligence product type."""

    INCIDENT_REPORT = "incident_report"
    THREAT_ACTOR_PROFILE = "threat_actor_profile"
    CAMPAIGN_ANALYSIS = "campaign_analysis"
    DAILY_BRIEF = "daily_brief"
    VULNERABILITY_ADVISORY = "vulnerability_advisory"
    FINISHED_INTELLIGENCE = "finished_intelligence"


class ReportStatusEnum(str, Enum):
    """Lifecycle state of a Report."""

    DRAFT = "draft"
    REVIEW = "review"
    APPROVED = "approved"
    PUBLISHED = "published"
    ARCHIVED = "archived"


class EvidenceLinkTypeEnum(str, Enum):
    """How an artifact relates to a statement."""

    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    CONTEXTUALIZES = "contextualizes"

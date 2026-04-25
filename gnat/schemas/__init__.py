# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.schemas
=============

Pydantic v2 schema exports mirroring every domain dataclass.

Each schema uses ``ConfigDict(from_attributes=True)`` so Pydantic can
hydrate directly from dataclass instances via the ``from_domain()``
classmethod.
"""

from gnat.schemas.analysis.confidence import ConfidenceScoreSchema
from gnat.schemas.analysis.copilot import DraftResultSchema, GapRecommendationSchema
from gnat.schemas.analysis.graph import GraphContextSchema
from gnat.schemas.analysis.investigation import (
    AnalystNoteSchema,
    HypothesisSchema,
    InvestigationSchema,
    InvestigationScopeSchema,
    InvestigationTaskSchema,
)
from gnat.schemas.analysis.timeline import TimelineEventSchema
from gnat.schemas.analysis.tlp import TLPLevelSchema
from gnat.schemas.auth.identity import APIKeySchema, OIDCIdentitySchema
from gnat.schemas.investigations.graph import (
    EvidenceEdgeSchema,
    EvidenceGraphSchema,
    EvidenceNodeSchema,
)
from gnat.schemas.investigations.seed import SeedSchema
from gnat.schemas.reporting.lifecycle import (
    EvidenceLinkTypeEnum,
    ReportStatusEnum,
    ReportTypeEnum,
)
from gnat.schemas.reporting.report import (
    AttributionSchema,
    ChangelogEntrySchema,
    EvidenceLinkSchema,
    FindingSchema,
    ReportSchema,
    ReportSectionSchema,
)
from gnat.schemas.rules.audit import RuleAuditEntrySchema
from gnat.schemas.rules.rule import RuleSchema

__all__ = [
    "APIKeySchema",
    "AnalystNoteSchema",
    "AttributionSchema",
    "ChangelogEntrySchema",
    "ConfidenceScoreSchema",
    "DraftResultSchema",
    "EvidenceEdgeSchema",
    "EvidenceGraphSchema",
    "EvidenceLinkSchema",
    "EvidenceLinkTypeEnum",
    "EvidenceNodeSchema",
    "FindingSchema",
    "GapRecommendationSchema",
    "GraphContextSchema",
    "HypothesisSchema",
    "InvestigationSchema",
    "InvestigationScopeSchema",
    "InvestigationTaskSchema",
    "OIDCIdentitySchema",
    "ReportSchema",
    "ReportSectionSchema",
    "ReportStatusEnum",
    "ReportTypeEnum",
    "RuleAuditEntrySchema",
    "RuleSchema",
    "SeedSchema",
    "TLPLevelSchema",
    "TimelineEventSchema",
]

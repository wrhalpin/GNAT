# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.attribution
============================

Attribution and campaign tracking for GNAT.

Provides campaign lifecycle management, actor profile enrichment,
Diamond Model formalization, kill-chain tracking, infrastructure
classification, and competing-attribution hypothesis management.
"""

from gnat.analysis.attribution.actor_profile import ActorProfile
from gnat.analysis.attribution.diamond import DiamondAnalyzer, DiamondVertex
from gnat.analysis.attribution.hypothesis import (
    AttributionEngine,
    AttributionEvidence,
    AttributionHypothesis,
)
from gnat.analysis.attribution.infrastructure import (
    InfrastructureClassifier,
    InfrastructureNode,
    InfrastructureRole,
)
from gnat.analysis.attribution.killchain import (
    KillChainProgression,
    KillChainTracker,
)
from gnat.analysis.attribution.models import (
    CampaignProfile,
    CampaignStatus,
)
from gnat.analysis.attribution.query import CampaignQuery
from gnat.analysis.attribution.service import CampaignService
from gnat.analysis.attribution.storage import CampaignStore

__all__ = [
    "ActorProfile",
    "AttributionEngine",
    "AttributionEvidence",
    "AttributionHypothesis",
    "CampaignProfile",
    "CampaignQuery",
    "CampaignService",
    "CampaignStatus",
    "CampaignStore",
    "DiamondAnalyzer",
    "DiamondVertex",
    "InfrastructureClassifier",
    "InfrastructureNode",
    "InfrastructureRole",
    "KillChainProgression",
    "KillChainTracker",
]

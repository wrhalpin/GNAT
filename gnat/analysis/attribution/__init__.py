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

from gnat.analysis.attribution.models import (
    CampaignProfile,
    CampaignStatus,
)
from gnat.analysis.attribution.query import CampaignQuery
from gnat.analysis.attribution.service import CampaignService
from gnat.analysis.attribution.storage import CampaignStore

__all__ = [
    "CampaignProfile",
    "CampaignQuery",
    "CampaignService",
    "CampaignStatus",
    "CampaignStore",
]

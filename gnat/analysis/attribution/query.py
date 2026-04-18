# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.attribution.query
===================================

Query specification for listing/filtering campaigns, following the same
pattern as :class:`~gnat.analysis.investigations.query.InvestigationQuery`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from gnat.analysis.attribution.models import CampaignStatus


@dataclass
class CampaignQuery:
    """
    Filter criteria for campaign listing.

    All fields are optional — ``None`` means "no filter on this field".
    """

    status: list[CampaignStatus] | None = None
    tags: list[str] | None = None
    threat_actor_id: str | None = None
    parent_campaign_id: str | None = None
    text_search: str | None = None
    page: int = 1
    page_size: int = 25

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CampaignQuery:
        status = data.get("status")
        if isinstance(status, list):
            status = [CampaignStatus(s) for s in status]
        elif isinstance(status, str):
            status = [CampaignStatus(status)]
        else:
            status = None

        return cls(
            status=status,
            tags=data.get("tags"),
            threat_actor_id=data.get("threat_actor_id"),
            parent_campaign_id=data.get("parent_campaign_id"),
            text_search=data.get("text_search"),
            page=int(data.get("page", 1)),
            page_size=int(data.get("page_size", 25)),
        )

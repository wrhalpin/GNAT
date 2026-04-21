# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.attribution.service
=====================================

Business logic for campaign lifecycle management.

``CampaignService`` sits between the CLI / API layer and the
persistence layer (``CampaignStore``), enforcing invariants like
status transitions, sub-campaign hierarchy integrity, and
indicator/cluster linkage.
"""

from __future__ import annotations

import logging
from typing import Any

from gnat.analysis.attribution.models import CampaignProfile, CampaignStatus
from gnat.analysis.attribution.query import CampaignQuery
from gnat.analysis.attribution.storage import CampaignStore

logger = logging.getLogger(__name__)


class CampaignServiceError(Exception):
    """Raised when a campaign service operation fails."""


_VALID_TRANSITIONS: dict[CampaignStatus, frozenset[CampaignStatus]] = {
    CampaignStatus.SUSPECTED: frozenset({CampaignStatus.ACTIVE, CampaignStatus.CONCLUDED}),
    CampaignStatus.ACTIVE: frozenset({CampaignStatus.DORMANT, CampaignStatus.CONCLUDED}),
    CampaignStatus.DORMANT: frozenset({CampaignStatus.ACTIVE, CampaignStatus.CONCLUDED}),
    CampaignStatus.CONCLUDED: frozenset(),
}


class CampaignService:
    """
    Campaign lifecycle management service.

    Parameters
    ----------
    store : CampaignStore
        The persistence backend.
    """

    def __init__(self, store: CampaignStore) -> None:
        self._store = store

    # ── Create ────────────────────────────────────────────────────────────

    def create(
        self,
        name: str,
        *,
        description: str = "",
        objective: str = "",
        status: CampaignStatus = CampaignStatus.SUSPECTED,
        parent_campaign_id: str | None = None,
        threat_actor_id: str | None = None,
        tags: list[str] | None = None,
        classification: str = "amber",
        created_by: str = "analyst",
    ) -> CampaignProfile:
        """Create and persist a new campaign."""
        if not name:
            raise CampaignServiceError("campaign name is required")

        if parent_campaign_id:
            parent = self._store.get(parent_campaign_id)
            if parent is None:
                raise CampaignServiceError(f"parent campaign {parent_campaign_id!r} not found")

        campaign = CampaignProfile(
            name=name,
            description=description,
            objective=objective,
            status=status,
            parent_campaign_id=parent_campaign_id,
            threat_actor_id=threat_actor_id,
            tags=list(tags or []),
            classification=classification,
            created_by=created_by,
        )

        self._store.save(campaign)

        if parent_campaign_id:
            parent = self._store.get(parent_campaign_id)
            if parent and campaign.id not in parent.sub_campaign_ids:
                parent.sub_campaign_ids.append(campaign.id)
                self._store.save(parent)

        logger.info("Created campaign %s: %s", campaign.id, name)
        return campaign

    # ── Read ──────────────────────────────────────────────────────────────

    def get(self, campaign_id: str) -> CampaignProfile:
        """Retrieve a campaign by ID. Raises if not found."""
        campaign = self._store.get(campaign_id)
        if campaign is None:
            raise CampaignServiceError(f"campaign {campaign_id!r} not found")
        return campaign

    def list(self, query: CampaignQuery | None = None) -> list[CampaignProfile]:
        """List campaigns matching the given query."""
        return self._store.list(query)

    # ── Update ────────────────────────────────────────────────────────────

    def transition(self, campaign_id: str, new_status: CampaignStatus) -> CampaignProfile:
        """Change campaign status with transition validation."""
        campaign = self.get(campaign_id)
        old_status = campaign.status

        if new_status == old_status:
            return campaign

        valid = _VALID_TRANSITIONS.get(old_status, frozenset())
        if new_status not in valid:
            raise CampaignServiceError(
                f"invalid transition {old_status.value} → {new_status.value}; "
                f"allowed: {[s.value for s in valid]}"
            )

        campaign.status = new_status
        self._store.save(campaign)
        logger.info(
            "Campaign %s transitioned %s → %s",
            campaign_id,
            old_status.value,
            new_status.value,
        )
        return campaign

    def link_indicator(self, campaign_id: str, indicator_id: str) -> CampaignProfile:
        """Link an indicator to a campaign (deduplicated)."""
        campaign = self.get(campaign_id)
        if indicator_id not in campaign.indicator_ids:
            campaign.indicator_ids.append(indicator_id)
            self._store.save(campaign)
        return campaign

    def unlink_indicator(self, campaign_id: str, indicator_id: str) -> CampaignProfile:
        """Remove an indicator link from a campaign."""
        campaign = self.get(campaign_id)
        if indicator_id in campaign.indicator_ids:
            campaign.indicator_ids.remove(indicator_id)
            self._store.save(campaign)
        return campaign

    def link_investigation(self, campaign_id: str, investigation_id: str) -> CampaignProfile:
        """Link an investigation to a campaign (deduplicated)."""
        campaign = self.get(campaign_id)
        if investigation_id not in campaign.investigation_ids:
            campaign.investigation_ids.append(investigation_id)
            self._store.save(campaign)
        return campaign

    def link_cluster(self, campaign_id: str, cluster_id: str) -> CampaignProfile:
        """Link a cluster to a campaign (deduplicated)."""
        campaign = self.get(campaign_id)
        if cluster_id not in campaign.cluster_ids:
            campaign.cluster_ids.append(cluster_id)
            self._store.save(campaign)
        return campaign

    def set_threat_actor(self, campaign_id: str, threat_actor_id: str) -> CampaignProfile:
        """Set the primary attributed threat actor."""
        campaign = self.get(campaign_id)
        campaign.threat_actor_id = threat_actor_id
        self._store.save(campaign)
        return campaign

    def add_tag(self, campaign_id: str, tag: str) -> CampaignProfile:
        """Add a tag to a campaign (deduplicated)."""
        campaign = self.get(campaign_id)
        if tag not in campaign.tags:
            campaign.tags.append(tag)
            self._store.save(campaign)
        return campaign

    def update(
        self,
        campaign_id: str,
        **kwargs: Any,
    ) -> CampaignProfile:
        """Update arbitrary campaign fields."""
        campaign = self.get(campaign_id)
        for key, value in kwargs.items():
            if hasattr(campaign, key):
                setattr(campaign, key, value)
        self._store.save(campaign)
        return campaign

    # ── Delete ────────────────────────────────────────────────────────────

    def delete(self, campaign_id: str) -> bool:
        """Soft-delete a campaign."""
        return self._store.delete(campaign_id)

    # ── Introspection ─────────────────────────────────────────────────────

    def summary(self) -> dict[str, Any]:
        """Return a high-level summary of all campaigns."""
        all_campaigns = self._store.list()
        by_status: dict[str, int] = {}
        for c in all_campaigns:
            by_status[c.status.value] = by_status.get(c.status.value, 0) + 1
        return {
            "total": len(all_campaigns),
            "by_status": by_status,
        }

    def get_sub_campaigns(self, campaign_id: str) -> list[CampaignProfile]:
        """Return direct sub-campaigns of a campaign."""
        return self._store.list(CampaignQuery(parent_campaign_id=campaign_id))

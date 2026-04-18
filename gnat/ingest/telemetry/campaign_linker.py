# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.ingest.telemetry.campaign_linker
========================================

Auto-links ingested telemetry indicators to active campaigns by
matching IOC values against campaign indicator sets.
"""

from __future__ import annotations

import logging
from typing import Any

from gnat.orm.base import STIXBase

logger = logging.getLogger(__name__)


class CampaignLinker:
    """
    Post-ingest transform that links new indicators to active campaigns.

    Used as a pipeline transform via ``IngestPipeline.transform(linker)``.

    Parameters
    ----------
    campaign_service : CampaignService
        Campaign service instance for linking operations.
    campaign_ids : list[str], optional
        Specific campaign IDs to check against.  If None, checks all
        active campaigns.
    ioc_index : dict[str, list[str]], optional
        Pre-built IOC → campaign_id index for fast lookups.  If None,
        built lazily from the campaign service on first use.
    """

    def __init__(
        self,
        campaign_service: Any,
        campaign_ids: list[str] | None = None,
        ioc_index: dict[str, list[str]] | None = None,
    ):
        self._service = campaign_service
        self._campaign_ids = campaign_ids
        self._ioc_index = ioc_index
        self._link_count = 0

    @property
    def link_count(self) -> int:
        return self._link_count

    def build_ioc_index(self) -> dict[str, list[str]]:
        """
        Build a reverse index from IOC value → campaign IDs.

        Scans active campaigns for their linked indicator patterns
        and extracts IOC values for fast matching.
        """
        index: dict[str, list[str]] = {}
        try:
            from gnat.analysis.attribution.models import CampaignStatus

            profiles = self._service.list(status=CampaignStatus.ACTIVE)
            if self._campaign_ids:
                profiles = [p for p in profiles if p.id in self._campaign_ids]

            for profile in profiles:
                for ioc in profile.indicator_ids:
                    index.setdefault(ioc, [])
                    if profile.id not in index[ioc]:
                        index[ioc].append(profile.id)
        except Exception as exc:
            logger.warning("CampaignLinker: failed to build IOC index: %s", exc)

        self._ioc_index = index
        return index

    def __call__(self, stix_obj: STIXBase) -> STIXBase:
        """
        Check if the indicator matches any active campaign IOCs.

        Designed to be passed to ``IngestPipeline.transform()``.
        """
        if self._ioc_index is None:
            self.build_ioc_index()

        indicator_id = getattr(stix_obj, "id", "")
        pattern = getattr(stix_obj, "pattern", "") or stix_obj._properties.get("pattern", "")

        ioc_value = self._extract_ioc_from_pattern(pattern)
        if not ioc_value:
            return stix_obj

        index = self._ioc_index or {}
        campaign_ids = index.get(ioc_value, [])
        if not campaign_ids and indicator_id:
            campaign_ids = index.get(indicator_id, [])

        for cid in campaign_ids:
            try:
                self._service.link_indicator(cid, indicator_id)
                self._link_count += 1
                logger.info(
                    "CampaignLinker: linked %s to campaign %s",
                    indicator_id,
                    cid,
                )
            except Exception as exc:
                logger.warning(
                    "CampaignLinker: failed to link %s to %s: %s",
                    indicator_id,
                    cid,
                    exc,
                )

        return stix_obj

    @staticmethod
    def _extract_ioc_from_pattern(pattern: str) -> str:
        if not pattern:
            return ""
        start = pattern.find("'")
        if start < 0:
            return ""
        end = pattern.find("'", start + 1)
        if end < 0:
            return ""
        return pattern[start + 1 : end]

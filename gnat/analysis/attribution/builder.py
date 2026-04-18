# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.attribution.builder
=====================================

Campaign builder — promotes :class:`~gnat.analysis.correlation.cluster_detector.Cluster`
objects into :class:`CampaignProfile` instances and wires up indicator,
actor, and investigation linkage.

The builder is the bridge between the automated correlation layer
(which produces clusters) and the analyst-managed campaign layer
(which tracks lifecycle, attribution hypotheses, and kill-chain
progression). It is explicitly *not* automatic: clusters must be
promoted by an analyst or by a rule-triggered workflow.
"""

from __future__ import annotations

import logging
from typing import Any

from gnat.analysis.attribution.models import CampaignProfile, CampaignStatus

logger = logging.getLogger(__name__)


class CampaignBuilder:
    """
    Converts correlation clusters into campaign profiles.

    Stateless — takes cluster data as dicts (matching
    :meth:`Cluster.to_dict`) and returns :class:`CampaignProfile`
    instances ready for persistence via :class:`CampaignService`.
    """

    @staticmethod
    def from_cluster(
        cluster: dict[str, Any],
        *,
        created_by: str = "cluster_detector",
        classification: str = "amber",
    ) -> CampaignProfile:
        """
        Build a :class:`CampaignProfile` from a single cluster dict.

        Uses the cluster's ``suggested_campaign`` as the campaign name
        (falls back to the cluster label), and ``suggested_actor`` as
        the initial ``threat_actor_id``. Member IDs become the campaign's
        ``indicator_ids`` and the cluster ID is linked as a
        ``cluster_id``.

        Parameters
        ----------
        cluster : dict
            Output of ``Cluster.to_dict()``.
        created_by : str
            Principal that triggered the promotion.
        classification : str
            TLP classification for the new campaign.
        """
        name = (
            cluster.get("suggested_campaign")
            or cluster.get("label")
            or f"Cluster {cluster.get('id', 'unknown')}"
        )

        actor_id = None
        actor_label = cluster.get("suggested_actor")
        if actor_label:
            actor_id = f"threat-actor--{actor_label}"

        campaign = CampaignProfile(
            name=name,
            description=f"Auto-promoted from cluster {cluster.get('id', '')}. "
            f"Signals: {'; '.join(cluster.get('signals') or [])}",
            status=CampaignStatus.SUSPECTED,
            threat_actor_id=actor_id,
            indicator_ids=list(cluster.get("member_ids") or []),
            cluster_ids=[cluster.get("id", "")],
            tags=["auto-promoted", "from-cluster"],
            classification=classification,
            created_by=created_by,
        )

        logger.info(
            "CampaignBuilder: promoted cluster %s → campaign %s (%s)",
            cluster.get("id"),
            campaign.id,
            name,
        )
        return campaign

    @staticmethod
    def from_clusters(
        clusters: list[dict[str, Any]],
        *,
        created_by: str = "cluster_detector",
        min_confidence: int = 0,
    ) -> list[CampaignProfile]:
        """
        Batch-promote multiple clusters, optionally filtering by
        minimum STIX confidence.

        Parameters
        ----------
        clusters : list of dict
            Each dict is the output of ``Cluster.to_dict()``.
        min_confidence : int
            Skip clusters whose ``confidence.stix_confidence`` is below
            this threshold. Default 0 (promote all).
        """
        campaigns: list[CampaignProfile] = []
        for cluster in clusters:
            conf = cluster.get("confidence") or {}
            stix_conf = conf.get("stix_confidence", 0) if isinstance(conf, dict) else 0
            if stix_conf < min_confidence:
                logger.debug(
                    "CampaignBuilder: skipping cluster %s (confidence %d < %d)",
                    cluster.get("id"),
                    stix_conf,
                    min_confidence,
                )
                continue
            campaigns.append(
                CampaignBuilder.from_cluster(cluster, created_by=created_by)
            )
        return campaigns

    @staticmethod
    def merge_into_existing(
        campaign: CampaignProfile,
        cluster: dict[str, Any],
    ) -> CampaignProfile:
        """
        Merge a cluster's indicators into an existing campaign.

        Adds the cluster's ``member_ids`` to the campaign's
        ``indicator_ids`` (deduplicated) and links the cluster ID.
        Does NOT change campaign status or attribution.
        """
        for mid in cluster.get("member_ids") or []:
            if mid not in campaign.indicator_ids:
                campaign.indicator_ids.append(mid)
        cluster_id = cluster.get("id", "")
        if cluster_id and cluster_id not in campaign.cluster_ids:
            campaign.cluster_ids.append(cluster_id)
        return campaign

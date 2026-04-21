# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/analysis/test_campaign_builder.py
===============================================

Unit tests for the CampaignBuilder — cluster-to-campaign promotion
(Phase 4 of the attribution & campaign tracking extension).
"""

from __future__ import annotations

from gnat.analysis.attribution.builder import CampaignBuilder
from gnat.analysis.attribution.models import CampaignProfile, CampaignStatus


def _make_cluster(
    cluster_id: str = "cluster-1",
    label: str = "Subnet overlap cluster",
    member_ids: list[str] | None = None,
    signals: list[str] | None = None,
    suggested_campaign: str | None = None,
    suggested_actor: str | None = None,
    stix_confidence: int = 60,
) -> dict:
    return {
        "id": cluster_id,
        "label": label,
        "member_ids": member_ids or ["ioc-1", "ioc-2", "ioc-3"],
        "signals": signals or ["subnet_overlap", "timing_correlation"],
        "confidence": {
            "source_reliability": "C",
            "information_credibility": 3,
            "stix_confidence": stix_confidence,
            "band": "MEDIUM",
            "label": "C3 (MEDIUM)",
            "rationale": None,
        },
        "suggested_actor": suggested_actor,
        "suggested_campaign": suggested_campaign,
        "size": 3,
    }


class TestCampaignBuilderFromCluster:
    def test_basic_promotion(self):
        cluster = _make_cluster()
        campaign = CampaignBuilder.from_cluster(cluster)
        assert isinstance(campaign, CampaignProfile)
        assert campaign.status == CampaignStatus.SUSPECTED
        assert campaign.indicator_ids == ["ioc-1", "ioc-2", "ioc-3"]
        assert "cluster-1" in campaign.cluster_ids
        assert "auto-promoted" in campaign.tags

    def test_uses_suggested_campaign_as_name(self):
        cluster = _make_cluster(suggested_campaign="Operation Sunrise")
        campaign = CampaignBuilder.from_cluster(cluster)
        assert campaign.name == "Operation Sunrise"

    def test_falls_back_to_label(self):
        cluster = _make_cluster(label="Infrastructure overlap")
        campaign = CampaignBuilder.from_cluster(cluster)
        assert campaign.name == "Infrastructure overlap"

    def test_links_suggested_actor(self):
        cluster = _make_cluster(suggested_actor="APT28")
        campaign = CampaignBuilder.from_cluster(cluster)
        assert campaign.threat_actor_id == "threat-actor--APT28"

    def test_no_actor_when_not_suggested(self):
        cluster = _make_cluster(suggested_actor=None)
        campaign = CampaignBuilder.from_cluster(cluster)
        assert campaign.threat_actor_id is None

    def test_description_includes_signals(self):
        cluster = _make_cluster(signals=["subnet_overlap", "tag_match"])
        campaign = CampaignBuilder.from_cluster(cluster)
        assert "subnet_overlap" in campaign.description
        assert "tag_match" in campaign.description

    def test_created_by_default(self):
        cluster = _make_cluster()
        campaign = CampaignBuilder.from_cluster(cluster)
        assert campaign.created_by == "cluster_detector"

    def test_created_by_custom(self):
        cluster = _make_cluster()
        campaign = CampaignBuilder.from_cluster(cluster, created_by="senior_analyst")
        assert campaign.created_by == "senior_analyst"


class TestCampaignBuilderFromClusters:
    def test_batch_promotion(self):
        clusters = [
            _make_cluster(cluster_id="c1", label="A"),
            _make_cluster(cluster_id="c2", label="B"),
            _make_cluster(cluster_id="c3", label="C"),
        ]
        campaigns = CampaignBuilder.from_clusters(clusters)
        assert len(campaigns) == 3
        names = {c.name for c in campaigns}
        assert names == {"A", "B", "C"}

    def test_min_confidence_filter(self):
        clusters = [
            _make_cluster(cluster_id="c1", stix_confidence=80),
            _make_cluster(cluster_id="c2", stix_confidence=30),
            _make_cluster(cluster_id="c3", stix_confidence=60),
        ]
        campaigns = CampaignBuilder.from_clusters(clusters, min_confidence=50)
        assert len(campaigns) == 2

    def test_min_confidence_zero_includes_all(self):
        clusters = [
            _make_cluster(cluster_id="c1", stix_confidence=10),
            _make_cluster(cluster_id="c2", stix_confidence=0),
        ]
        campaigns = CampaignBuilder.from_clusters(clusters, min_confidence=0)
        assert len(campaigns) == 2

    def test_empty_list(self):
        assert CampaignBuilder.from_clusters([]) == []


class TestCampaignBuilderMerge:
    def test_merge_adds_indicators(self):
        campaign = CampaignProfile(
            name="Existing",
            indicator_ids=["ioc-a", "ioc-b"],
            cluster_ids=["old-cluster"],
        )
        cluster = _make_cluster(
            cluster_id="new-cluster",
            member_ids=["ioc-b", "ioc-c", "ioc-d"],
        )
        CampaignBuilder.merge_into_existing(campaign, cluster)
        assert set(campaign.indicator_ids) == {"ioc-a", "ioc-b", "ioc-c", "ioc-d"}
        assert "new-cluster" in campaign.cluster_ids
        assert "old-cluster" in campaign.cluster_ids

    def test_merge_deduplicates(self):
        campaign = CampaignProfile(
            name="Existing",
            indicator_ids=["ioc-1", "ioc-2"],
        )
        cluster = _make_cluster(member_ids=["ioc-1", "ioc-2", "ioc-3"])
        CampaignBuilder.merge_into_existing(campaign, cluster)
        assert campaign.indicator_ids == ["ioc-1", "ioc-2", "ioc-3"]

    def test_merge_does_not_change_status(self):
        campaign = CampaignProfile(
            name="Active Campaign",
            status=CampaignStatus.ACTIVE,
        )
        cluster = _make_cluster()
        CampaignBuilder.merge_into_existing(campaign, cluster)
        assert campaign.status == CampaignStatus.ACTIVE

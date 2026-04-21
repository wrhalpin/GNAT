"""
Unit tests for gnat.analysis.correlation
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from gnat.analysis.confidence import SourceReliability
from gnat.analysis.correlation import (
    ClusterDetector,
    EnrichmentDispatcher,
    EnrichmentResult,
    EntityGroup,
    EntityResolver,
    IndicatorRecord,
    RelationshipScorer,
)

# ── EntityResolver ────────────────────────────────────────────────────────────


class TestEntityResolver:
    def _make_record(self, ioc_type: str, value: str, platform: str = "test") -> IndicatorRecord:
        return IndicatorRecord(
            platform=platform,
            ioc_type=ioc_type,
            value=value,
            source_id=f"{platform}-1",
        )

    def test_resolve_deduplicates_same_ip(self):
        resolver = EntityResolver()
        records = [
            self._make_record("ipv4", "1.2.3.4", "platform_a"),
            self._make_record("ipv4", "1.2.3.4", "platform_b"),
        ]
        groups = resolver.resolve(records)
        assert len(groups) == 1
        group = next(iter(groups.values()))
        assert set(group.platforms) == {"platform_a", "platform_b"}
        assert group.is_cross_platform

    def test_resolve_strips_ipv4_host_route(self):
        resolver = EntityResolver()
        records = [
            self._make_record("ipv4", "10.0.0.1/32", "p1"),
            self._make_record("ipv4", "10.0.0.1", "p2"),
        ]
        groups = resolver.resolve(records)
        assert len(groups) == 1

    def test_resolve_lowercases_domain(self):
        resolver = EntityResolver()
        records = [
            self._make_record("domain", "EVIL.COM", "p1"),
            self._make_record("domain", "evil.com", "p2"),
        ]
        groups = resolver.resolve(records)
        assert len(groups) == 1
        group = next(iter(groups.values()))
        assert group.canonical_value == "evil.com"

    def test_resolve_lowercases_email(self):
        resolver = EntityResolver()
        records = [
            self._make_record("email", "User@Example.COM", "p1"),
            self._make_record("email", "user@example.com", "p2"),
        ]
        groups = resolver.resolve(records)
        assert len(groups) == 1

    def test_resolve_different_ioc_types_separate_groups(self):
        resolver = EntityResolver()
        records = [
            self._make_record("ipv4", "1.2.3.4", "p1"),
            self._make_record("domain", "1.2.3.4", "p2"),
        ]
        groups = resolver.resolve(records)
        assert len(groups) == 2

    def test_resolve_md5_hash_canonical(self):
        resolver = EntityResolver()
        records = [
            self._make_record("md5", "AABBCCDD" * 4, "p1"),
            self._make_record("md5", "aabbccdd" * 4, "p2"),
        ]
        groups = resolver.resolve(records)
        assert len(groups) == 1

    def test_entity_group_max_confidence(self):
        resolver = EntityResolver()
        from gnat.analysis.confidence import (
            ConfidenceScore,
        )

        r1 = IndicatorRecord("p1", "ipv4", "5.5.5.5", "x1", confidence=ConfidenceScore.high())
        r2 = IndicatorRecord("p2", "ipv4", "5.5.5.5", "x2", confidence=ConfidenceScore.low())
        groups = resolver.resolve([r1, r2])
        group = next(iter(groups.values()))
        assert group.max_confidence is not None
        assert group.max_confidence.stix_confidence >= 75

    def test_resolve_empty_input(self):
        resolver = EntityResolver()
        groups = resolver.resolve([])
        assert groups == {}

    def test_resolve_url_normalized(self):
        resolver = EntityResolver()
        records = [
            self._make_record("url", "HTTP://Evil.COM/path?q=1", "p1"),
            self._make_record("url", "http://evil.com/path?q=1", "p2"),
        ]
        groups = resolver.resolve(records)
        assert len(groups) == 1


# ── RelationshipScorer ────────────────────────────────────────────────────────


class TestRelationshipScorer:
    def test_single_platform_base_score(self):
        scorer = RelationshipScorer()
        score = scorer.score(platforms={"platform_a"})
        assert score.stix_confidence >= 20

    def test_two_platforms_higher_than_one(self):
        scorer = RelationshipScorer()
        s1 = scorer.score(platforms={"p1"})
        s2 = scorer.score(platforms={"p1", "p2"})
        assert s2.stix_confidence > s1.stix_confidence

    def test_max_co_occurrence_capped(self):
        scorer = RelationshipScorer()
        s4 = scorer.score(platforms={"p1", "p2", "p3", "p4"})
        s5 = scorer.score(platforms={"p1", "p2", "p3", "p4", "p5"})
        assert s4.stix_confidence == s5.stix_confidence

    def test_recent_observation_boosts_score(self):
        scorer = RelationshipScorer()
        recent = (datetime.now(tz=timezone.utc) - timedelta(days=3)).isoformat()
        old = (datetime.now(tz=timezone.utc) - timedelta(days=200)).isoformat()
        s_recent = scorer.score(platforms={"p1"}, last_observed_iso=recent)
        s_old = scorer.score(platforms={"p1"}, last_observed_iso=old)
        assert s_recent.stix_confidence > s_old.stix_confidence

    def test_high_reliability_bonus(self):
        scorer = RelationshipScorer()
        reliable = scorer.score(
            platforms=["p1", "p2"],
            source_reliabilities={
                "p1": SourceReliability.A_COMPLETELY_RELIABLE,
                "p2": SourceReliability.B_USUALLY_RELIABLE,
            },
        )
        unreliable = scorer.score(
            platforms=["p1", "p2"],
            source_reliabilities={
                "p1": SourceReliability.E_UNRELIABLE,
                "p2": SourceReliability.F_CANNOT_BE_JUDGED,
            },
        )
        assert reliable.stix_confidence > unreliable.stix_confidence

    def test_score_capped_at_100(self):
        scorer = RelationshipScorer()
        recent = (datetime.now(tz=timezone.utc) - timedelta(hours=1)).isoformat()
        score = scorer.score(
            platforms=["p1", "p2", "p3", "p4", "p5"],
            last_observed_iso=recent,
            source_reliabilities={
                "p1": SourceReliability.A_COMPLETELY_RELIABLE,
                "p2": SourceReliability.A_COMPLETELY_RELIABLE,
                "p3": SourceReliability.A_COMPLETELY_RELIABLE,
                "p4": SourceReliability.A_COMPLETELY_RELIABLE,
                "p5": SourceReliability.A_COMPLETELY_RELIABLE,
            },
        )
        assert score.stix_confidence <= 100

    def test_invalid_iso_date_ignored(self):
        scorer = RelationshipScorer()
        score = scorer.score(platforms={"p1"}, last_observed_iso="not-a-date")
        assert score.stix_confidence >= 20

    def test_rationale_included(self):
        scorer = RelationshipScorer()
        score = scorer.score(platforms={"p1", "p2"}, rationale="test rationale")
        assert "test rationale" in (score.rationale or "")


# ── ClusterDetector ───────────────────────────────────────────────────────────


class TestClusterDetector:
    def _make_group(
        self,
        canonical_id: str,
        ioc_type: str = "ipv4",
        canonical_value: str = "1.2.3.4",
        platforms: set | None = None,
        tags: set | None = None,
    ) -> EntityGroup:
        from gnat.analysis.correlation.entity_resolver import IndicatorRecord

        rec = IndicatorRecord(
            platform="p1",
            ioc_type=ioc_type,
            value=canonical_value,
            source_id=canonical_id,
        )
        group = EntityGroup(
            canonical_id=canonical_id,
            canonical_key=(ioc_type, canonical_value),
            ioc_type=ioc_type,
            canonical_value=canonical_value,
            records=[rec],
        )
        if platforms:
            group.records = [
                IndicatorRecord(p, ioc_type, canonical_value, f"{canonical_id}-{p}")
                for p in platforms
            ]
        if tags:
            for r in group.records:
                r.tags = list(tags)
        return group

    def test_no_groups_returns_empty(self):
        detector = ClusterDetector()
        clusters = detector.detect([])
        assert clusters == []

    def test_single_group_no_cluster(self):
        detector = ClusterDetector()
        group = self._make_group("g1", canonical_value="1.2.3.4")
        clusters = detector.detect([group])
        assert len(clusters) == 0

    def test_shared_platform_clusters(self):
        detector = ClusterDetector()
        g1 = self._make_group("g1", canonical_value="1.2.3.4", platforms={"xsoar", "tq"})
        g2 = self._make_group("g2", canonical_value="5.6.7.8", platforms={"xsoar", "tq"})
        clusters = detector.detect([g1, g2])
        assert len(clusters) >= 1
        assert "g1" in clusters[0].member_ids
        assert "g2" in clusters[0].member_ids

    def test_subnet_24_clusters(self):
        detector = ClusterDetector()
        g1 = self._make_group("g1", ioc_type="ipv4", canonical_value="192.168.1.1")
        g2 = self._make_group("g2", ioc_type="ipv4", canonical_value="192.168.1.200")
        clusters = detector.detect([g1, g2])
        assert len(clusters) >= 1

    def test_shared_tags_clusters(self):
        detector = ClusterDetector()
        g1 = self._make_group("g1", canonical_value="a.com", tags={"apt29", "cobalt"})
        g2 = self._make_group("g2", canonical_value="b.com", tags={"apt29", "cobalt"})
        clusters = detector.detect([g1, g2])
        assert len(clusters) >= 1

    def test_cluster_confidence_increases_with_signals(self):
        detector = ClusterDetector()
        g1 = self._make_group(
            "g1",
            ioc_type="ipv4",
            canonical_value="10.0.0.1",
            platforms={"xsoar", "tq"},
            tags={"apt29"},
        )
        g2 = self._make_group(
            "g2",
            ioc_type="ipv4",
            canonical_value="10.0.0.2",
            platforms={"xsoar", "tq"},
            tags={"apt29"},
        )
        clusters = detector.detect([g1, g2])
        assert clusters[0].confidence.stix_confidence >= 60

    def test_no_cross_group_signals(self):
        detector = ClusterDetector()
        g1 = self._make_group(
            "g1", ioc_type="ipv4", canonical_value="1.1.1.1", platforms={"p1"}, tags={"tagA"}
        )
        g2 = self._make_group(
            "g2", ioc_type="domain", canonical_value="evil.com", platforms={"p2"}, tags={"tagB"}
        )
        clusters = detector.detect([g1, g2])
        assert len(clusters) == 0

    def test_cluster_has_label(self):
        detector = ClusterDetector()
        g1 = self._make_group(
            "g1", ioc_type="ipv4", canonical_value="172.16.0.1", platforms={"xsoar", "tq"}
        )
        g2 = self._make_group(
            "g2", ioc_type="ipv4", canonical_value="172.16.0.2", platforms={"xsoar", "tq"}
        )
        clusters = detector.detect([g1, g2])
        assert clusters[0].label != ""


# ── EnrichmentDispatcher ──────────────────────────────────────────────────────


class TestEnrichmentDispatcher:
    def _make_connector(self, platform: str, results: list | None = None) -> object:
        """Minimal fake connector for enrichment tests."""

        class _FakeConnector:
            def search_indicators_by_value(self, value: str):
                if results is None:
                    raise AttributeError("no method")
                return results

        conn = _FakeConnector()
        conn.platform = platform
        return conn

    def test_enrich_returns_dict_keyed_by_platform(self):
        conn = self._make_connector("threatq", [{"value": "1.2.3.4", "type": "IP"}])
        dispatcher = EnrichmentDispatcher(connectors={"threatq": conn})
        results = dispatcher.enrich("1.2.3.4")
        assert "threatq" in results
        assert isinstance(results["threatq"], EnrichmentResult)

    def test_enrich_best_effort_skips_failures(self):
        class _FailConnector:
            platform = "fail_platform"

            def search_indicators_by_value(self, value):
                raise RuntimeError("connection refused")

        dispatcher = EnrichmentDispatcher(connectors={"fail_platform": _FailConnector()})
        results = dispatcher.enrich("1.2.3.4")
        assert results.get("fail_platform") is None or not results["fail_platform"].success

    def test_enrich_empty_connectors(self):
        dispatcher = EnrichmentDispatcher(connectors={})
        results = dispatcher.enrich("1.2.3.4")
        assert results == {}

    def test_enrich_batch(self):
        conn = self._make_connector("threatq", [{"value": "x", "type": "IP"}])
        dispatcher = EnrichmentDispatcher(connectors={"threatq": conn})
        batch = dispatcher.enrich_batch(["1.2.3.4", "evil.com"])
        assert "1.2.3.4" in batch
        assert "evil.com" in batch

    def test_enrich_result_attributes(self):
        conn = self._make_connector("tq", [{"value": "1.2.3.4"}])
        dispatcher = EnrichmentDispatcher(connectors={"tq": conn})
        results = dispatcher.enrich("1.2.3.4")
        r = results["tq"]
        assert hasattr(r, "platform")
        assert hasattr(r, "records")
        assert hasattr(r, "success")
        assert r.platform == "tq"
        assert r.success is True

    def test_enrich_platform_filter(self):
        c1 = self._make_connector("p1", [{"value": "x"}])
        c2 = self._make_connector("p2", [{"value": "x"}])
        dispatcher = EnrichmentDispatcher(connectors={"p1": c1, "p2": c2})
        results = dispatcher.enrich("x", platforms=["p1"])
        assert "p1" in results
        assert "p2" not in results

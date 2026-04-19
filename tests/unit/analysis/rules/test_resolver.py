# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for EvidenceResolver and trust_at_least."""

from __future__ import annotations

from unittest.mock import MagicMock

from gnat.analysis.rules.resolver import EvidenceResolver, trust_at_least


class TestEvidenceResolver:
    def _make_store(self, platform_map):
        store = MagicMock()
        store.get_source_platform = MagicMock(
            side_effect=lambda ws, sid: platform_map.get(sid)
        )
        store.get_source_platforms_bulk = MagicMock(
            side_effect=lambda ws, sids: {s: platform_map.get(s) for s in sids}
        )
        return store

    def test_resolve_known_connector(self):
        store = self._make_store({"ind-1": "crowdstrike"})
        r = EvidenceResolver(workspace_id=1, store=store)
        ev = r.resolve("ind-1")
        assert ev.source_platform == "crowdstrike"
        assert ev.is_known_connector is True
        assert ev.trust_level != "untrusted_external"

    def test_resolve_unknown_platform(self):
        store = self._make_store({"ind-1": None})
        r = EvidenceResolver(workspace_id=1, store=store)
        ev = r.resolve("ind-1")
        assert ev.source_platform is None
        assert ev.is_known_connector is False
        assert ev.trust_level == "untrusted_external"

    def test_resolve_unknown_connector_name(self):
        store = self._make_store({"ind-1": "nonexistent_platform"})
        r = EvidenceResolver(workspace_id=1, store=store)
        ev = r.resolve("ind-1")
        assert ev.source_platform == "nonexistent_platform"
        assert ev.is_known_connector is False
        assert ev.trust_level == "untrusted_external"

    def test_cache_hit(self):
        store = self._make_store({"ind-1": "crowdstrike"})
        r = EvidenceResolver(workspace_id=1, store=store)
        r.resolve("ind-1")
        r.resolve("ind-1")
        assert store.get_source_platform.call_count == 1

    def test_resolve_many_batch(self):
        store = self._make_store({
            "ind-1": "crowdstrike",
            "ind-2": "splunk",
        })
        r = EvidenceResolver(workspace_id=1, store=store)
        results = r.resolve_many(["ind-1", "ind-2"])
        assert len(results) == 2
        assert results["ind-1"].source_platform == "crowdstrike"
        assert results["ind-2"].source_platform == "splunk"

    def test_resolve_many_mixed(self):
        store = self._make_store({"ind-1": "crowdstrike", "ind-2": None})
        r = EvidenceResolver(workspace_id=1, store=store)
        results = r.resolve_many(["ind-1", "ind-2", "ind-3"])
        assert results["ind-1"].is_known_connector is True
        assert results["ind-2"].is_known_connector is False
        assert results["ind-3"].is_known_connector is False

    def test_resolve_many_uses_cache(self):
        store = self._make_store({"ind-1": "crowdstrike"})
        r = EvidenceResolver(workspace_id=1, store=store)
        r.resolve("ind-1")
        r.resolve_many(["ind-1"])
        assert store.get_source_platforms_bulk.call_count == 0


class TestTrustAtLeast:
    def test_trusted_meets_semi(self):
        assert trust_at_least("trusted_internal", "semi_trusted") is True

    def test_semi_meets_semi(self):
        assert trust_at_least("semi_trusted", "semi_trusted") is True

    def test_untrusted_fails_semi(self):
        assert trust_at_least("untrusted_external", "semi_trusted") is False

    def test_untrusted_meets_untrusted(self):
        assert trust_at_least("untrusted_external", "untrusted_external") is True

    def test_unknown_level_returns_false(self):
        assert trust_at_least("bogus", "semi_trusted") is False

    def test_unknown_minimum_returns_false(self):
        assert trust_at_least("semi_trusted", "bogus") is False

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for source/trust helpers."""

from __future__ import annotations

from gnat.analysis.rules.helpers.source import (
    ai_only,
    all_evidence_trusted,
    evidence_from,
    evidence_sources,
    has_trusted_evidence,
    trust_levels,
    unknown_source_count,
)
from tests.unit.analysis.rules.conftest import make_context, make_hypothesis


class TestSourceHelpers:
    def test_evidence_sources(self):
        h = make_hypothesis(supporting=["ind-1", "ind-2"])
        ctx = make_context(platform_map={"ind-1": "crowdstrike", "ind-2": "splunk"})
        sources = evidence_sources(h, ctx)
        assert sources == {"crowdstrike", "splunk"}

    def test_evidence_sources_empty(self):
        h = make_hypothesis()
        ctx = make_context()
        assert evidence_sources(h, ctx) == set()

    def test_trust_levels(self):
        h = make_hypothesis(supporting=["ind-1"])
        ctx = make_context(platform_map={"ind-1": "crowdstrike"})
        levels = trust_levels(h, ctx)
        assert len(levels) > 0

    def test_has_trusted_evidence_true(self):
        h = make_hypothesis(supporting=["ind-1"])
        ctx = make_context(platform_map={"ind-1": "crowdstrike"})
        from gnat.clients import CLIENT_REGISTRY

        cls = CLIENT_REGISTRY.get("crowdstrike")
        if cls and getattr(cls, "TRUST_LEVEL", "") == "trusted_internal":
            assert has_trusted_evidence(h, ctx) is True

    def test_has_trusted_evidence_false_when_no_evidence(self):
        h = make_hypothesis()
        ctx = make_context()
        assert has_trusted_evidence(h, ctx) is False

    def test_evidence_from(self):
        h = make_hypothesis(supporting=["ind-1"])
        ctx = make_context(platform_map={"ind-1": "splunk"})
        assert evidence_from(h, ctx, "splunk") is True
        assert evidence_from(h, ctx, "sentinel") is False

    def test_unknown_source_count(self):
        h = make_hypothesis(supporting=["ind-1", "ind-2"])
        ctx = make_context(platform_map={"ind-1": "crowdstrike", "ind-2": None})
        assert unknown_source_count(h, ctx) == 1

    def test_all_evidence_trusted_false_with_unknown(self):
        h = make_hypothesis(supporting=["ind-1"])
        ctx = make_context(platform_map={"ind-1": None})
        assert all_evidence_trusted(h, ctx) is False

    def test_all_evidence_trusted_empty(self):
        h = make_hypothesis()
        ctx = make_context()
        assert all_evidence_trusted(h, ctx) is False

    def test_ai_only_true(self):
        h = make_hypothesis(supporting=["ind-1"])
        ctx = make_context(platform_map={"ind-1": "chatgpt"})
        assert ai_only(h, ctx) is True

    def test_ai_only_false_mixed(self):
        h = make_hypothesis(supporting=["ind-1", "ind-2"])
        ctx = make_context(platform_map={"ind-1": "chatgpt", "ind-2": "crowdstrike"})
        assert ai_only(h, ctx) is False

    def test_ai_only_false_no_evidence(self):
        h = make_hypothesis()
        ctx = make_context()
        assert ai_only(h, ctx) is False

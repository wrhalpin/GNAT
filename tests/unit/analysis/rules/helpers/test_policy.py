# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for the AI ceiling policy helper."""

from __future__ import annotations

from gnat.analysis.rules.helpers.policy import within_ai_ceiling
from gnat.analysis.rules.policy import RuleEnginePolicy
from tests.unit.analysis.rules.conftest import (
    make_confidence,
    make_context,
    make_hypothesis,
)


class TestPolicyHelper:
    def test_within_ceiling_non_ai(self):
        h = make_hypothesis(
            supporting=["ind-1"],
            confidence=make_confidence(stix=90),
        )
        ctx = make_context(platform_map={"ind-1": "crowdstrike"})
        assert within_ai_ceiling(h, ctx) is True

    def test_within_ceiling_ai_below(self):
        h = make_hypothesis(
            supporting=["ind-1"],
            confidence=make_confidence(stix=50),
        )
        ctx = make_context(platform_map={"ind-1": "chatgpt"})
        assert within_ai_ceiling(h, ctx) is True

    def test_exceeds_ceiling_ai_above(self):
        h = make_hypothesis(
            supporting=["ind-1"],
            confidence=make_confidence(stix=75),
        )
        ctx = make_context(platform_map={"ind-1": "chatgpt"})
        assert within_ai_ceiling(h, ctx) is False

    def test_ceiling_boundary(self):
        h = make_hypothesis(
            supporting=["ind-1"],
            confidence=make_confidence(stix=60),
        )
        ctx = make_context(platform_map={"ind-1": "chatgpt"})
        assert within_ai_ceiling(h, ctx) is True

    def test_custom_ceiling(self):
        h = make_hypothesis(
            supporting=["ind-1"],
            confidence=make_confidence(stix=45),
        )
        policy = RuleEnginePolicy(ai_confidence_ceiling=40)
        ctx = make_context(platform_map={"ind-1": "chatgpt"}, policy=policy)
        assert within_ai_ceiling(h, ctx) is False

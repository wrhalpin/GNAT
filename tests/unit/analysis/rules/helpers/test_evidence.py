# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for evidence helpers."""

from __future__ import annotations

from gnat.analysis.rules.helpers.evidence import (
    evidence_count,
    has_refutation,
    refuting_count,
    support_ratio,
    supporting_count,
)
from tests.unit.analysis.rules.conftest import make_hypothesis


class TestEvidenceHelpers:
    def test_supporting_count(self):
        h = make_hypothesis(supporting=["a", "b", "c"])
        assert supporting_count(h) == 3

    def test_refuting_count(self):
        h = make_hypothesis(refuting=["x", "y"])
        assert refuting_count(h) == 2

    def test_evidence_count(self):
        h = make_hypothesis(supporting=["a", "b"], refuting=["x"])
        assert evidence_count(h) == 3

    def test_has_refutation_true(self):
        h = make_hypothesis(refuting=["x"])
        assert has_refutation(h) is True

    def test_has_refutation_false(self):
        h = make_hypothesis()
        assert has_refutation(h) is False

    def test_support_ratio(self):
        h = make_hypothesis(supporting=["a", "b"], refuting=["x"])
        assert support_ratio(h) == 2 / 4  # 2 / (3 + 1)

    def test_support_ratio_empty(self):
        h = make_hypothesis()
        assert support_ratio(h) == 0.0

    def test_counts_with_no_evidence(self):
        h = make_hypothesis()
        assert supporting_count(h) == 0
        assert refuting_count(h) == 0
        assert evidence_count(h) == 0

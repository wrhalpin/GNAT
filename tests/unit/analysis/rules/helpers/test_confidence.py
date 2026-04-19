# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for confidence helpers."""

from __future__ import annotations

from gnat.analysis.rules.helpers.confidence import (
    confidence_band,
    credibility_at_least,
    credibility_of,
    has_confidence,
    reliability_at_least,
    reliability_of,
    stix_confidence,
)
from tests.unit.analysis.rules.conftest import make_confidence, make_hypothesis


class TestConfidenceHelpers:
    def test_has_confidence_true(self):
        h = make_hypothesis(confidence=make_confidence())
        assert has_confidence(h) is True

    def test_has_confidence_false(self):
        h = make_hypothesis()
        assert has_confidence(h) is False

    def test_stix_confidence_value(self):
        h = make_hypothesis(confidence=make_confidence(stix=85))
        assert stix_confidence(h) == 85

    def test_stix_confidence_none(self):
        h = make_hypothesis()
        assert stix_confidence(h) == 0

    def test_confidence_band(self):
        h = make_hypothesis(confidence=make_confidence(stix=75))
        band = confidence_band(h)
        assert band is not None

    def test_confidence_band_none(self):
        h = make_hypothesis()
        assert confidence_band(h) is None

    def test_reliability_of(self):
        h = make_hypothesis(confidence=make_confidence(reliability="B"))
        assert reliability_of(h) == "B"

    def test_reliability_of_none(self):
        h = make_hypothesis()
        assert reliability_of(h) is None

    def test_credibility_of(self):
        h = make_hypothesis(confidence=make_confidence(credibility=2))
        assert credibility_of(h) == 2

    def test_credibility_of_none(self):
        h = make_hypothesis()
        assert credibility_of(h) is None

    def test_reliability_at_least_passes(self):
        h = make_hypothesis(confidence=make_confidence(reliability="B"))
        assert reliability_at_least(h, "C") is True

    def test_reliability_at_least_fails(self):
        h = make_hypothesis(confidence=make_confidence(reliability="D"))
        assert reliability_at_least(h, "B") is False

    def test_reliability_at_least_no_confidence(self):
        h = make_hypothesis()
        assert reliability_at_least(h, "C") is False

    def test_credibility_at_least_passes(self):
        h = make_hypothesis(confidence=make_confidence(credibility=2))
        assert credibility_at_least(h, 3) is True

    def test_credibility_at_least_fails(self):
        h = make_hypothesis(confidence=make_confidence(credibility=4))
        assert credibility_at_least(h, 2) is False

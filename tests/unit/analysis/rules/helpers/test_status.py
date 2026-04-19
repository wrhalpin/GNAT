# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for status helpers."""

from __future__ import annotations

from gnat.analysis.investigations.models import HypothesisStatus
from gnat.analysis.rules.helpers.status import (
    is_inconclusive,
    is_open,
    is_refuted,
    is_supported,
    status_of,
)
from tests.unit.analysis.rules.conftest import make_hypothesis


class TestStatusHelpers:
    def test_status_of(self):
        h = make_hypothesis(status=HypothesisStatus.SUPPORTED)
        assert status_of(h) == HypothesisStatus.SUPPORTED

    def test_is_open(self):
        assert is_open(make_hypothesis()) is True
        assert is_open(make_hypothesis(status=HypothesisStatus.SUPPORTED)) is False

    def test_is_supported(self):
        assert is_supported(make_hypothesis(status=HypothesisStatus.SUPPORTED)) is True
        assert is_supported(make_hypothesis()) is False

    def test_is_refuted(self):
        assert is_refuted(make_hypothesis(status=HypothesisStatus.REFUTED)) is True
        assert is_refuted(make_hypothesis()) is False

    def test_is_inconclusive(self):
        assert is_inconclusive(make_hypothesis(status=HypothesisStatus.INCONCLUSIVE)) is True
        assert is_inconclusive(make_hypothesis()) is False

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for temporal helpers."""

from __future__ import annotations

from gnat.analysis.rules.helpers.temporal import (
    age_days,
    days_since_update,
    fresh,
    stale,
)
from tests.unit.analysis.rules.conftest import make_hypothesis


class TestTemporalHelpers:
    def test_age_days(self):
        h = make_hypothesis(created_days_ago=10)
        assert age_days(h) == 10

    def test_age_days_zero(self):
        h = make_hypothesis(created_days_ago=0)
        assert age_days(h) == 0

    def test_days_since_update(self):
        h = make_hypothesis(updated_days_ago=5)
        assert days_since_update(h) == 5

    def test_stale_true(self):
        h = make_hypothesis(updated_days_ago=31)
        assert stale(h, days=30) is True

    def test_stale_false(self):
        h = make_hypothesis(updated_days_ago=5)
        assert stale(h, days=30) is False

    def test_fresh_true(self):
        h = make_hypothesis(updated_days_ago=3)
        assert fresh(h, days=7) is True

    def test_fresh_false(self):
        h = make_hypothesis(updated_days_ago=10)
        assert fresh(h, days=7) is False

    def test_stale_boundary(self):
        h = make_hypothesis(updated_days_ago=30)
        assert stale(h, days=30) is True

    def test_fresh_boundary(self):
        h = make_hypothesis(updated_days_ago=7)
        assert fresh(h, days=7) is True

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for PrologRuleEngine. Skips if pyswip is not installed."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

pyswip = pytest.importorskip("pyswip")

from gnat.analysis.rules.policy import RuleEnginePolicy  # noqa: E402
from gnat.analysis.rules.prolog_engine import PrologRuleEngine, PrologRuleLoader  # noqa: E402
from tests.unit.analysis.rules.conftest import make_hypothesis  # noqa: E402


def _store_mock():
    store = MagicMock()
    store.get_source_platform.return_value = None
    store.get_source_platforms_bulk.return_value = {}
    return store


class TestPrologRuleLoader:
    def test_load_empty_directory(self, tmp_path):
        loader = PrologRuleLoader(tmp_path)
        rules = loader.load()
        assert rules == []


class TestPrologRuleEngine:
    def test_disabled_returns_empty(self, tmp_path):
        loader = PrologRuleLoader(tmp_path)
        policy = RuleEnginePolicy(rule_evaluation_enabled=False)
        engine = PrologRuleEngine(loader=loader, policy=policy, store=_store_mock())
        h = make_hypothesis()
        result = engine.evaluate(h, MagicMock(), 1)
        assert result.firings == []

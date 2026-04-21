# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for AnalysisRuleEngine."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from gnat.analysis.investigations.models import HypothesisStatus
from gnat.analysis.rules.decisions import (
    annotate,
    no_op,
    set_status,
)
from gnat.analysis.rules.engine import AnalysisRuleEngine
from gnat.analysis.rules.loader import RuleLoader
from gnat.analysis.rules.policy import RuleEnginePolicy
from gnat.analysis.rules.registry import RegisteredRule
from tests.unit.analysis.rules.conftest import make_hypothesis


def _make_rule(
    name="test-rule",
    phase="open",
    priority=50,
    when_fn=None,
    then_fn=None,
    source_file="",
):
    return RegisteredRule(
        name=name,
        description="",
        phase=phase,
        target_status=None,
        priority=priority,
        tags=[],
        when_fn=when_fn or (lambda h, ctx: True),
        then_fn=then_fn or (lambda h, ctx: set_status("supported")),
        source_file=source_file,
    )


def _make_engine(rules=None, enabled=True, allow_dirty=True):
    loader = MagicMock(spec=RuleLoader)
    loader.rules = rules or []
    loader.load.return_value = rules or []
    loader.reload_if_changed.return_value = False
    policy = RuleEnginePolicy(
        rule_evaluation_enabled=enabled,
        allow_dirty_rules=allow_dirty,
    )
    store = MagicMock()
    store.get_source_platform.return_value = None
    store.get_source_platforms_bulk.return_value = {}
    return AnalysisRuleEngine(loader=loader, policy=policy, store=store)


class TestAnalysisRuleEngine:
    def test_disabled_returns_empty(self):
        engine = _make_engine(enabled=False)
        hyp = make_hypothesis()
        inv = MagicMock()
        result = engine.evaluate(hyp, inv, workspace_id=1)
        assert result.firings == []

    def test_matching_rule_fires(self):
        rule = _make_rule(
            when_fn=lambda h, ctx: True,
            then_fn=lambda h, ctx: set_status("supported", "matched"),
        )
        engine = _make_engine(rules=[rule])
        hyp = make_hypothesis(status=HypothesisStatus.OPEN)
        result = engine.evaluate(hyp, MagicMock(), workspace_id=1)
        assert len(result.firings) == 1
        assert result.primary_decision is not None

    def test_phase_gate_filters(self):
        rule = _make_rule(phase="supported")
        engine = _make_engine(rules=[rule])
        hyp = make_hypothesis(status=HypothesisStatus.OPEN)
        result = engine.evaluate(hyp, MagicMock(), workspace_id=1)
        assert len(result.firings) == 0

    def test_phase_none_matches_all(self):
        rule = _make_rule(phase=None)
        engine = _make_engine(rules=[rule])
        hyp = make_hypothesis(status=HypothesisStatus.OPEN)
        result = engine.evaluate(hyp, MagicMock(), workspace_id=1)
        assert len(result.firings) == 1

    def test_when_false_skips(self):
        rule = _make_rule(when_fn=lambda h, ctx: False)
        engine = _make_engine(rules=[rule])
        hyp = make_hypothesis()
        result = engine.evaluate(hyp, MagicMock(), workspace_id=1)
        assert len(result.firings) == 0

    def test_transition_slot_consumed(self):
        r1 = _make_rule(name="first", priority=100, then_fn=lambda h, ctx: set_status("supported"))
        r2 = _make_rule(name="second", priority=50, then_fn=lambda h, ctx: set_status("refuted"))
        engine = _make_engine(rules=[r1, r2])
        hyp = make_hypothesis()
        result = engine.evaluate(hyp, MagicMock(), workspace_id=1)
        assert len(result.firings) == 1
        assert result.firings[0].rule_name == "first"

    def test_annotations_always_fire(self):
        r1 = _make_rule(
            name="transition", priority=100, then_fn=lambda h, ctx: set_status("supported")
        )
        r2 = _make_rule(name="annotate", priority=50, then_fn=lambda h, ctx: annotate("key", "val"))
        engine = _make_engine(rules=[r1, r2])
        hyp = make_hypothesis()
        result = engine.evaluate(hyp, MagicMock(), workspace_id=1)
        assert len(result.firings) == 2

    def test_no_op_consumes_slot(self):
        r1 = _make_rule(name="blocker", priority=100, then_fn=lambda h, ctx: no_op("wait"))
        r2 = _make_rule(name="promote", priority=50, then_fn=lambda h, ctx: set_status("supported"))
        engine = _make_engine(rules=[r1, r2])
        hyp = make_hypothesis()
        result = engine.evaluate(hyp, MagicMock(), workspace_id=1)
        assert len(result.firings) == 1
        assert result.firings[0].rule_name == "blocker"

    def test_rule_exception_logged_not_fatal(self):
        def _boom(h, ctx):
            raise RuntimeError("broken rule")

        r1 = _make_rule(name="broken", when_fn=_boom)
        r2 = _make_rule(name="ok", then_fn=lambda h, ctx: set_status("supported"))
        engine = _make_engine(rules=[r1, r2])
        hyp = make_hypothesis()
        result = engine.evaluate(hyp, MagicMock(), workspace_id=1)
        assert len(result.errors) == 1
        assert result.errors[0][0] == "broken"
        assert len(result.firings) == 1

    @patch("gnat.analysis.rules.engine.git_file_is_clean", return_value=False)
    def test_dirty_rule_skipped_in_production(self, mock_clean):
        rule = _make_rule(source_file="/some/rule.hy")
        engine = _make_engine(rules=[rule], allow_dirty=False)
        hyp = make_hypothesis()
        result = engine.evaluate(hyp, MagicMock(), workspace_id=1)
        assert len(result.firings) == 0

    @patch("gnat.analysis.rules.engine.git_file_is_clean", return_value=True)
    def test_clean_rule_fires_in_production(self, mock_clean):
        rule = _make_rule(source_file="/some/rule.hy")
        engine = _make_engine(rules=[rule], allow_dirty=False)
        hyp = make_hypothesis()
        result = engine.evaluate(hyp, MagicMock(), workspace_id=1)
        assert len(result.firings) == 1

    def test_none_decision_skipped(self):
        rule = _make_rule(then_fn=lambda h, ctx: None)
        engine = _make_engine(rules=[rule])
        hyp = make_hypothesis()
        result = engine.evaluate(hyp, MagicMock(), workspace_id=1)
        assert len(result.firings) == 0

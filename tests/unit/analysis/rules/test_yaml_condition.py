# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for YAML condition DSL compiler."""

from __future__ import annotations

from gnat.analysis.rules.decisions import DecisionAction
from gnat.analysis.rules.yaml_condition import compile_action, compile_condition
from tests.unit.analysis.rules.conftest import (
    make_confidence,
    make_context,
    make_hypothesis,
)


class TestCompileCondition:
    def test_simple_bool_true(self):
        cond = compile_condition({"has_confidence": True})
        h = make_hypothesis(confidence=make_confidence())
        assert cond(h, None) is True

    def test_simple_bool_false(self):
        cond = compile_condition({"has_confidence": True})
        h = make_hypothesis()
        assert cond(h, None) is False

    def test_comparison_gte(self):
        cond = compile_condition({"supporting_count": {"gte": 3}})
        h = make_hypothesis(supporting=["a", "b", "c"])
        assert cond(h, None) is True

    def test_comparison_gte_fails(self):
        cond = compile_condition({"supporting_count": {"gte": 3}})
        h = make_hypothesis(supporting=["a"])
        assert cond(h, None) is False

    def test_comparison_gt(self):
        cond = compile_condition({"evidence_count": {"gt": 0}})
        h = make_hypothesis(supporting=["a"])
        assert cond(h, None) is True

    def test_comparison_lt(self):
        cond = compile_condition({"supporting_count": {"lt": 2}})
        h = make_hypothesis(supporting=["a"])
        assert cond(h, None) is True

    def test_string_arg(self):
        cond = compile_condition({"reliability_at_least": "B"})
        h = make_hypothesis(confidence=make_confidence(reliability="A"))
        assert cond(h, None) is True

    def test_int_arg(self):
        cond = compile_condition({"credibility_at_least": 3})
        h = make_hypothesis(confidence=make_confidence(credibility=2))
        assert cond(h, None) is True

    def test_all_combinator(self):
        cond = compile_condition({
            "all": [
                {"supporting_count": {"gte": 2}},
                {"has_refutation": False},
            ]
        })
        h = make_hypothesis(supporting=["a", "b"])
        assert cond(h, None) is True

    def test_all_combinator_fails(self):
        cond = compile_condition({
            "all": [
                {"supporting_count": {"gte": 5}},
                {"has_refutation": False},
            ]
        })
        h = make_hypothesis(supporting=["a", "b"])
        assert cond(h, None) is False

    def test_any_combinator(self):
        cond = compile_condition({
            "any": [
                {"supporting_count": {"gte": 10}},
                {"has_refutation": True},
            ]
        })
        h = make_hypothesis(refuting=["x"])
        assert cond(h, None) is True

    def test_not_combinator(self):
        cond = compile_condition({"not": {"has_refutation": True}})
        h = make_hypothesis()
        assert cond(h, None) is True

    def test_ctx_helper(self):
        cond = compile_condition({"ai_only": True})
        h = make_hypothesis(supporting=["ind-1"])
        ctx = make_context(platform_map={"ind-1": "chatgpt"})
        assert cond(h, ctx) is True

    def test_ctx_helper_false(self):
        cond = compile_condition({"ai_only": True})
        h = make_hypothesis(supporting=["ind-1"])
        ctx = make_context(platform_map={"ind-1": "crowdstrike"})
        assert cond(h, ctx) is False

    def test_stale_with_days(self):
        cond = compile_condition({"stale": {"days": 5}})
        h = make_hypothesis(updated_days_ago=10)
        assert cond(h, None) is True

    def test_unknown_helper_raises(self):
        import pytest
        with pytest.raises(ValueError, match="Unknown helper"):
            compile_condition({"nonexistent_helper": True})


class TestCompileAction:
    def test_set_status(self):
        fn = compile_action({"set_status": {"target": "supported", "reason": "test"}})
        d = fn(None, None)
        assert d.action == DecisionAction.SET_STATUS
        assert d.reason == "test"

    def test_annotate(self):
        fn = compile_action({"annotate": {"key": "flag", "value": "v", "reason": "r"}})
        d = fn(None, None)
        assert d.action == DecisionAction.ANNOTATE

    def test_no_op(self):
        fn = compile_action({"no_op": {"reason": "waiting"}})
        d = fn(None, None)
        assert d.action == DecisionAction.NO_OP

    def test_unknown_action_raises(self):
        import pytest
        with pytest.raises(ValueError, match="Unknown action"):
            compile_action({"explode": {}})

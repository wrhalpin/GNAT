# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for rule registry."""

from __future__ import annotations

from gnat.analysis.rules.registry import (
    RegisteredRule,
    clear_registry,
    drain_rules,
    register_rule,
)


class TestRuleRegistry:
    def setup_method(self):
        clear_registry()

    def test_register_and_drain(self):
        register_rule({
            "name": "test-rule",
            "description": "A test rule",
            "phase": "open",
            "target_status": "supported",
            "priority": 100,
            "tags": ["test"],
            "when_fn": lambda h, ctx: True,
            "then_fn": lambda h, ctx: None,
            "source_file": "test.hy",
        })
        rules = drain_rules()
        assert len(rules) == 1
        assert rules[0].name == "test-rule"
        assert rules[0].phase == "open"
        assert rules[0].priority == 100

    def test_drain_clears_registry(self):
        register_rule({
            "name": "r1",
            "when_fn": lambda h, ctx: True,
            "then_fn": lambda h, ctx: None,
        })
        drain_rules()
        assert drain_rules() == []

    def test_clear_registry(self):
        register_rule({
            "name": "r1",
            "when_fn": lambda h, ctx: True,
            "then_fn": lambda h, ctx: None,
        })
        clear_registry()
        assert drain_rules() == []

    def test_multiple_rules(self):
        for i in range(5):
            register_rule({
                "name": f"rule-{i}",
                "priority": i * 10,
                "when_fn": lambda h, ctx: True,
                "then_fn": lambda h, ctx: None,
            })
        rules = drain_rules()
        assert len(rules) == 5

    def test_defaults_for_optional_fields(self):
        register_rule({
            "name": "minimal",
            "when_fn": lambda h, ctx: True,
            "then_fn": lambda h, ctx: None,
        })
        rules = drain_rules()
        assert rules[0].description == ""
        assert rules[0].phase is None
        assert rules[0].target_status is None
        assert rules[0].priority == 50
        assert rules[0].tags == []
        assert rules[0].source_file == ""

    def test_registered_rule_is_dataclass(self):
        register_rule({
            "name": "dc-test",
            "when_fn": lambda h, ctx: True,
            "then_fn": lambda h, ctx: None,
        })
        rules = drain_rules()
        assert isinstance(rules[0], RegisteredRule)

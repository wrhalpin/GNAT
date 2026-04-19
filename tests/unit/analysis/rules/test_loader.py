# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for RuleLoader.

These tests cover the loader's behavior with and without Hy.
When Hy is not installed, the loader returns empty lists gracefully.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from gnat.analysis.rules.loader import _HY_AVAILABLE, RuleLoader
from gnat.analysis.rules.registry import clear_registry, register_rule


class TestRuleLoaderWithoutHy:
    def test_load_returns_empty_without_hy(self, tmp_path):
        with patch("gnat.analysis.rules.loader._HY_AVAILABLE", False):
            loader = RuleLoader(tmp_path)
            rules = loader.load()
            assert rules == []

    def test_reload_returns_false_without_hy(self, tmp_path):
        with patch("gnat.analysis.rules.loader._HY_AVAILABLE", False):
            loader = RuleLoader(tmp_path)
            assert loader.reload_if_changed() is False


class TestRuleLoaderDirectoryHandling:
    def test_load_nonexistent_directory(self):
        loader = RuleLoader(Path("/nonexistent/rules/dir"))
        if _HY_AVAILABLE:
            rules = loader.load()
            assert rules == []

    def test_load_empty_directory(self, tmp_path):
        if not _HY_AVAILABLE:
            return
        loader = RuleLoader(tmp_path)
        rules = loader.load()
        assert rules == []

    def test_rules_property(self, tmp_path):
        loader = RuleLoader(tmp_path)
        assert loader.rules == []


class TestRuleLoaderWithRegistry:
    """Test loader behavior using the registry directly (no Hy needed)."""

    def setup_method(self):
        clear_registry()

    def test_drain_after_manual_registration(self):
        register_rule({
            "name": "high-priority",
            "priority": 100,
            "when_fn": lambda h, ctx: True,
            "then_fn": lambda h, ctx: None,
        })
        register_rule({
            "name": "low-priority",
            "priority": 10,
            "when_fn": lambda h, ctx: True,
            "then_fn": lambda h, ctx: None,
        })
        from gnat.analysis.rules.registry import drain_rules
        rules = sorted(drain_rules(), key=lambda r: -r.priority)
        assert rules[0].name == "high-priority"
        assert rules[1].name == "low-priority"

    def test_reload_detects_new_file(self, tmp_path):
        if not _HY_AVAILABLE:
            return
        loader = RuleLoader(tmp_path)
        loader.load()
        (tmp_path / "new_rule.hy").write_text(";; placeholder")
        assert loader.reload_if_changed() is True

    def test_reload_detects_no_change(self, tmp_path):
        if not _HY_AVAILABLE:
            return
        loader = RuleLoader(tmp_path)
        loader.load()
        assert loader.reload_if_changed() is False

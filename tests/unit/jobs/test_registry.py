# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/jobs/test_registry.py
===================================

Unit tests for :mod:`gnat.jobs.registry` — @job decorator and JobRegistry.

Coverage:
- @job decorator registers a function
- JobRegistry.get() returns registered handler
- JobRegistry.get() returns None for unknown type
- JobRegistry.list_types() returns sorted names
- JobRegistry.register() programmatic registration
- JobRegistry.unregister() removes a handler
- JobRegistry.clear() empties the registry
- Overwrite warning on duplicate registration
"""

from __future__ import annotations

import pytest

from gnat.jobs.registry import _REGISTRY, JobRegistry, job

# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture(autouse=True)
def _clean_registry():
    """Clear the registry before and after each test."""
    saved = dict(_REGISTRY)
    _REGISTRY.clear()
    yield
    _REGISTRY.clear()
    _REGISTRY.update(saved)


# ===========================================================================
# @job decorator
# ===========================================================================


class TestJobDecorator:
    """Tests for the @job decorator."""

    def test_registers_function(self):
        """@job registers the decorated function."""

        @job("test_type")
        def my_handler(payload, progress_cb, cancel):
            pass

        assert JobRegistry.get("test_type") is my_handler

    def test_returns_original_function(self):
        """@job returns the original function unmodified."""

        @job("test_type")
        def my_handler(payload, progress_cb, cancel):
            pass

        assert callable(my_handler)
        assert my_handler.__name__ == "my_handler"

    def test_overwrite_warning(self, caplog):
        """@job logs a warning when overwriting an existing handler."""

        @job("dup")
        def first(payload, progress_cb, cancel):
            pass

        import logging

        with caplog.at_level(logging.WARNING, logger="gnat.jobs.registry"):

            @job("dup")
            def second(payload, progress_cb, cancel):
                pass

        assert "overwriting" in caplog.text
        assert JobRegistry.get("dup") is second


# ===========================================================================
# JobRegistry
# ===========================================================================


class TestJobRegistry:
    """Tests for the JobRegistry static class."""

    def test_get_registered(self):
        """get() returns a registered handler."""

        def handler(p, cb, c):
            pass

        JobRegistry.register("lookup_test", handler)
        assert JobRegistry.get("lookup_test") is handler

    def test_get_unknown(self):
        """get() returns None for unknown job type."""
        assert JobRegistry.get("nonexistent") is None

    def test_list_types_empty(self):
        """list_types() returns empty list when nothing is registered."""
        assert JobRegistry.list_types() == []

    def test_list_types_sorted(self):
        """list_types() returns sorted names."""

        def h(p, cb, c):
            pass

        JobRegistry.register("zebra", h)
        JobRegistry.register("alpha", h)
        JobRegistry.register("middle", h)
        assert JobRegistry.list_types() == ["alpha", "middle", "zebra"]

    def test_register_programmatic(self):
        """register() adds a handler programmatically."""

        def handler(p, cb, c):
            pass

        JobRegistry.register("programmatic", handler)
        assert JobRegistry.get("programmatic") is handler

    def test_unregister_existing(self):
        """unregister() removes a registered handler."""

        def handler(p, cb, c):
            pass

        JobRegistry.register("removeme", handler)
        assert JobRegistry.unregister("removeme") is True
        assert JobRegistry.get("removeme") is None

    def test_unregister_unknown(self):
        """unregister() returns False for unknown type."""
        assert JobRegistry.unregister("nonexistent") is False

    def test_clear(self):
        """clear() empties the registry."""

        def h(p, cb, c):
            pass

        JobRegistry.register("a", h)
        JobRegistry.register("b", h)
        JobRegistry.clear()
        assert JobRegistry.list_types() == []

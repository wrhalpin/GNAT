# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.rules.loader
==============================

Discovers ``.hy`` rule files in a directory and loads them into the
rule registry. Supports hot-reload via stat-on-call.

Requires ``hy`` to be installed (``pip install "gnat[rules]"``).
When Hy is not available, :meth:`load` returns an empty list and
logs a warning.
"""

from __future__ import annotations

import importlib.util
import logging
from pathlib import Path

from gnat.analysis.rules.registry import RegisteredRule, clear_registry, drain_rules

logger = logging.getLogger(__name__)

_HY_AVAILABLE = False
try:
    import hy  # noqa: F401

    _HY_AVAILABLE = True
except ImportError:
    pass


class RuleLoader:
    """Load ``.hy`` rule files from a directory."""

    def __init__(self, rules_dir: str | Path) -> None:
        self._rules_dir = Path(rules_dir)
        self._rules: list[RegisteredRule] = []
        self._mtimes: dict[Path, float] = {}

    @property
    def rules(self) -> list[RegisteredRule]:
        return list(self._rules)

    def load(self) -> list[RegisteredRule]:
        if not _HY_AVAILABLE:
            logger.warning(
                "Hy is not installed — rule loading skipped. "
                "Install with: pip install 'gnat[rules]'"
            )
            return []

        clear_registry()
        if not self._rules_dir.exists():
            logger.warning("Rules directory does not exist: %s", self._rules_dir)
            return []

        for hy_file in sorted(self._rules_dir.rglob("*.hy")):
            self._load_file(hy_file)
            self._mtimes[hy_file] = hy_file.stat().st_mtime

        self._rules = sorted(drain_rules(), key=lambda r: -r.priority)
        return list(self._rules)

    def reload_if_changed(self) -> bool:
        if not _HY_AVAILABLE:
            return False
        if not self._rules_dir.exists():
            return False

        current_files = set(self._rules_dir.rglob("*.hy"))
        tracked_files = set(self._mtimes.keys())

        if current_files != tracked_files:
            self.load()
            return True

        for hy_file in current_files:
            if hy_file.stat().st_mtime != self._mtimes.get(hy_file):
                self.load()
                return True

        return False

    def _load_file(self, hy_file: Path) -> None:
        try:
            mod_name = f"_gnat_rule_{hy_file.stem}_{id(hy_file)}"
            spec = importlib.util.spec_from_file_location(mod_name, hy_file)
            if spec is None or spec.loader is None:
                logger.error("Cannot create import spec for %s", hy_file)
                return
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load rule file %s: %s", hy_file, exc)

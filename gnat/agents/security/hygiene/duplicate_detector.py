# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.security.hygiene.duplicate_detector
===================================================

Duplicate detector utilities and helpers for the GNAT toolkit.
"""
from collections import defaultdict
from collections.abc import Iterable


class DuplicateDetector:
    """DuplicateDetector implementation."""
    def find_duplicates(self, values: Iterable[str]) -> dict[str, list[str]]:
        """Find and return duplicates."""
        index = defaultdict(list)
        for value in values:
            index[value].append(value)
        return {k: v for k, v in index.items() if len(v) > 1}

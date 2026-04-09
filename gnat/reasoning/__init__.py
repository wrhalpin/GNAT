# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.reasoning
==============

Phase 4C reasoning layer: hypothesis testing, negative evidence tracking,
and evidence-weighted prioritisation.
"""

from gnat.reasoning.hypothesis import HypothesisEngine
from gnat.reasoning.engine import ReasoningEngine

__all__ = ["HypothesisEngine", "ReasoningEngine"]

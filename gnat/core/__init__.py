# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.core
=========

Cross-cutting infrastructure for GNAT Phase 4: execution tracing,
domain boundary enforcement, and trust-level control.
"""

from gnat.core.context import ExecutionContext, QueryBudget
from gnat.core.domains import (
    Domain,
    DomainBoundaryViolation,
    domain_boundary,
    require_trust_level,
)

__all__ = [
    "ExecutionContext",
    "QueryBudget",
    "Domain",
    "DomainBoundaryViolation",
    "domain_boundary",
    "require_trust_level",
]

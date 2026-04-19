# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.rules.protocol
================================

Structural typing protocol for rule engine implementations.
Any class implementing ``evaluate()`` with this signature satisfies
the protocol — no explicit inheritance needed.
"""

from __future__ import annotations

from typing import Any, Protocol

from gnat.analysis.rules.result import RuleEvaluationResult


class RuleEngineProtocol(Protocol):
    def evaluate(
        self,
        hypothesis: Any,
        investigation: Any,
        workspace_id: int,
    ) -> RuleEvaluationResult: ...

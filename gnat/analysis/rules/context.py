# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""RuleContext — evaluation-scoped state passed to rule predicates."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from gnat.analysis.rules.policy import RuleEnginePolicy
from gnat.analysis.rules.resolver import EvidenceResolver


@dataclass(frozen=True)
class RuleContext:
    resolver: EvidenceResolver
    policy: RuleEnginePolicy
    now: datetime
    workspace_id: int
    engine_version: str = "1.0.0"

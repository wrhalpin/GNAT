# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Decision dataclasses returned by rules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from gnat.analysis.investigations.models import HypothesisStatus


class DecisionAction(str, Enum):
    SET_STATUS = "set_status"
    ANNOTATE = "annotate"
    NO_OP = "no_op"


@dataclass(frozen=True)
class Decision:
    action: DecisionAction
    reason: str
    timestamp: datetime

    def should_mutate(self) -> bool:
        return self.action == DecisionAction.SET_STATUS

    def consumes_transition_slot(self) -> bool:
        return self.action in (DecisionAction.SET_STATUS, DecisionAction.NO_OP)


@dataclass(frozen=True)
class SetStatusDecision(Decision):
    target_status: HypothesisStatus = HypothesisStatus.OPEN


@dataclass(frozen=True)
class AnnotateDecision(Decision):
    key: str = ""
    value: Any = None


@dataclass(frozen=True)
class NoOpDecision(Decision):
    pass


def set_status(target: HypothesisStatus | str, reason: str = "") -> SetStatusDecision:
    if isinstance(target, str):
        target = HypothesisStatus(target)
    return SetStatusDecision(
        action=DecisionAction.SET_STATUS,
        reason=reason,
        timestamp=datetime.now(timezone.utc),
        target_status=target,
    )


def annotate(key: str, value: Any, reason: str = "") -> AnnotateDecision:
    return AnnotateDecision(
        action=DecisionAction.ANNOTATE,
        reason=reason,
        timestamp=datetime.now(timezone.utc),
        key=key,
        value=value,
    )


def no_op(reason: str = "") -> NoOpDecision:
    return NoOpDecision(
        action=DecisionAction.NO_OP,
        reason=reason,
        timestamp=datetime.now(timezone.utc),
    )

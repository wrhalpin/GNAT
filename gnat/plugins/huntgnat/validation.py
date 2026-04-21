# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.plugins.huntgnat.validation
====================================

Detection validation — tests whether HuntGNAT rules actually fire
when the corresponding ATT&CK techniques are executed.

Uses Atomic Red Team-style test execution against lab infrastructure
to close the detect → validate loop. Each validation run scores
every rule in a hunt package as fired / missed / timeout / error.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class ValidationOutcome(str, Enum):
    FIRED = "fired"
    MISSED = "missed"
    TIMEOUT = "timeout"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class RuleValidationResult:
    """Result of validating a single rule against a test execution."""

    rule_id: str = ""
    technique_id: str = ""
    outcome: ValidationOutcome = ValidationOutcome.SKIPPED
    details: str = ""
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "technique_id": self.technique_id,
            "outcome": self.outcome.value,
            "details": self.details,
            "duration_seconds": self.duration_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RuleValidationResult:
        return cls(
            rule_id=data.get("rule_id", ""),
            technique_id=data.get("technique_id", ""),
            outcome=ValidationOutcome(data.get("outcome", "skipped")),
            details=data.get("details", ""),
            duration_seconds=float(data.get("duration_seconds", 0.0)),
        )


@dataclass
class ValidationRun:
    """
    A validation run executing ATT&CK techniques against lab infra
    and checking whether detection rules fire.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    package_id: str = ""
    target_hosts: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=_utcnow)
    finished_at: datetime | None = None
    status: str = "running"
    results: list[RuleValidationResult] = field(default_factory=list)
    executed_by: str = "analyst"

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def fired_count(self) -> int:
        return sum(1 for r in self.results if r.outcome == ValidationOutcome.FIRED)

    @property
    def missed_count(self) -> int:
        return sum(1 for r in self.results if r.outcome == ValidationOutcome.MISSED)

    @property
    def pass_rate(self) -> float:
        if not self.results:
            return 0.0
        return self.fired_count / len(self.results) * 100

    def complete(self) -> None:
        self.finished_at = _utcnow()
        self.status = "completed"

    def add_result(self, result: RuleValidationResult) -> None:
        self.results.append(result)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "package_id": self.package_id,
            "target_hosts": list(self.target_hosts),
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "status": self.status,
            "executed_by": self.executed_by,
            "total": self.total,
            "fired": self.fired_count,
            "missed": self.missed_count,
            "pass_rate": round(self.pass_rate, 1),
            "results": [r.to_dict() for r in self.results],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ValidationRun:
        sa = data.get("started_at")
        if isinstance(sa, str):
            sa = datetime.fromisoformat(sa)
        else:
            sa = _utcnow()
        fa = data.get("finished_at")
        if isinstance(fa, str):
            fa = datetime.fromisoformat(fa)
        return cls(
            id=data.get("id") or str(uuid.uuid4()),
            package_id=data.get("package_id", ""),
            target_hosts=list(data.get("target_hosts") or []),
            started_at=sa,
            finished_at=fa,
            status=data.get("status", "running"),
            executed_by=data.get("executed_by", "analyst"),
            results=[RuleValidationResult.from_dict(r) for r in (data.get("results") or [])],
        )

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Models for GNAT connector repository maintenance."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ChangeImpact(str, Enum):
    """High-level compatibility impact detected for a connector."""

    NO_CHANGE = "no_change"
    BACKWARD_COMPATIBLE = "backward_compatible"
    ADAPTER_UPDATE = "adapter_update"
    TRANSLATION_UPDATE = "translation_update"
    BREAKING_CHANGE = "breaking_change"
    SECURITY_REVIEW = "security_review"


@dataclass
class DriftSignal:
    """Observed discovery-time signal indicating potential connector drift."""

    kind: str
    severity: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProbeResult:
    """Outcome of one probe defined in the connector registry."""

    probe_type: str
    target: str
    success: bool
    status_code: int | None = None
    latency_ms: float | None = None
    fingerprint: str | None = None
    payload_excerpt: str | None = None
    error: str | None = None


@dataclass
class ConnectorDiscoveryResult:
    """End-to-end discovery result for one connector."""

    connector: str
    impact: ChangeImpact
    probes: list[ProbeResult] = field(default_factory=list)
    signals: list[DriftSignal] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return self.impact != ChangeImpact.NO_CHANGE


@dataclass
class PullRequestPlan:
    """Metadata for the branch/PR step."""

    branch_name: str
    title: str
    body: str
    labels: list[str] = field(default_factory=list)
    draft: bool = True


@dataclass
class RepairAction:
    """A deterministic file-level maintenance action."""

    action_type: str
    path: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    requires_review: bool = True


@dataclass
class RepairPlan:
    """Planned code or test changes for one connector."""

    connector: str
    impact: ChangeImpact
    actions: list[RepairAction] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def has_actions(self) -> bool:
        return bool(self.actions)


@dataclass
class VerificationCheck:
    """One verification check outcome."""

    name: str
    passed: bool
    details: str = ""
    artifacts: list[str] = field(default_factory=list)


@dataclass
class VerificationResult:
    """Aggregate verification outcome for a connector repair."""

    connector: str
    passed: bool
    checks: list[VerificationCheck] = field(default_factory=list)
    summary: str = ""


@dataclass
class ExecutionResult:
    """Branch / commit / PR execution outcome."""

    success: bool
    branch_name: str = ""
    commit_sha: str | None = None
    pr_url: str | None = None
    steps_completed: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class RepoMaintenancePlan:
    """Combined discovery, repair, verification, and PR plan."""

    connector: str
    impact: ChangeImpact
    discovery: ConnectorDiscoveryResult
    pull_request: PullRequestPlan
    files_to_touch: list[str] = field(default_factory=list)
    confidence: float = 0.0
    repair: RepairPlan | None = None
    verification: VerificationResult | None = None

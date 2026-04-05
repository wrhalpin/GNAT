"""Repository-maintenance helpers for GNAT connector compatibility work."""

from gnat.agents.repo_maintenance.discovery import DiscoveryEngine
from gnat.agents.repo_maintenance.executor import MaintenanceExecutor
from gnat.agents.repo_maintenance.models import (
    ChangeImpact,
    ConnectorDiscoveryResult,
    DriftSignal,
    ExecutionResult,
    ProbeResult,
    PullRequestPlan,
    RepairAction,
    RepairPlan,
    RepoMaintenancePlan,
    VerificationCheck,
    VerificationResult,
)
from gnat.agents.repo_maintenance.registry import ConnectorRegistry, ConnectorSpec
from gnat.agents.repo_maintenance.repair import RepairPlanner
from gnat.agents.repo_maintenance.verifier import VerificationEngine

__all__ = [
    "ChangeImpact",
    "ConnectorDiscoveryResult",
    "ConnectorRegistry",
    "ConnectorSpec",
    "DiscoveryEngine",
    "DriftSignal",
    "ExecutionResult",
    "MaintenanceExecutor",
    "ProbeResult",
    "PullRequestPlan",
    "RepairAction",
    "RepairPlan",
    "RepairPlanner",
    "RepoMaintenancePlan",
    "VerificationCheck",
    "VerificationEngine",
    "VerificationResult",
]

"""Deterministic repair planning for connector compatibility issues."""

from __future__ import annotations

from pathlib import Path

from gnat.agents.repo_maintenance.models import (
    ChangeImpact,
    RepairAction,
    RepairPlan,
    RepoMaintenancePlan,
)
from gnat.agents.repo_maintenance.registry import ConnectorRegistry


class RepairPlanner:
    """Build a conservative file-level repair plan from discovery results."""

    def __init__(self, registry: ConnectorRegistry, repo_root: str | Path = "."):
        self.registry = registry
        self.repo_root = Path(repo_root)

    def build(self, plan: RepoMaintenancePlan) -> RepairPlan:
        spec = self.registry.get(plan.connector)
        actions: list[RepairAction] = []
        notes: list[str] = []

        for path in spec.files:
            full_path = self.repo_root / path
            if not full_path.exists():
                continue
            if plan.impact in {ChangeImpact.ADAPTER_UPDATE, ChangeImpact.BACKWARD_COMPATIBLE}:
                if path.endswith("client.py"):
                    actions.append(
                        RepairAction(
                            action_type="patch_client_adapter",
                            path=path,
                            summary="Adjust request/response adapter while preserving public method signatures.",
                            details={
                                "insert_compatibility_aliases": True,
                                "preserve_signatures": True,
                            },
                            requires_review=True,
                        )
                    )
            if plan.impact == ChangeImpact.TRANSLATION_UPDATE and (
                path.endswith("stix_mapper.py") or "mapper" in path
            ):
                actions.append(
                    RepairAction(
                        action_type="patch_translation",
                        path=path,
                        summary="Update translation layer and preserve golden STIX bundle semantics.",
                        details={
                            "preserve_output_shape": True,
                            "backfill_missing_fields": True,
                        },
                        requires_review=True,
                    )
                )

        for test_path in spec.tests:
            if (self.repo_root / test_path).exists():
                actions.append(
                    RepairAction(
                        action_type="update_test",
                        path=test_path,
                        summary="Extend targeted regression coverage for the detected drift.",
                        requires_review=False,
                    )
                )

        if spec.golden_fixtures:
            for fixture_path in spec.golden_fixtures:
                actions.append(
                    RepairAction(
                        action_type="verify_fixture",
                        path=fixture_path,
                        summary="Replay and compare fixture-driven output against expected results.",
                        requires_review=False,
                    )
                )

        if plan.impact in {ChangeImpact.BREAKING_CHANGE, ChangeImpact.SECURITY_REVIEW}:
            notes.append("Open as draft PR only; do not merge without maintainer review.")
        if not actions and plan.impact != ChangeImpact.NO_CHANGE:
            notes.append("No deterministic file-level patch was inferred; manual connector review required.")

        repair_plan = RepairPlan(connector=plan.connector, impact=plan.impact, actions=actions, notes=notes)
        plan.repair = repair_plan
        return repair_plan

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Optional lightweight CLI wrapper for phased repo maintenance runs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from gnat.agents.repo_maintenance.discovery import DiscoveryEngine
from gnat.agents.repo_maintenance.executor import MaintenanceExecutor
from gnat.agents.repo_maintenance.registry import ConnectorRegistry
from gnat.agents.repo_maintenance.repair import RepairPlanner
from gnat.agents.repo_maintenance.verifier import VerificationEngine


def build_parser() -> argparse.ArgumentParser:
    """Build and return the parser."""
    parser = argparse.ArgumentParser(prog="gnat-maintain")
    parser.add_argument("connector")
    parser.add_argument("--registry", default="gnat/connectors/_registry/connector_registry.yaml")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--baseline-dir", default=".gnat/maintenance-baselines")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--commit", action="store_true")
    parser.add_argument("--push", action="store_true")
    parser.add_argument("--create-pr", action="store_true")
    parser.add_argument("--github-token")
    parser.add_argument("--upstream-repo")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Main."""
    args = build_parser().parse_args(argv)
    registry = ConnectorRegistry.load(args.registry)
    repo_root = Path(args.repo_root)
    discovery = DiscoveryEngine(registry, baseline_dir=args.baseline_dir, repo_root=repo_root)
    repair = RepairPlanner(registry, repo_root=repo_root)
    verifier = VerificationEngine(registry, repo_root=repo_root)

    plan = discovery.discover(args.connector)
    discovery.persist_baseline(args.connector, plan)
    repair.build(plan)
    verification = verifier.verify(args.connector)
    plan.verification = verification

    output = {
        "connector": plan.connector,
        "impact": plan.impact.value,
        "confidence": plan.confidence,
        "repair_actions": [
            action.__dict__ for action in (plan.repair.actions if plan.repair else [])
        ],
        "verification_passed": verification.passed,
    }

    if args.execute:
        executor = MaintenanceExecutor(
            repo_root=repo_root,
            github_token=args.github_token,
            upstream_repo=args.upstream_repo,
        )
        execution = executor.execute(
            plan,
            verification=verification,
            commit=args.commit,
            push=args.push,
            create_pr=args.create_pr,
        )
        output["execution"] = execution.__dict__

    print(json.dumps(output, indent=2))
    return 0

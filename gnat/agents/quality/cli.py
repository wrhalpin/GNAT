# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.quality.cli
===========================

Cli utilities and helpers for the GNAT toolkit.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .contract import ConnectorContractProfile, ContractAgent
from .fixture_coverage import FixtureCoverageAgent


def build_parser() -> argparse.ArgumentParser:
    """Build and return the parser."""
    parser = argparse.ArgumentParser(description="Run GNAT quality agents")
    subparsers = parser.add_subparsers(dest="command", required=True)

    contract = subparsers.add_parser("contract", help="Run connector contract checks")
    contract.add_argument("--repo-root", required=True)
    contract.add_argument("--profiles", required=True, help="Path to json file with contract profiles")

    fixtures = subparsers.add_parser("fixtures", help="Run fixture coverage checks")
    fixtures.add_argument("--repo-root", required=True)
    fixtures.add_argument("--registry", required=True, help="Path to json file mapping connector -> fixture globs")

    return parser


def main() -> int:
    """Main."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "contract":
        agent = ContractAgent(repo_root=args.repo_root)
        profiles_payload = json.loads(Path(args.profiles).read_text(encoding="utf-8"))
        profiles = [ConnectorContractProfile(**item) for item in profiles_payload]
        results = agent.evaluate_many(profiles)
        print(json.dumps([{
            "connector_name": result.connector_name,
            "passed": result.passed,
            "errors": result.errors,
            "warnings": result.warnings,
        } for result in results], indent=2))
        return 0 if all(result.passed for result in results) else 2

    if args.command == "fixtures":
        agent = FixtureCoverageAgent(repo_root=args.repo_root)
        registry = json.loads(Path(args.registry).read_text(encoding="utf-8"))
        results = agent.evaluate_many(registry)
        print(json.dumps([{
            "connector_name": r.connector_name,
            "fixture_count": r.fixture_count,
            "has_error_fixture": r.has_error_fixture,
            "has_backward_fixture": r.has_backward_fixture,
            "warnings": r.warnings,
            "score": r.score,
        } for r in results], indent=2))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

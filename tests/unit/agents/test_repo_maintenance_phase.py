"""Tests for Phase 2 repo-maintenance scaffolding."""

from __future__ import annotations

import json
from pathlib import Path

from gnat.agents.repo_maintenance.discovery import DiscoveryEngine
from gnat.agents.repo_maintenance.executor import MaintenanceExecutor
from gnat.agents.repo_maintenance.models import ChangeImpact
from gnat.agents.repo_maintenance.registry import ConnectorRegistry
from gnat.agents.repo_maintenance.repair import RepairPlanner
from gnat.agents.repo_maintenance.verifier import VerificationEngine


def _write_registry(tmp_path: Path, sample_file: Path, fixture_file: Path) -> Path:
    registry_path = tmp_path / "registry.yaml"
    registry_path.write_text(
        f"""
example:
  package_path: gnat/connectors/example
  compatibility_strategy: translation
  files:
    - gnat/connectors/example/client.py
    - gnat/connectors/example/stix_mapper.py
  tests:
    - tests/unit/agents/test_repo_maintenance_phase2.py
  golden_fixtures:
    - {fixture_file}
  probes:
    - type: local_schema
      target: file://{sample_file.relative_to(tmp_path)}
""",
        encoding="utf-8",
    )
    return registry_path


def test_repair_planner_builds_translation_actions(tmp_path: Path) -> None:
    sample_file = tmp_path / "gnat/connectors/example/stix_mapper.py"
    sample_file.parent.mkdir(parents=True, exist_ok=True)
    sample_file.write_text("print('v2')\n", encoding="utf-8")

    fixture_file = tmp_path / "fixture.json"
    fixture_file.write_text(json.dumps({"expected": {"a": 1}, "actual": {"a": 1}}), encoding="utf-8")

    registry = ConnectorRegistry.load(_write_registry(tmp_path, sample_file, fixture_file))
    baseline_dir = tmp_path / "baselines"
    baseline_dir.mkdir()
    (baseline_dir / "example.json").write_text(
        json.dumps({"connector": "example", "probes": [{"target": str(sample_file), "fingerprint": "old"}]}),
        encoding="utf-8",
    )

    engine = DiscoveryEngine(registry=registry, baseline_dir=baseline_dir, repo_root=tmp_path)
    plan = engine.discover("example")
    repair = RepairPlanner(registry=registry, repo_root=tmp_path).build(plan)

    assert plan.impact == ChangeImpact.TRANSLATION_UPDATE
    assert any(action.action_type == "patch_translation" for action in repair.actions)


def test_verification_engine_checks_golden_fixture(tmp_path: Path) -> None:
    fixture_file = tmp_path / "fixture.json"
    fixture_file.write_text(json.dumps({"expected": {"a": 1}, "actual": {"a": 1}}), encoding="utf-8")

    registry_path = tmp_path / "registry.yaml"
    registry_path.write_text(
        f"""
example:
  package_path: gnat/connectors/example
  compatibility_strategy: adapter
  golden_fixtures:
    - {fixture_file}
""",
        encoding="utf-8",
    )
    registry = ConnectorRegistry.load(registry_path)
    result = VerificationEngine(registry=registry, repo_root=tmp_path).verify("example")
    assert result.passed is True
    assert result.checks[0].name.startswith("golden:")


def test_executor_serializes_plan_without_pr(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()

    registry_path = tmp_path / "registry.yaml"
    registry_path.write_text(
        """
example:
  package_path: gnat/connectors/example
  compatibility_strategy: adapter
  files:
    - gnat/connectors/example/client.py
""",
        encoding="utf-8",
    )
    registry = ConnectorRegistry.load(registry_path)
    plan = DiscoveryEngine(registry=registry, baseline_dir=tmp_path / "baselines", repo_root=tmp_path).discover("example")

    executor = MaintenanceExecutor(repo_root=repo)

    class FakeProc:
        def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    calls: list[list[str]] = []

    def fake_run(cmd: list[str]) -> FakeProc:
        calls.append(cmd)
        if cmd[:3] == ["git", "rev-parse", "HEAD"]:
            return FakeProc(stdout="abc123\n")
        return FakeProc()

    executor._run = fake_run  # type: ignore[method-assign]
    result = executor.execute(plan, commit=False, push=False, create_pr=False)

    assert result.success is True
    assert ["git", "checkout", "-b", plan.pull_request.branch_name] in calls
    assert (repo / ".gnat" / "maintenance-plan.json").exists()

"""
gnat.agents.quality.normalization_regression
===========================================

Golden-fixture regression harness for connector normalization and STIX mapping.

This module gives GNAT a semantic guardrail: not merely "does the connector
run?" but "does it still produce the normalized objects we expect?".

A fixture describes:
- the connector or mapper under test
- the callable to invoke
- the raw native input payload
- the expected normalized or STIX output
- comparison policy, including ignored volatile fields

Typical fixture example::

    {
      "name": "cribl_event_to_observed_data",
      "connector": "cribl",
      "mapper": "gnat.connectors.cribl.stix_mapper:CriblSTIXMapper",
      "method": "event_to_observed_data",
      "input": {"_raw": "1.2.3.4 connected to evil.example", "ip": "1.2.3.4"},
      "expected": {
        "type": "observed-data",
        "number_observed": 1,
        "x_cribl_raw": "1.2.3.4 connected to evil.example"
      },
      "policy": {
        "ignore_fields": ["created", "modified", "first_observed", "last_observed"],
        "allow_additional_fields": true
      }
    }

The agent can be wired into CI and the connector-maintenance pipeline so that
patch-generated branches cannot silently change normalized meaning.
"""

from __future__ import annotations

import copy
import importlib
import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

JsonDict = dict[str, Any]


@dataclass(slots=True)
class RegressionPolicy:
    """Comparison policy controlling which differences are meaningful."""

    ignored_paths: Sequence[str] = field(default_factory=tuple)
    allow_additive_fields: bool = True
    strict_list_lengths: bool = True
    # New-style fields used by GoldenFixture / file-based fixtures
    ignore_fields: set[str] = field(default_factory=set)
    allow_additional_fields: bool = True
    require_exact_list_length: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.ignore_fields, set):
            self.ignore_fields = set(self.ignore_fields)


@dataclass(slots=True)
class RegressionDifference:
    """Describes a single deviation between expected and actual output."""

    path: str
    expected: Any
    actual: Any
    reason: str

    def __contains__(self, item: object) -> bool:
        """Allow ``"substring" in diff`` checks against the path and reason."""
        if not isinstance(item, str):
            return NotImplemented  # type: ignore[return-value]
        return item in self.path or item in self.reason or item in str(self.expected) or item in str(self.actual)


@dataclass(slots=True)
class RegressionFixture:
    """Old-style fixture for registry-based (callable) normalizers."""

    connector_name: str
    input_payload: JsonDict
    expected_output: JsonDict
    policy: RegressionPolicy = field(default_factory=RegressionPolicy)
    fixture_name: str = "default"


@dataclass
class GoldenFixture:
    """File-loadable fixture describing a mapper invocation and expected output."""

    name: str
    connector: str
    mapper: str
    method: str
    input: Any  # noqa: A003
    expected: Any
    policy: RegressionPolicy = field(default_factory=RegressionPolicy)

    @classmethod
    def from_path(cls, path: Path | str) -> GoldenFixture:
        """Load a GoldenFixture from a JSON file."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        policy_data = data.get("policy", {})
        policy = RegressionPolicy(
            ignore_fields=set(policy_data.get("ignore_fields", [])),
            allow_additional_fields=policy_data.get("allow_additional_fields", True),
            require_exact_list_length=policy_data.get("require_exact_list_length", False),
        )
        return cls(
            name=data["name"],
            connector=data["connector"],
            mapper=data.get("mapper", ""),
            method=data.get("method", ""),
            input=data.get("input", {}),
            expected=data.get("expected", {}),
            policy=policy,
        )


@dataclass(slots=True)
class RegressionResult:
    """Result from running a single fixture."""

    connector_name: str
    fixture_name: str
    passed: bool
    differences: list[RegressionDifference] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if self.passed:
            return f"{self.connector_name}:{self.fixture_name} passed"
        return f"{self.connector_name}:{self.fixture_name} failed with {len(self.differences)} differences"


@dataclass
class RunResult:
    """Aggregate result from running all fixtures for one connector (or all connectors)."""

    connector: str
    passed: bool
    results: list[RegressionResult] = field(default_factory=list)


class NormalizationRegressionAgent:
    """Golden-output verifier for connector normalization behavior."""

    def __init__(
        self,
        normalizer_registry: Mapping[str, Callable[[JsonDict], JsonDict]] | None = None,
        fixture_root: Path | str | None = None,
    ) -> None:
        self._registry = dict(normalizer_registry or {})
        self._fixture_root = Path(fixture_root) if fixture_root else None

    def register(self, connector_name: str, normalizer: Callable[[JsonDict], JsonDict]) -> None:
        self._registry[connector_name] = normalizer

    # ------------------------------------------------------------------
    # New file-based API
    # ------------------------------------------------------------------

    def run(self, connector: str | None = None) -> RunResult:
        """Run all fixtures (optionally filtered by connector name)."""
        fixtures = self._load_fixtures(connector)
        results = [self._run_golden_fixture(f) for f in fixtures]
        passed = all(r.passed for r in results)
        return RunResult(connector=connector or "", passed=passed, results=results)

    def _load_fixtures(self, connector: str | None) -> list[GoldenFixture]:
        if self._fixture_root is None:
            return []
        fixtures: list[GoldenFixture] = []
        for path in sorted(self._fixture_root.glob("*.json")):
            try:
                fixture = GoldenFixture.from_path(path)
                if connector is None or fixture.connector == connector:
                    fixtures.append(fixture)
            except (KeyError, json.JSONDecodeError):
                continue
        return fixtures

    def run_fixture(self, fixture: GoldenFixture | RegressionFixture) -> RegressionResult:
        """Run a single fixture (supports both GoldenFixture and RegressionFixture)."""
        if isinstance(fixture, GoldenFixture):
            return self._run_golden_fixture(fixture)
        return self._run_regression_fixture(fixture)

    # ------------------------------------------------------------------
    # Old registry-based API (kept for backward compatibility)
    # ------------------------------------------------------------------

    def run_all(self, fixtures: Iterable[RegressionFixture]) -> list[RegressionResult]:
        return [self._run_regression_fixture(fixture) for fixture in fixtures]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_golden_fixture(self, fixture: GoldenFixture) -> RegressionResult:
        try:
            actual = self._invoke_mapper(fixture)
        except Exception as exc:  # noqa: BLE001
            return RegressionResult(
                connector_name=fixture.connector,
                fixture_name=fixture.name,
                passed=False,
                differences=[
                    RegressionDifference(
                        path="$",
                        expected="successful invocation",
                        actual=str(exc),
                        reason="invocation error",
                    )
                ],
            )
        differences = self._compare_golden(fixture.expected, actual, policy=fixture.policy, path="$")
        return RegressionResult(
            connector_name=fixture.connector,
            fixture_name=fixture.name,
            passed=not differences,
            differences=differences,
        )

    def _invoke_mapper(self, fixture: GoldenFixture) -> Any:
        if fixture.connector in self._registry:
            return self._registry[fixture.connector](copy.deepcopy(fixture.input))
        if not fixture.mapper:
            raise ValueError(f"no mapper registered or specified for connector '{fixture.connector}'")
        module_path, class_name = fixture.mapper.rsplit(":", 1)
        module = importlib.import_module(module_path)
        mapper_class = getattr(module, class_name)
        mapper_instance = mapper_class()
        method = getattr(mapper_instance, fixture.method)
        return method(copy.deepcopy(fixture.input))

    def _run_regression_fixture(self, fixture: RegressionFixture) -> RegressionResult:
        if fixture.connector_name not in self._registry:
            return RegressionResult(
                connector_name=fixture.connector_name,
                fixture_name=fixture.fixture_name,
                passed=False,
                differences=[
                    RegressionDifference(
                        path="$",
                        expected="registered normalizer",
                        actual="missing",
                        reason="no normalizer registered for connector",
                    )
                ],
            )

        actual = self._registry[fixture.connector_name](copy.deepcopy(fixture.input_payload))
        differences = self._compare(
            fixture.expected_output,
            actual,
            policy=fixture.policy,
            path="$",
        )
        return RegressionResult(
            connector_name=fixture.connector_name,
            fixture_name=fixture.fixture_name,
            passed=not differences,
            differences=differences,
        )

    def _compare_golden(
        self,
        expected: Any,
        actual: Any,
        *,
        policy: RegressionPolicy,
        path: str,
    ) -> list[RegressionDifference]:
        """Compare expected vs actual using the new ignore_fields / allow_additional_fields policy."""
        differences: list[RegressionDifference] = []

        if isinstance(expected, dict) and isinstance(actual, dict):
            for key, exp_val in expected.items():
                if key in policy.ignore_fields:
                    continue
                child_path = f"{path}.{key}"
                if key not in actual:
                    differences.append(RegressionDifference(child_path, exp_val, None, "missing field"))
                else:
                    differences.extend(self._compare_golden(exp_val, actual[key], policy=policy, path=child_path))
            if not policy.allow_additional_fields:
                for key, act_val in actual.items():
                    if key not in expected and key not in policy.ignore_fields:
                        differences.append(RegressionDifference(f"{path}.{key}", None, act_val, "unexpected field"))
        elif isinstance(expected, list) and isinstance(actual, list):
            if policy.require_exact_list_length and len(expected) != len(actual):
                differences.append(
                    RegressionDifference(path, len(expected), len(actual), "list length changed")
                )
                return differences
            # Order-independent matching
            unmatched = list(actual)
            for i, exp_item in enumerate(expected):
                matched = False
                for j, act_item in enumerate(unmatched):
                    if not self._compare_golden(exp_item, act_item, policy=policy, path=f"{path}[{i}]"):
                        unmatched.pop(j)
                        matched = True
                        break
                if not matched:
                    differences.append(
                        RegressionDifference(f"{path}[{i}]", exp_item, None, "no matching list item")
                    )
        else:
            if expected != actual:
                differences.append(RegressionDifference(path, expected, actual, "value changed"))

        return differences

    def _compare(
        self,
        expected: Any,
        actual: Any,
        *,
        policy: RegressionPolicy,
        path: str,
    ) -> list[RegressionDifference]:
        """Old-style comparison using ignored_paths."""
        if path in policy.ignored_paths:
            return []

        differences: list[RegressionDifference] = []

        if isinstance(expected, dict) and isinstance(actual, dict):
            for key, expected_value in expected.items():
                child_path = f"{path}.{key}"
                if child_path in policy.ignored_paths:
                    continue
                if key not in actual:
                    differences.append(RegressionDifference(child_path, expected_value, None, "missing field"))
                    continue
                differences.extend(self._compare(expected_value, actual[key], policy=policy, path=child_path))

            if not policy.allow_additive_fields:
                for key, actual_value in actual.items():
                    if key not in expected:
                        differences.append(RegressionDifference(f"{path}.{key}", None, actual_value, "unexpected field"))
        elif isinstance(expected, list) and isinstance(actual, list):
            if policy.strict_list_lengths and len(expected) != len(actual):
                differences.append(RegressionDifference(path, len(expected), len(actual), "list length changed"))
                return differences
            for idx, expected_item in enumerate(expected):
                if idx >= len(actual):
                    differences.append(RegressionDifference(f"{path}[{idx}]", expected_item, None, "missing list item"))
                    continue
                differences.extend(self._compare(expected_item, actual[idx], policy=policy, path=f"{path}[{idx}]"))
        else:
            if expected != actual:
                differences.append(RegressionDifference(path, expected, actual, "value changed"))

        return differences


def render_regression_report(run: RunResult) -> str:
    """Render a human-readable regression report from a RunResult."""
    lines: list[str] = []
    label = run.connector or "all"
    lines.append(f"=== Normalization Regression Report: {label} ===")
    lines.append(f"Overall: {'PASSED' if run.passed else 'FAILED'}")
    for result in run.results:
        status = "PASS" if result.passed else "FAIL"
        lines.append(f"  [{status}] {result.fixture_name}")
        for diff in result.differences:
            lines.append(f"    - {diff.path}: expected {diff.expected!r}, got {diff.actual!r} ({diff.reason})")
    return "\n".join(lines)

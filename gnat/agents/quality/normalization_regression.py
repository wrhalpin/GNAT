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

from dataclasses import dataclass, field
from importlib import import_module
import json
from pathlib import Path
from typing import Any, Iterable


@dataclass
class RegressionPolicy:
    """Rules used while comparing actual normalized output with a golden file."""

    ignore_fields: set[str] = field(default_factory=set)
    allow_additional_fields: bool = False
    require_exact_list_length: bool = True

    @classmethod
    def from_dict(cls, value: dict[str, Any] | None) -> "RegressionPolicy":
        value = value or {}
        return cls(
            ignore_fields=set(value.get("ignore_fields", [])),
            allow_additional_fields=bool(value.get("allow_additional_fields", False)),
            require_exact_list_length=bool(value.get("require_exact_list_length", True)),
        )


@dataclass
class GoldenFixture:
    """One golden normalization fixture."""

    name: str
    connector: str
    mapper: str
    method: str
    input: Any
    expected: Any
    policy: RegressionPolicy = field(default_factory=RegressionPolicy)
    notes: str | None = None

    @classmethod
    def from_path(cls, path: str | Path) -> "GoldenFixture":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            name=raw["name"],
            connector=raw["connector"],
            mapper=raw["mapper"],
            method=raw["method"],
            input=raw["input"],
            expected=raw["expected"],
            policy=RegressionPolicy.from_dict(raw.get("policy")),
            notes=raw.get("notes"),
        )


@dataclass
class ComparisonResult:
    """Outcome of comparing one fixture's actual output against its golden output."""

    fixture_name: str
    passed: bool
    actual: Any
    expected: Any
    differences: list[str] = field(default_factory=list)


@dataclass
class RegressionRun:
    """Aggregated result for one normalization regression session."""

    results: list[ComparisonResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(result.passed for result in self.results)

    @property
    def failed(self) -> list[ComparisonResult]:
        return [result for result in self.results if not result.passed]

    def summary(self) -> str:
        total = len(self.results)
        failed = len(self.failed)
        passed = total - failed
        return f"Normalization regression: {passed}/{total} passed, {failed} failed"


class NormalizationRegressionAgent:
    """Runs golden normalization fixtures against connector mapper callables."""

    def __init__(self, fixture_root: str | Path = "tests/unit/agents/data") -> None:
        self.fixture_root = Path(fixture_root)

    def load_fixtures(self, connector: str | None = None) -> list[GoldenFixture]:
        if not self.fixture_root.exists():
            return []

        fixtures: list[GoldenFixture] = []
        for path in sorted(self.fixture_root.glob("*_normalization_fixture.json")):
            fixture = GoldenFixture.from_path(path)
            if connector and fixture.connector != connector:
                continue
            fixtures.append(fixture)
        return fixtures

    def run(self, connector: str | None = None) -> RegressionRun:
        run = RegressionRun()
        for fixture in self.load_fixtures(connector=connector):
            run.results.append(self.run_fixture(fixture))
        return run

    def run_fixture(self, fixture: GoldenFixture) -> ComparisonResult:
        actual = self._invoke_fixture(fixture)
        differences = self._compare(
            expected=fixture.expected,
            actual=actual,
            policy=fixture.policy,
            path="root",
        )
        return ComparisonResult(
            fixture_name=fixture.name,
            passed=not differences,
            actual=actual,
            expected=fixture.expected,
            differences=differences,
        )

    def _invoke_fixture(self, fixture: GoldenFixture) -> Any:
        target = self._build_target(fixture.mapper)
        method = getattr(target, fixture.method)
        return method(fixture.input)

    def _build_target(self, target: str) -> Any:
        module_name, _, attribute_name = target.partition(":")
        if not module_name or not attribute_name:
            raise ValueError(
                "Mapper target must use '<module.path>:<ClassOrFactory>' syntax."
            )

        module = import_module(module_name)
        attribute = getattr(module, attribute_name)
        return attribute() if callable(attribute) else attribute

    def _compare(
        self,
        *,
        expected: Any,
        actual: Any,
        policy: RegressionPolicy,
        path: str,
    ) -> list[str]:
        differences: list[str] = []

        if isinstance(expected, dict) and isinstance(actual, dict):
            differences.extend(self._compare_dicts(expected, actual, policy, path))
            return differences

        if isinstance(expected, list) and isinstance(actual, list):
            differences.extend(self._compare_lists(expected, actual, policy, path))
            return differences

        if expected != actual:
            differences.append(
                f"{path}: expected {expected!r}, got {actual!r}"
            )
        return differences

    def _compare_dicts(
        self,
        expected: dict[str, Any],
        actual: dict[str, Any],
        policy: RegressionPolicy,
        path: str,
    ) -> list[str]:
        differences: list[str] = []

        expected_keys = {key for key in expected if key not in policy.ignore_fields}
        actual_keys = {key for key in actual if key not in policy.ignore_fields}

        missing_keys = sorted(expected_keys - actual_keys)
        for key in missing_keys:
            differences.append(f"{path}.{key}: expected key missing from actual output")

        if not policy.allow_additional_fields:
            extra_keys = sorted(actual_keys - expected_keys)
            for key in extra_keys:
                differences.append(f"{path}.{key}: unexpected key present in actual output")

        for key in sorted(expected_keys & actual_keys):
            differences.extend(
                self._compare(
                    expected=expected[key],
                    actual=actual[key],
                    policy=policy,
                    path=f"{path}.{key}",
                )
            )
        return differences

    def _compare_lists(
        self,
        expected: list[Any],
        actual: list[Any],
        policy: RegressionPolicy,
        path: str,
    ) -> list[str]:
        differences: list[str] = []

        if policy.require_exact_list_length and len(expected) != len(actual):
            differences.append(
                f"{path}: expected list length {len(expected)}, got {len(actual)}"
            )
            return differences

        expected_norm = [self._normalize_for_list(item, policy) for item in expected]
        actual_norm = [self._normalize_for_list(item, policy) for item in actual]

        expected_pairs = sorted(
            zip(expected, expected_norm),
            key=lambda pair: json.dumps(pair[1], sort_keys=True),
        )
        actual_pairs = sorted(
            zip(actual, actual_norm),
            key=lambda pair: json.dumps(pair[1], sort_keys=True),
        )

        for index, (expected_item, actual_item) in enumerate(
            zip([p[0] for p in expected_pairs], [p[0] for p in actual_pairs], strict=False)
        ):
            differences.extend(
                self._compare(
                    expected=expected_item,
                    actual=actual_item,
                    policy=policy,
                    path=f"{path}[{index}]",
                )
            )

        return differences

    def _normalize_for_list(self, value: Any, policy: RegressionPolicy) -> Any:
        if isinstance(value, dict):
            return {
                key: self._normalize_for_list(item, policy)
                for key, item in value.items()
                if key not in policy.ignore_fields
            }
        if isinstance(value, list):
            return [self._normalize_for_list(item, policy) for item in value]
        return value


def render_regression_report(run: RegressionRun) -> str:
    """Return a human-readable multi-line report for CI output or PR comments."""
    lines = [run.summary()]
    for result in run.failed:
        lines.append(f"- {result.fixture_name}")
        for diff in result.differences:
            lines.append(f"  * {diff}")
    return "\n".join(lines)


def iter_fixture_paths(root: str | Path) -> Iterable[Path]:
    """Yield fixture files under *root* in deterministic order."""
    base = Path(root)
    yield from sorted(base.glob("*_normalization_fixture.json"))

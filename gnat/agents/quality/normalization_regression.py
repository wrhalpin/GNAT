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
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence
import copy


JsonDict = Dict[str, Any]


@dataclass(slots=True)
class RegressionPolicy:
    ignored_paths: Sequence[str] = field(default_factory=tuple)
    allow_additive_fields: bool = True
    strict_list_lengths: bool = True


@dataclass(slots=True)
class RegressionFixture:
    connector_name: str
    input_payload: JsonDict
    expected_output: JsonDict
    policy: RegressionPolicy = field(default_factory=RegressionPolicy)
    fixture_name: str = "default"


@dataclass(slots=True)
class RegressionDifference:
    path: str
    expected: Any
    actual: Any
    reason: str


@dataclass(slots=True)
class RegressionResult:
    connector_name: str
    fixture_name: str
    passed: bool
    differences: List[RegressionDifference] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if self.passed:
            return f"{self.connector_name}:{self.fixture_name} passed"
        return f"{self.connector_name}:{self.fixture_name} failed with {len(self.differences)} differences"


class NormalizationRegressionAgent:
    """Golden-output verifier for connector normalization behavior."""

    def __init__(self, normalizer_registry: Optional[Mapping[str, Callable[[JsonDict], JsonDict]]] = None) -> None:
        self._registry = dict(normalizer_registry or {})

    def register(self, connector_name: str, normalizer: Callable[[JsonDict], JsonDict]) -> None:
        self._registry[connector_name] = normalizer

    def run_fixture(self, fixture: RegressionFixture) -> RegressionResult:
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

    def run_all(self, fixtures: Iterable[RegressionFixture]) -> List[RegressionResult]:
        return [self.run_fixture(fixture) for fixture in fixtures]

    def _compare(self, expected: Any, actual: Any, *, policy: RegressionPolicy, path: str) -> List[RegressionDifference]:
        if path in policy.ignored_paths:
            return []

        differences: List[RegressionDifference] = []

        if isinstance(expected, dict) and isinstance(actual, dict):
            for key, expected_value in expected.items():
                child_path = f"{path}.{key}"
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

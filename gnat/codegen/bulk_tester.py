# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.codegen.bulk_tester
=========================

Orchestrate pytest execution across all (or selected) connector test files.

Discovers test files, runs pytest in subprocesses (one per connector or in
batches), parses JUnit XML output, and returns a structured :class:`BulkTestResult`
summary.

Usage::

    from gnat.codegen.bulk_tester import run_bulk_tests, BulkTestResult

    result = run_bulk_tests(connectors=["crowdstrike", "sentinel"], parallel=4)
    print(f"{result.passed}/{result.total} passed  coverage={result.coverage_pct:.0f}%")
    for cr in result.connector_results:
        if not cr.passed:
            print(f"  FAIL {cr.name}: {cr.error_summary}")
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_TEST_DIR = "tests/unit/connectors"
_DEFAULT_WORKERS = 4
_PYTEST_TIMEOUT = 120  # seconds per connector test file


@dataclass
class ConnectorTestResult:
    """
    Test result for a single connector.

    Parameters
    ----------
    name : str
        Connector name (matches registry key).
    passed : bool
        ``True`` when all tests pass.
    total_tests : int
        Number of test cases discovered.
    passed_tests : int
        Number of tests that passed.
    failed_tests : int
        Number of tests that failed.
    error_tests : int
        Number of tests that errored (not the same as failed).
    skipped_tests : int
        Number of skipped tests.
    elapsed_seconds : float
        Wall-clock time for this connector's test run.
    error_summary : str
        Short description of failures (empty when all pass).
    test_file : str
        Path to the test file that was executed.
    """

    name: str
    passed: bool = False
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    error_tests: int = 0
    skipped_tests: int = 0
    elapsed_seconds: float = 0.0
    error_summary: str = ""
    test_file: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-friendly dict."""
        return {
            "name": self.name,
            "passed": self.passed,
            "total_tests": self.total_tests,
            "passed_tests": self.passed_tests,
            "failed_tests": self.failed_tests,
            "error_tests": self.error_tests,
            "skipped_tests": self.skipped_tests,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "error_summary": self.error_summary,
            "test_file": self.test_file,
        }


@dataclass
class BulkTestResult:
    """
    Aggregated result of a bulk connector test run.

    Parameters
    ----------
    total : int
        Total number of connectors tested.
    passed : int
        Number of connectors where all tests passed.
    failed : int
        Number of connectors with at least one test failure/error.
    skipped : int
        Number of connectors with no test file found.
    coverage_pct : float
        Percentage of connectors that have test files (0–100).
    total_test_cases : int
        Total individual test cases across all connectors.
    elapsed_seconds : float
        Total wall-clock time.
    connector_results : list[ConnectorTestResult]
        Per-connector details.
    """

    total: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    coverage_pct: float = 0.0
    total_test_cases: int = 0
    elapsed_seconds: float = 0.0
    connector_results: list[ConnectorTestResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-friendly dict."""
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "coverage_pct": round(self.coverage_pct, 1),
            "total_test_cases": self.total_test_cases,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "connector_results": [r.to_dict() for r in self.connector_results],
        }


def run_bulk_tests(
    connectors: list[str] | None = None,
    test_dir: str = _DEFAULT_TEST_DIR,
    parallel: int = _DEFAULT_WORKERS,
    project_root: str | None = None,
    verbose: bool = False,
) -> BulkTestResult:
    """
    Run pytest for all (or specified) connector test files.

    Parameters
    ----------
    connectors : list[str], optional
        Connector names to test.  When ``None`` all connectors with test files
        in *test_dir* are run.
    test_dir : str
        Directory containing connector test files.
    parallel : int
        Number of parallel pytest processes.
    project_root : str, optional
        Repository root for resolving paths.  Defaults to CWD.
    verbose : bool
        Pass ``-v`` to pytest for richer output.

    Returns
    -------
    BulkTestResult
    """
    root = Path(project_root or os.getcwd())
    test_path = root / test_dir
    start = time.monotonic()

    # Discover test files
    connector_files = _discover_test_files(test_path, connectors)

    if not connector_files:
        logger.warning("bulk_tester: no test files found in %s", test_path)
        return BulkTestResult(total=0, coverage_pct=0.0)

    logger.info(
        "bulk_tester: testing %d connector(s) with %d workers", len(connector_files), parallel
    )

    workers = min(parallel, len(connector_files))
    connector_results: list[ConnectorTestResult] = []

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="bulk-test") as pool:
        future_to_name = {
            pool.submit(_run_single, name, path, root, verbose): name
            for name, path in connector_files.items()
        }
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                cr = future.result(timeout=_PYTEST_TIMEOUT + 10)
            except Exception as exc:
                cr = ConnectorTestResult(
                    name=name,
                    passed=False,
                    error_summary=f"Executor error: {exc}",
                )
            connector_results.append(cr)

    elapsed = time.monotonic() - start

    # Aggregate
    passed = sum(1 for r in connector_results if r.passed)
    failed = sum(1 for r in connector_results if not r.passed and r.total_tests > 0)
    skipped = sum(1 for r in connector_results if r.total_tests == 0 and not r.error_summary)
    total_tcs = sum(r.total_tests for r in connector_results)
    tested = passed + failed
    cov_pct = (tested / len(connector_files) * 100) if connector_files else 0.0

    connector_results.sort(key=lambda r: r.name)

    return BulkTestResult(
        total=len(connector_files),
        passed=passed,
        failed=failed,
        skipped=skipped,
        coverage_pct=cov_pct,
        total_test_cases=total_tcs,
        elapsed_seconds=elapsed,
        connector_results=connector_results,
    )


# ── Internal helpers ──────────────────────────────────────────────────────────


def _discover_test_files(
    test_path: Path,
    connectors: list[str] | None,
) -> dict[str, Path]:
    """Return {connector_name: test_file_path} for discovered files."""
    result: dict[str, Path] = {}

    if not test_path.exists():
        return result

    if connectors:
        for name in connectors:
            # Try both test_<name>.py and test_connectors.py
            candidates = [
                test_path / f"test_{name}.py",
                test_path / f"test_{name}_client.py",
            ]
            for c in candidates:
                if c.exists():
                    result[name] = c
                    break
    else:
        for f in sorted(test_path.glob("test_*.py")):
            # Derive connector name from filename
            stem = f.stem  # test_crowdstrike
            name = stem.removeprefix("test_").removesuffix("_client")
            result[name] = f

    return result


def _run_single(
    name: str,
    path: Path,
    root: Path,
    verbose: bool,
) -> ConnectorTestResult:
    """Run pytest for a single connector test file and parse the XML output."""
    start = time.monotonic()
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_path = tmp.name

    try:
        cmd = [
            sys.executable,
            "-m",
            "pytest",
            str(path),
            f"--junitxml={xml_path}",
            "--tb=short",
            "-q",
        ]
        if verbose:
            cmd.append("-v")

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_PYTEST_TIMEOUT,
            cwd=str(root),
        )
        elapsed = time.monotonic() - start

        return _parse_junit_xml(name, xml_path, str(path), elapsed, proc)

    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - start
        return ConnectorTestResult(
            name=name,
            passed=False,
            elapsed_seconds=elapsed,
            error_summary=f"Timed out after {_PYTEST_TIMEOUT}s",
            test_file=str(path),
        )
    except Exception as exc:
        elapsed = time.monotonic() - start
        return ConnectorTestResult(
            name=name,
            passed=False,
            elapsed_seconds=elapsed,
            error_summary=str(exc),
            test_file=str(path),
        )
    finally:
        import contextlib

        with contextlib.suppress(OSError):
            os.unlink(xml_path)


def _parse_junit_xml(
    name: str,
    xml_path: str,
    test_file: str,
    elapsed: float,
    proc: subprocess.CompletedProcess,
) -> ConnectorTestResult:
    """Parse JUnit XML output and build a :class:`ConnectorTestResult`."""
    try:
        tree = ET.parse(xml_path)  # nosec B314
        root = tree.getroot()

        # Handle both <testsuites> and <testsuite> roots
        if root.tag == "testsuites":
            suites = list(root)
        else:
            suites = [root]

        total = 0
        failed = 0
        errors = 0
        skipped = 0
        failures_text: list[str] = []

        for suite in suites:
            total += int(suite.get("tests", 0))
            failed += int(suite.get("failures", 0))
            errors += int(suite.get("errors", 0))
            skipped += int(suite.get("skipped", 0))
            for tc in suite.findall(".//failure"):
                msg = tc.get("message", "") or tc.text or ""
                failures_text.append(msg[:200])

        passed_count = total - failed - errors - skipped
        all_passed = failed == 0 and errors == 0 and total > 0
        error_summary = (
            "; ".join(failures_text[:3])
            if failures_text
            else ("" if all_passed else (proc.stderr or proc.stdout or "")[:300])
        )

        return ConnectorTestResult(
            name=name,
            passed=all_passed,
            total_tests=total,
            passed_tests=max(0, passed_count),
            failed_tests=failed,
            error_tests=errors,
            skipped_tests=skipped,
            elapsed_seconds=elapsed,
            error_summary=error_summary,
            test_file=test_file,
        )

    except Exception:
        # XML missing or malformed — fall back to return code
        passed = proc.returncode == 0
        return ConnectorTestResult(
            name=name,
            passed=passed,
            elapsed_seconds=elapsed,
            error_summary="" if passed else (proc.stderr or proc.stdout or "")[:300],
            test_file=test_file,
        )

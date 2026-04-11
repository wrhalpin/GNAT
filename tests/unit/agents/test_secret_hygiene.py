# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/agents/test_secret_hygiene.py
============================================

Tests for the three secret-hygiene helpers that live under
``gnat.agents.security.hygiene``:

* :class:`LeakScanner` — filesystem scan for hard-coded credentials
* :class:`DuplicateDetector` — find repeated secret values
* :class:`UnsafePatternDetector` — audit connector configs for inline
  credentials that should be secret refs instead

The previous version of this file imported from the wrong package path
(``gnat.agents.secrets.*``) with class/method names that never existed;
it was dead code that broke pytest collection on every run.  This
rewrite exercises the actual public surface.
"""

from __future__ import annotations

from pathlib import Path

from gnat.agents.security.hygiene.duplicate_detector import DuplicateDetector
from gnat.agents.security.hygiene.leak_scanner import LeakFinding, LeakScanner
from gnat.agents.security.hygiene.unsafe_patterns import (
    UnsafePatternDetector,
    UnsafePatternFinding,
)

# ---------------------------------------------------------------------------
# LeakScanner
# ---------------------------------------------------------------------------


class TestLeakScanner:
    def test_finds_aws_access_key(self, tmp_path: Path) -> None:
        bad = tmp_path / "config.py"
        bad.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\nprint("ok")\n')
        findings = LeakScanner().scan_paths([str(tmp_path)])
        assert any(f.rule == "aws_access_key" for f in findings)

    def test_finds_private_key_header(self, tmp_path: Path) -> None:
        bad = tmp_path / "key.pem"
        bad.write_text("-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n")
        findings = LeakScanner().scan_paths([str(tmp_path)])
        assert any(f.rule == "private_key_header" for f in findings)

    def test_finds_generic_token_assignment(self, tmp_path: Path) -> None:
        bad = tmp_path / "app.py"
        bad.write_text('api_key = "abc123456789XYZ"\n')
        findings = LeakScanner().scan_paths([str(tmp_path)])
        assert any(f.rule == "generic_token_assignment" for f in findings)

    def test_generic_token_is_medium_severity(self, tmp_path: Path) -> None:
        bad = tmp_path / "app.py"
        bad.write_text('api_key = "abc123456789XYZ"\n')
        findings = LeakScanner().scan_paths([str(tmp_path)])
        match = [f for f in findings if f.rule == "generic_token_assignment"]
        assert match and match[0].severity == "medium"

    def test_aws_is_high_severity(self, tmp_path: Path) -> None:
        bad = tmp_path / "aws.py"
        bad.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = LeakScanner().scan_paths([str(tmp_path)])
        match = [f for f in findings if f.rule == "aws_access_key"]
        assert match and match[0].severity == "high"

    def test_allowlist_filters_finding(self, tmp_path: Path) -> None:
        good = tmp_path / "test_fixture.py"
        line = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        good.write_text(line + "\n")
        findings = LeakScanner(allowlist=[line]).scan_paths([str(tmp_path)])
        assert not findings

    def test_skips_git_directory(self, tmp_path: Path) -> None:
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "leaked.py").write_text('api_key = "abc123456789XYZ"\n')
        findings = LeakScanner().scan_paths([str(tmp_path)])
        assert not findings

    def test_clean_tree_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / "clean.py").write_text("print('hello')\n")
        assert LeakScanner().scan_paths([str(tmp_path)]) == []

    def test_leak_finding_dataclass(self) -> None:
        finding = LeakFinding(
            path="a.py", line_number=3, severity="high", rule="aws_access_key", snippet="..."
        )
        assert finding.line_number == 3
        assert finding.severity == "high"


# ---------------------------------------------------------------------------
# DuplicateDetector
# ---------------------------------------------------------------------------


class TestDuplicateDetector:
    def test_groups_identical_values(self) -> None:
        dups = DuplicateDetector().find_duplicates(
            ["same", "same", "different", "same"]
        )
        assert "same" in dups
        assert len(dups["same"]) == 3

    def test_ignores_unique_values(self) -> None:
        assert DuplicateDetector().find_duplicates(["a", "b", "c"]) == {}

    def test_empty_input(self) -> None:
        assert DuplicateDetector().find_duplicates([]) == {}

    def test_returns_dict_of_lists(self) -> None:
        dups = DuplicateDetector().find_duplicates(["x", "y", "x", "y", "z"])
        assert set(dups) == {"x", "y"}
        assert all(isinstance(v, list) for v in dups.values())


# ---------------------------------------------------------------------------
# UnsafePatternDetector
# ---------------------------------------------------------------------------


class TestUnsafePatternDetector:
    def test_plain_text_secret_flagged(self) -> None:
        findings = UnsafePatternDetector().inspect_connector_config(
            {"credentials": {"api_key": "hardcoded-value"}}
        )
        assert any(f.rule == "plain_text_secret" for f in findings)

    def test_embedded_value_dict_flagged(self) -> None:
        findings = UnsafePatternDetector().inspect_connector_config(
            {"credentials": {"token": {"value": "hardcoded-value"}}}
        )
        assert any(f.rule == "embedded_secret_value" for f in findings)

    def test_secret_ref_is_clean(self) -> None:
        findings = UnsafePatternDetector().inspect_connector_config(
            {"credentials": {"api_key": {"secret_ref": "vault://dev/key"}}}
        )
        assert findings == []

    def test_no_credentials_key(self) -> None:
        findings = UnsafePatternDetector().inspect_connector_config({"host": "https://x"})
        assert findings == []

    def test_bad_credentials_type_ignored(self) -> None:
        findings = UnsafePatternDetector().inspect_connector_config(
            {"credentials": "not-a-dict"}
        )
        assert findings == []

    def test_finding_location_contains_field(self) -> None:
        findings = UnsafePatternDetector().inspect_connector_config(
            {"credentials": {"my_token": "plain"}}
        )
        assert findings[0].location == "credentials.my_token"

    def test_unsafe_finding_dataclass(self) -> None:
        finding = UnsafePatternFinding(
            location="credentials.api_key",
            rule="plain_text_secret",
            message="test",
        )
        assert finding.rule == "plain_text_secret"

"""
gnat.codegen.contribute
========================

Opt-in pipeline for submitting a new or updated GNAT connector as a
draft pull request against the upstream ``wrhalpin/GNAT`` repository.

The pipeline:

1. Validates that the ``[contribute]`` section has ``enabled = true``.
2. Confirms the connector exists in ``CLIENT_REGISTRY``.
3. Runs the **compliance matrix** — verifies all eight required
   :class:`~gnat.connectors.base_connector.ConnectorMixin` methods are
   implemented in the concrete class and that unit tests exist.
4. Executes the full unit-test suite (``pytest tests/unit/``); aborts on
   failure.
5. Creates a fresh ``contribute/<platform>-<date>`` branch (never
   ``main`` or ``master``).
6. Stages the connector files, commits, and pushes to the configured
   fork remote.
7. Optionally opens a **draft** PR via the GitHub REST API (requires
   ``github_token``).

Safety rules (non-negotiable):

* Draft-only PRs — ``draft_pr = true`` cannot be overridden by CLI.
* Never pushes to ``main`` or ``master``.
* Connector must pass the compliance matrix before any git operations.
* Tests must pass before any git operations.

Configuration (``config.ini``)::

    [contribute]
    enabled         = false          ; must be set to true to use
    github_token    = ghp_...        ; PAT with repo scope on your fork
    fork_remote     = origin
    upstream_remote = upstream
    upstream_repo   = wrhalpin/GNAT
    draft_pr        = true

CLI::

    gnat contribute --connector myplatform --message "Add MyPlatform connector"
    gnat contribute --connector myplatform --no-pr --message "WIP: draft"
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import urllib3

logger = logging.getLogger(__name__)

# Required methods every connector must implement (item #15 matrix)
REQUIRED_METHODS: List[str] = [
    "authenticate",
    "health_check",
    "get_object",
    "list_objects",
    "upsert_object",
    "delete_object",
    "to_stix",
    "from_stix",
]

# Classes whose method definitions count as "stub / not implemented"
_BASE_MODULE_NAMES = frozenset({"ConnectorMixin", "BaseClient", "object"})

# Protected branch names — never push to these
_PROTECTED_BRANCHES = frozenset({"main", "master"})

# Upstream repository (owner/name)
_UPSTREAM_REPO = "wrhalpin/GNAT"


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class ContributeConfig:
    """
    Configuration for the upstream contribution pipeline.

    Attributes
    ----------
    enabled : bool
        Must be ``True`` to allow any operations.  Default ``False``.
    github_token : str
        Personal Access Token with ``repo`` scope on the fork.  Empty
        string disables PR creation.
    fork_remote : str
        Git remote name for the user's fork.  Default ``"origin"``.
    upstream_remote : str
        Git remote name for the upstream repo.  Default ``"upstream"``.
    upstream_repo : str
        ``owner/repo`` path on GitHub.  Default ``"wrhalpin/GNAT"``.
    draft_pr : bool
        Always ``True`` — not overridable.
    """

    enabled:         bool  = False
    github_token:    str   = ""
    fork_remote:     str   = "origin"
    upstream_remote: str   = "upstream"
    upstream_repo:   str   = _UPSTREAM_REPO
    draft_pr:        bool  = True   # immutable; PR always draft

    @classmethod
    def from_ini(cls, config_path: str) -> "ContributeConfig":
        """Read ``[contribute]`` from an INI config file."""
        import configparser
        cp = configparser.ConfigParser()
        cp.read(config_path)
        if "contribute" not in cp:
            return cls()
        sec = cp["contribute"]
        return cls(
            enabled         = sec.getboolean("enabled", fallback=False),
            github_token    = sec.get("github_token", fallback="") or "",
            fork_remote     = sec.get("fork_remote", fallback="origin"),
            upstream_remote = sec.get("upstream_remote", fallback="upstream"),
            upstream_repo   = sec.get("upstream_repo", fallback=_UPSTREAM_REPO),
            draft_pr        = True,  # always True regardless of INI
        )


# ---------------------------------------------------------------------------
# Compliance matrix
# ---------------------------------------------------------------------------

@dataclass
class MethodStatus:
    name:        str
    implemented: bool
    note:        str = ""


@dataclass
class ComplianceResult:
    """
    Compliance check outcome for one connector.

    Attributes
    ----------
    connector : str
    method_statuses : list of MethodStatus
    has_tests : bool
    passed : bool
    """

    connector:        str
    method_statuses:  List[MethodStatus] = field(default_factory=list)
    has_tests:        bool               = False

    @property
    def passed(self) -> bool:
        """``True`` when every required method is implemented and a test file exists."""
        return (
            all(s.implemented for s in self.method_statuses)
            and self.has_tests
        )

    def report(self) -> str:
        """Human-readable compliance report."""
        lines = [f"Compliance matrix for {self.connector!r}:"]
        for s in self.method_statuses:
            mark = "✓" if s.implemented else "✗"
            line = f"  {mark} {s.name}"
            if s.note:
                line += f" — {s.note}"
            lines.append(line)
        test_mark = "✓" if self.has_tests else "✗"
        lines.append(f"  {test_mark} unit tests")
        lines.append("")
        lines.append("PASSED" if self.passed else "FAILED")
        return "\n".join(lines)


class ComplianceMatrix:
    """
    Checks a connector class against the eight-method contract.

    A method is considered **implemented** if it is defined in the
    concrete connector class or any non-base superclass (i.e. not only
    inherited as a stub from :class:`ConnectorMixin` or
    :class:`~gnat.clients.base.BaseClient`).
    """

    @staticmethod
    def check(connector_name: str, repo_root: Optional[str] = None) -> ComplianceResult:
        """
        Run the compliance matrix for *connector_name*.

        Parameters
        ----------
        connector_name : str
            Key in ``CLIENT_REGISTRY`` (e.g. ``"threatq"``).
        repo_root : str, optional
            Repository root for test-file lookup.  Defaults to CWD.

        Returns
        -------
        ComplianceResult
        """
        from gnat.clients import CLIENT_REGISTRY
        from gnat.connectors.base_connector import ConnectorMixin
        from gnat.clients.base import BaseClient

        base_classes = {ConnectorMixin, BaseClient, object}

        result = ComplianceResult(connector=connector_name)

        connector_cls = CLIENT_REGISTRY.get(connector_name)
        if connector_cls is None:
            # Unknown connector — all methods fail
            for name in REQUIRED_METHODS:
                result.method_statuses.append(
                    MethodStatus(name, False, "connector not in CLIENT_REGISTRY")
                )
            return result

        for method_name in REQUIRED_METHODS:
            implemented = False
            note = ""
            for cls in connector_cls.__mro__:
                if cls in base_classes:
                    continue
                if method_name in vars(cls):
                    implemented = True
                    break
            if not implemented:
                note = "only inherited stub from ConnectorMixin"
            result.method_statuses.append(MethodStatus(method_name, implemented, note))

        # Check for unit tests
        result.has_tests = ComplianceMatrix._has_tests(connector_name, repo_root)
        return result

    @staticmethod
    def _has_tests(connector_name: str, repo_root: Optional[str] = None) -> bool:
        """Return ``True`` if test coverage exists for *connector_name*."""
        root = Path(repo_root) if repo_root else Path.cwd()
        test_file = root / "tests" / "unit" / "connectors" / "test_connectors.py"
        if not test_file.exists():
            return False
        content = test_file.read_text(encoding="utf-8", errors="replace").lower()
        # Look for "Test{PlatformTitleCase}Client" or "{connector_name}" in test class names
        name_lower = connector_name.replace("_", "").lower()
        patterns = [
            f"test{name_lower}client",
            f"test{name_lower}",
            f"test_{connector_name.lower()}",
            connector_name.lower(),
        ]
        return any(p in content for p in patterns)


# ---------------------------------------------------------------------------
# Subprocess runner (injectable for testing)
# ---------------------------------------------------------------------------

class SubprocessRunner:
    """
    Thin wrapper around :func:`subprocess.run`.

    Injected into :class:`ContributionPipeline` so tests can substitute
    a mock without patching the ``subprocess`` module globally.
    """

    def run(
        self,
        cmd: List[str],
        cwd: Optional[str] = None,
        capture: bool = True,
        check: bool = False,
    ) -> subprocess.CompletedProcess:
        """Execute *cmd* and return the :class:`subprocess.CompletedProcess` result."""
        return subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=capture,
            text=True,
            check=check,
        )


# ---------------------------------------------------------------------------
# Contribution result
# ---------------------------------------------------------------------------

@dataclass
class ContributionResult:
    """
    Outcome of one :meth:`ContributionPipeline.run` call.

    Attributes
    ----------
    success : bool
    branch : str
        Branch name created and pushed (empty if pipeline aborted).
    pr_url : str
        GitHub pull request URL if one was created.
    error : str
        Human-readable error message on failure.
    steps_completed : list of str
        Names of steps that completed successfully.
    """

    success:         bool      = False
    branch:          str       = ""
    pr_url:          str       = ""
    error:           str       = ""
    steps_completed: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class ContributionPipeline:
    """
    Orchestrates the upstream contribution workflow.

    Parameters
    ----------
    runner : SubprocessRunner, optional
        Subprocess wrapper.  Defaults to a real :class:`SubprocessRunner`.
    repo_root : str, optional
        Repository root directory.  Defaults to CWD.
    http_client : urllib3.PoolManager, optional
        HTTP client for GitHub API calls.  Defaults to a new instance.
    """

    def __init__(
        self,
        runner: Optional[SubprocessRunner] = None,
        repo_root: Optional[str] = None,
        http_client: Optional[urllib3.PoolManager] = None,
    ) -> None:
        self._runner      = runner or SubprocessRunner()
        self._root        = repo_root or str(Path.cwd())
        self._http        = http_client or urllib3.PoolManager(
            timeout=urllib3.Timeout(connect=10, read=30)
        )

    # ── Public entry point ──────────────────────────────────────────────────

    def run(
        self,
        connector_name: str,
        message: str,
        config: ContributeConfig,
        create_pr: bool = True,
    ) -> ContributionResult:
        """
        Execute the full contribution pipeline.

        Parameters
        ----------
        connector_name : str
            Platform key (e.g. ``"myplatform"``).
        message : str
            Commit/PR title message.
        config : ContributeConfig
            Loaded configuration.
        create_pr : bool
            Whether to attempt PR creation (requires ``github_token``).
            Default ``True``.

        Returns
        -------
        ContributionResult
        """
        result = ContributionResult()

        # Step 0: enabled guard
        if not config.enabled:
            result.error = (
                "Contribution pipeline is disabled.  "
                "Set [contribute] enabled = true in config.ini to opt in."
            )
            return result

        # Step 1: connector exists
        from gnat.clients import CLIENT_REGISTRY
        if connector_name not in CLIENT_REGISTRY:
            result.error = (
                f"Unknown connector {connector_name!r}.  "
                f"Available: {sorted(CLIENT_REGISTRY.keys())}"
            )
            return result

        # Step 2: compliance matrix
        compliance = ComplianceMatrix.check(connector_name, self._root)
        if not compliance.passed:
            result.error = (
                f"Compliance check failed for {connector_name!r}.\n\n"
                + compliance.report()
            )
            return result
        result.steps_completed.append("compliance")

        # Step 3: run tests
        test_ok, test_output = self._run_tests()
        if not test_ok:
            result.error = (
                f"Unit tests failed — fix before contributing.\n\n{test_output}"
            )
            return result
        result.steps_completed.append("tests")

        # Step 4: create branch
        branch = self._branch_name(connector_name)
        ok, err = self._git_create_branch(branch)
        if not ok:
            result.error = f"Failed to create branch {branch!r}: {err}"
            return result
        result.branch = branch
        result.steps_completed.append("branch")

        # Step 5: stage connector files
        ok, err = self._git_stage(connector_name)
        if not ok:
            result.error = f"Failed to stage files: {err}"
            return result
        result.steps_completed.append("stage")

        # Step 6: commit
        ok, err = self._git_commit(message)
        if not ok:
            result.error = f"Commit failed: {err}"
            return result
        result.steps_completed.append("commit")

        # Step 7: push
        ok, err = self._git_push(branch, config.fork_remote)
        if not ok:
            result.error = f"Push to {config.fork_remote!r} failed: {err}"
            return result
        result.steps_completed.append("push")

        # Step 8: create PR (optional)
        if create_pr and config.github_token:
            fork_owner = self._get_remote_owner(config.fork_remote)
            pr_url, err = self._create_github_pr(
                branch       = branch,
                message      = message,
                connector    = connector_name,
                config       = config,
                fork_owner   = fork_owner,
            )
            if pr_url:
                result.pr_url = pr_url
                result.steps_completed.append("pr")
            else:
                logger.warning("PR creation failed (non-fatal): %s", err)

        result.success = True
        return result

    # ── Git helpers ─────────────────────────────────────────────────────────

    def _branch_name(self, connector_name: str) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return f"contribute/{connector_name}-{ts}"

    def _git_create_branch(self, branch: str) -> tuple:
        """Create and check out *branch*.  Refuse if it's a protected name."""
        if branch in _PROTECTED_BRANCHES or any(
            branch == p for p in _PROTECTED_BRANCHES
        ):
            return False, f"Refused to create protected branch {branch!r}"
        proc = self._runner.run(
            ["git", "checkout", "-b", branch], cwd=self._root, capture=True
        )
        if proc.returncode != 0:
            return False, proc.stderr.strip()
        return True, ""

    def _git_stage(self, connector_name: str) -> tuple:
        """Stage connector files and related changed files."""
        connector_dir = f"gnat/connectors/{connector_name}"
        paths_to_stage = [connector_dir]

        # Also stage these if they contain unstaged changes for this connector
        for candidate in (
            "gnat/clients/__init__.py",
            "tests/unit/connectors/test_connectors.py",
            "config/config.ini.example",
        ):
            full = Path(self._root) / candidate
            if full.exists():
                # Check if file is modified (git status --porcelain)
                check = self._runner.run(
                    ["git", "status", "--porcelain", candidate],
                    cwd=self._root, capture=True,
                )
                if check.returncode == 0 and check.stdout.strip():
                    paths_to_stage.append(candidate)

        proc = self._runner.run(
            ["git", "add"] + paths_to_stage, cwd=self._root, capture=True
        )
        if proc.returncode != 0:
            return False, proc.stderr.strip()
        return True, ""

    def _git_commit(self, message: str) -> tuple:
        proc = self._runner.run(
            ["git", "commit", "-m", message], cwd=self._root, capture=True
        )
        if proc.returncode != 0:
            return False, proc.stderr.strip()
        return True, ""

    def _git_push(self, branch: str, remote: str) -> tuple:
        """Push *branch* to *remote*.  Refuses if branch is main/master."""
        base = branch.split("/")[-1]   # e.g. "myplatform-20260101-120000"
        if branch in _PROTECTED_BRANCHES or base in _PROTECTED_BRANCHES:
            return False, f"Safety: refused to push protected branch {branch!r}"
        proc = self._runner.run(
            ["git", "push", "-u", remote, branch], cwd=self._root, capture=True
        )
        if proc.returncode != 0:
            return False, proc.stderr.strip()
        return True, ""

    def _run_tests(self) -> tuple:
        """Run the unit test suite.  Returns ``(passed, output)``."""
        proc = self._runner.run(
            [sys.executable, "-m", "pytest", "tests/unit/", "-q", "--tb=short"],
            cwd=self._root,
            capture=True,
        )
        return proc.returncode == 0, (proc.stdout or "") + (proc.stderr or "")

    def _get_remote_owner(self, remote: str) -> str:
        """
        Extract the GitHub owner (username) from a git remote URL.

        Handles both HTTPS (``https://github.com/owner/repo.git``) and
        SSH (``git@github.com:owner/repo.git``) formats.
        """
        proc = self._runner.run(
            ["git", "remote", "get-url", remote], cwd=self._root, capture=True
        )
        if proc.returncode != 0:
            return "unknown"
        url = proc.stdout.strip()
        # HTTPS: https://github.com/owner/repo.git
        m = re.search(r"github\.com[/:]([^/]+)/", url)
        return m.group(1) if m else "unknown"

    # ── GitHub API ──────────────────────────────────────────────────────────

    def _create_github_pr(
        self,
        branch: str,
        message: str,
        connector: str,
        config: ContributeConfig,
        fork_owner: str,
    ) -> tuple:
        """
        Create a draft pull request via the GitHub REST API.

        Returns ``(pr_url, error_message)``.  On success ``error_message``
        is empty; on failure ``pr_url`` is empty.
        """
        owner, repo = config.upstream_repo.split("/", 1)
        api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
        body = (
            f"## Summary\n\n"
            f"Add `{connector}` connector.\n\n"
            f"Generated by `gnat contribute`.\n\n"
            f"## Checklist\n\n"
            f"- [ ] All 8 ConnectorMixin methods implemented\n"
            f"- [ ] Unit tests added in `tests/unit/connectors/test_connectors.py`\n"
            f"- [ ] `[{connector}]` section added to `config/config.ini.example`\n"
            f"- [ ] `CLIENT_REGISTRY` entry added in `gnat/clients/__init__.py`\n"
        )
        payload = {
            "title": message,
            "body":  body,
            "head":  f"{fork_owner}:{branch}",
            "base":  "main",
            "draft": True,  # always draft — safety rule
        }
        try:
            resp = self._http.request(
                "POST",
                api_url,
                body=json.dumps(payload).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {config.github_token}",
                    "Accept":        "application/vnd.github+json",
                    "Content-Type":  "application/json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            data = json.loads(resp.data.decode("utf-8"))
            if resp.status in (200, 201):
                return data.get("html_url", ""), ""
            return "", f"GitHub API {resp.status}: {data.get('message', resp.data)}"
        except Exception as exc:
            return "", str(exc)

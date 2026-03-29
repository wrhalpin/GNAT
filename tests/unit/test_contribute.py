"""
tests/unit/test_contribute.py
==============================
Unit tests for gnat.codegen.contribute.

Tests cover:
1.  ContributeConfig defaults and INI reading
2.  ContributeConfig.draft_pr is always True regardless of INI value
3.  ComplianceMatrix.check() — all methods present (passing connector)
4.  ComplianceMatrix.check() — unknown connector (all fail)
5.  ComplianceMatrix.check() — missing method
6.  ComplianceMatrix._has_tests() — test file present with class
7.  ComplianceMatrix._has_tests() — test file missing
8.  ComplianceResult.passed / .report()
9.  ContributionPipeline.run() — disabled config aborts
10. ContributionPipeline.run() — unknown connector aborts
11. ContributionPipeline.run() — compliance failure aborts
12. ContributionPipeline.run() — test failure aborts
13. ContributionPipeline.run() — success path (no PR)
14. ContributionPipeline.run() — success with PR
15. ContributionPipeline.run() — push safety (main/master refused)
16. ContributionPipeline._run_tests() — returncode 0 → True
17. ContributionPipeline._run_tests() — returncode 1 → False
18. ContributionPipeline._get_remote_owner() — HTTPS URL
19. ContributionPipeline._get_remote_owner() — SSH URL
20. ContributionPipeline._get_remote_owner() — git command fails
21. ContributionPipeline._create_github_pr() — 201 response
22. ContributionPipeline._create_github_pr() — error response
23. ContributionPipeline._create_github_pr() — exception
24. ContributionPipeline._git_push() — refuses protected branches
25. ContributionPipeline._branch_name() format
26. CLI subcommand registration
27. CLI contribute --help exits 0
28. CLI disabled config exits 1
29. CLI dry-run path (no git ops)
30. CLI compliance failure exits 1
"""

from __future__ import annotations

import subprocess
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

from gnat.codegen.contribute import (
    REQUIRED_METHODS,
    ComplianceMatrix,
    ComplianceResult,
    ContributeConfig,
    ContributionPipeline,
    MethodStatus,
    SubprocessRunner,
    _PROTECTED_BRANCHES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_runner(returncode: int = 0, stdout: str = "", stderr: str = "") -> SubprocessRunner:
    """Return a SubprocessRunner whose .run() always returns a fixed result."""
    runner = MagicMock(spec=SubprocessRunner)
    result = MagicMock(spec=subprocess.CompletedProcess)
    result.returncode = returncode
    result.stdout = stdout
    result.stderr = stderr
    runner.run.return_value = result
    return runner


def _make_pipeline(
    runner: Optional[SubprocessRunner] = None,
    repo_root: Optional[str] = None,
    http_client=None,
) -> ContributionPipeline:
    return ContributionPipeline(
        runner=runner or _make_runner(),
        repo_root=repo_root or "/fake/repo",
        http_client=http_client or MagicMock(),
    )


def _enabled_config(**kwargs) -> ContributeConfig:
    defaults = dict(
        enabled=True,
        github_token="ghp_test",
        fork_remote="origin",
        upstream_remote="upstream",
        upstream_repo="wrhalpin/GNAT",
    )
    defaults.update(kwargs)
    return ContributeConfig(**defaults)


# ---------------------------------------------------------------------------
# ContributeConfig
# ---------------------------------------------------------------------------

class TestContributeConfig:

    def test_defaults(self):
        cfg = ContributeConfig()
        assert cfg.enabled is False
        assert cfg.fork_remote == "origin"
        assert cfg.upstream_remote == "upstream"
        assert cfg.upstream_repo == "wrhalpin/GNAT"
        assert cfg.draft_pr is True
        assert cfg.github_token == ""

    def test_from_ini_reads_section(self, tmp_path):
        ini = tmp_path / "gnat.ini"
        ini.write_text(
            "[contribute]\n"
            "enabled = true\n"
            "github_token = ghp_abc123\n"
            "fork_remote = myfork\n"
            "upstream_remote = up\n"
            "upstream_repo = alice/GNAT\n"
        )
        cfg = ContributeConfig.from_ini(str(ini))
        assert cfg.enabled is True
        assert cfg.github_token == "ghp_abc123"
        assert cfg.fork_remote == "myfork"
        assert cfg.upstream_remote == "up"
        assert cfg.upstream_repo == "alice/GNAT"

    def test_from_ini_missing_section_returns_defaults(self, tmp_path):
        ini = tmp_path / "gnat.ini"
        ini.write_text("[threatq]\nhost = https://tq.example.com\n")
        cfg = ContributeConfig.from_ini(str(ini))
        assert cfg.enabled is False

    def test_draft_pr_always_true_regardless_of_ini(self, tmp_path):
        """draft_pr cannot be set to False via INI."""
        ini = tmp_path / "gnat.ini"
        ini.write_text("[contribute]\nenabled = true\ndraft_pr = false\n")
        cfg = ContributeConfig.from_ini(str(ini))
        assert cfg.draft_pr is True

    def test_from_ini_nonexistent_file(self, tmp_path):
        cfg = ContributeConfig.from_ini(str(tmp_path / "nofile.ini"))
        assert cfg.enabled is False


# ---------------------------------------------------------------------------
# ComplianceMatrix
# ---------------------------------------------------------------------------

class TestComplianceMatrix:

    def test_known_connector_passes(self):
        """threatq is fully implemented — should pass compliance."""
        result = ComplianceMatrix.check("threatq")
        assert len(result.method_statuses) == len(REQUIRED_METHODS)
        # All methods should be implemented
        not_impl = [s.name for s in result.method_statuses if not s.implemented]
        assert not_impl == [], f"Unexpectedly unimplemented: {not_impl}"

    def test_unknown_connector_all_fail(self):
        result = ComplianceMatrix.check("no_such_platform_xyz")
        assert all(not s.implemented for s in result.method_statuses)
        assert result.passed is False

    def test_method_status_count_matches_required(self):
        result = ComplianceMatrix.check("threatq")
        assert len(result.method_statuses) == len(REQUIRED_METHODS)

    def test_has_tests_file_present(self, tmp_path):
        test_file = tmp_path / "tests" / "unit" / "connectors" / "test_connectors.py"
        test_file.parent.mkdir(parents=True)
        test_file.write_text("class TestMyPlatformClient:\n    pass\n")
        assert ComplianceMatrix._has_tests("myplatform", str(tmp_path)) is True

    def test_has_tests_file_missing(self, tmp_path):
        assert ComplianceMatrix._has_tests("myplatform", str(tmp_path)) is False

    def test_has_tests_class_not_found(self, tmp_path):
        test_file = tmp_path / "tests" / "unit" / "connectors" / "test_connectors.py"
        test_file.parent.mkdir(parents=True)
        test_file.write_text("class TestOtherClient:\n    pass\n")
        assert ComplianceMatrix._has_tests("myplatform", str(tmp_path)) is False

    def test_report_contains_method_names(self):
        result = ComplianceMatrix.check("threatq")
        result.has_tests = True
        report = result.report()
        for method in REQUIRED_METHODS:
            assert method in report

    def test_report_shows_failed(self):
        result = ComplianceResult(connector="fake")
        result.method_statuses = [MethodStatus("health_check", False, "stub")]
        result.has_tests = False
        assert "FAILED" in result.report()

    def test_compliance_result_passed_requires_tests(self):
        result = ComplianceResult(connector="fake")
        result.method_statuses = [MethodStatus(m, True) for m in REQUIRED_METHODS]
        result.has_tests = False
        assert result.passed is False

    def test_compliance_result_passed_requires_all_methods(self):
        result = ComplianceResult(connector="fake")
        result.method_statuses = [MethodStatus(m, True) for m in REQUIRED_METHODS]
        result.method_statuses[0] = MethodStatus(REQUIRED_METHODS[0], False)
        result.has_tests = True
        assert result.passed is False


# ---------------------------------------------------------------------------
# ContributionPipeline.run() — abort paths
# ---------------------------------------------------------------------------

class TestContributionPipelineAbortPaths:

    def test_disabled_config_aborts(self):
        pipeline = _make_pipeline()
        cfg = ContributeConfig(enabled=False)
        result = pipeline.run("threatq", "msg", cfg)
        assert result.success is False
        assert "disabled" in result.error.lower()

    def test_unknown_connector_aborts(self):
        pipeline = _make_pipeline()
        cfg = _enabled_config()
        # Patch compliance to pass but connector is unknown
        result = pipeline.run("no_such_connector_xyz", "msg", cfg)
        assert result.success is False
        assert "Unknown connector" in result.error

    def test_compliance_failure_aborts(self, tmp_path):
        """A connector with no tests → compliance fails → pipeline aborts."""
        runner = _make_runner()
        pipeline = _make_pipeline(runner=runner, repo_root=str(tmp_path))
        cfg = _enabled_config()
        # Use a known connector but patch has_tests to return False
        with patch.object(ComplianceMatrix, "_has_tests", return_value=False):
            result = pipeline.run("threatq", "msg", cfg)
        assert result.success is False
        assert "Compliance check failed" in result.error
        assert "compliance" not in result.steps_completed

    def test_test_failure_aborts(self, tmp_path):
        """When pytest returns non-zero, pipeline aborts before git ops."""
        runner = _make_runner(returncode=1, stdout="FAILED tests/unit/...", stderr="")
        pipeline = _make_pipeline(runner=runner, repo_root=str(tmp_path))
        cfg = _enabled_config()
        with patch.object(ComplianceMatrix, "check") as mock_check:
            compliance = ComplianceResult("threatq")
            compliance.method_statuses = [
                MethodStatus(m, True) for m in REQUIRED_METHODS
            ]
            compliance.has_tests = True
            mock_check.return_value = compliance
            result = pipeline.run("threatq", "msg", cfg)
        assert result.success is False
        assert "tests" not in result.steps_completed
        assert "FAILED" in result.error


# ---------------------------------------------------------------------------
# ContributionPipeline.run() — success path
# ---------------------------------------------------------------------------

class TestContributionPipelineSuccess:

    def _passing_compliance(self) -> ComplianceResult:
        c = ComplianceResult("threatq")
        c.method_statuses = [MethodStatus(m, True) for m in REQUIRED_METHODS]
        c.has_tests = True
        return c

    def _run_with_mocks(
        self,
        tmp_path,
        runner_kwargs=None,
        create_pr=True,
        github_token="ghp_test",
        pr_url="https://github.com/wrhalpin/GNAT/pull/42",
    ):
        runner = _make_runner(**(runner_kwargs or {}))
        http = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.data = f'{{"html_url": "{pr_url}"}}'.encode()
        http.request.return_value = mock_resp

        pipeline = _make_pipeline(runner=runner, repo_root=str(tmp_path), http_client=http)
        cfg = _enabled_config(github_token=github_token)

        with patch.object(ComplianceMatrix, "check", return_value=self._passing_compliance()):
            # Also override _run_tests to return success
            pipeline._run_tests = lambda: (True, "all passed")  # type: ignore
            result = pipeline.run("threatq", "Add threatq", cfg, create_pr=create_pr)
        return result, runner, http

    def test_success_path_all_steps(self, tmp_path):
        result, runner, http = self._run_with_mocks(tmp_path)
        assert result.success is True
        assert "compliance" in result.steps_completed
        assert "tests" in result.steps_completed
        assert "branch" in result.steps_completed
        assert "stage" in result.steps_completed
        assert "commit" in result.steps_completed
        assert "push" in result.steps_completed
        assert "pr" in result.steps_completed

    def test_success_sets_pr_url(self, tmp_path):
        result, _, _ = self._run_with_mocks(tmp_path)
        assert result.pr_url == "https://github.com/wrhalpin/GNAT/pull/42"

    def test_success_no_pr_skips_api_call(self, tmp_path):
        result, _, http = self._run_with_mocks(tmp_path, create_pr=False)
        assert result.success is True
        assert result.pr_url == ""
        http.request.assert_not_called()

    def test_success_no_token_skips_pr(self, tmp_path):
        result, _, http = self._run_with_mocks(tmp_path, github_token="")
        assert result.success is True
        assert result.pr_url == ""
        http.request.assert_not_called()

    def test_branch_name_format(self, tmp_path):
        result, _, _ = self._run_with_mocks(tmp_path)
        assert result.branch.startswith("contribute/threatq-")

    def test_git_operations_called(self, tmp_path):
        result, runner, _ = self._run_with_mocks(tmp_path, create_pr=False)
        calls = [str(c) for c in runner.run.call_args_list]
        # Should have called git checkout, add, commit, push
        assert any("checkout" in c for c in calls)
        assert any("add" in c for c in calls)
        assert any("commit" in c for c in calls)
        assert any("push" in c for c in calls)


# ---------------------------------------------------------------------------
# Git safety
# ---------------------------------------------------------------------------

class TestGitSafety:

    def test_push_refuses_main(self):
        pipeline = _make_pipeline()
        ok, err = pipeline._git_push("main", "origin")
        assert ok is False
        assert "Safety" in err

    def test_push_refuses_master(self):
        pipeline = _make_pipeline()
        ok, err = pipeline._git_push("master", "origin")
        assert ok is False
        assert "Safety" in err

    def test_push_allows_contribute_branch(self):
        runner = _make_runner(returncode=0)
        pipeline = _make_pipeline(runner=runner)
        ok, err = pipeline._git_push("contribute/myplatform-20260101", "origin")
        assert ok is True

    def test_create_branch_refuses_protected(self):
        pipeline = _make_pipeline()
        ok, err = pipeline._git_create_branch("main")
        assert ok is False


# ---------------------------------------------------------------------------
# _run_tests
# ---------------------------------------------------------------------------

class TestRunTests:

    def test_returncode_zero_is_passing(self):
        runner = _make_runner(returncode=0, stdout="5 passed")
        pipeline = _make_pipeline(runner=runner)
        passed, output = pipeline._run_tests()
        assert passed is True
        assert "passed" in output

    def test_returncode_nonzero_is_failing(self):
        runner = _make_runner(returncode=1, stdout="", stderr="3 failed")
        pipeline = _make_pipeline(runner=runner)
        passed, output = pipeline._run_tests()
        assert passed is False
        assert "failed" in output


# ---------------------------------------------------------------------------
# _get_remote_owner
# ---------------------------------------------------------------------------

class TestGetRemoteOwner:

    def test_https_url(self):
        runner = _make_runner(returncode=0, stdout="https://github.com/alice/GNAT.git\n")
        pipeline = _make_pipeline(runner=runner)
        assert pipeline._get_remote_owner("origin") == "alice"

    def test_ssh_url(self):
        runner = _make_runner(returncode=0, stdout="git@github.com:bob/GNAT.git\n")
        pipeline = _make_pipeline(runner=runner)
        assert pipeline._get_remote_owner("origin") == "bob"

    def test_git_failure_returns_unknown(self):
        runner = _make_runner(returncode=128, stderr="not a git repo")
        pipeline = _make_pipeline(runner=runner)
        assert pipeline._get_remote_owner("origin") == "unknown"


# ---------------------------------------------------------------------------
# _create_github_pr
# ---------------------------------------------------------------------------

class TestCreateGithubPR:

    def _http_client(self, status: int, body: str):
        http = MagicMock()
        resp = MagicMock()
        resp.status = status
        resp.data = body.encode()
        http.request.return_value = resp
        return http

    def test_201_returns_pr_url(self):
        http = self._http_client(201, '{"html_url": "https://github.com/wrhalpin/GNAT/pull/1"}')
        pipeline = _make_pipeline(http_client=http)
        cfg = _enabled_config()
        url, err = pipeline._create_github_pr("contribute/tq-20260101", "msg", "threatq", cfg, "alice")
        assert url == "https://github.com/wrhalpin/GNAT/pull/1"
        assert err == ""

    def test_422_returns_error(self):
        http = self._http_client(422, '{"message": "Validation Failed"}')
        pipeline = _make_pipeline(http_client=http)
        cfg = _enabled_config()
        url, err = pipeline._create_github_pr("branch", "msg", "tq", cfg, "alice")
        assert url == ""
        assert "422" in err

    def test_exception_returns_error(self):
        http = MagicMock()
        http.request.side_effect = Exception("network error")
        pipeline = _make_pipeline(http_client=http)
        cfg = _enabled_config()
        url, err = pipeline._create_github_pr("branch", "msg", "tq", cfg, "alice")
        assert url == ""
        assert "network error" in err

    def test_pr_always_draft(self):
        http = self._http_client(201, '{"html_url": "https://github.com/wrhalpin/GNAT/pull/1"}')
        pipeline = _make_pipeline(http_client=http)
        cfg = _enabled_config()
        pipeline._create_github_pr("branch", "msg", "tq", cfg, "alice")
        call_kwargs = http.request.call_args
        body = call_kwargs[1].get("body") or call_kwargs[0][2]
        import json
        payload = json.loads(body)
        assert payload["draft"] is True


# ---------------------------------------------------------------------------
# _branch_name
# ---------------------------------------------------------------------------

class TestBranchName:

    def test_format(self):
        pipeline = _make_pipeline()
        name = pipeline._branch_name("threatq")
        assert name.startswith("contribute/threatq-")
        assert name != "main"
        assert name != "master"

    def test_not_protected(self):
        pipeline = _make_pipeline()
        name = pipeline._branch_name("threatq")
        assert name not in _PROTECTED_BRANCHES


# ---------------------------------------------------------------------------
# CLI subcommand
# ---------------------------------------------------------------------------

class TestCLIContribute:

    def test_help_exits_zero(self):
        from gnat.cli.main import main
        with pytest.raises(SystemExit) as exc:
            main(["contribute", "--help"])
        assert exc.value.code == 0

    def test_registered_in_parser(self):
        from gnat.cli.main import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["contribute", "--connector", "threatq"])
        assert args.command == "contribute"
        assert args.connector == "threatq"

    def test_no_pr_flag(self):
        from gnat.cli.main import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["contribute", "--connector", "threatq", "--no-pr"])
        assert args.no_pr is True

    def test_dry_run_flag(self):
        from gnat.cli.main import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["contribute", "--connector", "threatq", "--dry-run"])
        assert args.dry_run is True

    def test_disabled_config_exits_1(self, tmp_path):
        ini = tmp_path / "gnat.ini"
        ini.write_text("[contribute]\nenabled = false\n")
        from gnat.cli.main import main
        result = main(["--config", str(ini), "contribute", "--connector", "threatq"])
        assert result == 1

    def test_dry_run_compliance_pass_exits_zero(self, tmp_path):
        ini = tmp_path / "gnat.ini"
        ini.write_text("[contribute]\nenabled = true\n")
        # threatq is fully implemented — compliance should pass
        with patch.object(ComplianceMatrix, "_has_tests", return_value=True):
            from gnat.cli.main import main
            result = main([
                "--config", str(ini),
                "contribute", "--connector", "threatq", "--dry-run",
            ])
        assert result == 0

    def test_dry_run_compliance_fail_exits_1(self, tmp_path):
        ini = tmp_path / "gnat.ini"
        ini.write_text("[contribute]\nenabled = true\n")
        with patch.object(ComplianceMatrix, "_has_tests", return_value=False):
            from gnat.cli.main import main
            result = main([
                "--config", str(ini),
                "contribute", "--connector", "threatq", "--dry-run",
            ])
        assert result == 1

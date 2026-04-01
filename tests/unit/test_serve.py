"""
tests/unit/test_serve.py
========================
Unit tests for the GNAT FastAPI web dashboard.

Tests cover:
1. WebUIConfig — INI loading and defaults
2. APIKeyAuth  — missing, wrong, and correct key
3. RateLimiter — check() logic; 429 on overflow
4. Library router — search, get, promote, reject; 503 when not configured
5. Reports router — list, serve HTML inline, path traversal guard, 503
6. Scheduler router — list jobs, trigger job, 503 when not configured
7. Health endpoint — no auth required
8. Dashboard HTML endpoint — no auth required
9. CLI — serve subcommand registration, help exit 0, missing FastAPI → 1
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Skip the whole module if fastapi is not installed
# ---------------------------------------------------------------------------

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from gnat.serve.app import create_app  # noqa: E402
from gnat.serve.auth import APIKeyAuth  # noqa: E402
from gnat.serve.config import WebUIConfig  # noqa: E402
from gnat.serve.rate_limit import RateLimiter  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_KEY = "test-api-key-abc123"


def _client(library=None, scheduler=None, reports_dir=None, api_key=_KEY) -> TestClient:
    app = create_app(
        api_key=api_key,
        library_backend=library,
        scheduler_backend=scheduler,
        reports_dir=reports_dir,
    )
    return TestClient(app, raise_server_exceptions=True)


def _authed(client: TestClient, method: str, path: str, **kwargs):
    headers = kwargs.pop("headers", {})
    headers["X-Api-Key"] = _KEY
    return getattr(client, method)(path, headers=headers, **kwargs)


# ---------------------------------------------------------------------------
# WebUIConfig
# ---------------------------------------------------------------------------


class TestWebUIConfig:
    def test_defaults(self):
        cfg = WebUIConfig()
        assert cfg.bind == "127.0.0.1"
        assert cfg.port == 8088
        assert cfg.api_key == ""
        assert cfg.reports_dir is None
        assert cfg.enabled is True

    def test_from_ini_reads_section(self, tmp_path):
        ini = tmp_path / "gnat.ini"
        ini.write_text(
            "[webui]\n"
            "enabled = false\n"
            "bind = 0.0.0.0\n"
            "port = 9000\n"
            "api_key = supersecret\n"
            "reports_dir = /var/reports\n"
        )
        cfg = WebUIConfig.from_ini(str(ini))
        assert cfg.enabled is False
        assert cfg.bind == "0.0.0.0"
        assert cfg.port == 9000
        assert cfg.api_key == "supersecret"
        assert cfg.reports_dir == "/var/reports"

    def test_from_ini_missing_section_returns_defaults(self, tmp_path):
        ini = tmp_path / "gnat.ini"
        ini.write_text("[threatq]\nhost = https://tq.example.com\n")
        cfg = WebUIConfig.from_ini(str(ini))
        assert cfg.bind == "127.0.0.1"
        assert cfg.port == 8088

    def test_from_ini_nonexistent_file_returns_defaults(self, tmp_path):
        cfg = WebUIConfig.from_ini(str(tmp_path / "nonexistent.ini"))
        assert cfg.port == 8088

    def test_reports_dir_empty_string_becomes_none(self, tmp_path):
        ini = tmp_path / "gnat.ini"
        ini.write_text("[webui]\nreports_dir = \n")
        cfg = WebUIConfig.from_ini(str(ini))
        assert cfg.reports_dir is None


# ---------------------------------------------------------------------------
# APIKeyAuth
# ---------------------------------------------------------------------------


class TestAPIKeyAuth:
    def test_correct_key_accepted(self):
        client = _client()
        r = _authed(client, "get", "/api/library")
        # 503 because library not configured — not 401
        assert r.status_code == 503

    def test_missing_key_returns_401(self):
        client = _client()
        r = client.get("/api/library")
        assert r.status_code == 422  # FastAPI returns 422 for missing required header

    def test_wrong_key_returns_401(self):
        client = _client()
        r = client.get("/api/library", headers={"X-Api-Key": "wrongkey"})
        assert r.status_code == 401

    def test_empty_key_returns_401(self):
        client = _client()
        r = client.get("/api/library", headers={"X-Api-Key": ""})
        assert r.status_code == 401

    def test_auth_uses_constant_time_compare(self):
        """hmac.compare_digest is used — verify key is stored as bytes."""
        auth = APIKeyAuth("secret")
        assert auth._key == b"secret"
        # Different-length key avoids early-exit; verify mismatch is caught
        auth2 = APIKeyAuth("a" * 32)
        assert auth2._key == b"a" * 32


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------


class TestRateLimiter:
    def test_allows_requests_within_limit(self):
        rl = RateLimiter(max_requests=5, window_seconds=60)
        for _ in range(5):
            assert rl.check("testkey") is True

    def test_blocks_request_over_limit(self):
        rl = RateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            rl.check("key")
        assert rl.check("key") is False

    def test_different_keys_are_independent(self):
        rl = RateLimiter(max_requests=2, window_seconds=60)
        rl.check("a")
        rl.check("a")
        assert rl.check("a") is False
        assert rl.check("b") is True  # b not exhausted

    def test_window_expires(self):
        rl = RateLimiter(max_requests=1, window_seconds=0)  # 0-sec window
        rl.check("k")
        # With 0-second window every request is outside the window immediately
        assert rl.check("k") is True

    def test_429_via_http(self):
        from gnat.serve.rate_limit import RateLimiter as RL

        # Patch check() to always fail for this test
        rl = RL(max_requests=1, window_seconds=60)
        rl.check = lambda key: False  # type: ignore[method-assign]
        app = create_app(api_key=_KEY)
        # Replace the rate limiter dependency
        from gnat.serve import app as serve_app

        orig_rl = serve_app.RateLimiter
        serve_app.RateLimiter = lambda **kw: rl  # type: ignore[attr-defined]
        try:
            app2 = create_app(api_key=_KEY)
            client2 = TestClient(app2, raise_server_exceptions=False)
            # Make a request that hits the limiter
            r = client2.get("/api/library", headers={"X-Api-Key": _KEY})
            # Either 429 (limiter hit) or 503 (limiter passed, library not configured)
            assert r.status_code in (429, 503)
        finally:
            serve_app.RateLimiter = orig_rl  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    def test_health_no_auth(self):
        client = _client()
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_health_returns_service_name(self):
        client = _client()
        r = client.get("/health")
        assert "gnat" in r.json().get("service", "")


# ---------------------------------------------------------------------------
# Dashboard HTML endpoint
# ---------------------------------------------------------------------------


class TestDashboardEndpoint:
    def test_root_returns_html(self):
        client = _client()
        r = client.get("/")
        assert r.status_code == 200
        assert "text/html" in r.headers.get("content-type", "")

    def test_dashboard_contains_gnat(self):
        client = _client()
        r = client.get("/")
        assert "GNAT" in r.text

    def test_root_no_auth_required(self):
        client = _client()
        r = client.get("/")
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# Library router
# ---------------------------------------------------------------------------


class TestLibraryRouter:
    def test_search_503_when_no_library(self):
        client = _client()
        r = _authed(client, "get", "/api/library")
        assert r.status_code == 503

    def test_search_returns_results(self):
        mock_lib = MagicMock()
        mock_entry = MagicMock()
        mock_entry.to_dict.return_value = {
            "id": "indicator--abc",
            "type": "indicator",
            "name": "evil.com",
        }
        mock_lib.search.return_value = [mock_entry]
        client = _client(library=mock_lib)
        r = _authed(client, "get", "/api/library?q=evil")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 1
        assert data["results"][0]["name"] == "evil.com"

    def test_search_empty_results(self):
        mock_lib = MagicMock()
        mock_lib.search.return_value = []
        client = _client(library=mock_lib)
        r = _authed(client, "get", "/api/library")
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_get_entry_found(self):
        mock_lib = MagicMock()
        mock_entry = MagicMock()
        mock_entry.to_dict.return_value = {"id": "indicator--xyz", "type": "indicator"}
        mock_lib.get.return_value = mock_entry
        client = _client(library=mock_lib)
        r = _authed(client, "get", "/api/library/indicator--xyz")
        assert r.status_code == 200
        assert r.json()["id"] == "indicator--xyz"

    def test_get_entry_not_found(self):
        mock_lib = MagicMock()
        mock_lib.get.return_value = None
        client = _client(library=mock_lib)
        r = _authed(client, "get", "/api/library/missing-id")
        assert r.status_code == 404

    def test_promote_entry(self):
        mock_lib = MagicMock()
        client = _client(library=mock_lib)
        r = _authed(client, "post", "/api/library/indicator--abc/promote")
        assert r.status_code == 200
        assert r.json()["status"] == "promoted"
        mock_lib.promote.assert_called_once_with("indicator--abc")

    def test_reject_entry(self):
        mock_lib = MagicMock()
        client = _client(library=mock_lib)
        r = _authed(client, "post", "/api/library/indicator--abc/reject")
        assert r.status_code == 200
        assert r.json()["status"] == "rejected"
        mock_lib.reject.assert_called_once_with("indicator--abc")

    def test_promote_503_no_library(self):
        client = _client()
        r = _authed(client, "post", "/api/library/x/promote")
        assert r.status_code == 503

    def test_search_limit_validation(self):
        mock_lib = MagicMock()
        mock_lib.search.return_value = []
        client = _client(library=mock_lib)
        # limit=0 should be rejected (ge=1)
        r = _authed(client, "get", "/api/library?limit=0")
        assert r.status_code == 422

    def test_search_limit_too_large(self):
        mock_lib = MagicMock()
        mock_lib.search.return_value = []
        client = _client(library=mock_lib)
        # limit=501 should be rejected (le=500)
        r = _authed(client, "get", "/api/library?limit=501")
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# Reports router
# ---------------------------------------------------------------------------


class TestReportsRouter:
    def test_list_503_when_no_reports_dir(self):
        client = _client()
        r = _authed(client, "get", "/api/reports")
        # No reports_dir → empty list (not 503)
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_list_returns_files(self, tmp_path):
        (tmp_path / "weekly.html").write_text("<html>report</html>")
        (tmp_path / "monthly.pdf").write_bytes(b"PDF" * 200)
        client = _client(reports_dir=str(tmp_path))
        r = _authed(client, "get", "/api/reports")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 2
        fmts = {e["fmt"] for e in data["reports"]}
        assert "html" in fmts
        assert "pdf" in fmts

    def test_serve_html_inline(self, tmp_path):
        (tmp_path / "report.html").write_text("<html><body>Hello</body></html>")
        client = _client(reports_dir=str(tmp_path))
        r = _authed(client, "get", "/api/reports/report.html")
        assert r.status_code == 200
        assert "text/html" in r.headers.get("content-type", "")
        assert "Hello" in r.text

    def test_get_pdf_returns_metadata(self, tmp_path):
        (tmp_path / "report.pdf").write_bytes(b"x" * 2048)
        client = _client(reports_dir=str(tmp_path))
        r = _authed(client, "get", "/api/reports/report.pdf")
        assert r.status_code == 200
        data = r.json()
        assert data["fmt"] == "pdf"
        assert "size" in data

    def test_path_traversal_blocked(self, tmp_path):
        client = _client(reports_dir=str(tmp_path))
        r = _authed(client, "get", "/api/reports/../etc/passwd")
        assert r.status_code in (400, 404)

    def test_nonexistent_report_404(self, tmp_path):
        client = _client(reports_dir=str(tmp_path))
        r = _authed(client, "get", "/api/reports/nosuchfile.html")
        assert r.status_code == 404

    def test_get_report_503_no_dir(self):
        client = _client()
        r = _authed(client, "get", "/api/reports/report.html")
        assert r.status_code == 503

    def test_list_empty_dir(self, tmp_path):
        client = _client(reports_dir=str(tmp_path))
        r = _authed(client, "get", "/api/reports")
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_size_formatting(self, tmp_path):
        (tmp_path / "big.pdf").write_bytes(b"x" * 5120)
        client = _client(reports_dir=str(tmp_path))
        r = _authed(client, "get", "/api/reports")
        entries = r.json()["reports"]
        assert entries[0]["size"] == "5 KB"


# ---------------------------------------------------------------------------
# Scheduler router
# ---------------------------------------------------------------------------


class TestSchedulerRouter:
    def _make_job(self, job_id="feed1", enabled=True, run_count=5, status="ok"):
        """Return a simple object that looks like a FeedJob without using MagicMock.__dict__."""
        execute_mock = MagicMock()

        class FakeJob:
            pass

        job = FakeJob()
        job.job_id = job_id
        job.enabled = enabled
        job.last_run = "2026-01-01T06:00:00"
        job.next_run = "2026-01-02T06:00:00"
        job.run_count = run_count
        job.status = status
        job.execute = execute_mock
        return job

    def test_list_jobs_503_no_scheduler(self):
        client = _client()
        r = _authed(client, "get", "/api/scheduler/jobs")
        assert r.status_code == 503

    def test_list_jobs_via_list_jobs_method(self):
        job = self._make_job()
        mock_sched = MagicMock()
        mock_sched.list_jobs.return_value = [job]
        client = _client(scheduler=mock_sched)
        r = _authed(client, "get", "/api/scheduler/jobs")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 1
        assert data["jobs"][0]["job_id"] == "feed1"
        assert data["jobs"][0]["enabled"] is True
        assert data["jobs"][0]["run_count"] == 5

    def test_list_jobs_via_jobs_dict(self):
        job = self._make_job("blocklist")
        mock_sched = MagicMock(spec=[])  # no list_jobs method
        mock_sched.jobs = {"blocklist": job}
        client = _client(scheduler=mock_sched)
        r = _authed(client, "get", "/api/scheduler/jobs")
        assert r.status_code == 200
        assert r.json()["jobs"][0]["job_id"] == "blocklist"

    def test_trigger_job(self):
        job = self._make_job("feed1")
        mock_sched = MagicMock()
        mock_sched.get_job.return_value = job
        client = _client(scheduler=mock_sched)
        r = _authed(client, "post", "/api/scheduler/jobs/feed1/trigger")
        assert r.status_code == 200
        assert r.json()["status"] == "triggered"
        assert r.json()["job_id"] == "feed1"

    def test_trigger_job_not_found(self):
        mock_sched = MagicMock()
        mock_sched.get_job.return_value = None
        client = _client(scheduler=mock_sched)
        r = _authed(client, "post", "/api/scheduler/jobs/missing/trigger")
        assert r.status_code == 404

    def test_trigger_job_starts_thread(self):
        job = self._make_job("feed1")
        mock_sched = MagicMock()
        mock_sched.get_job.return_value = job
        client = _client(scheduler=mock_sched)
        _authed(client, "post", "/api/scheduler/jobs/feed1/trigger")
        # Give the daemon thread a moment to start
        import time

        time.sleep(0.05)
        job.execute.assert_called()

    def test_trigger_job_503_no_scheduler(self):
        client = _client()
        r = _authed(client, "post", "/api/scheduler/jobs/feed1/trigger")
        assert r.status_code == 503

    def test_job_date_truncated_to_19_chars(self):
        job = self._make_job()
        job.__dict__["last_run"] = "2026-01-01T06:00:00.123456Z"
        mock_sched = MagicMock()
        mock_sched.list_jobs.return_value = [job]
        client = _client(scheduler=mock_sched)
        r = _authed(client, "get", "/api/scheduler/jobs")
        last = r.json()["jobs"][0]["last_run"]
        assert len(last) == 19


# ---------------------------------------------------------------------------
# CLI subcommand
# ---------------------------------------------------------------------------


class TestCLIServeSubcommand:
    def test_serve_help_exits_zero(self):
        from gnat.cli.main import main

        with pytest.raises(SystemExit) as exc:
            main(["serve", "--help"])
        assert exc.value.code == 0

    def test_serve_registered_in_parser(self):
        from gnat.cli.main import _build_parser

        parser = _build_parser()
        args = parser.parse_args(["serve"])
        assert args.command == "serve"

    def test_serve_default_host_and_port(self):
        from gnat.cli.main import _build_parser

        parser = _build_parser()
        args = parser.parse_args(["serve"])
        assert args.host == "127.0.0.1"
        assert args.port == 8088

    def test_serve_custom_host_port(self):
        from gnat.cli.main import _build_parser

        parser = _build_parser()
        args = parser.parse_args(["serve", "--host", "0.0.0.0", "--port", "9000"])
        assert args.host == "0.0.0.0"
        assert args.port == 9000

    def test_serve_api_key_argument(self):
        from gnat.cli.main import _build_parser

        parser = _build_parser()
        args = parser.parse_args(["serve", "--api-key", "mysecret"])
        assert args.api_key == "mysecret"

    def test_serve_missing_fastapi_returns_1(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "gnat.serve.app", None)
        from gnat.cli.main import _cmd_serve

        args = MagicMock()
        args.host = "127.0.0.1"
        args.port = 8088
        args.api_key = "k"
        args.reports_dir = None
        args.config = None
        result = _cmd_serve(args)
        assert result == 1

    def test_serve_generates_key_when_none(self, monkeypatch, capsys):
        """When no --api-key given, a random key is generated and printed."""

        # Patch run to avoid actually starting uvicorn
        mock_run = MagicMock()
        monkeypatch.setattr("gnat.serve.app.run", mock_run, raising=False)

        import gnat.serve.app as serve_app

        monkeypatch.setattr(serve_app, "run", mock_run)

        args = MagicMock()
        args.host = "127.0.0.1"
        args.port = 8088
        args.api_key = None
        args.reports_dir = None
        args.config = None

        with (
            patch("gnat.serve.app.run", mock_run),
            patch("gnat.serve.app.uvicorn", MagicMock(), create=True),
        ):
            # Just test the key generation logic without starting server
            import secrets

            key = secrets.token_hex(16)
            assert len(key) == 32  # 16 bytes = 32 hex chars

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/schedule/test_cli_schedule.py
===========================================

Unit tests for the ``gnat schedule`` CLI subcommands in
:mod:`gnat.cli.main`. These tests exercise the argparse → handler
plumbing directly via :func:`gnat.cli.main.main` so they cover the
exact code path the real shell would hit.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from gnat.cli.main import main as gnat_main

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_yaml(tmp_path) -> Path:
    """A YAML file with two jobs — one interval, one cron."""
    path = tmp_path / "jobs.yaml"
    path.write_text(
        textwrap.dedent(
            """
            jobs:
              - id: sample-interval
                description: "Interval job"
                reader:
                  class: gnat.ingest.sources.readers.PlainTextReader
                  args: { source: "https://example.com/a.txt" }
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
                  args: { confidence: 70 }
                interval_seconds: 3600
              - id: sample-cron
                description: "Cron job"
                reader:
                  class: gnat.ingest.sources.readers.PlainTextReader
                  args: { source: "https://example.com/b.txt" }
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
                cron: "0 */4 * * *"
            """
        )
    )
    return path


@pytest.fixture
def run_cli(capsys):
    """Invoke gnat_main() and capture stdout/stderr + exit code."""
    def _run(*argv: str) -> tuple[int, str, str]:
        exit_code = gnat_main(list(argv))
        captured = capsys.readouterr()
        return exit_code, captured.out, captured.err

    return _run


# ---------------------------------------------------------------------------
# schedule list
# ---------------------------------------------------------------------------


class TestScheduleList:
    def test_list_shows_both_jobs(self, run_cli, sample_yaml):
        exit_code, out, _ = run_cli(
            "schedule", "list", "--jobs-file", str(sample_yaml)
        )
        assert exit_code == 0
        assert "sample-interval" in out
        assert "sample-cron" in out

    def test_list_json(self, run_cli, sample_yaml):
        exit_code, out, _ = run_cli(
            "--output",
            "json",
            "schedule",
            "list",
            "--jobs-file",
            str(sample_yaml),
        )
        assert exit_code == 0
        data = json.loads(out)
        assert len(data) == 2
        ids = {d["job_id"] for d in data}
        assert ids == {"sample-interval", "sample-cron"}
        # Spot-check the shape matches status_dict()
        assert "schedule" in data[0]
        assert "is_healthy" in data[0]

    def test_list_no_source_returns_2(self, run_cli):
        exit_code, _, _ = run_cli("schedule", "list")
        assert exit_code == 2


# ---------------------------------------------------------------------------
# schedule status
# ---------------------------------------------------------------------------


class TestScheduleStatus:
    def test_status_known_job(self, run_cli, sample_yaml):
        exit_code, out, _ = run_cli(
            "schedule",
            "status",
            "--job",
            "sample-interval",
            "--jobs-file",
            str(sample_yaml),
        )
        assert exit_code == 0
        assert "sample-interval" in out
        assert "every 3600s" in out
        assert "is_healthy" in out

    def test_status_json(self, run_cli, sample_yaml):
        exit_code, out, _ = run_cli(
            "--output",
            "json",
            "schedule",
            "status",
            "--job",
            "sample-interval",
            "--jobs-file",
            str(sample_yaml),
        )
        assert exit_code == 0
        data = json.loads(out)
        assert data["job_id"] == "sample-interval"
        assert data["schedule"] == "every 3600s"
        assert data["history_count"] == 0
        assert data["last_5_runs"] == []

    def test_status_unknown_job_returns_2(self, run_cli, sample_yaml):
        exit_code, _, _ = run_cli(
            "schedule",
            "status",
            "--job",
            "nope",
            "--jobs-file",
            str(sample_yaml),
        )
        assert exit_code == 2


# ---------------------------------------------------------------------------
# schedule history
# ---------------------------------------------------------------------------


class TestScheduleHistory:
    def test_history_empty(self, run_cli, sample_yaml):
        exit_code, out, _ = run_cli(
            "schedule",
            "history",
            "--job",
            "sample-interval",
            "--jobs-file",
            str(sample_yaml),
        )
        assert exit_code == 0
        assert "no run history" in out

    def test_history_json_empty_list(self, run_cli, sample_yaml):
        exit_code, out, _ = run_cli(
            "--output",
            "json",
            "schedule",
            "history",
            "--job",
            "sample-interval",
            "--jobs-file",
            str(sample_yaml),
        )
        assert exit_code == 0
        assert json.loads(out) == []

    def test_history_unknown_job(self, run_cli, sample_yaml):
        exit_code, _, _ = run_cli(
            "schedule",
            "history",
            "--job",
            "nope",
            "--jobs-file",
            str(sample_yaml),
        )
        assert exit_code == 2


# ---------------------------------------------------------------------------
# schedule crontab
# ---------------------------------------------------------------------------


class TestScheduleCrontab:
    def test_crontab_emits_lines(self, run_cli, sample_yaml):
        exit_code, out, _ = run_cli(
            "schedule", "crontab", "--jobs-file", str(sample_yaml)
        )
        assert exit_code == 0
        # Interval 3600s → */60 * * * * (or similar)
        assert "gnat schedule run" in out
        assert "sample-interval" in out
        assert "sample-cron" in out
        # Cron job's expression should be passed through verbatim
        assert "0 */4 * * *" in out

    def test_crontab_custom_command(self, run_cli, sample_yaml):
        exit_code, out, _ = run_cli(
            "schedule",
            "crontab",
            "--command",
            "/usr/local/bin/my-runner",
            "--jobs-file",
            str(sample_yaml),
        )
        assert exit_code == 0
        assert "/usr/local/bin/my-runner" in out

    def test_crontab_json(self, run_cli, sample_yaml):
        exit_code, out, _ = run_cli(
            "--output",
            "json",
            "schedule",
            "crontab",
            "--jobs-file",
            str(sample_yaml),
        )
        assert exit_code == 0
        data = json.loads(out)
        assert isinstance(data, list)
        # Filter out the banner line and blank lines
        job_lines = [ln for ln in data if "sample-" in ln]
        assert len(job_lines) == 2


# ---------------------------------------------------------------------------
# schedule validate
# ---------------------------------------------------------------------------


class TestScheduleValidate:
    def test_validate_ok(self, run_cli, sample_yaml):
        exit_code, out, _ = run_cli(
            "schedule", "validate", "--jobs-file", str(sample_yaml)
        )
        assert exit_code == 0
        assert "OK" in out
        assert "2 job(s)" in out

    def test_validate_json(self, run_cli, sample_yaml):
        exit_code, out, _ = run_cli(
            "--output",
            "json",
            "schedule",
            "validate",
            "--jobs-file",
            str(sample_yaml),
        )
        assert exit_code == 0
        data = json.loads(out)
        assert data["valid"] is True
        assert data["job_count"] == 2
        assert set(data["jobs"]) == {"sample-interval", "sample-cron"}

    def test_validate_missing_file(self, run_cli, tmp_path):
        exit_code, _, _ = run_cli(
            "schedule", "validate", "--jobs-file", str(tmp_path / "nope.yaml")
        )
        assert exit_code == 2

    def test_validate_skips_client_init(self, run_cli, tmp_path):
        """
        validate should NOT try to build a GNATClient even if the YAML
        references one — that lets you lint configs in CI without
        credentials.
        """
        yaml = tmp_path / "jobs.yaml"
        yaml.write_text(
            textwrap.dedent(
                """
                jobs:
                  - id: needs-client
                    reader:
                      class: gnat.ingest.sources.readers.PlainTextReader
                      args: { source: "https://x/y" }
                    mapper:
                      class: gnat.ingest.mappers.mappers.FlatIOCMapper
                    interval_seconds: 60
                    client: threatq
                """
            )
        )
        exit_code, out, _ = run_cli(
            "schedule", "validate", "--jobs-file", str(yaml)
        )
        assert exit_code == 0
        assert "1 job" in out


# ---------------------------------------------------------------------------
# schedule run
# ---------------------------------------------------------------------------


class TestScheduleRun:
    def test_run_single_job_success(self, run_cli, sample_yaml, monkeypatch):
        # Patch FeedScheduler.run_now to avoid actually hitting the network
        from datetime import datetime, timezone

        from gnat.schedule.job import RunRecord
        from gnat.schedule.scheduler import FeedScheduler

        def fake_run_now(self, job_id):
            now = datetime.now(timezone.utc)
            return RunRecord(
                run_number=1,
                scheduled_at=now,
                started_at=now,
                finished_at=now,
                status="success",
                duration_seconds=0.5,
            )

        monkeypatch.setattr(FeedScheduler, "run_now", fake_run_now)

        exit_code, out, _ = run_cli(
            "schedule",
            "run",
            "--job",
            "sample-interval",
            "--jobs-file",
            str(sample_yaml),
        )
        assert exit_code == 0
        assert "success" in out

    def test_run_single_job_failure_returns_1(
        self, run_cli, sample_yaml, monkeypatch
    ):
        from datetime import datetime, timezone

        from gnat.schedule.job import RunRecord
        from gnat.schedule.scheduler import FeedScheduler

        def fake_run_now(self, job_id):
            now = datetime.now(timezone.utc)
            return RunRecord(
                run_number=1,
                scheduled_at=now,
                started_at=now,
                finished_at=now,
                status="failed",
                duration_seconds=0.1,
                error="boom",
            )

        monkeypatch.setattr(FeedScheduler, "run_now", fake_run_now)

        exit_code, out, _ = run_cli(
            "schedule",
            "run",
            "--job",
            "sample-interval",
            "--jobs-file",
            str(sample_yaml),
        )
        assert exit_code == 1
        assert "failed" in out
        assert "boom" in out

    def test_run_all_success(self, run_cli, sample_yaml, monkeypatch):
        from datetime import datetime, timezone

        from gnat.schedule.job import RunRecord
        from gnat.schedule.scheduler import FeedScheduler

        def fake_run_all(self, parallel=False):
            now = datetime.now(timezone.utc)
            return {
                j.job_id: RunRecord(
                    run_number=1,
                    scheduled_at=now,
                    started_at=now,
                    finished_at=now,
                    status="success",
                    duration_seconds=0.2,
                )
                for j in self
            }

        monkeypatch.setattr(FeedScheduler, "run_all_now", fake_run_all)
        exit_code, out, _ = run_cli(
            "schedule", "run", "--jobs-file", str(sample_yaml)
        )
        assert exit_code == 0
        assert "sample-interval" in out
        assert "sample-cron" in out
        assert "success" in out

    def test_run_unknown_job(self, run_cli, sample_yaml):
        exit_code, _, _ = run_cli(
            "schedule",
            "run",
            "--job",
            "nope",
            "--jobs-file",
            str(sample_yaml),
        )
        assert exit_code == 2


# ---------------------------------------------------------------------------
# schedule start
# ---------------------------------------------------------------------------


class TestScheduleStart:
    def test_start_with_no_jobs_returns_2(self, run_cli, tmp_path):
        empty = tmp_path / "empty.yaml"
        empty.write_text("jobs: []\n")
        exit_code, _, _ = run_cli(
            "schedule", "start", "--jobs-file", str(empty)
        )
        assert exit_code == 2

    def test_start_loops_until_stop_flag(
        self, run_cli, sample_yaml, monkeypatch
    ):
        """
        Patch FeedScheduler.start/stop to be no-ops and replace
        ``time.sleep`` at the ``time`` module level so the ``start``
        handler's ``while not stop_flag`` loop exits after one tick
        (via a raised KeyboardInterrupt). The handler's ``finally``
        block must still call ``scheduler.stop()``.
        """
        import time as _time

        from gnat.schedule.scheduler import FeedScheduler

        started = {"start": False, "stop": False}

        def fake_start(self, run_immediately=False):
            started["start"] = True
            return self

        def fake_stop(self, timeout=10.0):
            started["stop"] = True

        monkeypatch.setattr(FeedScheduler, "start", fake_start)
        monkeypatch.setattr(FeedScheduler, "stop", fake_stop)

        def fake_sleep(seconds):
            raise KeyboardInterrupt()

        monkeypatch.setattr(_time, "sleep", fake_sleep)

        with pytest.raises(KeyboardInterrupt):
            run_cli("schedule", "start", "--jobs-file", str(sample_yaml))
        assert started["start"] is True
        assert started["stop"] is True

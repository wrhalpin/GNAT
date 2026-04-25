# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/jobs/test_models.py
=================================

Unit tests for :mod:`gnat.jobs.models` — Job, JobStatus, and event dataclasses.

Coverage:
- JobStatus enum values and string coercion
- Job creation with defaults
- Job creation with explicit fields
- Job.is_terminal property
- Job.duration_seconds property
- Job.to_dict() serialisation
- ProgressEvent, ResultEvent, ErrorEvent construction
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from gnat.jobs.models import (
    ErrorEvent,
    Job,
    JobStatus,
    ProgressEvent,
    ResultEvent,
)

# ===========================================================================
# JobStatus
# ===========================================================================


class TestJobStatus:
    """Tests for the JobStatus enum."""

    def test_values(self):
        """All expected status values exist."""
        assert JobStatus.QUEUED == "queued"
        assert JobStatus.RUNNING == "running"
        assert JobStatus.SUCCEEDED == "succeeded"
        assert JobStatus.FAILED == "failed"
        assert JobStatus.CANCELLED == "cancelled"

    def test_string_coercion(self):
        """JobStatus values work as plain strings."""
        assert str(JobStatus.QUEUED) == "JobStatus.QUEUED"
        assert JobStatus.QUEUED.value == "queued"
        assert JobStatus("running") == JobStatus.RUNNING

    def test_membership(self):
        """All five statuses are present."""
        assert len(JobStatus) == 5


# ===========================================================================
# Job
# ===========================================================================


class TestJob:
    """Tests for the Job dataclass."""

    def test_defaults(self):
        """Job can be created with minimal arguments; defaults are sane."""
        job = Job(job_type="test")
        assert job.job_type == "test"
        assert job.status == JobStatus.QUEUED
        assert job.submitted_by == ""
        assert job.tenant is None
        assert job.progress == 0.0
        assert job.progress_message == ""
        assert job.result is None
        assert job.error is None
        assert job.parent_job_id is None
        assert job.request_payload == {}
        assert isinstance(job.id, str)
        assert len(job.id) == 36  # UUID format
        assert isinstance(job.submitted_at, datetime)

    def test_explicit_fields(self):
        """Job accepts explicit field values."""
        now = datetime.now(timezone.utc)
        job = Job(
            id="abc-123",
            job_type="gap_detection",
            status=JobStatus.RUNNING,
            submitted_by="analyst@corp.com",
            tenant="tenant-a",
            submitted_at=now,
            started_at=now,
            progress=0.5,
            progress_message="halfway",
            parent_job_id="parent-1",
            request_payload={"target": "APT29"},
        )
        assert job.id == "abc-123"
        assert job.job_type == "gap_detection"
        assert job.status == JobStatus.RUNNING
        assert job.submitted_by == "analyst@corp.com"
        assert job.tenant == "tenant-a"
        assert job.progress == 0.5
        assert job.parent_job_id == "parent-1"
        assert job.request_payload == {"target": "APT29"}

    def test_is_terminal_queued(self):
        """QUEUED jobs are not terminal."""
        job = Job(job_type="t", status=JobStatus.QUEUED)
        assert job.is_terminal is False

    def test_is_terminal_running(self):
        """RUNNING jobs are not terminal."""
        job = Job(job_type="t", status=JobStatus.RUNNING)
        assert job.is_terminal is False

    def test_is_terminal_succeeded(self):
        """SUCCEEDED jobs are terminal."""
        job = Job(job_type="t", status=JobStatus.SUCCEEDED)
        assert job.is_terminal is True

    def test_is_terminal_failed(self):
        """FAILED jobs are terminal."""
        job = Job(job_type="t", status=JobStatus.FAILED)
        assert job.is_terminal is True

    def test_is_terminal_cancelled(self):
        """CANCELLED jobs are terminal."""
        job = Job(job_type="t", status=JobStatus.CANCELLED)
        assert job.is_terminal is True

    def test_duration_seconds_not_started(self):
        """Duration is None before the job starts."""
        job = Job(job_type="t")
        assert job.duration_seconds is None

    def test_duration_seconds_running(self):
        """Duration is computed for running jobs (elapsed since started_at)."""
        job = Job(job_type="t", started_at=datetime.now(timezone.utc))
        duration = job.duration_seconds
        assert duration is not None
        assert duration >= 0.0

    def test_duration_seconds_finished(self):
        """Duration is computed from started_at to finished_at."""
        now = datetime.now(timezone.utc)
        from datetime import timedelta

        job = Job(
            job_type="t",
            started_at=now,
            finished_at=now + timedelta(seconds=5),
        )
        assert job.duration_seconds == pytest.approx(5.0, abs=0.01)

    def test_to_dict(self):
        """to_dict() produces a complete JSON-serializable dict."""
        now = datetime.now(timezone.utc)
        job = Job(
            id="test-id",
            job_type="analysis",
            status=JobStatus.SUCCEEDED,
            submitted_by="user1",
            tenant="t1",
            submitted_at=now,
            started_at=now,
            finished_at=now,
            progress=1.0,
            progress_message="done",
            result={"count": 42},
            error=None,
            parent_job_id="parent-x",
            request_payload={"key": "val"},
        )
        d = job.to_dict()
        assert d["id"] == "test-id"
        assert d["job_type"] == "analysis"
        assert d["status"] == "succeeded"
        assert d["submitted_by"] == "user1"
        assert d["tenant"] == "t1"
        assert d["progress"] == 1.0
        assert d["progress_message"] == "done"
        assert d["result"] == {"count": 42}
        assert d["error"] is None
        assert d["parent_job_id"] == "parent-x"
        assert d["request_payload"] == {"key": "val"}
        # Timestamps are ISO strings
        assert isinstance(d["submitted_at"], str)
        assert isinstance(d["started_at"], str)
        assert isinstance(d["finished_at"], str)
        assert isinstance(d["duration_seconds"], float)

    def test_to_dict_none_timestamps(self):
        """to_dict() handles None timestamps gracefully."""
        job = Job(job_type="t")
        d = job.to_dict()
        assert d["started_at"] is None
        assert d["finished_at"] is None
        assert d["duration_seconds"] is None


# ===========================================================================
# Event dataclasses
# ===========================================================================


class TestProgressEvent:
    """Tests for ProgressEvent."""

    def test_defaults(self):
        """ProgressEvent can be created with just progress."""
        e = ProgressEvent(progress=0.5)
        assert e.progress == 0.5
        assert e.message == ""

    def test_with_message(self):
        """ProgressEvent accepts a message."""
        e = ProgressEvent(progress=0.75, message="3/4 done")
        assert e.progress == 0.75
        assert e.message == "3/4 done"


class TestResultEvent:
    """Tests for ResultEvent."""

    def test_defaults(self):
        """ResultEvent defaults to empty dict."""
        e = ResultEvent()
        assert e.result == {}

    def test_with_result(self):
        """ResultEvent accepts a result dict."""
        e = ResultEvent(result={"hits": 10})
        assert e.result == {"hits": 10}


class TestErrorEvent:
    """Tests for ErrorEvent."""

    def test_defaults(self):
        """ErrorEvent defaults to empty strings."""
        e = ErrorEvent()
        assert e.error == ""
        assert e.traceback == ""

    def test_with_values(self):
        """ErrorEvent accepts error and traceback."""
        e = ErrorEvent(error="boom", traceback="Traceback (most recent call last)...")
        assert e.error == "boom"
        assert e.traceback.startswith("Traceback")

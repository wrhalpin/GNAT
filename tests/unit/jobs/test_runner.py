# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/jobs/test_runner.py
=================================

Unit tests for :class:`gnat.jobs.runner.JobRunner` — thread-pool executor.

Coverage:
- submit() creates a job and executes it asynchronously
- Job transitions: QUEUED -> RUNNING -> SUCCEEDED
- Progress updates propagate to the store
- Handler errors transition to FAILED with error message
- cancel() sets the cancel event and transitions to CANCELLED
- Unknown job type raises ValueError
- Shutdown waits for completion
"""

from __future__ import annotations

import time

import pytest

from gnat.jobs.models import JobStatus
from gnat.jobs.registry import _REGISTRY, JobRegistry
from gnat.jobs.runner import JobRunner
from gnat.jobs.store import JobStore

# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture(autouse=True)
def _clean_registry():
    """Clear the registry before and after each test."""
    saved = dict(_REGISTRY)
    _REGISTRY.clear()
    yield
    _REGISTRY.clear()
    _REGISTRY.update(saved)


@pytest.fixture
def store():
    """Return a fresh JobStore."""
    return JobStore()


@pytest.fixture
def runner(store):
    """Return a JobRunner with a single worker thread."""
    r = JobRunner(store, max_workers=2)
    yield r
    r.shutdown(wait=True)


# ===========================================================================
# Test helpers (job functions)
# ===========================================================================


def _register_echo():
    """Register a simple echo job that returns the payload."""

    def echo_handler(payload, progress_cb, cancel_event):
        progress_cb(0.5, "echoing")
        return {"echo": payload}

    JobRegistry.register("echo", echo_handler)


def _register_slow():
    """Register a job that sleeps and checks cancellation."""

    def slow_handler(payload, progress_cb, cancel_event):
        for i in range(10):
            if cancel_event.is_set():
                return {"cancelled": True}
            progress_cb(i / 10.0, f"step {i}")
            time.sleep(0.05)
        return {"done": True}

    JobRegistry.register("slow", slow_handler)


def _register_failing():
    """Register a job that raises an exception."""

    def failing_handler(payload, progress_cb, cancel_event):
        raise RuntimeError("intentional failure")

    JobRegistry.register("failing", failing_handler)


def _register_progress_tracker():
    """Register a job that records progress steps."""

    def progress_handler(payload, progress_cb, cancel_event):
        progress_cb(0.25, "step 1")
        progress_cb(0.50, "step 2")
        progress_cb(0.75, "step 3")
        return {"steps": 3}

    JobRegistry.register("progress_tracker", progress_handler)


# ===========================================================================
# Tests
# ===========================================================================


class TestJobRunnerSubmit:
    """Tests for JobRunner.submit()."""

    def test_submit_returns_job(self, runner):
        """submit() returns a Job with correct fields."""
        _register_echo()
        job = runner.submit("echo", submitted_by="user", request_payload={"msg": "hi"})
        assert job.job_type == "echo"
        assert job.submitted_by == "user"
        # The job may already be running or finished by the time we check,
        # since execution starts immediately in the thread pool.
        assert job.status in (
            JobStatus.QUEUED,
            JobStatus.RUNNING,
            JobStatus.SUCCEEDED,
        )

    def test_submit_unknown_type_raises(self, runner):
        """submit() raises ValueError for unregistered job type."""
        with pytest.raises(ValueError, match="unknown job type"):
            runner.submit("nonexistent")

    def test_submit_executes_to_success(self, runner, store):
        """Submitted job transitions to SUCCEEDED."""
        _register_echo()
        job = runner.submit("echo", request_payload={"msg": "hello"})

        # Wait for completion (with timeout)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            fetched = store.get(job.id)
            if fetched and fetched.is_terminal:
                break
            time.sleep(0.05)

        fetched = store.get(job.id)
        assert fetched is not None
        assert fetched.status == JobStatus.SUCCEEDED
        assert fetched.result == {"echo": {"msg": "hello"}}
        assert fetched.progress == 1.0
        assert fetched.started_at is not None
        assert fetched.finished_at is not None

    def test_submit_with_tenant(self, runner, store):
        """submit() passes tenant to the created job."""
        _register_echo()
        job = runner.submit("echo", tenant="acme", request_payload={})

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            fetched = store.get(job.id)
            if fetched and fetched.is_terminal:
                break
            time.sleep(0.05)

        assert store.get(job.id).tenant == "acme"

    def test_submit_with_parent(self, runner, store):
        """submit() passes parent_job_id to the created job."""
        _register_echo()
        job = runner.submit("echo", parent_job_id="p-1", request_payload={})

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            fetched = store.get(job.id)
            if fetched and fetched.is_terminal:
                break
            time.sleep(0.05)

        assert store.get(job.id).parent_job_id == "p-1"


class TestJobRunnerProgress:
    """Tests for progress callback propagation."""

    def test_progress_updates(self, runner, store):
        """Progress callback updates are visible in the store."""
        _register_progress_tracker()
        job = runner.submit("progress_tracker", request_payload={})

        # Wait for completion
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            fetched = store.get(job.id)
            if fetched and fetched.is_terminal:
                break
            time.sleep(0.05)

        fetched = store.get(job.id)
        assert fetched.status == JobStatus.SUCCEEDED
        assert fetched.progress == 1.0
        assert fetched.result == {"steps": 3}


class TestJobRunnerErrors:
    """Tests for error handling."""

    def test_handler_error_transitions_to_failed(self, runner, store):
        """Handler exceptions transition the job to FAILED."""
        _register_failing()
        job = runner.submit("failing", request_payload={})

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            fetched = store.get(job.id)
            if fetched and fetched.is_terminal:
                break
            time.sleep(0.05)

        fetched = store.get(job.id)
        assert fetched.status == JobStatus.FAILED
        assert fetched.error == "intentional failure"
        assert fetched.finished_at is not None


class TestJobRunnerCancel:
    """Tests for job cancellation."""

    def test_cancel_sets_event_and_status(self, runner, store):
        """cancel() sets the threading event and marks job CANCELLED."""
        _register_slow()
        job = runner.submit("slow", request_payload={})

        # Wait until the job is running
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            fetched = store.get(job.id)
            if fetched and fetched.status == JobStatus.RUNNING:
                break
            time.sleep(0.05)

        result = runner.cancel(job.id)
        assert result is True

        # Wait for the job to finish
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            fetched = store.get(job.id)
            if fetched and fetched.is_terminal:
                break
            time.sleep(0.05)

        fetched = store.get(job.id)
        assert fetched.status == JobStatus.CANCELLED

    def test_cancel_unknown_returns_false(self, runner):
        """cancel() returns False for unknown job id."""
        assert runner.cancel("nonexistent") is False


class TestJobRunnerShutdown:
    """Tests for runner shutdown."""

    def test_shutdown_completes(self, store):
        """shutdown() completes without error."""
        runner = JobRunner(store, max_workers=1)
        _register_echo()
        runner.submit("echo", request_payload={})
        runner.shutdown(wait=True)
        # No exception means success

    def test_store_property(self, runner, store):
        """store property returns the underlying store."""
        assert runner.store is store

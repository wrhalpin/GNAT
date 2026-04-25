# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/jobs/test_store.py
================================

Unit tests for :class:`gnat.jobs.store.JobStore` — in-memory job state tracking.

Coverage:
- create(): new job in QUEUED state, UUID assigned
- get(): lookup by id, returns None for unknown
- update(): persists changes, raises KeyError for unknown
- list(): filtering by status, tenant, job_type, limit
- list(): newest-first ordering
- cancel(): transitions QUEUED/RUNNING to CANCELLED, rejects terminal
- __len__ and __contains__
- eviction of oldest terminal jobs when max_jobs exceeded
"""

from __future__ import annotations

import pytest

from gnat.jobs.models import JobStatus
from gnat.jobs.store import JobStore

# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def store():
    """Return a fresh JobStore."""
    return JobStore()


# ===========================================================================
# Tests
# ===========================================================================


class TestJobStoreCreate:
    """Tests for JobStore.create()."""

    def test_create_returns_job(self, store):
        """create() returns a Job with QUEUED status."""
        job = store.create("analysis", submitted_by="user1")
        assert job.job_type == "analysis"
        assert job.status == JobStatus.QUEUED
        assert job.submitted_by == "user1"
        assert len(job.id) == 36  # UUID

    def test_create_stores_job(self, store):
        """Created job is retrievable via get()."""
        job = store.create("test")
        assert store.get(job.id) is not None
        assert store.get(job.id).job_type == "test"

    def test_create_with_payload(self, store):
        """create() accepts request_payload."""
        job = store.create("test", request_payload={"key": "val"})
        assert job.request_payload == {"key": "val"}

    def test_create_with_tenant(self, store):
        """create() accepts tenant."""
        job = store.create("test", tenant="acme")
        assert job.tenant == "acme"

    def test_create_with_parent(self, store):
        """create() accepts parent_job_id."""
        job = store.create("test", parent_job_id="parent-123")
        assert job.parent_job_id == "parent-123"


class TestJobStoreGet:
    """Tests for JobStore.get()."""

    def test_get_existing(self, store):
        """get() returns the correct job."""
        job = store.create("test")
        fetched = store.get(job.id)
        assert fetched is not None
        assert fetched.id == job.id

    def test_get_unknown(self, store):
        """get() returns None for unknown id."""
        assert store.get("nonexistent-id") is None


class TestJobStoreUpdate:
    """Tests for JobStore.update()."""

    def test_update_persists(self, store):
        """update() persists field changes."""
        job = store.create("test")
        job.status = JobStatus.RUNNING
        job.progress = 0.5
        store.update(job)
        fetched = store.get(job.id)
        assert fetched.status == JobStatus.RUNNING
        assert fetched.progress == 0.5

    def test_update_unknown_raises(self, store):
        """update() raises KeyError for unknown job id."""
        from gnat.jobs.models import Job

        unknown = Job(id="not-in-store", job_type="t")
        with pytest.raises(KeyError, match="unknown job"):
            store.update(unknown)


class TestJobStoreList:
    """Tests for JobStore.list()."""

    def test_list_all(self, store):
        """list() returns all jobs."""
        store.create("a")
        store.create("b")
        store.create("c")
        assert len(store.list()) == 3

    def test_list_filter_status(self, store):
        """list() filters by status."""
        j1 = store.create("test")
        j2 = store.create("test")
        j1.status = JobStatus.RUNNING
        store.update(j1)
        result = store.list(status=JobStatus.RUNNING)
        assert len(result) == 1
        assert result[0].id == j1.id

    def test_list_filter_tenant(self, store):
        """list() filters by tenant."""
        store.create("test", tenant="a")
        store.create("test", tenant="b")
        result = store.list(tenant="a")
        assert len(result) == 1
        assert result[0].tenant == "a"

    def test_list_filter_job_type(self, store):
        """list() filters by job_type."""
        store.create("alpha")
        store.create("beta")
        result = store.list(job_type="alpha")
        assert len(result) == 1
        assert result[0].job_type == "alpha"

    def test_list_limit(self, store):
        """list() respects the limit parameter."""
        for _ in range(10):
            store.create("test")
        result = store.list(limit=3)
        assert len(result) == 3

    def test_list_newest_first(self, store):
        """list() returns newest jobs first."""
        j1 = store.create("first")
        j2 = store.create("second")
        result = store.list()
        assert result[0].id == j2.id
        assert result[1].id == j1.id


class TestJobStoreCancel:
    """Tests for JobStore.cancel()."""

    def test_cancel_queued(self, store):
        """cancel() transitions QUEUED to CANCELLED."""
        job = store.create("test")
        assert store.cancel(job.id) is True
        assert store.get(job.id).status == JobStatus.CANCELLED
        assert store.get(job.id).finished_at is not None

    def test_cancel_running(self, store):
        """cancel() transitions RUNNING to CANCELLED."""
        job = store.create("test")
        job.status = JobStatus.RUNNING
        store.update(job)
        assert store.cancel(job.id) is True
        assert store.get(job.id).status == JobStatus.CANCELLED

    def test_cancel_terminal_noop(self, store):
        """cancel() returns False for already-terminal jobs."""
        job = store.create("test")
        job.status = JobStatus.SUCCEEDED
        store.update(job)
        assert store.cancel(job.id) is False
        assert store.get(job.id).status == JobStatus.SUCCEEDED

    def test_cancel_unknown(self, store):
        """cancel() returns False for unknown job id."""
        assert store.cancel("nonexistent") is False


class TestJobStoreDunder:
    """Tests for __len__ and __contains__."""

    def test_len(self, store):
        """__len__ reflects the number of tracked jobs."""
        assert len(store) == 0
        store.create("a")
        assert len(store) == 1
        store.create("b")
        assert len(store) == 2

    def test_contains(self, store):
        """__contains__ checks job id membership."""
        job = store.create("test")
        assert job.id in store
        assert "nonexistent" not in store


class TestJobStoreEviction:
    """Tests for max_jobs eviction."""

    def test_eviction_removes_oldest_terminal(self):
        """When max_jobs is exceeded, oldest terminal jobs are evicted."""
        store = JobStore(max_jobs=3)
        j1 = store.create("test")
        j2 = store.create("test")
        # Make j1 terminal
        j1.status = JobStatus.SUCCEEDED
        store.update(j1)

        # These two should push us over the limit
        j3 = store.create("test")
        j4 = store.create("test")

        # j1 (oldest terminal) should be evicted
        assert store.get(j1.id) is None
        # j2, j3, j4 should remain
        assert store.get(j2.id) is not None
        assert store.get(j3.id) is not None
        assert len(store) == 3

    def test_eviction_preserves_non_terminal(self):
        """Non-terminal jobs are not evicted even when over capacity."""
        store = JobStore(max_jobs=2)
        j1 = store.create("test")
        j2 = store.create("test")
        j3 = store.create("test")
        # All three are QUEUED (non-terminal) — nothing to evict
        assert len(store) == 3
        assert store.get(j1.id) is not None

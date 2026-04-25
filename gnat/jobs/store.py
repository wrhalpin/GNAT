# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.jobs.store
==================

:class:`JobStore` — thread-safe, in-memory job state tracking.

The store is the single source of truth for all :class:`~gnat.jobs.models.Job`
objects within a process.  It provides CRUD operations and filtering by status,
tenant, and job type.

Design
------
Jobs are stored in an ``OrderedDict`` keyed by ``job.id`` so insertion order
is preserved and listing returns newest-last by default.  All public methods
are protected by a :class:`threading.Lock` to allow safe concurrent access
from the :class:`~gnat.jobs.runner.JobRunner` thread pool.

This is intentionally a simple in-memory store.  External persistence (SQL,
Redis) can be added as a subclass or adapter without changing the runner.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any

from gnat.jobs.models import Job, JobStatus

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    """Return the current time in UTC."""
    return datetime.now(timezone.utc)


class JobStore:
    """
    Thread-safe, in-memory job state store.

    Parameters
    ----------
    max_jobs : int
        Maximum number of completed jobs to retain.  When exceeded the
        oldest *terminal* jobs are evicted.  Default ``1000``.

    Examples
    --------
    ::

        store = JobStore()
        job = store.create("gap_detection", submitted_by="analyst@corp.com",
                           request_payload={"target": "APT29"})
        print(store.get(job.id).status)  # JobStatus.QUEUED
    """

    def __init__(self, max_jobs: int = 1000) -> None:
        """Initialize JobStore."""
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._lock = threading.Lock()
        self._max_jobs = max_jobs

    # ── CRUD ──────────────────────────────────────────────────────────────

    def create(
        self,
        job_type: str,
        submitted_by: str = "",
        tenant: str | None = None,
        request_payload: dict[str, Any] | None = None,
        parent_job_id: str | None = None,
    ) -> Job:
        """
        Create a new job in QUEUED state.

        Parameters
        ----------
        job_type : str
            Registered job type name.
        submitted_by : str
            Identity of the submitter.
        tenant : str or None
            Tenant identifier.
        request_payload : dict or None
            Original request parameters for replay.
        parent_job_id : str or None
            Parent job id for sub-job hierarchies.

        Returns
        -------
        Job
            The newly created job.
        """
        job = Job(
            id=str(uuid.uuid4()),
            job_type=job_type,
            status=JobStatus.QUEUED,
            submitted_by=submitted_by,
            tenant=tenant,
            submitted_at=_utcnow(),
            request_payload=request_payload or {},
            parent_job_id=parent_job_id,
        )
        with self._lock:
            self._jobs[job.id] = job
            self._evict_if_needed()
        logger.debug("JobStore: created job %s (type=%s)", job.id, job_type)
        return job

    def get(self, job_id: str) -> Job | None:
        """
        Retrieve a job by id.

        Parameters
        ----------
        job_id : str
            The job UUID.

        Returns
        -------
        Job or None
            The job, or ``None`` if not found.
        """
        with self._lock:
            return self._jobs.get(job_id)

    def update(self, job: Job) -> None:
        """
        Persist updated job state.

        Parameters
        ----------
        job : Job
            The job with updated fields.

        Raises
        ------
        KeyError
            If the job id is not in the store.
        """
        with self._lock:
            if job.id not in self._jobs:
                raise KeyError(f"JobStore: unknown job {job.id!r}")
            self._jobs[job.id] = job

    def list(
        self,
        status: JobStatus | None = None,
        tenant: str | None = None,
        job_type: str | None = None,
        limit: int = 50,
    ) -> list[Job]:
        """
        List jobs with optional filtering.

        Parameters
        ----------
        status : JobStatus or None
            Filter by status.
        tenant : str or None
            Filter by tenant.
        job_type : str or None
            Filter by job type.
        limit : int
            Maximum number of jobs to return (newest first).  Default ``50``.

        Returns
        -------
        list of Job
            Matching jobs, newest first.
        """
        with self._lock:
            jobs = list(self._jobs.values())

        # Apply filters
        if status is not None:
            jobs = [j for j in jobs if j.status == status]
        if tenant is not None:
            jobs = [j for j in jobs if j.tenant == tenant]
        if job_type is not None:
            jobs = [j for j in jobs if j.job_type == job_type]

        # Newest first, capped
        jobs.reverse()
        return jobs[:limit]

    def cancel(self, job_id: str) -> bool:
        """
        Mark a job as CANCELLED.

        Only jobs in QUEUED or RUNNING state can be cancelled.

        Parameters
        ----------
        job_id : str
            The job UUID.

        Returns
        -------
        bool
            ``True`` if the job was cancelled, ``False`` if not found or
            already terminal.
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return False
            if job.is_terminal:
                return False
            job.status = JobStatus.CANCELLED
            job.finished_at = _utcnow()
            logger.debug("JobStore: cancelled job %s", job_id)
            return True

    # ── Introspection ─────────────────────────────────────────────────────

    def __len__(self) -> int:
        """Return the total number of tracked jobs."""
        with self._lock:
            return len(self._jobs)

    def __contains__(self, job_id: str) -> bool:
        """Check if a job id exists in the store."""
        with self._lock:
            return job_id in self._jobs

    # ── Internal helpers ──────────────────────────────────────────────────

    def _evict_if_needed(self) -> None:
        """Remove oldest terminal jobs when over capacity.  Caller holds lock."""
        if len(self._jobs) <= self._max_jobs:
            return
        # Build list of terminal job ids in insertion order (oldest first)
        terminal_ids = [jid for jid, j in self._jobs.items() if j.is_terminal]
        to_remove = len(self._jobs) - self._max_jobs
        for jid in terminal_ids[:to_remove]:
            del self._jobs[jid]

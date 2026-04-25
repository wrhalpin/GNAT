# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.jobs.runner
===================

:class:`JobRunner` — executes jobs in a thread pool with progress tracking.

Design
------
The runner wraps a :class:`concurrent.futures.ThreadPoolExecutor`.  Each
:meth:`submit` call creates a :class:`~gnat.jobs.models.Job` in the
:class:`~gnat.jobs.store.JobStore`, submits the matching handler from the
:class:`~gnat.jobs.registry.JobRegistry` to the executor, and returns
immediately.

Inside the worker thread, the runner:

1. Transitions the job to ``RUNNING``.
2. Calls the handler with ``(request_payload, progress_callback, cancel_event)``.
3. On success: stores the returned dict as ``job.result`` and transitions to ``SUCCEEDED``.
4. On failure: stores the exception message and traceback, transitions to ``FAILED``.

Cancellation
------------
Each job gets its own :class:`threading.Event`.  When :meth:`cancel` is called,
the event is set and the job is marked ``CANCELLED`` in the store.  Cooperative
handlers should poll ``cancel_event.is_set()`` at checkpoints.

Usage::

    from gnat.jobs import JobRunner, JobStore, JobRegistry, job

    @job("echo")
    def echo_job(payload, progress_cb, cancel):
        progress_cb(0.5, "echoing...")
        return {"echo": payload}

    store = JobStore()
    runner = JobRunner(store)
    job = runner.submit("echo", submitted_by="analyst", request_payload={"msg": "hi"})
    # ... poll store.get(job.id).status ...
    runner.shutdown()
"""

from __future__ import annotations

import logging
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from gnat.jobs.models import Job, JobStatus, _utcnow
from gnat.jobs.registry import JobRegistry
from gnat.jobs.store import JobStore

logger = logging.getLogger(__name__)


class JobRunner:
    """
    Executes registered job functions in a bounded thread pool.

    Parameters
    ----------
    store : JobStore
        Job state store for persistence and queries.
    max_workers : int
        Maximum number of concurrent job threads.  Default ``4``.

    Attributes
    ----------
    store : JobStore
        The underlying job store.
    """

    def __init__(self, store: JobStore, max_workers: int = 4) -> None:
        """Initialize JobRunner."""
        self._store = store
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="gnat-job")
        self._cancel_events: dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    @property
    def store(self) -> JobStore:
        """Return the underlying job store."""
        return self._store

    # ── Public API ────────────────────────────────────────────────────────

    def submit(
        self,
        job_type: str,
        submitted_by: str = "",
        tenant: str | None = None,
        request_payload: dict[str, Any] | None = None,
        parent_job_id: str | None = None,
    ) -> Job:
        """
        Submit a job for asynchronous execution.

        The handler for *job_type* is looked up in the
        :class:`~gnat.jobs.registry.JobRegistry`.

        Parameters
        ----------
        job_type : str
            Registered job type name.
        submitted_by : str
            Identity of the submitter.
        tenant : str or None
            Tenant identifier.
        request_payload : dict or None
            Request parameters passed to the handler.
        parent_job_id : str or None
            Parent job id for sub-job hierarchies.

        Returns
        -------
        Job
            The newly created job in ``QUEUED`` state.

        Raises
        ------
        ValueError
            If *job_type* is not registered.
        """
        handler = JobRegistry.get(job_type)
        if handler is None:
            raise ValueError(
                f"JobRunner: unknown job type {job_type!r}. "
                f"Registered types: {JobRegistry.list_types()}"
            )

        job = self._store.create(
            job_type=job_type,
            submitted_by=submitted_by,
            tenant=tenant,
            request_payload=request_payload,
            parent_job_id=parent_job_id,
        )

        cancel_event = threading.Event()
        with self._lock:
            self._cancel_events[job.id] = cancel_event

        self._executor.submit(self._execute, job, cancel_event)
        logger.info(
            "JobRunner: submitted job %s (type=%s, by=%s)",
            job.id,
            job_type,
            submitted_by,
        )
        return job

    def cancel(self, job_id: str) -> bool:
        """
        Request cancellation of a running or queued job.

        Sets the cancel event so cooperative handlers can check it, and
        marks the job ``CANCELLED`` in the store.

        Parameters
        ----------
        job_id : str
            The job UUID.

        Returns
        -------
        bool
            ``True`` if cancellation was applied, ``False`` if the job
            was not found or already terminal.
        """
        with self._lock:
            cancel_event = self._cancel_events.get(job_id)
            if cancel_event is not None:
                cancel_event.set()

        cancelled = self._store.cancel(job_id)
        if cancelled:
            logger.info("JobRunner: cancelled job %s", job_id)
        return cancelled

    def shutdown(self, wait: bool = True) -> None:
        """
        Shut down the thread pool.

        Parameters
        ----------
        wait : bool
            If ``True`` (default), block until all running jobs finish.
            If ``False``, return immediately (running jobs may be interrupted).
        """
        logger.info("JobRunner: shutting down (wait=%s)", wait)
        self._executor.shutdown(wait=wait)

    # ── Internal execution ────────────────────────────────────────────────

    def _execute(self, job: Job, cancel_event: threading.Event) -> None:
        """
        Execute a single job in a worker thread.

        Looks up the handler, transitions the job through its lifecycle,
        and stores results or errors.
        """
        # Transition to RUNNING
        job.status = JobStatus.RUNNING
        job.started_at = _utcnow()
        self._store.update(job)

        handler = JobRegistry.get(job.job_type)
        if handler is None:
            # Should not happen (checked in submit), but guard anyway
            job.status = JobStatus.FAILED
            job.error = f"Handler for {job.job_type!r} not found"
            job.finished_at = _utcnow()
            self._store.update(job)
            return

        def progress_callback(progress: float, message: str = "") -> None:
            """Update job progress in the store."""
            job.progress = max(0.0, min(1.0, progress))
            job.progress_message = message
            self._store.update(job)

        try:
            result = handler(job.request_payload, progress_callback, cancel_event)

            # Check if cancelled during execution
            if cancel_event.is_set():
                if not job.is_terminal:
                    job.status = JobStatus.CANCELLED
                    job.finished_at = _utcnow()
                    self._store.update(job)
                return

            job.status = JobStatus.SUCCEEDED
            job.progress = 1.0
            job.result = result if isinstance(result, dict) else {"result": result}
            job.finished_at = _utcnow()
            self._store.update(job)

            logger.info(
                "JobRunner: job %s succeeded in %.1fs",
                job.id,
                job.duration_seconds or 0,
            )

        except Exception as exc:  # noqa: BLE001
            if cancel_event.is_set():
                # Exception during cancellation — treat as cancelled
                if not job.is_terminal:
                    job.status = JobStatus.CANCELLED
                    job.finished_at = _utcnow()
                    self._store.update(job)
                return

            job.status = JobStatus.FAILED
            job.error = str(exc)
            job.finished_at = _utcnow()
            self._store.update(job)

            logger.error(
                "JobRunner: job %s failed: %s\n%s",
                job.id,
                exc,
                traceback.format_exc(),
            )

        finally:
            with self._lock:
                self._cancel_events.pop(job.id, None)

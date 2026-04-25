# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.jobs
============

First-class job framework for async / long-running operations.

This package provides non-blocking execution with progress tracking for
user-initiated, one-shot operations such as:

- LLM-backed analysis (gap detection, report drafting)
- Investigation graph builds
- Rule evaluation batches
- STIX bundle exports

Unlike :mod:`gnat.schedule` — which handles recurring, cron-style feed
jobs in daemon threads — the job framework handles single-shot operations
submitted by users (via the web app or CLI), executed in a bounded thread
pool, and tracked through their full lifecycle.

Quick start::

    from gnat.jobs import JobRunner, JobStore, job

    @job("echo")
    def echo_handler(request_payload, progress_callback, cancel_event):
        progress_callback(0.5, "Processing...")
        return {"echo": request_payload.get("message", "")}

    store = JobStore()
    runner = JobRunner(store)
    j = runner.submit("echo", submitted_by="analyst", request_payload={"message": "hi"})
    # Poll: store.get(j.id).status
    runner.shutdown()

Architecture
------------
- :class:`Job` — dataclass representing a tracked async operation.
- :class:`JobStatus` — enum of lifecycle states (QUEUED, RUNNING, SUCCEEDED,
  FAILED, CANCELLED).
- :class:`JobStore` — thread-safe in-memory job state store.
- :class:`JobRunner` — thread-pool executor with progress callback support.
- :class:`JobRegistry` — name-to-handler dispatch table.
- :func:`job` — decorator for registering job handlers.
"""

from gnat.jobs.models import (
    ErrorEvent,
    Job,
    JobStatus,
    ProgressEvent,
    ResultEvent,
)
from gnat.jobs.registry import JobRegistry, job
from gnat.jobs.runner import JobRunner
from gnat.jobs.store import JobStore

__all__ = [
    "ErrorEvent",
    "Job",
    "JobRegistry",
    "JobRunner",
    "JobStatus",
    "JobStore",
    "ProgressEvent",
    "ResultEvent",
    "job",
]

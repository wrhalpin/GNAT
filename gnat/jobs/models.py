# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.jobs.models
===================

Data models for the GNAT job framework.

:class:`Job` represents a user-initiated, one-shot asynchronous operation
(LLM analysis, investigation graph build, rule evaluation, report draft).
Unlike :class:`~gnat.schedule.job.FeedJob` — which is a recurring, daemon-
driven ingest job — a ``Job`` is submitted once, executed in a thread pool,
and tracked to completion.

Event dataclasses (:class:`ProgressEvent`, :class:`ResultEvent`,
:class:`ErrorEvent`) are lightweight value objects used to communicate
status changes from the executing thread back to the :class:`JobStore`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# JobStatus enum
# ---------------------------------------------------------------------------


class JobStatus(str, Enum):
    """
    Lifecycle states for a :class:`Job`.

    Transitions
    -----------
    ::

        QUEUED ──▶ RUNNING ──▶ SUCCEEDED
                         │──▶ FAILED
        QUEUED ──▶ CANCELLED
        RUNNING ──▶ CANCELLED
    """

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ---------------------------------------------------------------------------
# Job dataclass
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    """Return the current time in UTC."""
    return datetime.now(timezone.utc)


@dataclass
class Job:
    """
    Represents a user-initiated asynchronous operation.

    Parameters
    ----------
    id : str
        Unique identifier (UUID).
    job_type : str
        Registered job type name (e.g. ``"gap_detection"``, ``"report_draft"``).
    status : JobStatus
        Current lifecycle state.
    submitted_by : str
        Identity of the submitter (from ``AnalystContext.actor``).
    tenant : str or None
        Tenant identifier for multi-tenant deployments.
    submitted_at : datetime
        Timestamp when the job was created (UTC).
    started_at : datetime or None
        Timestamp when execution began (UTC).
    finished_at : datetime or None
        Timestamp when execution completed (UTC).
    progress : float
        Execution progress from ``0.0`` to ``1.0``.
    progress_message : str
        Human-readable description of current step.
    result : dict or None
        JSON-serializable result payload on success.
    error : str or None
        Error message on failure.
    parent_job_id : str or None
        Identifier of a parent job (for sub-job hierarchies).
    request_payload : dict
        Original request parameters, retained for replay.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    job_type: str = ""
    status: JobStatus = JobStatus.QUEUED
    submitted_by: str = ""
    tenant: str | None = None
    submitted_at: datetime = field(default_factory=_utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    progress: float = 0.0
    progress_message: str = ""
    result: dict[str, Any] | None = None
    error: str | None = None
    parent_job_id: str | None = None
    request_payload: dict[str, Any] = field(default_factory=dict)

    # -- Derived properties -------------------------------------------------

    @property
    def is_terminal(self) -> bool:
        """``True`` if the job has reached a final state."""
        return self.status in (
            JobStatus.SUCCEEDED,
            JobStatus.FAILED,
            JobStatus.CANCELLED,
        )

    @property
    def duration_seconds(self) -> float | None:
        """
        Wall-clock duration in seconds, or ``None`` if still running.

        For running jobs, returns elapsed time since ``started_at``.
        """
        if self.started_at is None:
            return None
        end = self.finished_at or _utcnow()
        return (end - self.started_at).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        """
        Serialise to a plain dict for JSON responses / logging.

        Returns
        -------
        dict
            All fields serialised with ISO 8601 timestamps.
        """
        return {
            "id": self.id,
            "job_type": self.job_type,
            "status": self.status.value,
            "submitted_by": self.submitted_by,
            "tenant": self.tenant,
            "submitted_at": self.submitted_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "progress": self.progress,
            "progress_message": self.progress_message,
            "result": self.result,
            "error": self.error,
            "parent_job_id": self.parent_job_id,
            "request_payload": self.request_payload,
            "duration_seconds": self.duration_seconds,
        }


# ---------------------------------------------------------------------------
# Event dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ProgressEvent:
    """
    Emitted by a running job to report progress.

    Parameters
    ----------
    progress : float
        Completion fraction from ``0.0`` to ``1.0``.
    message : str
        Human-readable description of current step.
    """

    progress: float
    message: str = ""


@dataclass
class ResultEvent:
    """
    Emitted when a job completes successfully.

    Parameters
    ----------
    result : dict
        JSON-serializable result payload.
    """

    result: dict[str, Any] = field(default_factory=dict)


@dataclass
class ErrorEvent:
    """
    Emitted when a job fails.

    Parameters
    ----------
    error : str
        Human-readable error message.
    traceback : str
        Full traceback string for debugging.
    """

    error: str = ""
    traceback: str = ""

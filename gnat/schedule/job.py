# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.schedule.job
=====================

:class:`FeedJob` — declarative specification of a scheduled ingest run.

A ``FeedJob`` binds together:

* **What to read** — a :class:`~gnat.ingest.base.SourceReader` factory
  (called fresh each run so the reader can carry per-run state like
  ``newer_than`` derived from the previous run's timestamp).
* **How to map** — a :class:`~gnat.ingest.base.RecordMapper` factory.
* **Where to write** — an optional :class:`~gnat.client.GNATClient`.
* **When to run** — interval in seconds, or a cron expression.
* **Run history** — a rolling log of :class:`~gnat.ingest.base.IngestResult`
  objects from past runs, used for health monitoring and backfill.

The reader factory pattern is central to correct incremental ingestion.
Readers that support time-windowed queries (TAXII, Feedly, Splunk) need to
receive a ``newer_than`` / ``added_after`` derived from the *previous run's
completion time*.  The factory receives a :class:`JobRunContext` with that
information::

    def my_reader_factory(ctx: JobRunContext):
        return TAXIICollectionReader(
            collection,
            added_after=ctx.last_success_iso or "2024-01-01T00:00:00Z",
        )

    job = FeedJob(
        job_id="taxii-daily",
        reader_factory=my_reader_factory,
        mapper_factory=lambda ctx: STIXPassthroughMapper(),
        interval_seconds=86400,
    )

For stateless readers (plaintext blocklists, CSV exports) a plain callable
that ignores ``ctx`` works fine::

    job = FeedJob(
        job_id="blocklist-hourly",
        reader_factory=lambda ctx: PlainTextReader("https://blocklist.example.com"),
        mapper_factory=lambda ctx: FlatIOCMapper(confidence=70),
        interval_seconds=3600,
    )
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from gnat.client import GNATClient
    from gnat.ingest.base import RecordMapper, SourceReader

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# JobRunContext — passed to reader/mapper factories each run
# ---------------------------------------------------------------------------


@dataclass
class JobRunContext:
    """
    Contextual information passed to reader and mapper factories at run time.

    Attributes
    ----------
    job_id : str
        Identifier of the job being run.
    run_number : int
        How many times this job has run (1-indexed).  First run = 1.
    scheduled_at : datetime
        When this run was scheduled to start (UTC).
    last_success_at : datetime or None
        Timestamp of the last *successful* run completion (UTC), or ``None``
        if the job has never succeeded.
    last_success_iso : str or None
        Same as ``last_success_at`` but as an ISO 8601 string, convenient
        for passing to ``added_after`` / ``newer_than`` parameters.
    last_result : IngestResult or None
        The :class:`~gnat.ingest.base.IngestResult` from the most recent
        run (successful or not), or ``None`` on the first run.
    custom : dict
        Arbitrary key/value store for job-specific state that reader
        factories want to carry between runs (e.g. pagination cursors).
    """

    job_id: str
    run_number: int
    scheduled_at: datetime
    last_success_at: datetime | None = None
    last_success_iso: str | None = None
    last_result: Any | None = None  # IngestResult
    custom: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# RunRecord — lightweight record of one run's outcome
# ---------------------------------------------------------------------------


@dataclass
class RunRecord:
    """
    Immutable record of a single job run.

    Attributes
    ----------
    run_number : int
        Sequence number of this run.
    scheduled_at : datetime
        When the run was scheduled (UTC).
    started_at : datetime
        When execution actually began (UTC).
    finished_at : datetime or None
        When execution completed (UTC), or ``None`` if still running.
    status : str
        ``"success"``, ``"partial"`` (completed with errors), or ``"failed"``.
    result : IngestResult or None
        The full ingest result, or ``None`` if the run raised an exception.
    error : str or None
        Exception message if the run raised, else ``None``.
    duration_seconds : float
        Wall-clock time in seconds for the run.
    """

    run_number: int
    scheduled_at: datetime
    started_at: datetime
    finished_at: datetime | None = None
    status: str = "running"
    result: Any | None = None
    error: str | None = None
    duration_seconds: float = 0.0
    run_count: int = 0

    def as_dict(self) -> dict:
        """Serialise to a plain dict for logging or persistence."""
        return {
            "run_number": self.run_number,
            "scheduled_at": self.scheduled_at.isoformat(),
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "status": self.status,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
            "total_records": self.result.total_records if self.result else 0,
            "written_objects": self.result.written_objects if self.result else 0,
            "errors": len(self.result.errors) if self.result else 0,
        }


# ---------------------------------------------------------------------------
# FeedJob
# ---------------------------------------------------------------------------


class FeedJob:
    """
    Declarative specification of a scheduled feed ingestion job.

    Parameters
    ----------
    job_id : str
        Unique identifier for this job.  Used in logs and history.
    reader_factory : callable
        ``(JobRunContext) -> SourceReader`` — called at the start of each
        run to produce a fresh reader, potentially time-windowed from the
        previous run's completion timestamp.
    mapper_factory : callable
        ``(JobRunContext) -> RecordMapper`` — called at the start of each
        run to produce a fresh mapper.
    interval_seconds : int, optional
        Run every N seconds.  Mutually exclusive with ``cron``.
    cron : str, optional
        Cron expression (``"*/15 * * * *"`` = every 15 minutes).
        Requires ``croniter``: ``pip install "gnat[schedule]"``.
        Mutually exclusive with ``interval_seconds``.
    client : GNATClient, optional
        Connected platform client to write results to.  If omitted, results
        are collected but not written (dry-run mode).
    deduplicate : bool
        Enable deduplication by name.  Default ``True``.
    dedup_key_fields : list of str
        Fields used for dedup fingerprinting.  Default ``["name"]``.
    confidence : int
        Default confidence passed to mapper factory context.  Default ``50``.
    tlp_marking : str
        Default TLP marking.  Default ``"white"``.
    on_success : callable, optional
        ``(RunRecord) -> None`` — called after each successful run.
    on_failure : callable, optional
        ``(RunRecord) -> None`` — called after each failed run.
    max_history : int
        Maximum number of :class:`RunRecord` entries to keep in memory.
        Default ``100``.
    overlap_policy : str
        What to do if a run is still executing when the next one is due:
        ``"skip"`` (default) or ``"queue"`` (wait until current finishes).
    enabled : bool
        Whether the job is active.  Default ``True``.

    Attributes
    ----------
    history : list of RunRecord
        Recent run records, newest last.
    run_count : int
        Total number of times this job has been attempted.
    last_success_at : datetime or None
        Timestamp of the last successful run.

    Examples
    --------
    Incremental TAXII feed::

        from gnat.schedule import FeedJob, FeedScheduler

        def make_taxii_reader(ctx):
            return TAXIICollectionReader(
                collection,
                added_after=ctx.last_success_iso or "2024-01-01T00:00:00Z",
            )

        job = FeedJob(
            job_id="taxii-daily",
            reader_factory=make_taxii_reader,
            mapper_factory=lambda ctx: STIXPassthroughMapper(client=tq_cli),
            interval_seconds=86400,
            client=tq_cli,
        )

    Simple blocklist every hour::

        job = FeedJob(
            job_id="blocklist-hourly",
            reader_factory=lambda ctx: PlainTextReader("blocklist.txt"),
            mapper_factory=lambda ctx: FlatIOCMapper(confidence=70),
            interval_seconds=3600,
            client=tq_cli,
        )

    Cron-based (requires croniter)::

        job = FeedJob(
            job_id="feedly-morning",
            reader_factory=lambda ctx: FeedlyReader(...),
            mapper_factory=lambda ctx: FeedlyMapper(),
            cron="0 7 * * *",   # 07:00 daily
            client=tq_cli,
        )
    """

    def __init__(
        self,
        job_id: str,
        reader_factory: Callable[[JobRunContext], SourceReader],
        mapper_factory: Callable[[JobRunContext], RecordMapper],
        interval_seconds: int | None = None,
        cron: str | None = None,
        client: GNATClient | None = None,
        deduplicate: bool = True,
        dedup_key_fields: list[str] | None = None,
        confidence: int = 50,
        tlp_marking: str = "white",
        on_success: Callable[[RunRecord], None] | None = None,
        on_failure: Callable[[RunRecord], None] | None = None,
        max_history: int = 100,
        overlap_policy: str = "skip",
        enabled: bool = True,
    ):
        if interval_seconds is None and cron is None:
            raise ValueError(f"FeedJob {job_id!r}: must specify either interval_seconds or cron.")
        if interval_seconds is not None and cron is not None:
            raise ValueError(
                f"FeedJob {job_id!r}: interval_seconds and cron are mutually exclusive."
            )
        if overlap_policy not in ("skip", "queue"):
            raise ValueError(f"FeedJob {job_id!r}: overlap_policy must be 'skip' or 'queue'.")

        self.job_id = job_id
        self.reader_factory = reader_factory
        self.mapper_factory = mapper_factory
        self.interval_seconds = interval_seconds
        self.cron = cron
        self.client = client
        self.deduplicate = deduplicate
        self.dedup_key_fields = dedup_key_fields or ["name"]
        self.confidence = confidence
        self.tlp_marking = tlp_marking
        self.on_success = on_success
        self.on_failure = on_failure
        self.max_history = max_history
        self.overlap_policy = overlap_policy
        self.enabled = enabled

        self.history: list[RunRecord] = []
        self.run_count: int = 0
        self.last_success_at: datetime | None = None
        self._running_lock = threading.Lock()
        self._custom_state: dict[str, Any] = {}

    # ── Run execution ──────────────────────────────────────────────────────

    def execute(self, scheduled_at: datetime | None = None) -> RunRecord:
        """
        Execute one run of this job synchronously.

        Called by :class:`FeedScheduler` on each trigger, but can also be
        called directly for manual/on-demand runs.

        Parameters
        ----------
        scheduled_at : datetime, optional
            When this run was scheduled.  Defaults to now.

        Returns
        -------
        RunRecord
            Record of this run's outcome.
        """
        from gnat.ingest import IngestPipeline

        if not self.enabled:
            logger.debug("FeedJob %r: skipped (disabled)", self.job_id)
            rec = RunRecord(
                run_number=self.run_count + 1,
                scheduled_at=scheduled_at or _utcnow(),
                started_at=_utcnow(),
                finished_at=_utcnow(),
                status="skipped",
            )
            return rec

        # Overlap guard
        if self.overlap_policy == "skip":
            acquired = self._running_lock.acquire(blocking=False)
        else:  # "queue" — block until the current run finishes
            acquired = self._running_lock.acquire(blocking=True)
        if not acquired:
            logger.warning(
                "FeedJob %r: previous run still active, skipping (overlap_policy=skip)",
                self.job_id,
            )
            rec = RunRecord(
                run_number=self.run_count + 1,
                scheduled_at=scheduled_at or _utcnow(),
                started_at=_utcnow(),
                finished_at=_utcnow(),
                status="skipped",
                error="skipped: previous run still active",
            )
            return rec

        self.run_count += 1
        started_at = _utcnow()
        sched_at = scheduled_at or started_at

        ctx = JobRunContext(
            job_id=self.job_id,
            run_number=self.run_count,
            scheduled_at=sched_at,
            last_success_at=self.last_success_at,
            last_success_iso=(self.last_success_at.isoformat() if self.last_success_at else None),
            last_result=self.history[-1].result if self.history else None,
            custom=self._custom_state,
        )

        record = RunRecord(
            run_number=self.run_count,
            scheduled_at=sched_at,
            started_at=started_at,
        )

        try:
            reader = self.reader_factory(ctx)
            mapper = self.mapper_factory(ctx)

            pipeline = IngestPipeline(self.job_id).read_from(reader).map_with(mapper)
            if self.deduplicate:
                pipeline.deduplicate(key_fields=self.dedup_key_fields)
            if self.client is not None:
                pipeline.write_to(self.client)

            result = pipeline.run()

            record.result = result
            record.finished_at = _utcnow()
            record.duration_seconds = (record.finished_at - record.started_at).total_seconds()

            if result.errors:
                record.status = "partial"
                logger.warning(
                    "FeedJob %r run #%d: partial (%d records, %d written, %d errors)",
                    self.job_id,
                    self.run_count,
                    result.total_records,
                    result.written_objects,
                    len(result.errors),
                )
            else:
                record.status = "success"
                self.last_success_at = record.finished_at
                logger.info(
                    "FeedJob %r run #%d: success (%d records, %d written) in %.1fs",
                    self.job_id,
                    self.run_count,
                    result.total_records,
                    result.written_objects,
                    record.duration_seconds,
                )

            if record.status == "success" and self.on_success:
                self._safe_callback(self.on_success, record)
            elif record.status == "partial" and self.on_failure:
                self._safe_callback(self.on_failure, record)

        except Exception as exc:  # noqa: BLE001
            record.finished_at = _utcnow()
            record.duration_seconds = (record.finished_at - record.started_at).total_seconds()
            record.status = "failed"
            record.error = str(exc)
            logger.error(
                "FeedJob %r run #%d: FAILED — %s",
                self.job_id,
                self.run_count,
                exc,
            )
            if self.on_failure:
                self._safe_callback(self.on_failure, record)

        finally:
            self._running_lock.release()

        self._append_history(record)
        return record

    # ── Introspection ──────────────────────────────────────────────────────

    @property
    def is_healthy(self) -> bool:
        """
        ``True`` if the most recent completed run was successful or partial.

        Returns ``True`` if the job has never run (no data to indicate failure).
        """
        if not self.history:
            return True
        last = self.history[-1]
        return last.status in ("success", "partial", "skipped", "running")

    @property
    def last_run(self) -> RunRecord | None:
        """The most recent :class:`RunRecord`, or ``None`` if never run."""
        return self.history[-1] if self.history else None

    def _skipped_record(self) -> RunRecord:
        """Return a RunRecord representing a skipped (disabled) job."""
        now = _utcnow()
        return RunRecord(
            run_number=self.run_count,
            scheduled_at=now,
            started_at=now,
            finished_at=now,
            status="skipped",
            duration_seconds=0.0,
        )

    @property
    def consecutive_failures(self) -> int:
        """Number of consecutive failed runs from the most recent backwards."""
        count = 0
        for rec in reversed(self.history):
            if rec.status == "failed":
                count += 1
            elif rec.status in ("success", "partial"):
                break
        return count

    def next_run_at(self) -> datetime | None:
        """
        Estimated next run time based on interval or cron expression.

        Returns ``None`` if the job is disabled or has no last run.
        """
        if not self.enabled:
            return None
        if self.interval_seconds:
            if not self.history:
                return _utcnow()
            from datetime import timedelta

            return self.history[-1].started_at + timedelta(seconds=self.interval_seconds)
        if self.cron:
            try:
                from croniter import croniter  # type: ignore

                base = self.history[-1].started_at if self.history else _utcnow()
                return croniter(self.cron, base).get_next(datetime)
            except ImportError:
                return None
        return None

    def status_dict(self) -> dict:
        """Return a plain-dict status summary for logging or dashboards."""
        last = self.last_run
        return {
            "job_id": self.job_id,
            "enabled": self.enabled,
            "schedule": (
                f"every {self.interval_seconds}s" if self.interval_seconds else f"cron:{self.cron}"
            ),
            "run_count": self.run_count,
            "is_healthy": self.is_healthy,
            "consecutive_failures": self.consecutive_failures,
            "last_run_status": last.status if last else None,
            "last_run_at": last.started_at.isoformat() if last else None,
            "last_success_at": (self.last_success_at.isoformat() if self.last_success_at else None),
            "next_run_at": (self.next_run_at().isoformat() if self.next_run_at() else None),
        }

    # ── Internal helpers ───────────────────────────────────────────────────

    def _append_history(self, record: RunRecord) -> None:
        self.history.append(record)
        if len(self.history) > self.max_history:
            self.history = self.history[-self.max_history :]

    @staticmethod
    def _safe_callback(fn: Callable, record: RunRecord) -> None:
        try:
            fn(record)
        except Exception as exc:  # noqa: BLE001
            logger.warning("FeedJob: callback raised %s", exc)

    def __repr__(self) -> str:  # pragma: no cover
        sched = (
            f"every {self.interval_seconds}s" if self.interval_seconds else f"cron={self.cron!r}"
        )
        return (
            f"FeedJob(id={self.job_id!r}, {sched}, "
            f"runs={self.run_count}, healthy={self.is_healthy})"
        )


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

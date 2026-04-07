# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.export.jobs
=====================

:class:`ExportJob` — a :class:`~gnat.schedule.job.FeedJob` subclass
that wraps an :class:`~gnat.export.base.ExportPipeline` for scheduled
delivery.

Because ``ExportJob`` inherits from ``FeedJob``, it works identically with
:class:`~gnat.schedule.scheduler.FeedScheduler` — you get drift-corrected
timing, overlap prevention, history tracking, ``on_success``/``on_failure``
callbacks, APScheduler export, and everything else for free.

Usage::

    from gnat.export.jobs import ExportJob
    from gnat.export import ExportPipeline
    from gnat.export.filters import TypeFilter, ConfidenceFilter, TLPFilter
    from gnat.export.transforms.edl import EDLTransform
    from gnat.export.delivery.targets import FileDelivery, MultiDelivery, EDLServer
    from gnat.schedule import FeedScheduler

    edl_server = EDLServer(port=8080)

    def build_pipeline(ctx):
        return (
            ExportPipeline("tq-to-palo-alto")
            .read_from(workspace)
            .filter_with(TypeFilter("indicator"))
            .filter_with(ConfidenceFilter(min_confidence=70))
            .filter_with(TLPFilter(["white", "green"]))
            .transform_with(EDLTransform(ioc_types=["ipv4", "domain", "url"]))
            .deliver_to(MultiDelivery(
                FileDelivery("/var/www/edl/"),
                edl_server,
            ))
        )

    job = ExportJob(
        job_id="tq-to-palo-alto-edl",
        pipeline_factory=build_pipeline,
        interval_seconds=3600,
        on_failure=lambda rec: alert("EDL export failed"),
    )

    scheduler = FeedScheduler()
    scheduler.add(job)
    scheduler.start()

ThreatQ → Netskope CE example::

    from gnat.export.transforms.netskope import NetskopeCETransform
    from gnat.export.delivery.targets import HTTPDelivery

    def tq_to_netskope(ctx):
        return (
            ExportPipeline("tq-to-netskope-ce")
            .read_from(workspace)
            .filter_with(TypeFilter("indicator"))
            .filter_with(ConfidenceFilter(min_confidence=60))
            .filter_with(IOCTypeFilter(["domain", "url", "sha256"]))
            .transform_with(NetskopeCETransform(source_label="ThreatQ"))
            .deliver_to(HTTPDelivery(
                url="https://netskope-ce.example.com/api/plugin/threatintel/pushData",
                headers={"Authorization": "Bearer <token>"},
            ))
        )

    job = ExportJob(
        job_id="tq-to-netskope-hourly",
        pipeline_factory=tq_to_netskope,
        interval_seconds=3600,
    )
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Callable

from gnat.schedule.job import FeedJob, JobRunContext, RunRecord, _utcnow

if TYPE_CHECKING:
    from gnat.export.base import ExportPipeline, ExportResult

logger = logging.getLogger(__name__)


class ExportJob(FeedJob):
    """
    A scheduled export job — wraps an :class:`~gnat.export.base.ExportPipeline`
    as a :class:`~gnat.schedule.job.FeedJob`.

    The ``pipeline_factory`` is called fresh on each run, allowing the
    pipeline to incorporate per-run state from ``JobRunContext`` (e.g.
    filtering by objects modified since the last successful run).

    Parameters
    ----------
    job_id : str
        Unique job identifier.
    pipeline_factory : callable
        ``(JobRunContext) -> ExportPipeline`` — called at the start of each
        run to produce a fresh pipeline.
    interval_seconds : int, optional
        Run every N seconds.
    cron : str, optional
        Cron expression (requires ``croniter``).
    on_success : callable, optional
        ``(RunRecord) -> None`` called after each successful run.
    on_failure : callable, optional
        ``(RunRecord) -> None`` called after each failed run.
    max_history : int
        Maximum run records to keep.  Default ``100``.
    overlap_policy : str
        ``"skip"`` or ``"queue"``.  Default ``"skip"``.
    enabled : bool
        Whether the job is active.  Default ``True``.

    Attributes
    ----------
    last_export_result : ExportResult or None
        The :class:`~gnat.export.base.ExportResult` from the most
        recent run.

    Examples
    --------
    ::

        job = ExportJob(
            job_id="tq-to-edl-hourly",
            pipeline_factory=lambda ctx: build_pipeline(ctx),
            interval_seconds=3600,
        )
    """

    def __init__(
        self,
        job_id: str,
        pipeline_factory: Callable[[JobRunContext], ExportPipeline],
        interval_seconds: int | None = None,
        cron: str | None = None,
        on_success: Callable[[RunRecord], None] | None = None,
        on_failure: Callable[[RunRecord], None] | None = None,
        max_history: int = 100,
        overlap_policy: str = "skip",
        enabled: bool = True,
    ):
        self._pipeline_factory = pipeline_factory
        self.last_export_result: ExportResult | None = None

        # FeedJob uses reader_factory / mapper_factory; we stub those and
        # override execute() to call the pipeline instead.
        super().__init__(
            job_id=job_id,
            reader_factory=lambda ctx: None,  # never called
            mapper_factory=lambda ctx: None,  # never called
            interval_seconds=interval_seconds,
            cron=cron,
            client=None,
            on_success=on_success,
            on_failure=on_failure,
            max_history=max_history,
            overlap_policy=overlap_policy,
            enabled=enabled,
        )

    def execute(self, scheduled_at: datetime | None = None) -> RunRecord:
        """
        Execute the export pipeline for one run.

        Overrides :meth:`~gnat.schedule.job.FeedJob.execute` to call
        the pipeline factory and run the export pipeline directly, bypassing
        the ingest-oriented reader/mapper/pipeline logic.

        Returns
        -------
        RunRecord
            Run record with ``result.total_records = source_objects``,
            ``result.written_objects = filtered_objects``.
        """
        from gnat.ingest.base import IngestResult

        if not self.enabled:
            rec = RunRecord(
                run_number=self.run_count + 1,
                scheduled_at=scheduled_at or _utcnow(),
                started_at=_utcnow(),
                finished_at=_utcnow(),
                status="skipped",
            )
            return rec

        # Overlap guard (re-use parent's lock)
        if self.overlap_policy == "skip":
            acquired = self._running_lock.acquire(blocking=False)
        else:
            acquired = self._running_lock.acquire(blocking=True)

        if not acquired:
            logger.warning("ExportJob %r: previous run still active, skipping", self.job_id)
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
            pipeline = self._pipeline_factory(ctx)
            export_result = pipeline.run()
            self.last_export_result = export_result

            # Bridge ExportResult → IngestResult shape for RunRecord
            ingest_proxy = IngestResult(
                source_id=self.job_id,
                total_records=export_result.source_objects,
                mapped_objects=export_result.filtered_objects,
                written_objects=(
                    export_result.transform_result.object_count
                    if export_result.transform_result
                    else 0
                ),
                errors=list(export_result.errors),
            )

            record.result = ingest_proxy
            record.finished_at = _utcnow()
            record.duration_seconds = (record.finished_at - record.started_at).total_seconds()

            if export_result.success:
                record.status = "success"
                self.last_success_at = record.finished_at
                logger.info(
                    "ExportJob %r run #%d: success (%d source → %d delivered) in %.1fs",
                    self.job_id,
                    self.run_count,
                    export_result.source_objects,
                    ingest_proxy.written_objects,
                    record.duration_seconds,
                )
                if self.on_success:
                    self._safe_callback(self.on_success, record)
            else:
                record.status = "partial" if ingest_proxy.written_objects > 0 else "failed"
                logger.warning(
                    "ExportJob %r run #%d: %s — %s",
                    self.job_id,
                    self.run_count,
                    record.status,
                    export_result.errors,
                )
                if self.on_failure:
                    self._safe_callback(self.on_failure, record)

        except Exception as exc:  # noqa: BLE001
            record.finished_at = _utcnow()
            record.duration_seconds = (record.finished_at - record.started_at).total_seconds()
            record.status = "failed"
            record.error = str(exc)
            logger.error("ExportJob %r run #%d: FAILED — %s", self.job_id, self.run_count, exc)
            if self.on_failure:
                self._safe_callback(self.on_failure, record)
        finally:
            self._running_lock.release()

        self._append_history(record)
        return record

    def __repr__(self) -> str:  # pragma: no cover
        sched = (
            f"every {self.interval_seconds}s" if self.interval_seconds else f"cron={self.cron!r}"
        )
        return f"ExportJob(id={self.job_id!r}, {sched})"

"""
ctm_sak.research.curation
==========================

:class:`CurationJob` — a :class:`~ctm_sak.schedule.job.FeedJob` subclass
that runs the staging → library promotion pipeline on a schedule.

What it does
------------
On each run the curation job:

1. Loads all pending entries from the staging workspace
2. Deduplicates by topic key — keeps the most recent entry per topic,
   archives older entries (they remain in storage for audit)
3. Applies TTL — sets ``expires_at`` based on category and configured hours
4. Writes surviving entries to the library with ``curator_status = "curated"``
5. Archives superseded entries in staging so they don't re-appear

The job keeps a count of promoted, deduplicated, and archived entries in
each ``RunRecord`` so the scheduler status output shows what happened.

Usage
-----
::

    from ctm_sak.research import ResearchLibrary, CurationJob
    from ctm_sak.schedule import FeedScheduler

    lib = ResearchLibrary.default()

    # Curate every 4 hours
    curation = CurationJob(lib, interval_seconds=4 * 3600)

    with FeedScheduler() as scheduler:
        scheduler.add(curation)

The curation job can also be run manually::

    result = curation.execute()
    print(result.status, result.result)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from ctm_sak.schedule.job import FeedJob, JobRunContext, RunRecord, _utcnow
from ctm_sak.ingest.base import IngestResult, SourceReader, RecordMapper, RawRecord

if TYPE_CHECKING:
    from ctm_sak.research.library import ResearchLibrary
    from ctm_sak.research.entry import ResearchEntry

logger = logging.getLogger(__name__)


class _CurationReader(SourceReader):
    """Internal reader that yields pending staging entries as raw records."""

    def __init__(self, library: "ResearchLibrary"):
        super().__init__(source_id="curation_reader")
        self._lib = library

    def _iter_records(self):
        for entry in self._lib._load_all_entries(
            self._lib._staging_name, status="pending"
        ):
            yield entry.to_dict()


class _CurationMapper(RecordMapper):
    """
    Internal mapper that deduplicates, applies TTLs, and writes to library.

    Returns a synthetic IngestResult-compatible output.
    """

    def __init__(self, library: "ResearchLibrary", stats: Dict[str, int]):
        super().__init__()
        self._lib   = library
        self._stats = stats
        self._seen_topics: Dict[str, "ResearchEntry"] = {}

    def map(self, record: RawRecord):
        """
        Process one staging entry dict.

        Because the dedup decision requires seeing all entries for a topic,
        the mapper collects entries into ``_seen_topics`` on the first pass
        and commits the winner when :meth:`flush` is called.  This is a
        departure from the standard mapper contract — the caller
        (:class:`CurationJob`) calls :meth:`flush` after the pipeline run.
        """
        from ctm_sak.research.entry import ResearchEntry, topic_key

        try:
            entry = ResearchEntry.from_dict(record)
        except (KeyError, ValueError) as exc:
            logger.warning("CurationJob: bad entry data skipped — %s", exc)
            self._stats["skipped"] += 1
            return iter([])

        tkey = topic_key(entry.topic)
        existing = self._seen_topics.get(tkey)

        if existing is None:
            self._seen_topics[tkey] = entry
        elif entry.promoted_at > existing.promoted_at:
            # This entry is newer — archive the old one
            existing.mark_archived()
            self._lib._save_entry(existing, self._lib._staging_name)
            self._stats["archived"] += 1
            self._seen_topics[tkey] = entry
        else:
            # This entry is older — archive it
            entry.mark_archived()
            self._lib._save_entry(entry, self._lib._staging_name)
            self._stats["archived"] += 1

        return iter([])  # no STIX objects emitted — we write entries directly

    def flush(self) -> None:
        """
        Write all deduplication winners to the library.

        Called by :class:`CurationJob` after the pipeline finishes collecting
        all staging entries.
        """
        for tkey, entry in self._seen_topics.items():
            # Apply TTL
            ttl_hours = self._lib._ttls.get(entry.category, 168)
            entry.set_ttl(ttl_hours)
            entry.mark_curated()

            # Write to library
            self._lib._write_entry_to_library(entry)

            # Mark as curated in staging too (so it won't re-appear)
            entry.curator_status = "curated"  # already set by mark_curated
            self._lib._save_entry(entry, self._lib._staging_name)

            self._stats["promoted"] += 1
            logger.info(
                "CurationJob: promoted %r → library (category=%r, ttl=%dh)",
                entry.topic, entry.category, ttl_hours,
            )


class CurationJob(FeedJob):
    """
    Scheduled job that runs the staging → library curation pipeline.

    Deduplicates pending staging entries by topic (most recent wins),
    applies category TTLs, and writes curated entries to the library.
    Archives superseded entries in staging.

    Parameters
    ----------
    library : ResearchLibrary
        The research library to curate.
    interval_seconds : int, optional
        Run every N seconds.  Default 4 hours (14400).
    cron : str, optional
        Cron expression instead of interval.
    on_success : callable, optional
        Called after each successful curation run with the ``RunRecord``.
    on_failure : callable, optional
        Called after each failed run.
    job_id : str
        Scheduler job identifier.  Default ``"ctmsak-curation"``.

    Examples
    --------
    ::

        from ctm_sak.research import ResearchLibrary, CurationJob
        from ctm_sak.schedule import FeedScheduler

        lib = ResearchLibrary.default()
        job = CurationJob(lib, interval_seconds=4 * 3600)

        with FeedScheduler() as sched:
            sched.add(job)
    """

    def __init__(
        self,
        library: "ResearchLibrary",
        interval_seconds: Optional[int] = 14_400,
        cron: Optional[str] = None,
        on_success=None,
        on_failure=None,
        job_id: str = "ctmsak-curation",
    ):
        self._library = library

        # Build dummy reader/mapper factories; execute() is overridden
        super().__init__(
            job_id          = job_id,
            reader_factory  = lambda ctx: _CurationReader(library),
            mapper_factory  = lambda ctx: None,  # replaced in execute()
            interval_seconds = interval_seconds,
            cron            = cron,
            on_success      = on_success,
            on_failure      = on_failure,
        )

    def execute(
        self, scheduled_at: Optional[datetime] = None
    ) -> RunRecord:
        """
        Run one curation cycle.

        Overrides :meth:`~ctm_sak.schedule.job.FeedJob.execute` to use
        the two-pass curation logic (collect all → dedup → flush) rather
        than the standard stream-processing pipeline.
        """
        if not self.enabled:
            rec = RunRecord(
                run_number   = self.run_count + 1,
                scheduled_at = scheduled_at or _utcnow(),
                started_at   = _utcnow(),
                finished_at  = _utcnow(),
                status       = "skipped",
            )
            return rec

        if not self._running_lock.acquire(blocking=False):
            rec = RunRecord(
                run_number   = self.run_count + 1,
                scheduled_at = scheduled_at or _utcnow(),
                started_at   = _utcnow(),
                finished_at  = _utcnow(),
                status       = "skipped",
                error        = "skipped: previous run still active",
            )
            return rec

        self.run_count += 1
        started_at = _utcnow()
        sched_at   = scheduled_at or started_at

        record = RunRecord(
            run_number   = self.run_count,
            scheduled_at = sched_at,
            started_at   = started_at,
        )

        stats = {"promoted": 0, "archived": 0, "skipped": 0}

        try:
            # Load all pending staging entries
            pending = self._library._load_all_entries(
                self._library._staging_name, status="pending"
            )
            logger.info(
                "CurationJob: run #%d — found %d pending staging entries",
                self.run_count, len(pending),
            )

            if not pending:
                record.status       = "success"
                record.finished_at  = _utcnow()
                record.duration_seconds = (
                    record.finished_at - started_at
                ).total_seconds()
                record.result = IngestResult(
                    source_id="curation",
                    total_records=0,
                    written_objects=0,
                )
                record.result.metadata = stats
                self.last_success_at = record.finished_at
                self._append_history(record)
                if self.on_success:
                    self._safe_callback(self.on_success, record)
                return record

            # Dedup: group by topic key, keep most recent
            from ctm_sak.research.entry import topic_key
            by_topic: Dict[str, "ResearchEntry"] = {}
            for entry in pending:
                tkey = topic_key(entry.topic)
                existing = by_topic.get(tkey)
                if existing is None or entry.promoted_at > existing.promoted_at:
                    if existing is not None:
                        existing.mark_archived()
                        self._library._save_entry(
                            existing, self._library._staging_name
                        )
                        stats["archived"] += 1
                    by_topic[tkey] = entry
                else:
                    entry.mark_archived()
                    self._library._save_entry(
                        entry, self._library._staging_name
                    )
                    stats["archived"] += 1

            # Promote winners to library
            for entry in by_topic.values():
                ttl_hours = self._library._ttls.get(entry.category, 168)
                entry.set_ttl(ttl_hours)
                entry.mark_curated()

                # Check if library already has a newer curated entry
                existing_curated = self._library._find_entry(
                    entry.topic,
                    workspace_name=self._library._library_name,
                    status="curated",
                )
                if (existing_curated is not None and
                        existing_curated.promoted_at >= entry.promoted_at):
                    # Library already has something newer — archive this one
                    entry.mark_archived()
                    self._library._save_entry(
                        entry, self._library._staging_name
                    )
                    stats["archived"] += 1
                    continue

                # Archive any existing library entry for this topic
                if existing_curated is not None:
                    existing_curated.mark_archived()
                    self._library._save_entry(
                        existing_curated, self._library._library_name
                    )

                self._library._write_entry_to_library(entry)
                # Mark staging copy as curated
                entry.curator_status = "curated"
                self._library._save_entry(entry, self._library._staging_name)
                stats["promoted"] += 1

                logger.info(
                    "CurationJob: promoted %r → library "
                    "(category=%r, ttl=%dh, objects=%d)",
                    entry.topic, entry.category, ttl_hours,
                    len(entry.stix_objects),
                )

            record.status       = "success"
            record.finished_at  = _utcnow()
            record.duration_seconds = (
                record.finished_at - started_at
            ).total_seconds()
            record.result = IngestResult(
                source_id      = "curation",
                total_records  = len(pending),
                written_objects= stats["promoted"],
            )
            record.result.metadata = stats
            self.last_success_at = record.finished_at

            logger.info(
                "CurationJob: run #%d complete — "
                "promoted=%d archived=%d skipped=%d in %.2fs",
                self.run_count,
                stats["promoted"], stats["archived"], stats["skipped"],
                record.duration_seconds,
            )

            if self.on_success:
                self._safe_callback(self.on_success, record)

        except Exception as exc:  # noqa: BLE001
            record.finished_at      = _utcnow()
            record.duration_seconds = (
                record.finished_at - started_at
            ).total_seconds()
            record.status = "failed"
            record.error  = str(exc)
            logger.error("CurationJob run #%d FAILED — %s", self.run_count, exc)
            if self.on_failure:
                self._safe_callback(self.on_failure, record)

        finally:
            self._running_lock.release()

        self._append_history(record)
        return record

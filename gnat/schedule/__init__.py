"""
ctm_sak.schedule
=================

Scheduled feed ingestion for CTM-SAK.

Binds :class:`~ctm_sak.ingest.base.SourceReader` /
:class:`~ctm_sak.ingest.base.RecordMapper` factories into recurring jobs,
manages job threads, and exposes adapters for APScheduler and Celery.

Quick start::

    from ctm_sak.schedule import FeedJob, FeedScheduler
    from ctm_sak.ingest.sources.readers import PlainTextReader
    from ctm_sak.ingest.mappers.mappers import FlatIOCMapper

    job = FeedJob(
        job_id="blocklist",
        reader_factory=lambda ctx: PlainTextReader("https://example.com/ips.txt"),
        mapper_factory=lambda ctx: FlatIOCMapper(confidence=70),
        interval_seconds=3600,
        client=tq_client,
    )

    with FeedScheduler() as scheduler:
        scheduler.add(job)
        # jobs run in background threads
        import time; time.sleep(7200)   # run for 2 hours
"""

from ctm_sak.schedule.job import FeedJob, JobRunContext, RunRecord
from ctm_sak.schedule.scheduler import FeedScheduler

__all__ = [
    "FeedJob",
    "FeedScheduler",
    "JobRunContext",
    "RunRecord",
]

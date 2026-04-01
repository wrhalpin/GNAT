# ADR-0016: Feed Scheduling

**Decision:** Built-in threading scheduler (`FeedScheduler`) as the primary
path, with export adapters for APScheduler and Celery.

### Why not just APScheduler

APScheduler is excellent but adds a dependency and a learning curve for a
feature analysts need to configure on day one. The built-in scheduler covers
the common case (interval + cron) in ~200 lines. Teams that already have
APScheduler or Celery can use the export adapters.

### Reader factory pattern — the key to correct incremental ingestion

The `reader_factory` callable receives a `JobRunContext` on every run. This
is the correct place to construct time-windowed readers:

```python
def make_taxii_reader(ctx):
    return TAXIICollectionReader(
        collection,
        added_after=ctx.last_success_iso or "2024-01-01T00:00:00Z",
    )
```

`ctx.last_success_iso` is `None` on the first run (full backfill) and the
ISO timestamp of the last successful completion on all subsequent runs.
This means incremental ingestion is automatic — readers only fetch new data.

**Why factory and not instance:** Readers are not reusable across runs —
they may hold open connections, carry file pointers, or depend on the
`added_after` computed from the previous run. A factory produces a fresh
reader each time with the correct parameters.

### FeedJob state machine

```
enabled=False → always "skipped"
overlap=skip, lock unavailable → "skipped"
reader/pipeline raises → "failed", on_failure callback
result.errors non-empty → "partial", on_failure callback
all clear → "success", on_success callback, last_success_at updated
```

`consecutive_failures` counts backwards through history and resets to 0
on the first "success" or "partial" result. Use it for alerting thresholds:
fire a PagerDuty alert when `job.consecutive_failures >= 3`.

### Drift-corrected timing

The scheduler computes `next_trigger = last_scheduled_at + interval` rather
than `time.time() + interval`. This means a 1-hour feed that takes 5 minutes
to run still fires at the next hour mark, not 65 minutes after the last run.
If the process was down and the next trigger is already in the past, it fires
immediately without trying to backfill the missed runs.

### Threading model

One daemon thread per job. Threads sleep in 1-second increments (not one
long sleep) so `stop()` responds within ~1 second regardless of interval.
`start(run_immediately=True)` is the right choice for startup backfill — it
fires all jobs once before entering the normal schedule loop.

### Overlap policy

`"skip"` (default): if a run is still executing when the next trigger fires,
the new run is logged as "skipped". Best for feeds where missing one run is
acceptable and you don't want a backlog of queued runs.

`"queue"`: the new run waits for the current one to finish. Use for feeds
where every run must complete, but beware that a slow source can cause
unlimited queueing.

### Config extras

`pip install "gnat[schedule]"` adds `croniter` for cron expression
support. Interval-based jobs work with no extras. APScheduler and Celery
adapters require those packages installed separately.

### Quick-reference: adding a scheduled feed

```python
from gnat.schedule import FeedJob, FeedScheduler
from gnat.ingest.sources.readers import PlainTextReader, TAXIICollectionReader
from gnat.ingest.mappers.mappers import FlatIOCMapper, STIXPassthroughMapper

# Stateless feed (blocklist)
blocklist = FeedJob(
    job_id="blocklist-hourly",
    reader_factory=lambda ctx: PlainTextReader("https://example.com/ips.txt"),
    mapper_factory=lambda ctx: FlatIOCMapper(confidence=70, tlp_marking="white"),
    interval_seconds=3600,
    client=tq_client,
)

# Incremental TAXII feed
taxii = FeedJob(
    job_id="taxii-daily",
    reader_factory=lambda ctx: TAXIICollectionReader(
        collection,
        added_after=ctx.last_success_iso or "2024-01-01T00:00:00Z",
    ),
    mapper_factory=lambda ctx: STIXPassthroughMapper(client=tq_client),
    cron="0 2 * * *",   # 02:00 daily — requires pip install "gnat[schedule]"
    client=tq_client,
    on_failure=lambda rec: logger.error("TAXII feed failed: %s", rec.error),
)

scheduler = FeedScheduler()
scheduler.add(blocklist)
scheduler.add(taxii)
scheduler.start(run_immediately=True)   # backfill on startup

# Health check
for status in scheduler.statuses():
    if not status["is_healthy"]:
        print(f"UNHEALTHY: {status['job_id']} — {status['last_run_status']}")
```

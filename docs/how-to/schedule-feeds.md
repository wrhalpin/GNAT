# How-to: Schedule Feeds

Configure recurring ingest and export jobs with `FeedScheduler`.

---

## Basic scheduled feed

```python
from gnat.schedule import FeedJob, FeedScheduler
from gnat.ingest.sources.readers import PlainTextReader
from gnat.ingest.mappers.mappers import FlatIOCMapper

job = FeedJob(
    job_id         = "blocklist-hourly",
    reader_factory = lambda ctx: PlainTextReader("https://blocklist.example.com/ips.txt"),
    mapper_factory = lambda ctx: FlatIOCMapper(confidence=70),
    interval_seconds = 3600,
    client           = threatq_client,
    on_failure       = lambda rec: logger.error("Feed failed: %s", rec.error),
)

with FeedScheduler() as scheduler:
    scheduler.add(job)
    # Runs in background threads until process exits
```

---

## Incremental TAXII feed (uses last_success_iso)

```python
job = FeedJob(
    job_id = "taxii-daily",
    reader_factory = lambda ctx: TAXIICollectionReader(
        collection,
        added_after = ctx.last_success_iso or "2024-01-01T00:00:00Z",
    ),
    mapper_factory = lambda ctx: STIXPassthroughMapper(client=tq_client),
    cron           = "0 2 * * *",   # 02:00 daily
    client         = threatq_client,
)
```

---

## Health monitoring

```python
scheduler = FeedScheduler()
# ... add jobs ...
scheduler.start()

# Check health
for status in scheduler.statuses():
    if not status["is_healthy"]:
        print(f"UNHEALTHY: {status['job_id']} — {status['last_run_status']}")

# Summary
print(scheduler.summary())
# {'running': True, 'total_jobs': 5, 'healthy': 4, 'failing': 1, 'total_runs': 47}
```

---

## See Also

- [How-to: Export Indicators](export-indicators.md)
- [How-to: Generate Reports](generate-reports.md)
- [Explanation: Feed Scheduling](../explanation/architecture/adrs/0016-feed-scheduling.md)

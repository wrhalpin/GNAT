# How-to: Schedule Feeds

Configure recurring ingest and export jobs with `FeedScheduler`, then
manage them from the command line with `gnat schedule ...`.

GNAT's scheduler supports two configuration styles:

1. **Declarative YAML** — describe jobs in `gnat-jobs.yaml` with plain
   dotted-path class references. No Python code required.
2. **Python module** — write a `build_jobs()` factory function for
   cases that need custom factory closures, runtime secret lookup, or
   tenant-scoped client resolution.

Both styles can be mixed: jobs from the YAML file and jobs from the
Python module are merged into a single scheduler.

---

## The CLI: `gnat schedule ...`

Once jobs are configured (see below), the CLI exposes the full
scheduler API:

| Command | Purpose |
|---|---|
| `gnat schedule list` | One-line-per-job table (id, schedule, health, last/next run) |
| `gnat schedule status --job ID` | Detailed view for one job + last 5 runs |
| `gnat schedule history --job ID [--limit N]` | Full run-history table |
| `gnat schedule run [--job ID] [--parallel]` | Trigger one or all jobs immediately |
| `gnat schedule crontab [--command CMD]` | Emit crontab lines for `crontab -e` |
| `gnat schedule validate` | Parse job definitions without touching credentials (for CI) |
| `gnat schedule start [--run-immediately]` | Run the scheduler in the foreground (Ctrl-C to stop) |

Every subcommand honors `--output json` for machine-readable output, and
accepts `--jobs-file PATH` / `--jobs-module DOTTED.PATH` to override the
config-file defaults.

---

## Option 1 — Declarative YAML

Point the CLI at a YAML file via `[schedule] jobs_file` in your
`gnat.ini`:

```ini
[schedule]
jobs_file = /etc/gnat/gnat-jobs.yaml
```

```yaml
# /etc/gnat/gnat-jobs.yaml
jobs:
  - id: urlhaus-hourly
    description: "Abuse.ch URLhaus malicious URL feed"
    reader:
      class: gnat.ingest.sources.readers.PlainTextReader
      args:
        source: "https://urlhaus.abuse.ch/downloads/text/"
    mapper:
      class: gnat.ingest.mappers.mappers.FlatIOCMapper
      args:
        confidence: 80
        tlp_marking: white
    interval_seconds: 3600
    client: threatq              # resolved via CLIENT_REGISTRY + [threatq]

  - id: opencti-taxii
    reader:
      class: gnat.ingest.sources.readers.TAXIICollectionReader
      args:
        url: https://opencti.example.com/taxii2
        collection_id: apt-feed
    mapper:
      class: gnat.ingest.mappers.mappers.STIXPassthroughMapper
    cron: "0 */4 * * *"
    client: opencti
```

Every YAML job supports:

| Field | Type | Required |
|---|---|---|
| `id` | str | ✓ |
| `reader.class` | dotted Python path | ✓ |
| `reader.args` | dict of kwargs | — |
| `mapper.class` | dotted Python path | ✓ |
| `mapper.args` | dict of kwargs | — |
| `interval_seconds` **or** `cron` | int / cron expr | ✓ (one or the other) |
| `client` | CLIENT_REGISTRY key | — |
| `description` | str | — |
| `enabled` | bool (default `true`) | — |
| `confidence` | int (default `50`) | — |
| `tlp_marking` | str (default `"white"`) | — |
| `deduplicate` | bool (default `true`) | — |
| `dedup_key_fields` | list[str] | — |
| `overlap_policy` | `"skip"` \| `"queue"` (default `"skip"`) | — |
| `max_history` | int (default `100`) | — |

**Validating a YAML file in CI** — `gnat schedule validate` parses the
file, resolves every class reference, and confirms every cron expression
is valid, **without** instantiating any GNATClient or touching
credentials:

```bash
$ gnat schedule validate --jobs-file gnat-jobs.yaml
OK: 2 job(s) parsed and class references resolved
  urlhaus-hourly                 every 3600s
  opencti-taxii                  cron '0 */4 * * *'
```

Put this in a pre-commit hook or CI job to catch typos before deploy.

---

## Option 2 — Python module

Point the CLI at a module via `[schedule] jobs_module` in your
`gnat.ini`:

```ini
[schedule]
jobs_module = my_project.gnat_jobs
```

```python
# my_project/gnat_jobs.py
from gnat.schedule import FeedJob
from gnat.ingest.sources.readers import PlainTextReader
from gnat.ingest.mappers.mappers import FlatIOCMapper


def build_jobs(config):
    """Return a list[FeedJob]. Called once per CLI invocation."""
    return [
        FeedJob(
            job_id="blocklist-hourly",
            reader_factory=lambda ctx: PlainTextReader(
                source=get_secret_at_runtime(ctx),
            ),
            mapper_factory=lambda ctx: FlatIOCMapper(confidence=70),
            interval_seconds=3600,
            # client resolved however you like
        ),
    ]
```

The loader looks for (in order):

1. `build_jobs(config)` — a function taking the parsed `ConfigParser`.
2. `build_jobs()` — same, but no config argument.
3. `scheduler: FeedScheduler` — a pre-built scheduler at module level.
4. `jobs: list[FeedJob]` — a plain list at module level.

Pick whichever matches your project's style. The Python module is the
right choice whenever you need:

- Secret lookup at runtime (not baked into YAML)
- Tenant-scoped client construction
- Dynamic job generation (e.g., one job per workspace)
- Readers/mappers whose constructors aren't pure kwargs

---

## Option 3 — Hybrid

Set both keys — jobs from both sources are merged into a single
scheduler:

```ini
[schedule]
jobs_file   = /etc/gnat/gnat-jobs.yaml
jobs_module = my_project.gnat_jobs
```

A typical layout: put simple "follow this URL every hour" feeds in the
YAML file where ops can review them in PRs, and put
credential-heavy or dynamic jobs in the Python module.

---

## Production deployment

The `gnat schedule start` command runs the scheduler in the foreground.
Put it behind your supervisor of choice:

**systemd** (recommended):

```ini
# /etc/systemd/system/gnat-scheduler.service
[Unit]
Description=GNAT feed scheduler
After=network.target

[Service]
Type=simple
User=gnat
Environment=GNAT_CONFIG=/etc/gnat/gnat.ini
ExecStart=/usr/local/bin/gnat schedule start
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now gnat-scheduler
sudo journalctl -u gnat-scheduler -f
```

**Docker**:

```dockerfile
CMD ["gnat", "schedule", "start"]
```

**cron** (if you prefer not to keep a long-running process):

```bash
# Generate crontab lines and install
gnat schedule crontab | crontab -

# Or merge with existing entries
(crontab -l; gnat schedule crontab) | crontab -
```

---

## Programmatic API (no CLI)

If you prefer to embed the scheduler in your own process instead of
using the CLI, the original Python API still works:

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

---

*Licensed under the Apache License, Version 2.0*

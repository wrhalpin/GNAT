# Tutorial: Production Scheduled Pipeline

This tutorial shows how to run a long-lived GNAT process that manages all
ingest, export, curation, and reporting jobs via `FeedScheduler`.

**Prerequisites**
- `gnat` installed and `config.ini` configured
- Platform clients (`tq_client`, `netskope_client`) already authenticated

---

## 1. Import dependencies

```python
from gnat.schedule import FeedJob, FeedScheduler
from gnat.reports import ReportJob, ReportConfig, AIMode
from gnat.research import ResearchLibrary, CurationJob
from gnat.agents import AgentConfig
from gnat.export import ExportJob, ExportPipeline
from gnat.export.filters import TypeFilter, ConfidenceFilter
from gnat.export.transforms.edl import EDLTransform
from gnat.export.transforms.netskope import NetskopeCETransform
from gnat.export.delivery.targets import FileDelivery, PlatformDelivery
from gnat.ingest.sources.readers import PlainTextReader, TAXIICollectionReader
from gnat.ingest.mappers.mappers import FlatIOCMapper, STIXPassthroughMapper
```

---

## 2. Initialise shared state

```python
lib       = ResearchLibrary.default()
agent_cfg = AgentConfig.from_ini()
scheduler = FeedScheduler(on_job_error=lambda jid, exc: alert(jid, exc))
```

---

## 3. Add ingest feeds

**Hourly blocklist** — runs every 60 minutes:

```python
scheduler.add(FeedJob(
    "blocklist",
    lambda ctx: PlainTextReader("https://blocklist.example.com/ips.txt"),
    lambda ctx: FlatIOCMapper(confidence=70),
    interval_seconds=3600,
    client=tq_client,
))
```

**Daily TAXII feed** — runs at 02:00 UTC, only fetching new objects:

```python
scheduler.add(FeedJob(
    "taxii",
    lambda ctx: TAXIICollectionReader(
        collection, added_after=ctx.last_success_iso
    ),
    lambda ctx: STIXPassthroughMapper(client=tq_client),
    cron="0 2 * * *",
))
```

---

## 4. Add export jobs

**EDL sync** — refreshes the indicator file every 15 minutes:

```python
scheduler.add(ExportJob("edl-sync", lambda ctx: (
    ExportPipeline("edl")
    .read_from(workspace)
    .filter_with(TypeFilter("indicator"))
    .filter_with(ConfidenceFilter(70))
    .transform_with(EDLTransform(ioc_types=["ipv4", "domain", "url"]))
    .deliver_to(FileDelivery("/var/edl/"))
), interval_seconds=900))
```

**Netskope CE sync** — pushes domains, URLs, and hashes every 15 minutes:

```python
scheduler.add(ExportJob("netskope-sync", lambda ctx: (
    ExportPipeline("nsk")
    .read_from(workspace)
    .filter_with(TypeFilter("indicator"))
    .filter_with(ConfidenceFilter(70))
    .transform_with(NetskopeCETransform(source_label="ThreatQ"))
    .deliver_to(PlatformDelivery(netskope_client))
), interval_seconds=900))
```

---

## 5. Add curation and reporting

**Research curation** — every 4 hours:

```python
scheduler.add(CurationJob(lib, interval_seconds=4 * 3600))
```

**Daily SOC report** — emailed at 06:00 every morning:

```python
scheduler.add(ReportJob(
    manager,
    ReportConfig(
        report_type="daily",
        formats=["pdf", "html"],
        delivery=["email"],
        email_to=["soc@example.com"],
        schedule="0 6 * * *",
    ),
    agent_cfg,
    lib,
))
```

---

## 6. Start the scheduler

```python
scheduler.start(run_immediately=True)
# Process keeps running — scheduler manages all jobs
```

---

## Next steps

- Monitor job health via `scheduler.statuses()` — see [How-to: Schedule Feeds](../how-to/schedule-feeds.md)
- Add an AI research feed — see [How-to: Use AI Agents](../how-to/use-ai-agents.md)
- Containerise this pipeline — see [Explanation: Docker Containerisation](../explanation/architecture/adrs/0029-docker-containerization.md)

---

*Licensed under the Apache License, Version 2.0*

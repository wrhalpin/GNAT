# ADR-0017: Export / Integration Pipeline

**Decision:** A separate push-oriented pipeline (Filter → Transform → Deliver)
distinct from the pull-oriented ingestion pipeline (Reader → Mapper → Pipeline).

### Why separate from ingestion

Ingestion is incremental — you fetch new records since last run and add them.
Export is often idempotent and authoritative — a firewall EDL must contain the
*current complete list*, not a diff. This fundamental difference in semantics
means the same pipeline abstraction doesn't fit both.

### Three-stage composable pipeline

```
ExportFilter → ExportTransform → ExportDelivery
```

All three are protocol classes. Filters are lazy generators (composable via `&`).
Transforms produce a `TransformResult` with named payloads (one per output file).
Delivery targets receive the full `TransformResult` and push each payload.

**Multiple outputs from one transform:** `EDLTransform` produces separate files
per IOC type (`indicators-ipv4.txt`, `indicators-domain.txt`, etc.) because
firewalls need to assign each type to the appropriate security policy — you can't
mix IPs and domains in a single EDL entry.

### Filter design decisions

All filters are lazy generators — they don't materialise intermediate lists.
Composable via `&` operator: `TypeFilter("indicator") & ConfidenceFilter(70)`.

`IOCTypeFilter` inspects the STIX pattern string rather than a separate IOC
type field because STIX patterns are the canonical representation. The type is
inferred from the observable keyword (`ipv4-addr`, `domain-name`, etc.).

`TLPFilter` defaults unlabelled objects to `"white"` — the most permissive
default. Override with `default_tlp="amber"` for strict environments that
should block unlabelled objects from leaving.

`AgeFilter` uses `modified` then `created` then the custom `time_field` in
fallback order. Missing timestamps default to "pass through" (`drop_missing=False`)
so old or partial objects aren't silently dropped — use `drop_missing=True` to
enforce freshness strictly.

### EDL transform — atomic file replace

`FileDelivery` uses write-to-temp-then-rename (atomic replace) so firewalls that
poll the EDL file via HTTP never see a partially-written file. The temp file is
created in the same directory as the destination to ensure both are on the same
filesystem (rename is atomic only within one filesystem).

### EDLServer — built-in HTTP server

`EDLServer` runs a background daemon thread serving EDL files directly.
Firewalls point to `http://<host>:8080/indicators-ipv4.txt`. On each export
pipeline run, the in-memory files are updated atomically (under a lock) and the
server immediately serves the new version on the next poll. No file system I/O
or nginx configuration needed for the most common case.

### ExportJob — bridges export to scheduling

`ExportJob` inherits from `FeedJob` and overrides `execute()` to call the
pipeline factory instead of the reader/mapper/ingest pipeline. This means
all scheduling features — drift-corrected timing, overlap prevention, history,
callbacks, APScheduler/Celery export — apply to export jobs automatically.

The `pipeline_factory(ctx) -> ExportPipeline` pattern allows the pipeline to
incorporate per-run context. A common pattern: filter objects modified since
`ctx.last_success_iso` so only newly-updated indicators are exported:

```python
def factory(ctx):
    filters = [TypeFilter("indicator"), ConfidenceFilter(70)]
    if ctx.last_success_iso:
        filters.append(AgeFilter(max_age_days=1, time_field="modified"))
    return (ExportPipeline("incremental")
            .read_from(workspace)
            .filter_with(*filters)
            .transform_with(NetskopeCETransform())
            .deliver_to(HTTPDelivery(url=NETSKOPE_CE_URL, headers=AUTH)))
```

### ThreatQ → Netskope CE → EDL reference workflow

This is the exact workflow from the design brief:

```python
from gnat.export import ExportPipeline
from gnat.export.filters import TypeFilter, ConfidenceFilter, IOCTypeFilter
from gnat.export.transforms.netskope import NetskopeCETransform
from gnat.export.delivery.targets import HTTPDelivery, MultiDelivery, FileDelivery, EDLServer
from gnat.export.jobs import ExportJob
from gnat.schedule import FeedScheduler

# ThreatQ workspace (populated by ingestion pipeline or direct load)
ws = manager.open("threat-intel")

# Build the delivery stack
edl_server = EDLServer(port=8080)   # started on first deliver()

def tq_to_netskope(ctx):
    return (
        ExportPipeline("tq-to-netskope-ce")
        .read_from(ws)
        .filter_with(TypeFilter("indicator"))
        .filter_with(ConfidenceFilter(min_confidence=60))
        .filter_with(IOCTypeFilter(["domain", "url", "sha256"]))
        .transform_with(NetskopeCETransform(
            source_label="ThreatQ",
            default_reputation=60,
        ))
        .deliver_to(HTTPDelivery(
            url="https://netskope-ce.example.com/api/plugin/threatintel/pushData",
            headers={"Authorization": "Bearer <token>"},
        ))
    )

def tq_to_edl(ctx):
    return (
        ExportPipeline("tq-to-palo-alto")
        .read_from(ws)
        .filter_with(TypeFilter("indicator"))
        .filter_with(ConfidenceFilter(min_confidence=70))
        .filter_with(IOCTypeFilter(["ipv4", "domain", "url"]))
        .transform_with(EDLTransform(
            ioc_types=["ipv4", "domain", "url"],
            max_per_file=100_000,
        ))
        .deliver_to(MultiDelivery(
            FileDelivery("/var/www/edl/"),   # nginx serves these
            edl_server,                      # also served live on :8080
        ))
    )

scheduler = FeedScheduler()
scheduler.add(ExportJob(
    job_id="tq-to-netskope-hourly",
    pipeline_factory=tq_to_netskope,
    interval_seconds=3600,
    on_failure=lambda rec: alert(f"Netskope sync failed: {rec.error}"),
))
scheduler.add(ExportJob(
    job_id="tq-to-edl-hourly",
    pipeline_factory=tq_to_edl,
    interval_seconds=3600,
))

scheduler.start(run_immediately=True)   # backfill on startup
# Firewalls poll http://<host>:8080/indicators-ipv4.txt on their own schedule
```

Netskope CE's sharing rules then push the received indicators to tenant URL/domain/IP
lists, which push to perimeter firewall EDLs. GNAT's role is the authoritative
push from ThreatQ into CE — everything downstream is Netskope's responsibility.

---

*Licensed under the Apache License, Version 2.0*

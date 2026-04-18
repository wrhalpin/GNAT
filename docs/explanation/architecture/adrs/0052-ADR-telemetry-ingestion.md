# ADR-0052: Telemetry Ingestion

**Decision:** Implement high-volume sensor telemetry ingestion by
subclassing the existing `SourceReader`/`RecordMapper` contracts
(ADR-0004), with Kafka as the transport, Redis for deduplication
(with in-memory fallback), and campaign auto-linking as an optional
pipeline transform. All external dependencies gated behind a
`[telemetry]` extras group (ADR-0015).

**Problem statement:**
GNAT ingests threat intelligence from 158 platform APIs but has no
path for high-volume sensor telemetry (honeypot captures, netflow
records, IDS alerts, passive DNS logs). With campaign tracking now
in place (ADR-0051), telemetry from lab infrastructure needs a way
to flow into the platform so that sensor-generated indicators can
be linked to active campaigns and coverage gaps.

## Reuse existing pipeline contracts

`KafkaSourceReader` subclasses `SourceReader`; `TelemetryMapper`
subclasses `RecordMapper`. No new pipeline abstractions were
introduced — telemetry plugs into the existing `IngestPipeline`
fluent API:

```python
result = (
    IngestPipeline("honeypot-feed")
    .read_from(KafkaSourceReader(topics=["honeypot-events"]))
    .map_with(TelemetryMapper(sensor_type=SensorType.HONEYPOT))
    .deduplicate()
    .transform(CampaignLinker(campaign_service))
    .write_to(client)
    .run()
)
```

**Rationale:** The `SourceReader` → `RecordMapper` → `IngestPipeline`
contract is well-tested (ADR-0004) and handles batching,
deduplication, error collection, lineage tracking, and result
reporting. Building a parallel pipeline for telemetry would duplicate
all of that infrastructure.

## Kafka via optional extras

`kafka-python-ng>=2.2` and `redis>=5.0` are gated behind
`pip install "gnat[telemetry]"`, following the extras pattern from
ADR-0015. The `KafkaSourceReader.open()` method performs an
import-time check and raises `ImportError` with an actionable
install command if kafka-python-ng is missing.

**Why kafka-python-ng, not confluent-kafka:**
`kafka-python-ng` is pure Python (no librdkafka C dependency), which
simplifies installation on all platforms GNAT supports. For
production deployments needing higher throughput, the reader can be
subclassed to swap in confluent-kafka — the consumer interface is
compatible.

## Redis dedup with memory fallback

`RedisDeduplicationCache` uses Redis SET operations for O(1) dedup at
high volume. SHA-256 fingerprints (IOC type + IOC value + sensor ID)
keep the Redis memory footprint bounded at 64 bytes per entry
regardless of IOC length.

**Fallback strategy:** When Redis is unavailable (connection refused,
timeout, or `redis` package not installed), the cache falls back to
an in-memory Python `set`. This means:
- Development and testing work without Redis infrastructure
- Production deployments should provision Redis for cross-process dedup
- The fallback is per-process — two workers won't share the in-memory set

TTL-based expiry (default 24 hours) prevents unbounded growth in Redis.
The memory fallback has no TTL — it grows until the pipeline run ends.

**Alternative considered:** Bloom filter for probabilistic dedup →
rejected because false positives (silently dropping real IOCs) are
worse than the modest memory cost of an exact set. At honeypot scale
(~100K unique IOCs/day), exact dedup in Redis is ~6 MB.

## Sensor schema normalization

Five sensor types are supported, each with a dedicated extractor:

| Type | Primary fields | Key variations handled |
|------|---------------|----------------------|
| `HONEYPOT` | src_ip, dst_ip, dst_port, attack_type | `source_ip` vs `src_ip`, `honeypot_id` vs `sensor_id` |
| `NETFLOW` | src/dst IP+port, bytes, duration | NetFlow v5/v9 field names (`IPV4_SRC_ADDR` vs `src_ip`) |
| `IDS_ALERT` | src/dst IP+port, signature, severity | `alert` vs `signature` |
| `DNS_LOG` | client_ip, query domain, resolved IP | `client_ip` vs `src_ip`, `query` vs `domain` |
| `GENERIC` | src_ip, domain, url, file_hash | Lowest-common-denominator fallback |

All types normalize to a common `SensorEvent` dataclass, which the
mapper consumes type-agnostically. Adding a new sensor type requires
only a new `_extract_*` method in `SensorSchema` — the mapper and
pipeline are unchanged.

## Private IP filtering

The `TelemetryMapper` silently drops RFC 1918 addresses (10.x,
172.16.x, 192.168.x, 127.x) from indicator generation.

**Rationale:** Honeypot destination IPs are typically internal lab
infrastructure, not IOCs. Netflow records contain large volumes of
internal traffic. Creating STIX Indicators for private addresses
would flood the platform with noise. Source IPs from private ranges
are also dropped — a honeypot reporting traffic from 192.168.x
indicates a misconfigured sensor, not a threat.

## CampaignLinker as pipeline transform

`CampaignLinker` implements `__call__(stix_obj) -> stix_obj` so it
can be passed to `IngestPipeline.transform()`. It extracts the IOC
value from the indicator's STIX pattern, looks it up in a pre-built
reverse index (IOC → campaign IDs), and calls
`CampaignService.link_indicator()` for each match.

The index is built lazily on first invocation from
`CampaignService.list(status=ACTIVE)`. This avoids a database query
if no indicators match any campaign.

**Why a transform, not a post-pipeline hook:**
Transforms run inline — each indicator is checked as it flows through
the pipeline. A post-pipeline hook would require materializing all
indicators first and then scanning them, doubling memory usage for
large batches. The transform also means campaign linking is composable
and optional — pipelines without `.transform(linker)` skip it entirely.

→ See: `gnat/ingest/telemetry/`
→ Related: ADR-0004 (Ingestion Framework — SourceReader/RecordMapper contracts)
→ Related: ADR-0015 (Packaging and Extras — optional dependency gating)
→ Related: ADR-0051 (Attribution — CampaignService.link_indicator)

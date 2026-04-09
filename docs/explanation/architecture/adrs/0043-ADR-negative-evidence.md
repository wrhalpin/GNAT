# ADR-0043 — Negative Evidence Tracking (Phase 4C)

**Date:** 2026-04-09  
**Status:** Accepted  
**Deciders:** GNAT Platform Team

---

## Context

When GNAT enriches a STIX observable (e.g. an IP address, a domain, a file
hash) it queries one or more connectors to retrieve additional context.  If a
connector returns no results for a given observable, that **absence of data is
itself intelligence**:

- If VirusTotal has never seen a particular file hash, that is meaningful.
- If CrowdStrike Falcon has no record of a domain, that reduces the likelihood
  that the domain is a known threat actor infrastructure.
- If Recorded Future has no intelligence on an IP address, that is different
  from "we have not checked yet."

Prior to this ADR, GNAT did not record negative results.  Every enrichment
request was treated as if no prior query had been made.  This created two
compounding problems:

### Problem 1: Redundant API calls

The enrichment dispatcher re-queried every connector for every observable on
every pipeline run, regardless of whether the same lookup had already returned
nothing.  In a typical production deployment:

- 10,000 observables × 5 connectors = 50,000 queries per pipeline run
- If 60% of queries return no results, roughly 30,000 of those calls are wasted
  against connectors that already had nothing to say
- Many commercial connectors enforce rate limits (e.g. VirusTotal: 500 requests
  per minute on the free tier); wasted calls exhaust quota that could serve
  novel indicators

### Problem 2: No negative signal in scoring

The `ReasoningEngine` (ADR-0044) scores observables using trust-weighted
evidence.  Without a record of which connectors have been queried and returned
nothing, the engine had no way to apply a **negative penalty** to observables
that multiple reputable connectors have explicitly found unremarkable.  An
observable with zero enrichment hits was treated the same as an observable that
had never been looked up — both received a neutral score rather than the
negative-evidence-adjusted lower score that a "not seen by three connectors"
result warrants.

### Requirements

1. Suppress redundant re-queries within a configurable time window (TTL).
2. Expose the negative result to scoring pipelines as a typed, machine-readable
   object.
3. Require no new database tables or services.
4. Survive process restarts (in-memory caches do not).

---

## Decision

### `NegativeEvidenceRecord` Custom SDO

A new custom STIX Domain Object is defined in
`gnat/stix/sdos/negative_evidence.py`:

```python
@dataclass
class NegativeEvidenceRecord(STIXBase):
    """
    x-gnat-negative-evidence — STIX custom SDO representing a confirmed
    absence of data from a specific connector for a specific observable.

    Stored via the workspace store like any other STIX object; no new
    tables or services required.
    """

    type: str = "x-gnat-negative-evidence"
    schema_version: int = 1

    # The STIX ID of the observable that was queried
    target_ref: str = ""

    # The connector that performed the query and found nothing
    queried_connector: str = ""

    # Suppression window in seconds (default: 1 hour)
    ttl_seconds: int = 3600

    # UTC timestamp of the query that returned no results
    query_timestamp: datetime | None = None
```

#### Key Methods

```python
def is_expired(self) -> bool:
    """
    Returns True if the TTL has elapsed since query_timestamp.
    An expired record does NOT suppress re-querying; a fresh record does.
    """
    if self.query_timestamp is None:
        return True
    elapsed = (datetime.utcnow() - self.query_timestamp).total_seconds()
    return elapsed > self.ttl_seconds

def seconds_remaining(self) -> float:
    """
    Returns the number of seconds before this record expires.
    Returns 0.0 if already expired.
    """
    if self.query_timestamp is None:
        return 0.0
    elapsed = (datetime.utcnow() - self.query_timestamp).total_seconds()
    return max(0.0, self.ttl_seconds - elapsed)
```

### Write Path: Recording a Negative Result

When an enrichment call returns an empty result set, the enrichment dispatcher
calls `NegativeEvidenceStore.record_miss()`:

```python
class NegativeEvidenceStore:
    """
    Thin wrapper around WorkspaceStore for NegativeEvidenceRecord objects.
    """

    def record_miss(
        self,
        target_ref: str,
        connector: str,
        ctx: ExecutionContext,
        ttl_seconds: int = 3600,
    ) -> NegativeEvidenceRecord:
        record = NegativeEvidenceRecord(
            id=f"x-gnat-negative-evidence--{uuid4()}",
            target_ref=target_ref,
            queried_connector=connector,
            ttl_seconds=ttl_seconds,
            query_timestamp=datetime.utcnow(),
        )
        self._store.upsert(record, ctx)
        return record

    def get_fresh(
        self,
        target_ref: str,
        connector: str,
        workspace_id: str,
    ) -> NegativeEvidenceRecord | None:
        """
        Returns an unexpired NegativeEvidenceRecord for the given
        (target_ref, connector) pair, or None if no fresh record exists.
        """
        records = self._store.query(
            type_filter="x-gnat-negative-evidence",
            workspace_id=workspace_id,
            filters={"target_ref": target_ref, "queried_connector": connector},
        )
        for record in records:
            if not record.is_expired():
                return record
        return None
```

### Read Path: Suppressing Redundant Queries

The enrichment dispatcher checks for a fresh negative record before calling
each connector:

```python
# gnat/ingest/enrichment.py
def _enrich_observable(
    self,
    observable: STIXBase,
    connector: BaseClient,
    ctx: ExecutionContext,
) -> list[STIXBase]:
    fresh_negative = self._neg_store.get_fresh(
        target_ref=observable.id,
        connector=type(connector).__module__.split(".")[-2],
        workspace_id=ctx.workspace_id,
    )
    if fresh_negative:
        logger.debug(
            "Skipping %s for %s — negative evidence fresh for %.0fs",
            type(connector).__name__,
            observable.id,
            fresh_negative.seconds_remaining(),
        )
        return []  # suppress API call

    results = connector.enrich(observable, ctx)

    if not results:
        self._neg_store.record_miss(
            target_ref=observable.id,
            connector=type(connector).__module__.split(".")[-2],
            ctx=ctx,
            ttl_seconds=self._ttl_seconds,
        )

    return results
```

### Integration with `ReasoningEngine`

`ReasoningEngine.prioritize()` (ADR-0044) reads fresh `NegativeEvidenceRecord`
objects for each observable and applies a negative penalty to the composite
score:

```python
# In ReasoningEngine._score_observable()
fresh_negatives = self._neg_store.query_fresh_count(
    target_ref=observable.id,
    workspace_id=ctx.workspace_id,
)
neg_penalty = min(0.3 * fresh_negatives, 0.6)
```

**Negative penalty table:**

| Fresh Negative Records | Penalty Applied |
|------------------------|-----------------|
| 0 | 0.0 |
| 1 | 0.3 |
| 2 | 0.6 (capped) |
| 3+ | 0.6 (capped) |

The cap at 0.6 ensures that even an observable with many negative hits retains
a non-zero score in case a trust-weighted positive hit arrives later.

### TTL Configuration

TTL defaults to 3600 seconds (1 hour) but is configurable per deployment in
the INI file:

```ini
[enrichment]
negative_evidence_ttl = 3600    ; seconds; default 1 hour
```

Connectors that update more slowly (e.g. threat intelligence databases that
publish weekly) may benefit from a longer TTL (e.g. 86400 seconds) configured
at the connector level:

```python
class ShadowserverClient(BaseClient):
    NEGATIVE_EVIDENCE_TTL: int = 86400  # 24 hours — weekly update cadence
```

`NegativeEvidenceStore.record_miss()` reads `NEGATIVE_EVIDENCE_TTL` from the
connector class when present, falling back to the INI-configured default.

---

## Consequences

### Positive

- **Quota preservation:** redundant queries are suppressed within the TTL
  window, directly reducing API call volume.  In a deployment with 10,000
  observables and 60% miss rate, suppression across a 1-hour window reduces
  repeat calls from 30,000 to near-zero during replays and subsequent runs.
- **Richer scoring:** the `ReasoningEngine` can now distinguish between
  "unknown" and "confirmed not seen by N connectors," producing lower scores for
  observables that multiple reputable connectors have explicitly found
  unremarkable.
- **Persistence across restarts:** `NegativeEvidenceRecord` is stored in the
  workspace like any other STIX object; suppression survives process restarts,
  unlike an in-memory cache.
- **Zero new infrastructure:** no new tables, queues, message brokers, or
  caching services are required.  The existing workspace store handles
  persistence; the existing query interface handles retrieval.
- **First-class STIX object:** negative evidence is exportable as part of a
  STIX bundle, shareable between workspaces, and auditable via the lineage
  tracker (ADR-0038).

### Negative / Trade-offs

- **Workspace store growth:** every enrichment miss creates a
  `NegativeEvidenceRecord` object.  A deployment with 10,000 observables
  queried against 5 connectors creates up to 50,000 records per TTL window.
  A cleanup job (see Deferred) is needed to purge expired records.
- **TTL is a blunt instrument:** a 1-hour TTL is appropriate for live threat
  feeds but too short for weekly-updated databases and too long for real-time
  feeds that update every minute.  The per-connector `NEGATIVE_EVIDENCE_TTL`
  class variable partially addresses this, but it requires connector authors to
  reason about update cadence.
- **No invalidation on connector update:** if a connector's data is known to
  have been refreshed (e.g. the operator manually triggers a full re-sync), the
  TTL-based suppression cannot be invalidated without deleting all matching
  `NegativeEvidenceRecord` objects.  Manual invalidation is not yet tooled.
- **False negative suppression:** if a connector initially returns no results
  but adds the indicator to its database within the TTL window, GNAT will not
  re-query until the TTL expires, missing the new data.

### Deferred

- **Expired record cleanup job:** a scheduled `NegativeEvidencePurgeJob` that
  deletes `NegativeEvidenceRecord` objects whose TTL has elapsed, preventing
  unbounded workspace store growth.
- **Per-observable TTL override:** allow analysts to set a shorter TTL on
  high-priority observables that should be re-queried more aggressively.
- **Manual invalidation API:** `gnat enrich invalidate-negative <stix_id>` CLI
  command to force re-querying by deleting all matching negative records.
- **Sharing across workspaces:** allow a negative evidence record in one
  workspace to suppress queries in a sibling workspace, reducing redundant calls
  in multi-tenant deployments.

---

## Alternatives Considered

### In-memory LRU cache

An in-process `functools.lru_cache` or `cachetools.TTLCache` keyed on
`(observable_id, connector_name)` was the simplest implementation.  Rejected
because:

1. **Lost on restart:** a cache flush caused by a container restart or worker
   crash would cause all missed queries to be re-issued, negating the quota
   savings on the very occasions when pipelines are most likely to be
   re-run (crash recovery).
2. **Not shared across workers:** in a multi-worker deployment each worker
   maintains an independent cache; a negative result learned by Worker A is not
   known to Worker B.
3. **Not auditable:** the `ReasoningEngine` cannot query an in-memory cache for
   the negative penalty calculation without tight coupling between the scoring
   engine and the enrichment dispatcher's runtime state.

### Connector-side rate limiting

Relying on each connector's own rate limiter to prevent redundant calls was
considered.  Rejected because:

1. Rate limiters enforce a maximum call *rate*, not a minimum interval between
   identical calls.  A rate limiter allows 500 calls/minute but does not prevent
   querying the same observable 500 times in a minute.
2. Rate limiters are applied globally per connector, not per observable.  They
   do not suppress re-querying a specific observable that already returned no
   results.
3. Rate limiters do not expose negative signal to the scoring pipeline.

### Extending `EnrichmentLogModel`

The existing `EnrichmentLogModel` (which records enrichment operations) could
have been extended with a `result_count: int` column so that a query returning
0 results is distinguishable from one not yet performed.

Rejected because:

1. `EnrichmentLogModel` is an append-only audit log, not a queryable state
   store; answering "is there a fresh negative result for (X, connector)?"
   would require a `MAX(timestamp)` query with a join, adding complexity.
2. `EnrichmentLogModel` is not a STIX object and is therefore not shareable via
   STIX bundles or exportable to partner workspaces.
3. The existing lineage event model (ADR-0038) serves the audit function;
   negative evidence requires a separate, queryable state representation.

---

*Licensed under the Apache License, Version 2.0*

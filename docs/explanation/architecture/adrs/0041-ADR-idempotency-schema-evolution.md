# ADR-0041 — Idempotency and ORM Schema Versioning

**Date:** 2026-04-09  
**Status:** Accepted  
**Deciders:** GNAT Platform Team

---

## Context

### The Replay Problem

GNAT pipelines are long-running processes that may be interrupted mid-flight:
network partitions, database deadlocks, container restarts, and operator
`SIGINT` are all common causes.  When a pipeline is restarted, it must be safe
to replay from the beginning without producing:

- **Duplicate STIX objects** in the workspace store (violating the uniqueness
  contract of STIX IDs per platform).
- **Double SOAR triggers** (sending the same alert to a SOAR platform twice).
- **Duplicate enrichment calls** (wasting API quota on already-processed
  indicators).

Prior to this ADR, GNAT had no pipeline-level idempotency mechanism.  Connector
code performed ad-hoc checks ("does this STIX ID already exist?") but these
were inconsistent and did not cover all write paths.  A crashed ingest run that
had completed 800 of 1,000 records before failing would, on restart, attempt to
re-process all 1,000 records and fail on uniqueness constraints in the ORM
layer.

### The Schema Evolution Problem

The STIX 2.1 ORM (ADR-0031, ADR-0032) uses a property-bag pattern:
`STIXBase._properties` stores all non-core fields as an untyped dict.  When a
breaking change is made to a field (e.g. `threat_score: float` renamed to
`confidence: float`, or a field's semantics change such that old serialised
values are incorrect), there is no mechanism to detect that persisted objects
were produced by an older version of the ORM and need migration.

Two independent deployment scenarios require schema versioning:

1. **Rolling upgrades:** a GNAT worker is upgraded to a new version while the
   workspace database still contains objects serialised by the previous version.
2. **Test isolation:** fixture factories in `tests/` need to produce objects that
   match the current schema without coupling to specific field values.

---

## Decision

### Part 1: Idempotency Keys

#### Key Format

Every write to the workspace store is gated by an idempotency key computed
by `WorkspaceStore.make_idempotency_key()`:

```
{connector_id}:{stix_type}:{external_id}:{sha1_content_hash[:12]}
```

- **`connector_id`** — the connector's module name (e.g. `crowdstrike`,
  `alienvault`).  Scopes the key to a source; the same external ID from two
  different connectors does not collide.
- **`stix_type`** — the STIX object type string (e.g. `indicator`,
  `threat-actor`).
- **`external_id`** — the platform-native identifier for the object (e.g. a
  ThreatQ indicator ID, a CrowdStrike IOC value).  If unavailable, the STIX
  `id` field is used.
- **`sha1_content_hash[:12]`** — first 12 hex characters of the SHA-1 digest of
  the object's canonical JSON representation (keys sorted, no whitespace).
  Detects content changes even when the external ID is stable.

```python
import hashlib, json

def make_idempotency_key(
    connector_id: str,
    stix_obj: STIXBase,
    external_id: str | None = None,
) -> str:
    ext = external_id or stix_obj.id
    payload = json.dumps(stix_obj.to_dict(), sort_keys=True, separators=(",", ":"))
    content_hash = hashlib.sha1(payload.encode()).hexdigest()[:12]
    return f"{connector_id}:{stix_obj.type}:{ext}:{content_hash}"
```

#### Database Storage

The idempotency key is stored as a `VARCHAR(255)` column on the
`workspace_objects` table, introduced via Alembic migration
`0005_add_idempotency_key.py`:

```sql
ALTER TABLE workspace_objects
  ADD COLUMN idempotency_key VARCHAR(255);

CREATE UNIQUE INDEX uix_workspace_objects_idempotency
  ON workspace_objects (workspace_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;
```

The partial unique index (`WHERE idempotency_key IS NOT NULL`) ensures that
objects written by code paths that pre-date this ADR (which will have
`NULL` keys) are not incorrectly flagged as duplicates.

#### Write Path

`WorkspaceStore.upsert()` now follows this sequence:

```python
def upsert(
    self,
    stix_obj: STIXBase,
    ctx: ExecutionContext,
    external_id: str | None = None,
) -> UpsertResult:
    key = make_idempotency_key(ctx.initiated_by, stix_obj, external_id)
    existing = self._session.query(WorkspaceObjectModel)\
        .filter_by(workspace_id=ctx.workspace_id, idempotency_key=key)\
        .first()

    if existing:
        _log_to_execution_log(ctx, event_type="idempotent_skip", key=key)
        return UpsertResult(skipped=True, object_id=existing.stix_id)

    # ... proceed with INSERT ...
    return UpsertResult(skipped=False, object_id=stix_obj.id)
```

`UpsertResult` is a small dataclass with `skipped: bool` and `object_id: str`.
Callers that need to distinguish new writes from idempotent skips (e.g. pipeline
progress reporters) can inspect `result.skipped`.

#### Replay Integration

When `ExecutionContext.is_replay` is `True`, idempotent skips are still
performed (preventing duplicate writes) but the skip is recorded with
`event_type="replay_skip"` in `execution_log` rather than
`"idempotent_skip"`.  This allows operators to distinguish between "normal
deduplication" and "replay recovery" in audit queries:

```sql
-- Count objects successfully replayed vs. newly written
SELECT event_type, COUNT(*) FROM execution_log
WHERE context_id = :replay_context_id
GROUP BY event_type;
```

SOAR triggers and external webhook emissions are suppressed when
`ctx.is_replay` is `True`, regardless of whether the write was skipped.

### Part 2: ORM Schema Versioning

#### `schema_version` Class Variable

`STIXBase` gains a class variable:

```python
class STIXBase:
    """Base class for all GNAT STIX ORM objects."""

    schema_version: int = 1
    """
    Monotonically increasing integer.  Increment only on breaking field changes.
    Additive changes (new optional fields) do not require a bump.
    """
```

Subclasses override `schema_version` when they introduce a breaking change:

```python
class STIXIndicator(STIXBase):
    schema_version: int = 2  # bumped when 'threat_score' was renamed 'confidence'
```

#### Serialisation

`STIXBase.to_dict()` includes `schema_version` in its output:

```python
def to_dict(self) -> dict:
    return {
        "type": self.type,
        "id": self.id,
        "schema_version": self.schema_version,
        **self._properties,
    }
```

#### Deserialisation and Migration

`STIXBase.from_dict()` reads the `schema_version` from the serialised payload
and, if it differs from the current class's `schema_version`, invokes the
registered migration chain:

```python
@classmethod
def from_dict(cls, data: dict) -> "STIXBase":
    stored_version = data.get("schema_version", 1)
    current_version = cls.schema_version
    if stored_version < current_version:
        data = _apply_migrations(cls, data, stored_version, current_version)
    obj = cls.__new__(cls)
    # ... populate fields from data ...
    return obj
```

Migration functions are registered per class in
`gnat/orm/migrations.py` using a simple decorator:

```python
@schema_migration(STIXIndicator, from_version=1, to_version=2)
def _migrate_indicator_v1_to_v2(data: dict) -> dict:
    # Rename 'threat_score' to 'confidence'
    if "threat_score" in data:
        data["confidence"] = data.pop("threat_score")
    return data
```

#### Version Bump Policy

| Change type | Version bump? |
|-------------|---------------|
| Add a new optional field | No |
| Add a new required field with a default value | No |
| Remove a field | Yes |
| Rename a field | Yes |
| Change a field's type or semantics | Yes |
| Add a new method (no field impact) | No |

This policy keeps the version number low and stable for the common additive
case while ensuring that breaking changes are detectable.

---

## Consequences

### Positive

- **Pipelines are fully idempotent:** restarting a crashed ingest job from the
  beginning is safe; already-written objects are skipped cleanly without
  database constraint violations or duplicate STIX IDs.
- **Replay is auditable:** `execution_log` records `replay_skip` events
  separately from normal `idempotent_skip` events, enabling operators to measure
  recovery completeness.
- **SOAR trigger safety:** `is_replay` suppression prevents double-alerting
  even when a replay re-processes objects that were already written in a prior
  partial run.
- **Schema evolution is controlled:** `schema_version` makes breaking field
  changes detectable and migrateable; additive changes do not require a bump,
  keeping the version number stable for routine development.
- **No new storage tables:** idempotency keys are a column on the existing
  `workspace_objects` table; schema versions are serialised into the existing
  JSON payload.  No additional infrastructure is required.

### Negative / Trade-offs

- **Key computation cost:** SHA-1 of the canonical JSON is computed on every
  write, adding ~0.1 ms per object on a typical developer machine.  At 10,000
  objects per ingest run this is ~1 second, acceptable for the safety guarantee.
- **Partial index coverage:** objects written before migration `0005` have
  `NULL` idempotency keys and are not protected by idempotency.  A backfill job
  can populate keys for existing objects but is not automated.
- **Migration chain maintenance:** as `schema_version` grows, the migration
  chain from version 1 to the current version must be maintained.  A test in
  `tests/unit/orm/test_schema_migrations.py` validates every registered
  migration in sequence.
- **Content-hash sensitivity:** if two connectors produce the same indicator
  with different metadata (e.g. different `labels` lists), the content hash
  differs and both are stored as distinct objects.  This is correct behaviour
  but may surprise operators who expect connector-level deduplication.

### Deferred

- **Backfill job** for populating idempotency keys on pre-migration objects.
- **Key expiry policy:** idempotency keys for objects deleted from the workspace
  should be cleaned up to prevent key exhaustion in very long-running
  deployments.
- **Cross-workspace deduplication:** the current scheme deduplicates within a
  single `workspace_id`; cross-workspace deduplication (e.g. between a staging
  and production workspace) is out of scope.
- **ORM migration CLI command:** `gnat orm migrate --dry-run` to preview
  pending migrations before a deployment.

---

## Alternatives Considered

### Content-addressed storage (STIX ID as primary key)

STIX IDs are already unique per platform: a STIX indicator with a given ID from
CrowdStrike is always the same logical object.  Using the STIX ID as the sole
uniqueness key was considered as an alternative to a separate idempotency key.

Rejected because:

1. The same logical indicator can arrive from multiple connectors with different
   STIX IDs (each connector may assign its own UUID-based ID) but the same
   content.  STIX ID uniqueness does not prevent cross-connector duplicates.
2. STIX IDs do not capture content changes: a connector may reassign the same
   ID to an updated indicator.  The content hash component of the idempotency
   key detects this case and allows the update through.

### Alembic-only schema versioning

Using Alembic migrations exclusively to manage ORM field changes was considered.
Alembic tracks database schema changes (table columns, indexes) but does not
address ORM-level field renames or semantic changes that are expressed in the
JSON property bag.  Alembic is still used for database schema changes
(migration `0005`); `schema_version` complements it by covering the ORM object
layer that Alembic cannot reach.

### Event sourcing for idempotency

An event-sourced store where every write is an event and idempotency is
guaranteed by event log position was considered.  Rejected because it would
require a fundamental redesign of the workspace store and all connectors,
displacing the existing `workspace_objects` table and the established connector
contract (ADR-0031).  Event sourcing remains a long-term architectural option
if GNAT grows to require it.

---

*Licensed under the Apache License, Version 2.0*

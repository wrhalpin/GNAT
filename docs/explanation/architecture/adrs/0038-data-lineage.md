# ADR-0038 — Data Lineage Tracking

**Date:** 2026-04-08  
**Status:** Accepted  
**Deciders:** GNAT Platform Team

---

## Context

GNAT's existing `EnrichmentLogModel` records enrichment operations but does
not cover ingestion, export, reporting, or inter-object linking.  Enterprise
operators need a cross-cutting audit trail that answers:

- "Where did this indicator come from?"
- "When was this report exported, and by whom?"
- "Has this object been normalised or modified since ingest?"
- "Which analyst linked this indicator to the investigation?"

Without cross-cutting lineage, GNAT cannot answer these questions from a
single source of truth.

---

## Decision

Add an **append-only lineage event log** as a thin cross-cutting concern:

### LineageEventType

Seven event types covering the full object lifecycle:

| Type | Trigger |
|------|---------|
| `INGESTED`   | Object first arrives from a connector |
| `ENRICHED`   | Enrichment dispatcher processes the object |
| `NORMALIZED` | Mapper normalises raw data to STIX |
| `LINKED`     | Object linked to an investigation |
| `EXPORTED`   | Object exported (STIX bundle, PDF, etc.) |
| `REPORTED`   | Object included in a published report |
| `DELETED`    | Object soft-deleted |

### LineageEvent (dataclass)

Immutable record: `id` (UUID4), `event_type`, `object_id` (STIX ID),
`object_type`, `actor`, `source`, `timestamp` (UTC), `metadata` (dict).

### LineageStore (SQLAlchemy)

- Table: `lineage_events` (append-only; no `is_deleted` column)
- Composite index on `(object_id, timestamp)` for object-timeline queries
- Methods: `append(event)`, `query(object_id)`, `query_by_type(event_type)`,
  `query_by_actor(actor)`, `count(event_type=None)`
- `create_all()` kept for test isolation; production uses Alembic migration
  `0002_add_lineage_events.py`

### LineageTracker

Convenience wrapper with one `record_*` method per event type.  Accepts
`store=None` for a no-op mode (safe in tests and optional deployments).
Exceptions during persistence are caught and logged — lineage failure never
propagates to callers.

### Integration points

- `gnat.dissemination.export` — emit `EXPORTED` after successful export
- `gnat.reporting.service` — emit `REPORTED` on `publish()`
- `gnat.analysis.investigations.service` — emit `LINKED` on link operations

---

## Consequences

### Positive

- **Traceability:** complete object history queryable by ID
- **Audit compliance:** immutable append-only log satisfies data residency requirements
- **No breaking changes:** lineage is emitted optionally; existing code paths are unchanged
- **Lightweight:** single SQLAlchemy table, zero new runtime dependencies

### Negative / Trade-offs

- **No real-time streaming:** lineage is async (fire-and-forget) — not suitable
  for real-time compliance hooks without an additional event bus
- **In-process only:** cross-service lineage (e.g. from an external TAXII
  consumer) requires a shared database

### Deferred

- Lineage graph visualisation in the TUI/dashboard
- Cross-service lineage via HookBus `api_request` events
- Lineage retention and archival policies

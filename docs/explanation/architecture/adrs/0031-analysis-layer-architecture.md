# ADR-0031: Analysis Layer Architecture

**Decision:** Implement three distinct analyst-facing modules —
`gnat.analysis`, `gnat.reporting`, and `gnat.dissemination` — as
consumers of the existing storage layer. No new storage backend is
introduced at this stage.

**Problem statement:**
GNAT fully covers the bottom half of the CTI lifecycle (Collection →
Processing → Storage) but has no analyst-facing layer. Intelligence
products (investigations, reports) live entirely outside the platform.
This forces analysts to maintain parallel systems and breaks provenance
from raw indicator to finished intelligence.

**Layered consumer model:**
The three new modules sit above the existing storage layer and do not
replace or bypass the ingestion pipeline:

```
[Connectors] → [Ingestion] → [Storage: Postgres + Solr]
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
              [Analysis]      [Reporting]    [Dissemination]
```

Each layer reads from storage; only `gnat.analysis` and `gnat.reporting`
write new objects (Investigation, Report) back to Postgres.

**Why not a separate analysis database:**
A separate graph or document database would introduce operational
overhead (new service, backup strategy, replication) for data that is
structurally similar to the STIX property-bag objects already in Postgres.
The `WorkspaceStore` SQLAlchemy pattern (serialize-to-JSON + indexed
metadata columns) is sufficient for Investigation and Report objects.
Revisit if graph traversal depth or full-text search requirements
exceed Postgres + Solr capabilities.

**Module boundaries:**

| Module | Responsibility | Writes to |
|--------|---------------|-----------|
| `gnat.analysis` | Investigation objects, correlation, confidence scoring, timeline | `analysis_*` tables |
| `gnat.reporting` | Report lifecycle, evidence binding, STIX serialization | `report_*` tables |
| `gnat.dissemination` | STIX bundle export, TAXII server, webhooks | Read-only (exports) |

**Persistence strategy:**
Follows the established `WorkspaceStore` pattern:
- SQLAlchemy declarative models with `create_all()` (no Alembic)
- Core dataclasses are pure Python — zero SQLAlchemy dependency in models
- Repository classes handle SQLAlchemy session lifecycle
- Objects serialized as JSON in `_json` text column + indexed metadata
  columns for efficient lookup

**Dependencies:**
- Core models: zero new dependencies
- Storage: `sqlalchemy>=2.0` (already in `[persist]` extra)
- STIX export: zero (uses existing ORM)
- TAXII server: `taxii2-server` (Phase 4, new `[taxii-server]` extra)

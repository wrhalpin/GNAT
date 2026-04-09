# ADR-0039 — Unified Execution Context

**Date:** 2026-04-09  
**Status:** Accepted  
**Deciders:** GNAT Platform Team

---

## Context

GNAT orchestrates a heterogeneous set of operations: ingestion pipeline runs,
connector enrichment calls, AI agent actions, export jobs, and report
publishing.  Each of these operations executes independently and, prior to
this ADR, had no mechanism to:

1. Establish **who** initiated the operation (a named connector, an agent
   identifier, or a human operator via the CLI).
2. Declare **which domain** the operation belongs to (`ingestion`, `analysis`,
   `investigation`, `reporting`, `execution`).
3. Carry a **trust level** that flows from the originating data source into
   downstream scoring and policy decisions.
4. Enforce **workspace isolation** — preventing an ingestion job from one
   tenant from accidentally writing objects into another tenant's workspace.
5. Record a **replay flag** so that a re-run of a crashed pipeline can suppress
   side effects (SOAR triggers, webhook emissions, duplicate enrichment calls).
6. Impose a **query budget** to prevent runaway agent loops from exhausting
   API quota or compute time.

Without a unifying carrier object, each component invented its own partial
solution: pipeline runners passed `workspace_id` as a bare string; the
enrichment dispatcher read `TRUST_LEVEL` from the connector class but did not
propagate it; agents tracked their own call counters in local state; replay
detection was entirely absent.

The result was a system that was difficult to trace, impossible to replay
safely, and unable to enforce trust-aware prioritisation consistently.

---

## Decision

Introduce `ExecutionContext` — a lightweight, immutable dataclass that every
pipeline entry point creates at startup and passes through the call chain.

### Location

`gnat/core/context.py`

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `context_id` | `UUID` | Unique identifier for this execution; used as correlation ID in logs and the `execution_log` table |
| `initiated_by` | `str` | Connector name, agent ID, or `"manual"` (CLI/TUI) |
| `domain` | `str` | One of `ingestion`, `analysis`, `investigation`, `reporting`, `execution` |
| `trust_level` | `str` | `trusted_internal`, `semi_trusted`, or `untrusted_external` |
| `policy_set` | `str \| None` | Named policy set applied to this context; `None` uses the default |
| `workspace_id` | `str` | Workspace isolation boundary; all writes are scoped to this ID |
| `created_at` | `datetime` | UTC timestamp at construction time |
| `parent_context_id` | `UUID \| None` | ID of the parent context when this is a child span |
| `is_replay` | `bool` | `True` suppresses SOAR triggers and idempotent write skip logging |
| `budget` | `QueryBudget \| None` | Optional call budget; `None` means unlimited |

`QueryBudget` is a small companion dataclass:

```python
@dataclass
class QueryBudget:
    max_connector_calls: int = 50
    max_agent_tokens: int = 100_000
    _connector_calls: int = field(default=0, repr=False)
    _agent_tokens: int = field(default=0, repr=False)

    def charge_connector(self, n: int = 1) -> None:
        self._connector_calls += n
        if self._connector_calls > self.max_connector_calls:
            raise BudgetExceededError("connector call budget exhausted")

    def charge_tokens(self, n: int) -> None:
        self._agent_tokens += n
        if self._agent_tokens > self.max_agent_tokens:
            raise BudgetExceededError("agent token budget exhausted")
```

### Factory Methods

**`ExecutionContext.create()`** — default factory for manual / CLI invocations:

```python
ctx = ExecutionContext.create(
    initiated_by="manual",
    domain="ingestion",
    workspace_id="default",
)
```

**`ExecutionContext.from_connector(connector)`** — reads `TRUST_LEVEL` from
the connector class variable and sets `initiated_by` to the connector's module
name:

```python
ctx = ExecutionContext.from_connector(
    connector=crowdstrike_client,
    domain="ingestion",
    workspace_id=workspace_id,
)
# ctx.trust_level == "semi_trusted"
# ctx.initiated_by == "crowdstrike"
```

**`ExecutionContext.child()`** — derives a child context that inherits
`workspace_id`, `trust_level`, and `budget` from the parent but receives a
new `context_id` and `parent_context_id`:

```python
child_ctx = ctx.child(domain="analysis", initiated_by="reasoning_engine")
assert child_ctx.workspace_id == ctx.workspace_id
assert child_ctx.parent_context_id == ctx.context_id
assert child_ctx.context_id != ctx.context_id
```

### Persistence

Every context is persisted to the `execution_log` table (introduced in Alembic
migration `0004_add_execution_log.py`):

| Column | Type | Notes |
|--------|------|-------|
| `id` | `UUID` | Primary key; maps to `context_id` |
| `initiated_by` | `VARCHAR(255)` | |
| `domain` | `VARCHAR(64)` | |
| `trust_level` | `VARCHAR(64)` | |
| `workspace_id` | `VARCHAR(255)` | Indexed |
| `parent_context_id` | `UUID` | Nullable; foreign key to same table |
| `is_replay` | `BOOLEAN` | |
| `created_at` | `TIMESTAMP` | UTC |
| `event_type` | `VARCHAR(64)` | `context_start`, `context_end`, `security_event` |
| `metadata` | `TEXT` | JSON-encoded supplementary data |

Trust escalation attempts (a caller supplying a higher trust level than its
connector class declares) are detected in `from_connector()` and written as
`security_event` rows in `execution_log`.

### Integration Points

All pipeline entry points create a context at startup:

```python
# gnat/ingest/pipeline.py
class IngestPipeline:
    def run(self, workspace_id: str, connector) -> IngestResult:
        ctx = ExecutionContext.from_connector(connector, domain="ingestion",
                                              workspace_id=workspace_id)
        self._ctx_store.persist(ctx)
        # ... pipeline body passes ctx through ...
```

```python
# gnat/export/pipeline.py
class ExportPipeline:
    def run(self, workspace_id: str) -> ExportResult:
        ctx = ExecutionContext.create(initiated_by="manual",
                                      domain="reporting",
                                      workspace_id=workspace_id)
        self._ctx_store.persist(ctx)
```

Agent actions use `child()` to preserve the parent trace:

```python
# gnat/agents/research.py
class ResearchAgent:
    def run(self, parent_ctx: ExecutionContext, query: str):
        ctx = parent_ctx.child(domain="analysis", initiated_by=self.agent_id)
        self._ctx_store.persist(ctx)
```

---

## Consequences

### Positive

- **Full traceability:** every operation, regardless of component, carries a
  correlation ID linkable back to a parent chain in `execution_log`.
- **Replay safety:** `is_replay=True` allows pipeline runners to re-run a
  crashed job without firing SOAR triggers or creating duplicate enrichment
  side effects.
- **Trust propagation:** `trust_level` flows from connector declaration through
  the pipeline to `ReasoningEngine` scoring without any caller needing to
  re-derive it.
- **Parent-child trace trees:** nested operations (agent spawning a connector
  call) produce traceable parent-child trees queryable from `execution_log`.
- **Budget enforcement:** `QueryBudget` prevents agent runaway without
  requiring each connector to implement its own call counter.
- **Zero new runtime dependencies:** `ExecutionContext` is a plain Python
  dataclass; persistence uses the existing SQLAlchemy `[persist]` extra.

### Negative / Trade-offs

- **Caller discipline required:** every pipeline entry point must remember to
  create and thread through the context; there is no automatic injection.
  Connectors called directly (outside a pipeline) will not have a context
  unless they construct one manually.
- **Database write on every operation:** persisting context to `execution_log`
  adds one `INSERT` per pipeline run.  High-frequency enrichment loops may
  produce large log volumes; a retention policy is needed.
- **Replay flag is advisory:** `is_replay=True` suppresses SOAR triggers only
  in GNAT-internal components.  External webhooks reached before the context
  was consulted are not automatically suppressed.

### Deferred

- Automatic context injection via a Python contextvars carrier (removes caller
  discipline requirement for async code paths).
- Streaming context events to an external observability backend (OpenTelemetry
  trace export).
- `execution_log` retention and archival policies.
- Budget accounting UI in the TUI dashboard.

---

## Alternatives Considered

### Thread-local context

Storing the current `ExecutionContext` in a `threading.local()` variable would
remove the need to pass it through every call site.  Rejected because GNAT
supports both sync (`urllib3`) and async (`httpx`) code paths.
`threading.local()` is invisible to `asyncio` tasks, so async connectors
launched in the same event loop but different coroutines would silently inherit
the wrong context or lose it entirely.

### Decorator injection (`@with_context`)

A class decorator that automatically wraps `authenticate()`, `get_object()`,
etc. with context creation was prototyped.  Rejected because:
1. It couples the decorator to the connector lifecycle, making it hard to use
   `ExecutionContext` in non-connector code (agents, pipelines).
2. It hides context creation from the caller, making replay control (setting
   `is_replay=True`) harder to express.
3. It does not support `child()` semantics where a parent context already
   exists.

### OpenTelemetry `Span` as the carrier

Using `opentelemetry.trace.Span` directly as the execution carrier was
considered.  Rejected because it would add a mandatory dependency on the
`opentelemetry-api` package for every GNAT installation, even those that do
not export traces.  `ExecutionContext` is a thin, dependency-free dataclass;
OTel integration can be layered on top as a future extra.

---

*Licensed under the Apache License, Version 2.0*

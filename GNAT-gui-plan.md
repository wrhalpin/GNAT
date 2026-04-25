# GNAT Core Changes Plan

**Repo:** `wrhalpin/GNAT`
**Companion plan:** `gnat_gui_repo_plan.md`
**Status:** Draft for review
**Owner:** @wrhalpin

-----

## Purpose

The new `GNAT-gui` web app (separate repo) imports `gnat` as a library and exposes the Analysis, Rules Builder, and Investigations modules through a FastAPI backend with a React frontend. This plan covers the changes required in GNAT core to make the web app cleanly possible without leaking UI concerns into the core domain.

The goal throughout: keep GNAT a usable Python library with CLI, TUI, and REST surfaces unchanged. UI-specific concerns live in `GNAT-gui`. Core only gains capabilities that are also useful to other consumers — other Python clients, future CLI improvements, automation playbooks, third-party integrations.

-----

## Guiding Principles

1. **No UI concerns in core.** No HTML, no CSS, no JS, no view models, no session handling, no auth state. Core stays headless.
1. **Schema parity.** Every analysis, investigations, and reporting domain object has a Pydantic v2 schema export. The web app and any future API consumer share these.
1. **Service wrappers, not service rewrites.** New analyst service modules are thin coordinators over existing code. Existing services keep working unchanged.
1. **Async progress, not silent waits.** Long-running operations (graph builds, LLM gap detection, report drafting) emit progress events through a job framework. Sync APIs remain available for CLI use.
1. **Backwards compatible.** No breaking changes to existing public APIs. New surface is additive. Existing 5,100+ tests must keep passing.
1. **Feature flagged where it matters.** New capabilities ship behind config flags so existing deployments are unaffected until they opt in.
1. **Optional dependencies stay optional.** New imports go under appropriate extras (`[gui]` or extending existing extras), never forced into the core install.

-----

## Scope of Changes

Four work streams, sequenced. Each ships independently — the web app does not need all four to start, but all four are confirmed in scope.

|Stream                     |New code                          |Risk  |GUI dependency                              |
|---------------------------|----------------------------------|------|--------------------------------------------|
|1. Pydantic schema exports |`gnat/schemas/`                   |Low   |Required for v0                             |
|2. Analyst service wrappers|`gnat/analyst_services/`          |Low   |Required for v0                             |
|3. Job framework           |`gnat/jobs/`                      |Medium|Required for LLM features (M4)              |
|4. Streaming/SSE hooks     |additions in 1–3 + core call sites|Medium|Required for graph builder (M3) and LLM (M4)|

Estimated total effort: 4–6 weeks of GNAT core work, parallelizable with GNAT-gui M0–M2.

-----

## Stream 1: Pydantic Schema Exports

### Why

The web app needs typed contracts for every domain object it touches. FastAPI auto-generates OpenAPI from Pydantic models, and the frontend generates TypeScript types from that OpenAPI document. Without schemas in core, the web app would re-implement them and they would drift over time.

Pydantic v2 schemas in core also help the existing REST gateway (`gnat/dissemination/api/`) and future API consumers — no UI lock-in. They are useful in their own right as a documentation/typing layer over the existing dataclass/SQLAlchemy mix.

### Scope

New top-level package `gnat/schemas/` mirroring the domain layout:

```
gnat/schemas/
├── __init__.py              # Public re-exports
├── analysis/
│   ├── __init__.py
│   ├── confidence.py        # ConfidenceScoreSchema (Admiralty + numeric)
│   ├── tlp.py               # TLPLevelSchema
│   ├── investigation.py     # InvestigationSchema, HypothesisSchema, AnalystNoteSchema, InvestigationTaskSchema
│   ├── correlation.py       # ClusterSchema, CorrelationEdgeSchema, EntityResolutionSchema
│   ├── timeline.py          # TimelineEventSchema, TimelineSchema
│   ├── graph.py             # GraphQuerySchema, GraphResultSchema
│   └── copilot.py           # GapAnalysisSchema, ReportDraftSchema
├── investigations/
│   ├── __init__.py
│   ├── seed.py              # SeedSchema, SeedTypeEnum
│   ├── graph.py             # EvidenceGraphSchema, EvidenceNodeSchema, EvidenceEdgeSchema
│   └── builder.py           # InvestigationBuildRequestSchema, InvestigationBuildResultSchema
├── reporting/
│   ├── __init__.py
│   ├── report.py            # ReportSchema, ReportSectionSchema, FindingSchema, EvidenceLinkSchema, AttributionSchema
│   └── lifecycle.py         # ReportStateEnum, StateTransitionSchema
├── rules/
│   ├── __init__.py
│   ├── rule.py              # RuleSchema (engine-agnostic), RuleEngineEnum, RuleScopeEnum
│   ├── audit.py             # RuleAuditEntrySchema, RuleEvaluationResultSchema
│   └── predicates.py        # HelperPredicateSchema (for the 26 helpers)
└── stix/
    ├── __init__.py
    └── observables.py       # Pydantic mirrors of STIX 2.1 ORM types for API exposure
```

### Implementation pattern

Each schema is a Pydantic v2 `BaseModel` with:

- Field types matching the dataclass/ORM source of truth
- `model_config = ConfigDict(from_attributes=True)` so it can hydrate from existing dataclasses or SQLAlchemy rows
- Round-trip helpers: `from_domain(obj)` and `to_domain()` where the conversion is non-trivial
- Explicit `Field()` declarations with descriptions (these become OpenAPI docs and TypeScript JSDoc comments)
- Discriminated unions for polymorphic types (e.g. seed types, evidence node types)

Example (illustrative):

```python
# gnat/schemas/analysis/investigation.py
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime
from typing import Literal

class InvestigationSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Unique investigation identifier")
    title: str
    status: Literal["OPEN", "IN_PROGRESS", "REVIEW", "CLOSED"]
    created_at: datetime
    updated_at: datetime
    owner: str = Field(..., description="Username or service principal")
    tlp: TLPLevelSchema
    hypotheses: list[HypothesisSchema] = Field(default_factory=list)
    notes: list[AnalystNoteSchema] = Field(default_factory=list)
    tasks: list[InvestigationTaskSchema] = Field(default_factory=list)

    @classmethod
    def from_domain(cls, inv: "Investigation") -> "InvestigationSchema":
        return cls.model_validate(inv)
```

### Tests

- One test file per schema module
- Round-trip tests: domain object → schema → JSON → schema → domain object equality
- Validation tests: malformed inputs raise expected `ValidationError`
- Snapshot tests: JSON schema output is stable across versions (regression guard)
- Compatibility tests: existing `to_dict()` / `from_dict()` methods on ORM types still work

### Public API additions

```python
# gnat/__init__.py
from gnat.schemas import (
    InvestigationSchema, HypothesisSchema, AnalystNoteSchema,
    EvidenceGraphSchema, EvidenceNodeSchema, EvidenceEdgeSchema,
    SeedSchema, RuleSchema, ReportSchema,
    ConfidenceScoreSchema, TLPLevelSchema,
    # ... etc
)
```

### Migration impact

- Zero. Pure addition. No existing code paths change.
- `requirements.txt` already includes Pydantic (FastAPI dashboard uses it). May need a version pin bump to ensure v2.

### Acceptance criteria

- Every domain object listed above has a schema with full field coverage
- `gnat.schemas` is importable without optional extras
- All schemas compile to valid OpenAPI 3.1 (verified by a CI check that runs FastAPI’s schema generator on a sample app)
- Round-trip parity test passes for every domain object
- Documentation page in `docs/reference/schemas.md`

-----

## Stream 2: Analyst Service Wrappers

### Why

The web app needs UI-friendly entry points that combine multiple core operations into single calls. For example, “open investigation” should atomically: load investigation, load related hypotheses, load timeline, load evidence graph references, check permissions (caller-supplied), record an access event. Doing this in the web backend means duplicating orchestration logic that should live closer to the domain.

These services also normalize the calling convention for the web app. Today, analysis logic is split across `gnat.analysis.investigations.service`, `gnat.investigations.builder`, `gnat.reporting.service`, etc. The web app sees a single coherent surface in `gnat.analyst_services`.

### Scope

New top-level package `gnat/analyst_services/`:

```
gnat/analyst_services/
├── __init__.py              # Public re-exports
├── base.py                  # AnalystServiceBase — shared concerns (logging, context)
├── context.py               # AnalystContext — caller identity, tenant, request id (no auth, just identity carrier)
├── analysis.py              # AnalysisService — investigations, hypotheses, notes, timeline, graph queries
├── investigations.py        # InvestigationsService — seed → build → expand → materialize
├── rules.py                 # RulesService — list, load, save, validate, test, promote, audit lookup
├── reporting.py             # ReportingService — draft, edit sections, publish, export
└── exceptions.py            # AnalystServiceError hierarchy
```

### `AnalystContext`

Every method accepts an `AnalystContext` as its first argument:

```python
@dataclass(frozen=True)
class AnalystContext:
    actor: str                       # "user@example.com" or "service:gnat-gui"
    tenant: str | None = None        # For multi-tenant deployments
    request_id: str | None = None    # For audit correlation
    locale: str = "en"
    capabilities: frozenset[str] = frozenset()  # Caller-supplied capability hints (NOT auth)
```

Core does **not** enforce auth; that is the caller’s job. The context exists so:

- Logs and audit trails can attribute actions to a specific actor without parsing FastAPI request state
- Multi-tenant deployments scope queries correctly without each call site doing it
- `request_id` flows through to LLM calls, DB queries, and emitted events for end-to-end tracing

### Service method shape

Each method:

1. Takes `AnalystContext` as first arg
1. Takes typed Pydantic schemas (from Stream 1) as data args
1. Returns Pydantic schemas
1. Raises typed exceptions from `gnat.analyst_services.exceptions`
1. Emits structured log events for every state change
1. Records an audit event in the existing audit log if applicable (note: GNAT may not currently have a unified audit log; this is a gap to address — see Open Questions)

Example (illustrative):

```python
# gnat/analyst_services/analysis.py
class AnalysisService:
    def __init__(self, store: InvestigationStore, llm: LLMClient | None = None):
        self._store = store
        self._llm = llm

    def get_investigation(
        self, ctx: AnalystContext, investigation_id: str
    ) -> InvestigationSchema:
        inv = self._store.get(investigation_id, tenant=ctx.tenant)
        if inv is None:
            raise InvestigationNotFound(investigation_id)
        return InvestigationSchema.from_domain(inv)

    def list_investigations(
        self,
        ctx: AnalystContext,
        status: list[str] | None = None,
        owner: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[InvestigationSchema]:
        ...

    def add_hypothesis(
        self,
        ctx: AnalystContext,
        investigation_id: str,
        hypothesis: HypothesisSchema,
    ) -> HypothesisSchema:
        ...
```

### What lives in services vs. core domain

- **Domain** (existing): state machines, validation invariants, persistence, correlation algorithms, graph algorithms, LLM prompts.
- **Services** (new): orchestration, schema conversion, multi-tenant scoping, structured event emission, optional async coordination.

Services should be 5–20 lines per method on average. If a service method is doing real logic, it belongs in the domain.

### Tests

- Unit tests with mocked stores
- Integration tests against real SQLite (matching existing `tests/` patterns)
- Multi-tenant isolation tests (query in tenant A cannot see tenant B’s data)
- Audit emission tests (every mutating method emits the expected event)

### Public API additions

```python
# gnat/__init__.py
from gnat.analyst_services import (
    AnalystContext,
    AnalysisService,
    InvestigationsService,
    RulesService,
    ReportingService,
)
```

### Migration impact

- Zero. Pure addition.
- Existing code (TUI, dashboard, CLI) continues to use the underlying services directly. They can be migrated to `analyst_services` opportunistically but it’s not required.

### Acceptance criteria

- All four services implemented with full coverage of CRUD + lifecycle operations
- Every method has a docstring with example usage
- 80% line coverage minimum on the new package
- Documentation page in `docs/reference/analyst-services.md` with worked examples

-----

## Stream 3: Job Framework

### Why

LLM-backed operations (gap detection, report drafting, investigation graph builds with enrichment) take seconds to minutes. The current pattern is synchronous calls that block the caller. For the web app, this means:

- Frontend requests would time out or require ad-hoc polling
- No progress indication during long operations
- Browser navigation away cancels the operation
- No way to resume after a reconnect

A first-class job framework solves these for the web app and for any future async caller (CLI with progress bars, scheduler tasks with status, automation pipelines).

### Scope

New top-level package `gnat/jobs/`:

```
gnat/jobs/
├── __init__.py              # Public API: Job, JobRegistry, JobRunner, JobResult, JobStatus
├── models.py                # Pydantic models for job state, progress events, results
├── registry.py              # JobRegistry — register job types, dispatch by name
├── runner.py                # JobRunner — execute jobs, manage lifecycle
├── store.py                 # JobStore — persist job state (SQLAlchemy, separate table)
├── events.py                # ProgressEvent, LogEvent, ResultEvent, ErrorEvent
├── decorators.py            # @job decorator for marking job functions
└── backends/
    ├── __init__.py
    ├── inprocess.py         # InProcessBackend — threadpool-based, default
    ├── apscheduler.py       # APSchedulerBackend — reuses existing FeedScheduler
    └── celery.py            # CeleryBackend — for distributed deployments (optional)
```

### Job model

```python
class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"

class Job(BaseModel):
    id: str                          # UUID
    type: str                        # Registered job type name
    status: JobStatus
    submitted_by: str                # AnalystContext.actor
    tenant: str | None
    submitted_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    progress: float = 0.0            # 0.0–1.0
    progress_message: str | None
    result: dict | None              # JSON-serializable result on success
    error: str | None                # Error message on failure
    parent_job_id: str | None        # For job chaining
    request_payload: dict            # The original request, for replay
```

### Progress events

Jobs emit events through an async generator interface:

```python
@job(type="investigations.build")
async def build_investigation_job(
    ctx: AnalystContext, request: InvestigationBuildRequestSchema
) -> AsyncIterator[ProgressEvent | ResultEvent]:
    yield ProgressEvent(progress=0.0, message="Validating seeds")
    seeds = validate_seeds(request.seeds)
    yield ProgressEvent(progress=0.1, message=f"Validated {len(seeds)} seeds")

    yield ProgressEvent(progress=0.2, message="Expanding from platforms")
    expanded = await expand_from_platforms(seeds, ctx)
    yield ProgressEvent(progress=0.5, message=f"Found {len(expanded)} related objects")

    yield ProgressEvent(progress=0.6, message="Normalizing")
    nodes = normalize_records(expanded)

    yield ProgressEvent(progress=0.75, message="Correlating")
    edges = correlate_nodes(nodes)

    yield ProgressEvent(progress=0.9, message="Building graph")
    graph = build_graph(nodes, edges)

    yield ResultEvent(result=InvestigationBuildResultSchema(graph=graph).model_dump())
```

The runner persists each event to the job store and pushes to any subscribed listeners.

### Backends

- **InProcessBackend**: default. Threadpool executor with asyncio event loop integration. Good for single-instance deployments (most users).
- **APSchedulerBackend**: reuses GNAT’s existing `FeedScheduler` infrastructure. Same overlap protection, callbacks, persistence.
- **CeleryBackend**: optional, behind `[jobs-celery]` extra. For multi-instance deployments needing distributed execution.

The framework is backend-agnostic; switching is a config change.

### Job types delivered with this stream

|Job type                    |Source operation                                     |
|----------------------------|-----------------------------------------------------|
|`investigations.build`      |`InvestigationBuilder.build()` (full 5-step pipeline)|
|`investigations.expand_node`|Pivot/expand from a graph node                       |
|`analysis.gap_detection`    |`GapDetector.run()`                                  |
|`analysis.report_draft`     |`ReportDraftingAssistant.draft()`                    |
|`rules.test_run`            |Run a rule against fixture(s) with full audit trail  |
|`rules.bulk_evaluate`       |Run a rule set against an evidence corpus            |

Each is a thin wrapper around existing core logic with progress yields inserted at natural checkpoints. No new business logic.

### Storage

New table in core DB:

```sql
CREATE TABLE jobs (
    id              UUID PRIMARY KEY,
    type            VARCHAR(128) NOT NULL,
    status          VARCHAR(32) NOT NULL,
    submitted_by    VARCHAR(255) NOT NULL,
    tenant          VARCHAR(255),
    submitted_at    TIMESTAMP NOT NULL,
    started_at      TIMESTAMP,
    finished_at     TIMESTAMP,
    progress        FLOAT NOT NULL DEFAULT 0.0,
    progress_message TEXT,
    result          JSONB,
    error           TEXT,
    parent_job_id   UUID REFERENCES jobs(id),
    request_payload JSONB NOT NULL
);

CREATE TABLE job_events (
    id          BIGSERIAL PRIMARY KEY,
    job_id      UUID NOT NULL REFERENCES jobs(id),
    event_time  TIMESTAMP NOT NULL,
    event_type  VARCHAR(32) NOT NULL,
    payload     JSONB NOT NULL
);
CREATE INDEX idx_job_events_job_id_time ON job_events(job_id, event_time);
```

Alembic migration. Compatible with the existing GNAT DB setup.

### Tests

- Unit tests for runner, registry, store
- Integration tests for each backend (in-process always; APScheduler if installed; Celery if installed)
- Job lifecycle tests (queue → run → succeed; queue → run → fail; queue → cancel)
- Progress event ordering tests
- Persistence/resume tests (kill runner mid-job, restart, verify state)

### Public API additions

```python
# gnat/__init__.py
from gnat.jobs import Job, JobStatus, JobRunner, JobRegistry, job
```

### Migration impact

- New DB tables (Alembic migration)
- New optional config section `[jobs]` with backend selection
- Existing sync APIs unchanged; jobs are an additive surface

### Acceptance criteria

- All six initial job types implemented and tested
- In-process backend production-ready; APScheduler backend functional; Celery backend documented but optional
- Documentation page in `docs/reference/jobs.md` and how-to in `docs/how-to/run-async-jobs.md`
- Performance: job submission overhead < 50ms, progress event latency < 100ms in-process

-----

## Stream 4: Streaming/SSE Support

### Why

For the web app to show live progress on the investigation graph builder and stream LLM output token-by-token (gap detection, report drafting), core needs to expose async generators that the FastAPI layer can pipe to SSE responses.

This is partly delivered by Stream 3 (jobs already emit progress events), but a few specific call sites also need to stream their internal output, especially anywhere that already calls into LLMs.

### Scope

#### 4a. LLM streaming pass-through

`gnat.agents.llm.LLMClient` already wraps Claude/OpenAI/Grok/Gemini. Extend with streaming method:

```python
class LLMClient:
    async def stream(
        self,
        messages: list[Message],
        model: str | None = None,
        **kwargs,
    ) -> AsyncIterator[StreamEvent]:
        ...
```

`StreamEvent` discriminated union covers token deltas, tool use, completion, errors. Each provider backend implements streaming via its native API.

Existing `LLMClient.complete()` continues to work unchanged.

#### 4b. Streaming-aware copilot operations

Update `gnat.analysis.copilot.gap_detector.GapDetector` and `gnat.analysis.copilot.drafting.ReportDraftingAssistant`:

- Add `astream()` methods returning `AsyncIterator[ProgressEvent | TokenEvent | ResultEvent]`
- Existing `run()` / `draft()` methods unchanged (they remain sync wrappers around the stream)

#### 4c. Investigation builder progress

Update `gnat.investigations.builder.InvestigationBuilder`:

- Add `abuild()` method returning `AsyncIterator[ProgressEvent | ResultEvent]`
- Per-step progress: seed validated, expansion started, expansion complete (with platform breakdown), normalization progress, correlation progress, materialization (if requested)
- Existing `build()` method unchanged

#### 4d. Rule test run streaming

Update `gnat.analysis.rule_engine.*`:

- Add streaming evaluation API that emits events per-rule-evaluated
- Useful for bulk evaluation against large fixture sets
- Existing batch API unchanged

### Implementation pattern

```python
class GapDetector:
    async def astream(
        self, ctx: AnalystContext, investigation_id: str
    ) -> AsyncIterator[StreamEvent]:
        yield ProgressEvent(progress=0.0, message="Loading investigation")
        inv = self._load(investigation_id, ctx)

        yield ProgressEvent(progress=0.1, message="Building gap analysis prompt")
        prompt = self._build_prompt(inv)

        yield ProgressEvent(progress=0.2, message="Querying LLM")
        async for event in self._llm.stream(prompt):
            if isinstance(event, TokenDelta):
                yield TokenEvent(text=event.text)
            elif isinstance(event, Completion):
                gaps = self._parse(event.full_text)
                yield ResultEvent(result=GapAnalysisSchema(gaps=gaps).model_dump())

    def run(self, ctx: AnalystContext, investigation_id: str) -> GapAnalysisSchema:
        # Sync wrapper
        return asyncio.run(self._collect(self.astream(ctx, investigation_id)))
```

### Tests

- Streaming order and completeness tests
- LLM provider streaming compatibility (mocked responses)
- Backpressure tests (slow consumer doesn’t drop events)
- Cancellation tests (caller closes stream cleanly)

### Migration impact

- Zero. All streaming methods are new and additive.
- Existing sync APIs preserved as wrappers around streams.

### Acceptance criteria

- All four streaming surfaces implemented
- Documentation in `docs/reference/streaming.md` and how-to in `docs/how-to/stream-llm-output.md`
- Performance: token-event latency overhead < 5ms per token

-----

## Cross-Cutting Concerns

### Auth, identity, and authorization

Core remains auth-free. `AnalystContext.actor` is a string the caller provides. The web app (or any other caller) is responsible for authentication and authorization.

This is a deliberate boundary — putting auth in the library would force every consumer to use it the same way. Today the dashboard uses API keys, the TUI uses none, the TAXII server uses API keys, and the GUI will use sessions and OIDC. Keeping auth out of core lets each surface make the right choice.

### Audit log

GNAT does not currently have a unified audit log abstraction. Components emit logs via `structlog` but there is no append-only “who did what when” record at the domain layer.

**Recommendation**: introduce `gnat/audit/` as a parallel stream (call it Stream 5 if needed):

- `AuditEvent` Pydantic schema
- `AuditLogger` interface with multiple backends (file, DB, Slack, none)
- `AnalystContext` auto-emits audit events when passed through services
- Backend-pluggable so GNAT-gui can plug its own DB-backed audit store while CLI uses a file backend

This is desirable independently of the GUI work. If it’s not done in core, the GUI’s `audit/` package becomes the audit source of truth, which means CLI/TUI actions wouldn’t be in the same audit log. Recommend doing it in core and having GUI extend it.

Decision needed: scope the audit framework into this plan, or punt to a follow-up?

### Multi-tenancy

GNAT already has `WorkspaceManager` and `TenantRegistry` for tenant isolation at the workspace layer. New analyst services need to honor this. `AnalystContext.tenant` flows through to all queries. Tests must verify isolation.

### Documentation

Each stream produces:

- A reference page (`docs/reference/<stream>.md`)
- A how-to page (`docs/how-to/<task>.md`) with worked examples
- Updates to the architecture overview (`docs/explanation/architecture.md`)
- An ADR for any significant design decision (e.g. `adr-NNN-job-framework.md`)

### Backwards compatibility

Every PR for these streams runs the existing test suite plus new tests. CI gates on:

- Existing tests pass unchanged
- No deprecation warnings introduced for existing public APIs
- `python -c "import gnat; gnat.GNATClient()"` works without any new optional extras installed

-----

## Sequencing and Milestones

### Phase A — Foundation (parallelizable with GNAT-gui M0)

**Stream 1 (Schemas)**: 1–2 weeks. Self-contained, no risk. Unblocks GNAT-gui M0.

**Stream 2 (Services)**: 1–2 weeks. Depends on Stream 1. Unblocks GNAT-gui M0.

**Audit decision**: choose whether to tackle in this work or defer.

### Phase B — Async (parallelizable with GNAT-gui M1–M2)

**Stream 3 (Jobs)**: 2 weeks. Independent of streaming. Unblocks GNAT-gui M3 (investigations) and M4 (LLM features).

### Phase C — Streaming (parallelizable with GNAT-gui M3)

**Stream 4 (Streaming)**: 1–2 weeks. Depends on Stream 3 for event types. Unblocks GNAT-gui M4 polish.

### Total

4–6 weeks of GNAT core work. Roughly half can be done in parallel with GUI development if a developer is dedicated to core. If the same person is doing both, expect 2–3 weeks of core work front-loaded before GUI module work begins.

-----

## Risks and Mitigations

|Risk                                                          |Mitigation                                                                                                                            |
|--------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
|Schema drift between Stream 1 and existing dataclasses        |Round-trip tests and CI contract tests. Single source of truth per object (dataclass remains canonical, schema mirrors).              |
|Job framework reinvents APScheduler                           |Use APScheduler under the hood for the relevant backend; framework adds the progress/persistence abstraction layer it lacks.          |
|Streaming complexity bleeds into sync APIs                    |Keep sync as wrappers around async, never the other way. Test both paths.                                                             |
|GNAT-gui ends up needing schemas/services that don’t exist yet|Maintain a “wishlist” doc in GNAT-gui repo; review weekly during dev; promote to GNAT issues.                                         |
|Audit framework punted, then GUI implements its own           |Surface this as a decision now (see Open Questions). Recommend doing it in core.                                                      |
|Optional extras explosion                                     |Group new dependencies into existing extras where possible (jobs → `[schedule]`, schemas → core). New extras only when truly optional.|

-----

## Public API Additions Summary

After all four streams ship, `gnat`’s public API gains:

```python
# Schemas
from gnat.schemas import (
    InvestigationSchema, HypothesisSchema, EvidenceGraphSchema,
    SeedSchema, RuleSchema, ReportSchema, ConfidenceScoreSchema,
    TLPLevelSchema, GapAnalysisSchema, ReportDraftSchema,
    # ... full list in Stream 1
)

# Services
from gnat.analyst_services import (
    AnalystContext,
    AnalysisService, InvestigationsService, RulesService, ReportingService,
)

# Jobs
from gnat.jobs import Job, JobStatus, JobRunner, JobRegistry, job

# Streaming (additions to existing classes)
LLMClient.stream(...)
GapDetector.astream(...)
ReportDraftingAssistant.astream(...)
InvestigationBuilder.abuild(...)
```

No existing public API removed or changed.

-----

## Open Questions

1. **Audit framework scope**: include in this plan as Stream 5, or defer? Recommendation: include. It’s a real gap and the GUI will surface it whether we like it or not.
1. **Pydantic v1 → v2 migration**: GNAT may have Pydantic v1 leftovers. Audit current usage and lock to v2 as part of Stream 1.
1. **AnalystContext propagation through existing code**: should the existing services (e.g. `InvestigationService`) be retrofitted to accept `AnalystContext`? Recommendation: no, retrofit lazily as services are touched. Stream 2 wrappers carry the context until then.
1. **Job framework vs FeedScheduler overlap**: clarify when to use which. Jobs are user-initiated and short-to-medium duration; FeedScheduler is for recurring cron-style work. Document this in the architecture overview.
1. **Streaming on the TAXII server / REST gateway**: Stream 4 is for in-process consumers. Should the existing REST gateway also gain SSE endpoints? Recommendation: out of scope here; let GNAT-gui be the first SSE consumer and prove the patterns before retrofitting the public REST surface.

-----

## Cross-References

- Companion plan for `wrhalpin/GNAT-gui`: `gnat_gui_repo_plan.md`
- Existing GNAT FastAPI dashboard: `gnat/serve/` — stays as-is, not replaced
- Existing GNAT REST gateway: `gnat/dissemination/api/` — stays as-is, public API surface
- Existing GNAT TUI: `gnat/tui/` — stays as-is, SSH-friendly alternative
- Existing GNAT scheduler: `gnat/schedule/` — Stream 3 reuses where possible
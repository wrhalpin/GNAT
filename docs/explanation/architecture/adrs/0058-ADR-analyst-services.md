# ADR-0058: Analyst Services Layer

**Status:** Accepted

**Date:** 2026-04-24

## Context

GNAT's domain layer contains well-factored service classes:
`InvestigationService`, `ReportService`, `RuleEngine`, and the
analysis attribution modules.  These services operate on domain
objects and are consumed directly by the CLI, TUI, and agent layer.
This works well for single-user, single-tenant use, but introduces
friction as GNAT gains a multi-user HTTP API (ADR-0028) and a web GUI
(ADR-0022):

1. **No identity context.**  Domain services accept object IDs and
   data but have no concept of "who is performing this action."  The
   serve layer must bolt on audit logging, tenant scoping, and
   attribution after the fact, leading to scattered boilerplate in
   endpoint handlers.

2. **No uniform API surface.**  Each domain service has its own method
   signatures, return types, and error conventions.  Endpoint handlers
   translate between HTTP request/response shapes and domain calls
   ad hoc.  This translation logic is duplicated when the same
   operation is exposed through both REST and SSE.

3. **Mixed concerns in endpoint handlers.**  Handlers currently
   perform identity extraction, tenant scoping, domain service calls,
   schema conversion, and error mapping in a single function.  This
   makes handlers hard to test and hard to reuse from non-HTTP
   contexts (e.g. the agent layer calling the same operation
   programmatically).

4. **Multi-tenancy is implicit.**  Tenant isolation (ADR-0027) is
   enforced by workspace filtering deep inside domain services, but
   the tenant ID must be threaded through manually.  There is no
   standard mechanism for passing the authenticated identity's tenant
   to every service call.

Requirements:

1. A thin orchestration layer that accepts caller identity and
   delegates to domain services.
2. Identity context must include actor, tenant, and request tracing.
3. The layer must not duplicate business logic — it orchestrates, not
   implements.
4. Input and output must use the Pydantic schemas from ADR-0057.
5. Domain services must remain unchanged and independently usable.
6. The layer must be usable from HTTP endpoints, CLI, TUI, agent
   layer, and tests without framework coupling.

## Decision

### 1. Add `gnat/analyst_services/` package with thin service wrappers

A new `gnat/analyst_services/` package contains service classes that
wrap existing domain services with identity-aware orchestration:

```
gnat/analyst_services/
├── __init__.py
├── context.py              # AnalystContext dataclass
├── analysis.py             # AnalysisService
├── investigations.py       # InvestigationsService
├── rules.py                # RulesService
└── reporting.py            # ReportingService
```

Each analyst service is a plain Python class with no framework
dependency.  It is instantiated with the domain services it
orchestrates and called with an `AnalystContext` as the first
argument.

### 2. AnalystContext as frozen dataclass

`AnalystContext` is a frozen dataclass that carries the identity of
the caller through every service call:

```python
@dataclass(frozen=True)
class AnalystContext:
    actor: str          # Subject identifier (username, API key label, agent name)
    tenant: str         # Tenant identifier for workspace isolation
    request_id: str     # Correlation ID for distributed tracing and audit logs
```

`AnalystContext` is frozen (immutable) to prevent accidental mutation
during a request lifecycle.  It is cheap to construct — three strings
— and is created at the boundary (HTTP middleware, CLI entry point,
agent harness) and passed inward.

The serve layer constructs `AnalystContext` from the
`AuthenticatedIdentity` (ADR-0056):

```python
ctx = AnalystContext(
    actor=identity.label,
    tenant=identity.tenant_id,
    request_id=request.state.request_id,
)
```

The CLI constructs it from the local config:

```python
ctx = AnalystContext(actor="cli", tenant="default", request_id=uuid4().hex)
```

### 3. Core does NOT enforce auth — AnalystContext is an identity carrier

`AnalystContext` carries identity but does not authenticate.
Authentication is the responsibility of the boundary layer (HTTP
middleware via ADR-0056, CLI config, agent harness).  By the time an
`AnalystContext` reaches an analyst service, the caller has already
been authenticated.

This separation means:

- Analyst services do not import auth modules.
- Tests can construct `AnalystContext` directly without mocking an
  auth backend.
- The same service code works behind API key auth, OIDC, or a test
  harness.

Authorization (permission checks beyond tenant scoping) is not in
scope for this ADR.  When role-based access control is needed, it
will be a separate concern layered on top of `AnalystContext.actor`
and the identity's role.

### 4. Services accept and return Pydantic schemas

Analyst service methods accept Pydantic request schemas and return
Pydantic response schemas from `gnat/schemas/` (ADR-0057):

```python
class InvestigationsService:
    def create(
        self,
        ctx: AnalystContext,
        request: CreateInvestigationRequest,
    ) -> InvestigationSchema:
        ...
```

This provides:

- Input validation at the service boundary via Pydantic.
- Typed return values that FastAPI can serialize directly.
- A contract that is testable without HTTP.

Domain objects are converted to/from schemas inside the service
methods using `Schema.from_domain()` and `schema.to_domain()`.

### 5. Each method is 5-20 lines of orchestration

Analyst service methods are intentionally thin.  A typical method:

1. Extracts validated fields from the request schema.
2. Calls one or more domain service methods.
3. Converts the domain result to a response schema.
4. Returns the schema.

```python
def create(self, ctx: AnalystContext, request: CreateInvestigationRequest) -> InvestigationSchema:
    inv = self._investigation_svc.create(
        title=request.title,
        description=request.description,
        tenant_id=ctx.tenant,
    )
    logger.info("investigation.created", actor=ctx.actor, id=inv.id, request_id=ctx.request_id)
    return InvestigationSchema.from_domain(inv)
```

If a method grows beyond ~20 lines, that is a signal that business
logic is leaking into the orchestration layer and should be pushed
down into the domain service.

### 6. Four services covering the primary API surface

| Service | Wraps | Responsibilities |
|---------|-------|-----------------|
| `AnalysisService` | `AttributionEngine`, `CampaignTracker`, `HypothesisEngine` | Campaign analysis, attribution hypotheses, Diamond Model operations |
| `InvestigationsService` | `InvestigationService` | CRUD for investigations, evidence linking, status transitions |
| `RulesService` | `RuleEngine` (Hy, YAML, Prolog backends) | Rule CRUD, evaluation, audit trail retrieval |
| `ReportingService` | `ReportService`, report generators | Report generation (PDF/DOCX), template listing, AI-assisted summaries |

Each service is independent and can be instantiated separately.
There is no god-object that aggregates all four.

### 7. Existing domain services remain unchanged

Domain services (`InvestigationService`, `ReportService`,
`RuleEngine`, etc.) are not modified by this ADR.  They continue to:

- Accept and return domain objects (dataclasses, ORM objects).
- Operate without identity context.
- Be callable directly from tests, CLI, and TUI.

The analyst services layer is additive.  It does not replace domain
services; it wraps them for contexts where identity, tenant scoping,
and schema contracts are needed.  Code that does not need these
features continues to call domain services directly.

### 8. Multi-tenant: AnalystContext.tenant flows through to all queries

Every analyst service method passes `ctx.tenant` to the underlying
domain service calls that support tenant filtering.  This ensures
workspace isolation (ADR-0027) is applied consistently without
relying on each endpoint handler to remember to pass the tenant:

```python
def list(self, ctx: AnalystContext, filters: ListFilters) -> list[InvestigationSchema]:
    investigations = self._investigation_svc.list(
        tenant_id=ctx.tenant,
        status=filters.status,
        limit=filters.limit,
    )
    return [InvestigationSchema.from_domain(inv) for inv in investigations]
```

Domain services that do not yet accept `tenant_id` are updated to
accept and filter by it as part of this work.  The domain service
changes are minimal (adding a `tenant_id: str | None = None`
parameter and a filter clause) and do not alter their public
contract for callers that do not pass a tenant.

## Consequences

**Positive:**

- Unified API surface for the web GUI, REST API, SSE, and future
  consumers.  All go through the same analyst service methods,
  eliminating duplicated translation logic in endpoint handlers.
- Audit attribution is built in: every operation logs `ctx.actor` and
  `ctx.request_id`, providing a complete audit trail without
  per-endpoint boilerplate.
- Tenant scoping is applied uniformly by the service layer, reducing
  the risk of a missed tenant filter in an endpoint handler.
- Testability improves: analyst services can be tested with a
  constructed `AnalystContext` and mocked domain services, without
  spinning up an HTTP server.
- Schema contracts (ADR-0057) at the service boundary mean that
  serialization and validation happen once, in a predictable location.

**Negative:**

- Additional abstraction layer between HTTP endpoints and domain
  services.  For simple CRUD operations, the analyst service method
  may feel like unnecessary indirection.  This is accepted as the
  cost of a uniform contract — the layer pays for itself as soon as
  a second consumer (beyond HTTP) uses it.
- Four new service classes must be maintained alongside the existing
  domain services.  Method signatures must stay aligned.  The thin
  nature of the methods (5-20 lines) limits the maintenance burden.

**Neutral:**

- Existing CLI and TUI code is unaffected.  They can migrate to
  analyst services opportunistically when they benefit from schema
  validation or audit logging, but are not required to.
- The agent layer (`gnat/agents/`) may adopt analyst services for
  operations that need audit attribution (e.g. AI-initiated
  investigation creation).  This is optional and can be done
  incrementally.
- No new dependencies are introduced.  `AnalystContext` is a stdlib
  dataclass; Pydantic is already a base dependency per ADR-0057.

---

Related: ADR-0022 (Web Dashboard — frontend architecture and API needs)
Related: ADR-0027 (Multi-Tenant Workspace Isolation — tenant scoping)
Related: ADR-0028 (TAXII 2.1 Server — serve layer design)
Related: ADR-0056 (Unified API Key Auth — AuthenticatedIdentity protocol)
Related: ADR-0057 (Pydantic Schemas — typed API contracts)

---

*Licensed under the Apache License, Version 2.0*

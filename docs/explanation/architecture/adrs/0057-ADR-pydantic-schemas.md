# ADR-0057: Pydantic Schemas for API Contracts

**Status:** Accepted

**Date:** 2026-04-24

## Context

GNAT's domain layer uses plain Python dataclasses and the property-bag
ORM (`STIXBase`) for all internal state.  This was a deliberate choice
(ADR-0002, ADR architecture table) to avoid coupling the core to any
validation framework.  The serve layer (`gnat/serve/`) exposes these
objects through FastAPI endpoints, but today endpoint handlers manually
construct response dicts from domain objects.  This creates several
problems:

1. **No typed API contracts.**  Endpoint return types are `dict` or
   `Any`.  FastAPI cannot generate accurate OpenAPI schemas, so
   consumers (frontend, CLI, addon tools) reverse-engineer the JSON
   shape from examples.  Changes to a domain dataclass silently alter
   the API surface with no compile-time or test-time signal.

2. **No input validation.**  Request bodies are accepted as raw dicts
   and validated ad hoc inside handler functions.  Validation rules are
   scattered, inconsistent, and untested.

3. **No frontend type safety.**  The planned web GUI (ADR-0022) needs
   TypeScript types.  Without an OpenAPI spec that accurately reflects
   the data shape, the frontend team would maintain hand-written type
   definitions that drift from the backend.

4. **Pydantic is already installed** as a transitive dependency of
   FastAPI, but it is not used for domain modelling.  This means the
   dependency cost is already paid for `gnat[serve]` users, yet the
   benefit is not captured.

Requirements:

1. Typed, validated schemas for every domain object exposed through
   the API.
2. Schemas must be derivable from existing domain dataclasses without
   duplicating field definitions manually.
3. FastAPI must auto-generate an accurate OpenAPI spec from the
   schemas.
4. The frontend must be able to generate TypeScript types from the
   OpenAPI spec.
5. Domain dataclasses must remain the authoritative source of truth —
   schemas are a projection, not a replacement.
6. Schema drift from domain objects must be detected automatically in
   CI.
7. Schemas must not encode UI concerns (display labels, widget hints,
   layout).

## Decision

### 1. Add `gnat/schemas/` package with Pydantic v2 BaseModel schemas

A new `gnat/schemas/` package contains one module per domain area
(e.g. `investigations.py`, `indicators.py`, `reports.py`, `rules.py`).
Each module defines Pydantic v2 `BaseModel` subclasses that mirror the
corresponding domain dataclasses field-for-field.

```
gnat/schemas/
├── __init__.py
├── base.py               # GNATSchema base class
├── indicators.py
├── investigations.py
├── reports.py
├── rules.py
├── campaigns.py
├── hypotheses.py
├── observables.py
└── common.py             # Shared field types (TLPLevel, ConfidenceScore, etc.)
```

All schema classes inherit from `GNATSchema`, a thin `BaseModel`
subclass that sets project-wide Pydantic configuration.

### 2. Schemas use `ConfigDict(from_attributes=True)`

Every schema class includes:

```python
model_config = ConfigDict(from_attributes=True)
```

This tells Pydantic v2 to read values from object attributes (not
only dicts), so a domain dataclass instance can be passed directly to
the schema's `model_validate()` constructor:

```python
schema = InvestigationSchema.model_validate(investigation)
```

No manual field-by-field mapping is needed for the common case where
field names and types align between domain and schema.

### 3. Each schema has `from_domain(cls, obj)` classmethod

For cases where the domain object's structure does not map one-to-one
to the schema (e.g. computed fields, nested object flattening, enum
conversions), each schema provides an explicit `from_domain`
classmethod:

```python
class InvestigationSchema(GNATSchema):
    @classmethod
    def from_domain(cls, obj: Investigation) -> "InvestigationSchema":
        return cls.model_validate(obj)
```

The default implementation delegates to `model_validate(obj)`.
Schemas that need transformation override this method.  Consumers
always call `from_domain` rather than `model_validate` directly, so
that transformation logic has a single home.

A corresponding `to_domain()` instance method reconstructs the domain
object from the schema, enabling the full round trip.

### 4. Pydantic added to base dependencies

Pydantic v2 (`pydantic>=2.0,<3`) is promoted from an indirect
dependency (via FastAPI in `gnat[serve]`) to a direct base dependency
in `pyproject.toml`.  This means all GNAT installations — including
CLI-only and library-only uses — can import `gnat.schemas`.

Rationale: schemas are the typed contract for all API consumers, not
just the HTTP layer.  The CLI, TUI, addon tools, and agent layer all
benefit from validated input/output.  Pydantic v2 is pure Python with
a Rust-accelerated core (`pydantic-core`), has minimal transitive
dependencies, and is already present in practice for most users.

### 5. Schemas are the typed contract for API consumers

FastAPI endpoint signatures use schema classes as request bodies and
response models:

```python
@router.post("/investigations", response_model=InvestigationSchema)
async def create_investigation(body: CreateInvestigationRequest, ...):
    ...
```

FastAPI auto-generates an OpenAPI 3.1 spec from these annotations.
The frontend build pipeline runs `openapi-typescript` against the spec
to produce TypeScript type definitions, closing the type safety chain
from database to browser.

### 6. Domain dataclasses remain the source of truth

The domain layer (`gnat/analysis/`, `gnat/orm/`, `gnat/research/`,
etc.) continues to use plain Python dataclasses and the property-bag
ORM.  No domain code imports from `gnat.schemas`.  The dependency
arrow is strictly one-directional:

```
gnat.schemas  -->  gnat.analysis / gnat.orm / gnat.research
```

If a domain dataclass gains a new field, the corresponding schema must
be updated.  This is enforced by round-trip tests (see next decision).

### 7. Round-trip tests verify parity

A dedicated test module `tests/unit/schemas/test_round_trip.py`
verifies that every schema/domain pair survives the full round trip:

```
domain_obj --> Schema.from_domain(domain_obj) --> .model_dump(mode="json")
           --> Schema.model_validate_json(json_bytes) --> .to_domain()
           --> assert equal to original domain_obj
```

These tests run as part of `make test` and fail if a domain field is
added without a corresponding schema field, or if serialization
changes the data.  This is the primary defence against schema drift.

### 8. No UI concerns in schemas

Schemas describe data shape only: field names, types, validation
constraints, and JSON serialization rules.  They do not include:

- Display labels or human-readable descriptions (beyond docstrings)
- Widget type hints (dropdown, date picker, etc.)
- Layout or ordering metadata
- Visibility rules (show/hide based on role)

UI metadata is the responsibility of the frontend application.  If a
future need arises for server-driven UI metadata, it will be a
separate layer that references schemas, not an extension of them.

## Consequences

**Positive:**

- FastAPI auto-generates an accurate OpenAPI 3.1 spec from schema
  annotations, eliminating hand-maintained API documentation.
- Frontend TypeScript types are generated from the OpenAPI spec,
  providing end-to-end type safety from domain dataclass to browser
  component.
- Request validation is handled declaratively by Pydantic, removing
  scattered ad hoc validation from endpoint handlers.
- Schema drift is caught by round-trip tests in CI before it reaches
  consumers.
- Addon tools (SandGNAT, SenseGNAT, RedGNAT) and the agent layer can
  import schemas for validated request/response construction without
  depending on FastAPI.

**Negative:**

- Schema drift risk: adding a field to a domain dataclass without
  updating the schema is possible.  This is mitigated by round-trip
  tests, but the tests only cover objects that have test fixtures.
  New domain objects without test coverage can drift silently until a
  fixture is added.
- Maintenance surface increases: each domain object now has a
  corresponding schema that must be kept in sync.  For the current
  ~20 domain types this is manageable; at scale, code generation from
  dataclass introspection may be warranted.

**Neutral:**

- Pydantic becomes a core dependency.  It was already an indirect
  dependency for `gnat[serve]` users and adds ~2 MB to the install
  footprint.  The Rust-accelerated core (`pydantic-core`) is a binary
  wheel, which may affect platforms without pre-built wheels, but
  Pydantic provides pure-Python fallback.
- Existing CLI and TUI code is unaffected.  They may adopt schemas
  incrementally for input validation but are not required to.

---

Related: ADR-0002 (ORM STIX Compatibility — property-bag design rationale)
Related: ADR-0022 (Web Dashboard — frontend architecture)
Related: ADR-0028 (TAXII 2.1 Server — serve layer design)
Related: ADR-0041 (Idempotency & Schema Evolution — data contract stability)

---

*Licensed under the Apache License, Version 2.0*

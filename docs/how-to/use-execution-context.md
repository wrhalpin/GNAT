# How-to: Use the Execution Context

Every GNAT operation — pipeline run, connector call, agent action — is tagged with an
`ExecutionContext` that carries its identity, domain, trust level, workspace boundary,
and optional resource budget.  This guide shows how to create, propagate, and query
execution contexts in your code.

---

## Prerequisites

- GNAT installed (`pip install gnat`)
- `sqlalchemy` installed for DB persistence (`pip install "gnat[persist]"`)
- At least one connector configured in `~/.gnat/config.ini`

---

## Create a Context

```python
from gnat.core.context import ExecutionContext

# Minimal context — defaults to semi_trusted, default policy set
ctx = ExecutionContext.create(
    initiated_by="manual",
    domain="ingestion",
    workspace_id="ws-apt28",
)
print(ctx.context_id)   # UUID string
print(ctx.trust_level)  # "semi_trusted"
print(ctx.is_replay)    # False
```

### Create from a connector (inherits trust level)

```python
from gnat.connectors.splunk.client import SplunkClient
from gnat.core.context import ExecutionContext

splunk = SplunkClient(host="https://splunk.example.com", ...)

# Reads SplunkClient.TRUST_LEVEL = "trusted_internal" automatically
ctx = ExecutionContext.from_connector(
    connector=splunk,
    domain="ingestion",
    workspace_id="ws-siem",
)
print(ctx.trust_level)    # "trusted_internal"
print(ctx.initiated_by)   # "SplunkClient"
```

### Create with a query budget

```python
ctx = ExecutionContext.create(
    initiated_by="automated-pipeline",
    domain="analysis",
    workspace_id="ws-enrichment",
    max_budget_units=500,   # connector calls are counted against this limit
)
print(ctx.budget.remaining)  # 500
```

---

## Propagate Through a Pipeline

Attach the context to a connector so budget tracking and logging work automatically:

```python
from gnat.connectors.virustotal.client import VirusTotalClient
from gnat.clients.base import BudgetExceeded
from gnat.core.context import ExecutionContext

ctx = ExecutionContext.create(
    initiated_by="enrichment-job",
    domain="analysis",
    workspace_id="ws-threats",
    max_budget_units=100,
)

vt = VirusTotalClient(host="https://www.virustotal.com", api_key="...")
vt._context = ctx   # attach context — budget will be deducted per request

try:
    result = vt.get("/api/v3/files/abc123")
except BudgetExceeded as e:
    print(f"Budget exhausted: {e.connector} wanted {e.cost} but only {e.remaining} left")
```

---

## Create Child Contexts

Sub-operations (e.g. an enrichment agent spawned by an ingestion pipeline) should use
child contexts so the parent→child trace is preserved in `execution_log`:

```python
parent_ctx = ExecutionContext.create(
    initiated_by="ingest-pipeline",
    domain="ingestion",
    workspace_id="ws-1",
)

# Child inherits workspace_id, trust_level, policy_set
child_ctx = parent_ctx.child(
    initiated_by="enrichment-agent",
    domain="analysis",
)

print(child_ctx.parent_context_id == parent_ctx.context_id)  # True
```

---

## Domain Boundaries

The `@domain_boundary` decorator enforces that a function is only called from permitted
upstream domains.  Violations raise `DomainBoundaryViolation`.

```python
from gnat.core.domains import Domain, domain_boundary, DomainBoundaryViolation

@domain_boundary(Domain.REPORTING, allowed_callers=[Domain.INVESTIGATION, Domain.REPORTING])
def generate_report(workspace, context):
    ...

@domain_boundary(Domain.INGESTION)
def run_ingest():
    # Calling generate_report from ingestion raises DomainBoundaryViolation
    try:
        generate_report(ws, ctx)
    except DomainBoundaryViolation as e:
        print(e)   # "ingestion cannot call into reporting domain"
```

---

## Trust Level Enforcement

Decorate functions that require a minimum trust level to execute:

```python
from gnat.core.domains import require_trust_level, TrustLevelViolation

@require_trust_level("trusted_internal")
def trigger_soar_playbook(playbook_id, context):
    ...

# Context with semi_trusted will raise
ctx = ExecutionContext.create(initiated_by="ot", domain="execution", workspace_id="ws")
try:
    trigger_soar_playbook("PB-001", context=ctx)
except TrustLevelViolation as e:
    print(e)  # "requires trusted_internal but active trust is semi_trusted"
```

---

## Replay Mode

Set `is_replay=True` to suppress SOAR triggers and side-effects during replay runs:

```python
ctx = ExecutionContext.create(
    initiated_by="replay-runner",
    domain="ingestion",
    workspace_id="ws-replay",
    is_replay=True,
)

# Pipelines check ctx.is_replay before firing SOAR actions
if not ctx.is_replay:
    xsoar_client.trigger_playbook(...)
```

---

## Serialise / Deserialise

```python
d = ctx.to_dict()
# Store d in DB, pass over API boundary, etc.
ctx2 = ExecutionContext.from_dict(d)
```

---

## See Also

- [ADR-0039 — Unified Execution Context](../explanation/architecture/adrs/0039-ADR-execution-context.md)
- [ADR-0040 — Connector Trust Model](../explanation/architecture/adrs/0040-ADR-connector-trust-model.md)
- [ADR-0048 — Query Budget](../explanation/architecture/adrs/0048-ADR-query-budget.md)
- [Reference: Configuration](../reference/configuration.md)

---

*Licensed under the Apache License, Version 2.0*

# ADR-0048 — Query Budget and Cost Tracking (Phase 4E)

**Date:** 2026-04-09  
**Status:** Accepted  
**Deciders:** GNAT Platform Team

---

## Context

GNAT coordinates calls to up to 99 external connector platforms.  Each
connector call may count against a paid API quota, consume compute time, or
contribute to rate-limit thresholds imposed by the upstream provider.

Prior to this ADR, two mechanisms provided partial protection:

1. **`AgentGovernor` rate limiting** (ADR-0045) — a sliding-window counter
   per agent per time window, expressed in *number of governor-checked agent
   actions*.  It does not account for the number of HTTP calls each action
   generates, which may be many (e.g. a `list_objects()` that pages through
   5 000 results).

2. **`QueryBudget` on `ExecutionContext`** (ADR-0039) — a `max_connector_calls`
   field on the context dataclass.  It was designed as a placeholder but had
   no enforcement mechanism: `BaseClient._request()` did not check it, and
   there was no `BudgetExceeded` exception class.

The consequence was that an agent or pipeline with unrestricted connector
access could:

- Page through an entire VirusTotal result set in a single `list_objects()`
  call, exhausting the day's API quota for the entire deployment.
- Create a thundering-herd problem where multiple parallel enrichment
  pipelines all call the same rate-limited platform simultaneously.
- Provide no cost attribution: there was no record of which connector, agent,
  or pipeline consumed the most API calls over a given period.

These gaps made GNAT unsuitable for deployments with strict API cost controls
or quota-sharing across teams.

---

## Decision

Extend `QueryBudget` (introduced as a stub in ADR-0039) into a fully
functional cost-tracking and enforcement mechanism, and wire it into the hot
path of `BaseClient._request()`.

### `QueryBudget` Dataclass (Extended)

Located in `gnat/core/context.py`, replacing the stub from ADR-0039:

```python
@dataclass
class QueryBudget:
    """Per-execution resource budget for connector API calls.

    Parameters
    ----------
    max_units : int
        Maximum total cost units for this execution.  Each connector call
        deducts ``COST_UNIT`` units from the budget.  Raise
        ``BudgetExceeded`` when the budget is exhausted.
    """

    max_units: int
    _consumed: int = field(default=0, repr=False, init=False)

    @property
    def remaining(self) -> int:
        """Remaining cost units."""
        return self.max_units - self._consumed

    @property
    def is_exhausted(self) -> bool:
        """True when no budget remains."""
        return self._consumed >= self.max_units

    def consume(self, units: int, connector: str) -> None:
        """Deduct *units* from the budget on behalf of *connector*.

        Parameters
        ----------
        units : int
            Cost units to deduct.  Use ``BaseClient.COST_UNIT`` (default 1)
            for single-item requests; use larger values for bulk/search ops.
        connector : str
            Connector class name, used for cost attribution logging.

        Raises
        ------
        BudgetExceeded
            If deducting *units* would exceed ``max_units``.
        """
        if self._consumed + units > self.max_units:
            raise BudgetExceeded(
                connector=connector,
                cost=units,
                remaining=self.remaining,
            )
        self._consumed += units
```

### `BudgetExceeded` Exception

```python
class BudgetExceeded(GNATClientError):
    """Raised when a connector call would exceed the active QueryBudget.

    Attributes
    ----------
    connector : str
        Name of the connector that attempted the call.
    cost : int
        Cost units the call would have consumed.
    remaining : int
        Budget units remaining at the time of the attempt.
    """

    def __init__(self, connector: str, cost: int, remaining: int) -> None:
        self.connector = connector
        self.cost = cost
        self.remaining = remaining
        super().__init__(
            f"Budget exhausted: connector='{connector}' attempted "
            f"cost={cost} but only {remaining} units remain."
        )
```

`BudgetExceeded` inherits from `GNATClientError` (from `gnat.clients.base`)
so it is caught by the standard error handling path and propagates through
pipelines identically to any other HTTP-layer failure.

### `COST_UNIT` Class Variable on `BaseClient`

```python
class BaseClient:
    COST_UNIT: int = 1        # default: 1 unit per HTTP request
    TRUST_LEVEL: str = "semi_trusted"

    def _request(self, method: str, path: str, **kwargs) -> urllib3.HTTPResponse:
        if self._context and self._context.budget:
            self._context.budget.consume(
                self.COST_UNIT,
                connector=type(self).__name__,
            )
        # ... existing HTTP dispatch ...
```

Connectors that make bulk or search calls override `COST_UNIT` to reflect
their relative expense:

| Connector Category | `COST_UNIT` | Rationale |
|---|---|---|
| Standard single-object GET / POST | `1` | Default; one API call, one result |
| Bulk list / paginated results | `10` | One call may return hundreds of objects |
| Full-text search queries | `5` | Search indexes are expensive to query at scale |
| AI inference calls (LLM connectors) | `20` | Token cost is orders of magnitude above REST calls |

Example for the VirusTotal connector, which supports paginated list endpoints:

```python
class VirusTotalClient(BaseClient):
    COST_UNIT = 1   # single-lookup default

    def list_objects(self, query: str, limit: int = 100) -> list[dict]:
        # Bulk paging — charge 10 per page
        results = []
        cursor = None
        while True:
            if self._context and self._context.budget:
                self._context.budget.consume(10, connector="VirusTotalClient")
            page = self._request("GET", f"/intelligence/search?query={query}&cursor={cursor}")
            # ... parse and accumulate ...
            if not page.get("meta", {}).get("cursor"):
                break
            cursor = page["meta"]["cursor"]
        return results
```

### `ExecutionContext.create()` with Budget

The `max_budget_units` parameter on `ExecutionContext.create()` is now wired:

```python
ctx = ExecutionContext.create(
    initiated_by="enrichment-pipeline",
    domain="analysis",
    workspace_id="production",
    max_budget_units=500,
)
# ctx.budget is a QueryBudget(max_units=500)

# With no budget limit:
ctx = ExecutionContext.create(
    initiated_by="manual",
    domain="ingestion",
    workspace_id="sandbox",
    # max_budget_units omitted → ctx.budget is None → unlimited
)
```

### Cost Logging — `query_cost_log` Table

Every call to `QueryBudget.consume()` appends a row to the `query_cost_log`
table (Alembic migration `0008_add_query_cost_log.py`):

| Column | Type | Notes |
|---|---|---|
| `id` | `INTEGER` | Auto-increment primary key |
| `context_id` | `VARCHAR(36)` | FK → `execution_log.id` |
| `connector` | `VARCHAR(200)` | Connector class name |
| `cost_units` | `INTEGER` | Units deducted by this call |
| `cumulative_consumed` | `INTEGER` | Budget state after deduction |
| `budget_max` | `INTEGER` | `max_units` of the owning `QueryBudget` |
| `recorded_at` | `DATETIME` | UTC timestamp |

```sql
-- Migration 0008 (excerpt)
CREATE TABLE query_cost_log (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    context_id          VARCHAR(36)  NOT NULL,
    connector           VARCHAR(200) NOT NULL,
    cost_units          INTEGER      NOT NULL,
    cumulative_consumed INTEGER      NOT NULL,
    budget_max          INTEGER      NOT NULL,
    recorded_at         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (context_id) REFERENCES execution_log(id)
);

CREATE INDEX ix_query_cost_log_context ON query_cost_log (context_id);
CREATE INDEX ix_query_cost_log_connector ON query_cost_log (connector, recorded_at);
```

Logging is best-effort: a failure to write to `query_cost_log` is caught and
logged at `WARNING` level but does not propagate.  The budget deduction itself
always occurs before the log write, so enforcement is never skipped.

### Querying Cost Attribution

```python
from gnat.core.context import CostAttributionQuery

report = CostAttributionQuery(db_session).by_connector(
    connector="VirusTotalClient",
    since=datetime(2026, 4, 1),
)
# Returns list of (date, connector, total_units, call_count)

report = CostAttributionQuery(db_session).by_context(context_id="...")
# Returns per-connector breakdown for a single execution
```

### Configuration

```ini
[context]
default_budget_units = 0          ; 0 = unlimited (default for manual runs)
pipeline_budget_units = 1000      ; budget applied to scheduled pipeline runs
agent_budget_units = 200          ; budget applied to each agent session
```

When `pipeline_budget_units` is set, `FeedScheduler` automatically creates
an `ExecutionContext` with `max_budget_units=pipeline_budget_units` for every
scheduled feed run.

---

## Consequences

### Positive

- **Hard resource limit for pipelines and agents:** a misconfigured
  `ResearchAgent` looping over VirusTotal will hit `BudgetExceeded` after
  `max_budget_units / COST_UNIT` calls rather than running indefinitely.
- **First-class error with actionable context:** `BudgetExceeded` carries
  `connector`, `cost`, and `remaining` — the operator can immediately see
  which connector triggered the limit and by how much.
- **Per-connector cost attribution:** `query_cost_log` provides a persistent,
  queryable record of which connectors consumed what share of the budget over
  any time window.  This enables quota planning and chargeback reporting for
  MSSP deployments.
- **Zero overhead when no budget is set:** if `ctx.budget` is `None`, the
  `if` guard in `_request()` is a single attribute lookup that short-circuits
  immediately.  Deployments that do not need budget enforcement pay no cost.
- **Bulk and search overrides enable accurate cost modelling:** connectors
  that page through large result sets can declare realistic `COST_UNIT`
  multipliers rather than counting every paginated request as 1 unit.

### Negative / Trade-offs

- **`COST_UNIT` is a class constant, not a per-call value:** a connector
  cannot dynamically adjust the cost of a call based on the response size
  (e.g. charging more for a response with 10 000 results than one with 10).
  Per-call dynamic costing is deferred.
- **Cost logging adds one `INSERT` per connector call when a budget is
  active:** high-frequency pipelines may produce large volumes of cost log
  rows.  A retention or aggregation policy is needed for long-running
  deployments.
- **Budget is per-execution-context, not global:** two concurrent pipelines
  each with a budget of 1 000 units can together consume 2 000 units from a
  platform with a 1 500-unit daily quota.  Cross-context global quota
  enforcement requires a shared counter (deferred).

### Deferred

- Global quota pool shared across concurrent `ExecutionContext` instances
  (requires a Redis or database-backed counter)
- Dynamic per-call cost calculation based on response size or token count
- `query_cost_log` retention policy and aggregation rollups
- Cost attribution dashboard in the TUI
- Per-connector quota configuration in `config.ini` (e.g. `[virustotal]
  daily_quota = 500`)

---

## Alternatives Considered

### Connector-Level Rate Limits Only

Apply rate limits at the connector level rather than introducing a budget
concept on `ExecutionContext`.  For example, each connector would track its
own call count and sleep or raise when a per-hour limit is reached.  Rejected
because:

1. Connector-level limits do not aggregate across connectors.  A pipeline
   that calls five connectors 200 times each has made 1 000 total calls, but
   no connector-level limit would fire.
2. Rate limits and budgets serve different purposes: rate limits protect
   against *throughput* spikes; budgets protect against *total cost* within
   an execution.  Both are needed; budget enforcement complements rather than
   replaces rate limiting.

### OS-Level Resource Limits (cgroups / `resource.setrlimit`)

Applying OS-level CPU or memory limits to pipeline processes was considered
as a coarser alternative.  Rejected because it does not provide per-connector
cost attribution, does not integrate with the GNAT audit trail, and does not
map naturally to API quota units (which are a business concept, not an
OS resource).

### OpenAI / Anthropic Cost Estimators as the Model

Using the token-count-based cost estimation models from LLM providers as the
primary budget unit was considered.  Rejected because GNAT's connectors are
predominantly REST API clients, not LLM callers.  A unified unit (abstract
cost units with connector-specific `COST_UNIT` multipliers) is more flexible
and does not require token counting infrastructure for non-LLM connectors.

### Queue-Based Throttling (Celery / RQ)

Routing all connector calls through a task queue and configuring per-connector
concurrency limits was prototyped.  Rejected because it introduces a mandatory
message broker dependency for a feature that should be available in single-
process deployments.  Queue-based throttling remains an option for scale-out
deployments but should not be required for the core use case.

---

*Licensed under the Apache License, Version 2.0*

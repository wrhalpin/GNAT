# ADR-0049 — Simulation-Based Testing Framework (Phase 4E)

**Date:** 2026-04-09  
**Status:** Accepted  
**Deciders:** GNAT Platform Team

---

## Context

GNAT's unit test suite (`tests/unit/`) exercises connector logic through the
`mock_http_response` and `mock_pool_manager` fixtures defined in
`tests/conftest.py`.  These fixtures mock at the HTTP layer (`urllib3.PoolManager`)
and are effective for testing single connector methods in isolation.

As GNAT's Phase 4 features were added, three gaps in the testing infrastructure
became significant:

### Gap 1 — No Full-Pipeline Connector Fixture

The `mock_pool_manager` fixture returns raw HTTP bytes.  Tests that need to
exercise a complete pipeline (ingest → enrich → export) must either:

- Construct a chain of `mock_http_response` objects for every API call the
  pipeline makes, which is brittle and tied to internal implementation order, or
- Use a live connector, which requires network access and real credentials.

There is no fixture connector that implements the full `ConnectorMixin` interface
with predictable, in-memory STIX data — making pipeline-level unit tests
impractical.

### Gap 2 — No Replay Testing

`ExecutionContext.is_replay` (ADR-0039) is set by pipeline runners to suppress
side effects during re-runs.  But there was no test framework support for
verifying that a pipeline produces idempotent output: given the same
`execution_log` entries from a previous run, a re-run should produce the same
STIX IDs without duplicate write calls.

### Gap 3 — Agent Tests Require Live Governor and Review Queue

Tests for `AgentGovernor` (ADR-0045) and `HITLGateway` (ADR-0046) need a
complete governance stack, including a `ReviewService` that auto-approves
actions so the test can proceed without human input.  Assembling this stack
from individual fixtures in each test file is repetitive and error-prone.

---

## Decision

Introduce a **`gnat/testing/`** package with three components that together
make full-pipeline, replay, and agent governance tests practical without
network access or live credentials.

All three components live in `gnat/testing/simulation.py` and are exported
from `gnat/testing/__init__.py`.

### Component 1 — `SimulationConnector`

A `ConnectorMixin`-compatible connector backed entirely by an in-memory list
of STIX fixture objects.  No HTTP calls are made.

```python
from gnat.testing import SimulationConnector
from gnat.orm.indicator import Indicator

connector = SimulationConnector(trust_level="semi_trusted")

# Preload fixtures
ioc = Indicator(name="evil.example.com", pattern="[domain-name:value = 'evil.example.com']")
connector.add_fixture(ioc.to_dict())

# Standard ConnectorMixin interface works as expected
objects = connector.list_objects()         # returns [ioc.to_dict()]
obj = connector.get_object(ioc.id)        # returns ioc.to_dict()
connector.upsert_object({"type": "indicator", ...})  # appended to fixture list
connector.delete_object(ioc.id)           # removes from fixture list

# Iterate all fixtures (useful for pipeline testing)
for stix_obj in connector.iter_fixtures():
    print(stix_obj["type"], stix_obj["id"])
```

#### Error-Path Testing

```python
# Simulate connector failures for error-path tests
connector = SimulationConnector(raise_on_request=True)
# All list_objects() / get_object() calls raise GNATClientError
```

#### Budget Integration

`SimulationConnector` deducts from the active `QueryBudget` on every call,
just as a real connector would.  This lets tests verify that a pipeline's
budget arithmetic is correct without making real HTTP calls:

```python
ctx = ExecutionContext.create(
    initiated_by="test",
    domain="ingestion",
    workspace_id="test-ws",
    max_budget_units=5,
)
connector = SimulationConnector()
connector._context = ctx

# Budget is charged on each call
connector.list_objects()   # consumes COST_UNIT (1)
connector.list_objects()   # consumes 1 more
# After 5 calls, BudgetExceeded is raised
```

#### Full `ConnectorMixin` Interface

| Method | Behaviour |
|---|---|
| `authenticate()` | No-op; always succeeds |
| `health_check()` | Returns `{"status": "ok"}` |
| `list_objects()` | Returns copy of the fixture list |
| `get_object(stix_id)` | Finds by `id` field; raises `KeyError` if not found |
| `upsert_object(obj)` | Appends if new `id`; replaces if existing `id` |
| `delete_object(stix_id)` | Removes by `id`; no-op if not found |
| `to_stix(obj)` | Identity transform (returns `obj`) |
| `from_stix(stix_obj)` | Identity transform (returns `stix_obj`) |
| `add_fixture(obj)` | Test helper: pre-loads a STIX object |
| `iter_fixtures()` | Test helper: yields all current fixture objects |

### Component 2 — `ReplayRunner`

A test helper that verifies pipeline idempotency using the `execution_log`.

```python
from gnat.testing import ReplayRunner

def my_pipeline(ctx: ExecutionContext) -> list[dict]:
    connector = SimulationConnector()
    connector.add_fixture(indicator_dict)
    return connector.list_objects()

runner = ReplayRunner(pipeline_fn=my_pipeline)

# First run: executes pipeline and records execution_log entries
first_run_ids = runner.run_first(workspace_id="test-ws")

# Replay: re-executes each log entry with is_replay=True,
# asserts all expected STIX IDs appear in output
runner.replay(
    execution_log=runner.last_execution_log,
    expected_stix_ids=first_run_ids,
)
# Raises AssertionError if any expected ID is missing from the replay output
```

#### `ReplayRunner` Internals

```python
class ReplayRunner:
    def __init__(self, pipeline_fn: Callable[[ExecutionContext], list[dict]]):
        self._pipeline_fn = pipeline_fn
        self.last_execution_log: list[dict] = []

    def run_first(self, workspace_id: str = "default") -> list[str]:
        ctx = ExecutionContext.create(
            initiated_by="test-replay-runner",
            domain="ingestion",
            workspace_id=workspace_id,
        )
        results = self._pipeline_fn(ctx)
        self.last_execution_log = ctx._store.query(ctx.context_id)
        return [obj["id"] for obj in results if "id" in obj]

    def replay(
        self,
        execution_log: list[dict],
        expected_stix_ids: list[str],
    ) -> None:
        replay_ctx = ExecutionContext.create(
            initiated_by="test-replay-runner",
            domain="ingestion",
            workspace_id="default",
            is_replay=True,
        )
        results = self._pipeline_fn(replay_ctx)
        result_ids = {obj["id"] for obj in results if "id" in obj}
        missing = set(expected_stix_ids) - result_ids
        if missing:
            raise AssertionError(
                f"Replay produced different STIX IDs. Missing: {missing}"
            )
```

### Component 3 — `AgentTestHarness`

A convenience wrapper around `AgentGovernor` and `HITLGateway` that uses a
`_MockReviewService` which auto-approves all submitted review items.

```python
from gnat.testing import AgentTestHarness
from gnat.agents.governor import AgentActionType

harness = AgentTestHarness(trust_level="semi_trusted")

# Run an action through the full governance stack
result = harness.run_action(
    agent_id="test-agent",
    action_type=AgentActionType.write_stix,
    target_ref="indicator--abc123",
    impact_level="high",  # normally blocked — auto-approved by MockReviewService
)

assert result["status"] == "approved"
assert result["approved_by"] == "mock-reviewer"

# Inspect all actions recorded during the test
for action in harness.recorded_actions:
    print(action.agent_id, action.action_type, action.status)

# Assert specific governance outcomes
harness.assert_action_recorded(
    action_type=AgentActionType.write_stix,
    status="approved",
)
harness.assert_no_permission_denied()
harness.assert_rate_limit_not_exceeded()
```

#### `_MockReviewService`

The mock review service used internally by `AgentTestHarness`:

```python
class _MockReviewService:
    """Auto-approves all submitted review items for use in tests."""

    def submit(self, item_type, payload, submitter, priority="normal"):
        item_id = str(uuid4())
        return ReviewItem(
            id=item_id,
            item_type=item_type,
            payload=payload,
            submitter=submitter,
            status=ReviewStatus.APPROVED,
            submitted_at=datetime.utcnow(),
            reviewed_by="mock-reviewer",
            reviewed_at=datetime.utcnow(),
        )

    def get(self, review_id: str) -> ReviewItem:
        return ReviewItem(status=ReviewStatus.APPROVED, ...)

    def reject(self, review_id: str, reason: str, reviewer: str) -> None:
        pass   # no-op in mock
```

#### Policy Override Support

`AgentTestHarness` exposes `set_policy_override()` for testing custom
permission configurations:

```python
harness = AgentTestHarness(trust_level="untrusted_external")

# Grant a normally-blocked action for this test
harness.set_policy_override(
    agent_id="test-agent",
    action_type=AgentActionType.export,
    allowed=True,
)

result = harness.run_action(
    agent_id="test-agent",
    action_type=AgentActionType.export,
    target_ref="bundle--xyz",
    impact_level="medium",
)
assert result["status"] == "approved"
```

### Package Layout

```
gnat/testing/
├── __init__.py          # Exports: SimulationConnector, ReplayRunner, AgentTestHarness
└── simulation.py        # All three components in one module
```

The `gnat/testing/` package is part of the `[dev]` extras group and is not
included in the core install:

```toml
[project.optional-dependencies]
dev = [
    # ... existing dev deps ...
    "gnat[testing]",
]
testing = []   # gnat/testing/ is pure Python; no extra deps required
```

### Integration with Existing Fixtures

`SimulationConnector` is compatible with the existing `mock_pool_manager`
fixture.  Tests that need both HTTP-level mocking (for a real connector) and
a simulation connector (for a parallel pipeline branch) can use both in the
same test:

```python
def test_enrichment_pipeline(mock_pool_manager, minimal_config):
    real_connector = VirusTotalClient.from_config(minimal_config)
    sim_connector = SimulationConnector(trust_level="trusted_internal")
    sim_connector.add_fixture(indicator_dict)

    pipeline = EnrichPipeline(
        source=sim_connector,
        enricher=real_connector,  # HTTP calls intercepted by mock_pool_manager
    )
    result = pipeline.run(workspace_id="test")
    assert len(result.enriched) == 1
```

---

## Consequences

### Positive

- **Full pipeline tests without network or credentials:** `SimulationConnector`
  implements the complete `ConnectorMixin` interface, so any pipeline that
  accepts a connector can be tested end-to-end in a unit test with no network
  dependency.
- **Idempotency assertions are built-in:** `ReplayRunner` provides a standard,
  reusable way to verify that a pipeline produces the same STIX IDs on first
  run and replay — a previously unverifiable property.
- **Agent tests are fully deterministic:** `AgentTestHarness` with
  `_MockReviewService` removes the non-determinism introduced by human review
  queue state, making governance tests runnable in CI without any external
  state.
- **Budget testing at no extra cost:** `SimulationConnector` participates in
  `QueryBudget` accounting, so budget arithmetic can be tested without real
  HTTP calls.
- **No new runtime dependencies:** `gnat/testing/` is pure Python and
  introduces no additional packages.  It reuses existing GNAT infrastructure
  (`ExecutionContext`, `AgentGovernor`, `HITLGateway`, `ReviewItem`).

### Negative / Trade-offs

- **`SimulationConnector` does not validate STIX schema:** objects loaded via
  `add_fixture()` are stored and returned as plain dicts without STIX 2.1
  schema validation.  Tests that depend on strict STIX conformance must add
  their own validation or use the `stix-validate` extra.
- **`ReplayRunner` assumes pure-function pipelines:** pipelines that produce
  different STIX IDs for the same input (e.g. because they embed
  `datetime.utcnow()` in generated object IDs) will fail the idempotency
  assertion.  These pipelines must be refactored to accept a deterministic
  clock before they can be replay-tested.
- **`_MockReviewService` always approves:** tests that need to verify
  rejection-path behaviour must subclass `AgentTestHarness` and supply a
  custom review service.

### Deferred

- `SimulationConnector` STIX schema validation mode (using `stix2-patterns`)
- `ReplayRunner` diff output: when IDs differ between runs, show which IDs
  were added and which were removed rather than a bare set difference
- `AgentTestHarness` rejection-path helper: `set_auto_reject(action_type)`
  to configure the mock service to reject specific action types
- Pytest plugin (`conftest.py` auto-injection) to make `SimulationConnector`
  and `AgentTestHarness` available as fixtures without explicit import

---

## Alternatives Considered

### VCR Cassette Recording

The `vcrpy` library records real HTTP interactions to YAML cassette files and
replays them in subsequent test runs.  This was evaluated as an alternative to
`SimulationConnector` for full-pipeline tests.  Rejected because:

1. Connector responses vary considerably across platforms: pagination cursors,
   timestamps, and session tokens change between runs, requiring heavy cassette
   filtering that is difficult to maintain.
2. Cassettes capture the *HTTP layer*, not the *connector interface*.  A change
   to a connector's internal request structure (e.g. adding a query parameter)
   invalidates the cassette even if the connector's public API is unchanged.
3. Cassettes for 99 connectors would add significant binary content to the
   repository.

`SimulationConnector` operates at the connector interface level, above HTTP,
and requires no cassette maintenance.

### Docker-Based Integration Tests Only

Accepting that full-pipeline tests require Docker (as the existing `--run-docker`
integration suite does) was evaluated.  Rejected for this use case because:

1. Docker integration tests are slow (30–120 seconds each) and cannot serve as
   unit tests that run on every pull request.
2. They require a running Docker daemon, which is not available in all CI
   environments.
3. They test against real connector implementations (Splunk, MISP containers),
   not against the GNAT pipeline logic itself.

Docker integration tests remain the correct tool for verifying connector
authentication and platform compatibility.  `gnat/testing/` is the correct
tool for pipeline logic verification.

### Pytest Fixtures for Each Governance Component

Rather than `AgentTestHarness`, individual pytest fixtures could be registered
in `tests/conftest.py` for `AgentGovernor`, `HITLGateway`, and
`_MockReviewService`.  Rejected because:

1. Fixtures are test-file-scoped; the harness is reusable outside the test
   suite (e.g. in a REPL or notebook for interactive development).
2. Assembling three fixtures in a consistent configuration is error-prone;
   `AgentTestHarness` encapsulates the wiring and ensures consistent defaults.
3. Per-component fixtures still require each test to know the correct wiring
   order; `AgentTestHarness.run_action()` expresses intent more clearly.

The existing `conftest.py` fixtures (`mock_http_response`, `mock_pool_manager`,
`minimal_config`, `sak_client`) remain unchanged and continue to cover
HTTP-level mocking.

---

*Licensed under the Apache License, Version 2.0*

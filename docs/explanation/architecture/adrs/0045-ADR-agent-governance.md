# ADR-0045 — Agent Governance Layer (Phase 4D)

**Date:** 2026-04-09
**Status:** Accepted
**Deciders:** GNAT Platform Team

---

## Context

GNAT's AI agent layer (`gnat/agents/`) had grown substantially through Phases 3 and 4 to include
`ResearchAgent`, `ParsingAgent`, `CopilotReader`, and a family of workflow and quality agents.
Each of these agents can invoke connector actions — fetching threat intelligence, enriching
indicators, exporting STIX bundles, and triggering SOAR playbooks.

As agents gained write access, two serious gaps emerged:

1. **No permission system.** Any agent could call any connector action regardless of its origin or
   the sensitivity of the target workspace. A `ParsingAgent` used in an untrusted enrichment
   pipeline had the same effective privileges as an internally authored `ResearchAgent`.

2. **No audit trail.** Agent-originated writes were indistinguishable in the enrichment log from
   direct analyst operations. When an indicator was modified by an agent, there was no record of
   which agent did it, under what context, or whether any human had authorised the change.

The absence of a governance layer made agent deployments unsuitable for production environments
with compliance requirements (SOC 2, ISO 27001, MSSPs serving regulated verticals). Operators
had no mechanism to restrict, monitor, or rate-limit agent activity.

---

## Decision

Introduce an **`AgentGovernor`** as the authoritative policy enforcement point for all agent
actions in GNAT. Every agent action must pass through the governor before it may execute.

### `AgentActionType` Enum

Ten action types covering the full range of agent-reachable operations:

| Action Type | Description |
|---|---|
| `read_stix` | Read STIX objects from a connector or workspace |
| `write_stix` | Create or update STIX objects |
| `delete_stix` | Soft-delete STIX objects |
| `enrich` | Call enrichment dispatcher against existing objects |
| `ingest` | Run an ingest pipeline or reader |
| `export` | Trigger an export (EDL, STIX bundle, Netskope CE) |
| `trigger_playbook` | Invoke an XSOAR or external SOAR playbook |
| `manage_workspace` | Create, rename, or delete a workspace |
| `escalate` | Route a finding to the review queue or analyst channel |
| `hypothesize` | Generate AI hypotheses (read-only, no state mutation) |

### Trust Levels

Three trust levels applied to every agent at registration time:

| Trust Level | Description |
|---|---|
| `trusted_internal` | Internally authored agents, admin-signed, registry-registered |
| `semi_trusted` | Third-party or plugin agents loaded at runtime |
| `untrusted_external` | Externally supplied agents (research pipeline agents, unverified) |

### Default Permission Matrix

```
                        trusted_internal  semi_trusted  untrusted_external
read_stix               ✓                 ✓             ✓
write_stix              ✓                 ✓             ✗
delete_stix             ✓                 ✗             ✗
enrich                  ✓                 ✓             ✓
ingest                  ✓                 ✓             ✗
export                  ✓                 ✗             ✗
trigger_playbook        ✓                 ✗             ✗
manage_workspace        ✓                 ✗             ✗
escalate                ✓                 ✓             ✓
hypothesize             ✓                 ✓             ✓
```

### `AgentAction` Dataclass

Immutable record created for every checked action, whether approved or denied:

```python
@dataclass
class AgentAction:
    action_id: str          # UUID4
    agent_id: str           # registered agent identifier
    action_type: AgentActionType
    target_ref: str         # STIX ID or connector name of the target
    impact_level: str       # "low" | "medium" | "high" | "critical"
    session_id: str         # owning agent session UUID
    context_id: str | None  # workspace or execution context name
    result_json: str        # JSON-encoded outcome or error
    approved_by: str | None # reviewer ID for HITL-approved actions
    submitted_at: datetime
    executed_at: datetime | None
    status: str             # "pending" | "approved" | "denied" | "executed" | "failed"
```

### `AgentGovernor` API

Located at `gnat/agents/governor.py`:

```python
from gnat.agents.governor import AgentGovernor, AgentActionType

governor = AgentGovernor()

# Check permission — returns True/False
governor.can_act(
    agent_id="research-agent-v2",
    action_type=AgentActionType.write_stix,
    trust_level="semi_trusted",
)

# Assert permission — raises AgentPermissionDenied if denied
governor.require_can_act(
    agent_id="research-agent-v2",
    action_type=AgentActionType.export,
    trust_level="semi_trusted",
)

# Record a completed action
governor.record_action(action)

# Sliding-window rate limit — raises RateLimitExceeded on breach
governor.rate_limit_check(
    agent_id="research-agent-v2",
    window_seconds=3600,  # configurable per agent
)

# Query audit log
log = governor.get_action_log(agent_id="research-agent-v2")
all_actions = governor.get_action_log()  # all agents

# Runtime policy override — persists for the process lifetime
governor.set_policy_override(
    agent_id="custom-agent",
    action_type=AgentActionType.export,
    allowed=True,
)
```

### Exceptions

```python
from gnat.agents.governor import AgentPermissionDenied, RateLimitExceeded

# AgentPermissionDenied(agent_id, action_type, trust_level, reason)
# RateLimitExceeded(agent_id, window_seconds, call_count, limit)
```

Both inherit from `GNATClientError` so they are caught by the standard error handling path.

### HookBus Integration

`record_action()` emits a `"agent_action_recorded"` event on the global `HookBus` after
persisting to the in-memory audit log. Operators can subscribe to receive real-time action
events for external SIEM forwarding:

```python
from gnat.agents.governor import AgentGovernor
from gnat.context import HookBus

bus = HookBus.get_default()
bus.subscribe("agent_action_recorded", lambda evt: siem_client.send(evt))
```

### Database Schema

Two new tables added via Alembic migration `0006_add_agent_governance.py`:

**`agent_sessions`**

| Column | Type | Notes |
|---|---|---|
| `id` | `VARCHAR(36)` | UUID4 primary key |
| `agent_id` | `VARCHAR(200)` | registered agent identifier |
| `trust_level` | `VARCHAR(50)` | one of the three trust levels |
| `context_id` | `VARCHAR(200)` | workspace or execution context |
| `started_at` | `DATETIME` | UTC |
| `ended_at` | `DATETIME` | nullable |
| `action_count` | `INTEGER` | incremented on each `record_action()` |
| `policy_overrides_json` | `TEXT` | JSON map of per-agent overrides active at session start |

**`agent_actions`**

| Column | Type | Notes |
|---|---|---|
| `id` | `VARCHAR(36)` | UUID4 primary key |
| `session_id` | `VARCHAR(36)` | FK → `agent_sessions.id` |
| `agent_id` | `VARCHAR(200)` | denormalised for query convenience |
| `action_type` | `VARCHAR(50)` | enum value |
| `target_ref` | `VARCHAR(500)` | STIX ID or connector name |
| `impact_level` | `VARCHAR(20)` | `low` / `medium` / `high` / `critical` |
| `status` | `VARCHAR(20)` | lifecycle status |
| `approved_by` | `VARCHAR(200)` | nullable |
| `result_json` | `TEXT` | outcome payload |
| `submitted_at` | `DATETIME` | UTC |
| `executed_at` | `DATETIME` | nullable |

Composite index on `(agent_id, submitted_at)` for time-range queries on a single agent.

---

## Consequences

### Positive

- **Least-privilege enforcement:** agents that do not need write access cannot obtain it
  regardless of the code paths they call; the permission matrix is the single source of truth.
- **Immutable audit trail:** every agent action — approved or denied — is recorded with full
  context, making compliance evidence generation straightforward.
- **Rate limiting prevents runaway agents:** a misconfigured `ResearchAgent` with
  `max_calls_per_run=9999` will be stopped by the sliding-window counter before it exhausts
  API quota on a connected platform.
- **Per-deployment customisation:** `set_policy_override()` lets operators grant or restrict
  individual agents at runtime without a code change — important for MSP deployments where
  customer-specific agents need tailored permissions.
- **HookBus integration enables SIEM forwarding** at zero additional cost to the caller.

### Negative / Trade-offs

- **Slight performance overhead:** every agent action incurs a permission check and an audit
  log write. For high-frequency ingest agents this adds a small but measurable latency.
- **In-memory rate limit counter:** the sliding-window counter resets on process restart.
  Distributed deployments where multiple GNAT workers serve the same agent pool should
  configure an external Redis counter (deferred, see below).
- **Policy matrix is static at import time:** the default permission matrix is a module-level
  dict; runtime overrides apply only to the running process. Multi-process deployments must
  configure overrides identically on each worker or use the shared DB override table.

### Deferred

- Distributed rate limiting via Redis sidecar
- Per-action approval workflow (short-circuited in Phase 4D by `HITLGateway` — see ADR-0046)
- Agent registry with cryptographic signing of agent identity
- Capability-based security tokens as an alternative to trust-level categories

---

## Alternatives Considered

### Capability-Based Security Tokens

Each agent would hold a signed token listing specific capabilities (analogous to OAuth2 scopes).
Token validation would replace the trust-level lookup. This model is more granular and suitable
for multi-organisation federation, but is significantly more complex to implement and operate —
particularly for the embedded agents that run inside the same process as the pipeline. It was
deferred as a future evolution once agent federation becomes a firm requirement.

### OAuth2 Scopes Per Agent

Define a fixed set of OAuth2 scopes (`gnat:read`, `gnat:write`, `gnat:export`, etc.) and issue
per-agent tokens from a lightweight authorization server. Rejected because it introduces an
external service dependency for what is currently a single-process feature. The scope model will
be revisited if GNAT ever exposes its agent layer over a network boundary.

### Audit Logging Only (No Permission Enforcement)

Log all agent actions but do not block anything. Rejected because post-hoc detection of
unauthorised agent writes is insufficient for regulated environments — damage may occur before
the audit log is reviewed. The prevention-first model of `require_can_act()` is the correct
default; audit logging is the secondary safeguard.

### Connector-Level Guards Only

Apply permission checks at the connector's `upsert_object()` / `delete_object()` entry points
rather than in a centralised governor. Rejected because it requires every connector
implementation to carry governance logic, creates inconsistent enforcement across the 99
connectors, and cannot easily support cross-cutting policies such as rate limiting and HookBus
emission.

---

*Licensed under the Apache License, Version 2.0*

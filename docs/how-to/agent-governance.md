# How-to: Agent Governance

GNAT's agent governance layer ensures that every AI agent action is authorised,
rate-limited, audited, and — for high-impact operations — reviewed by a human before
execution.

---

## Prerequisites

- GNAT installed (`pip install gnat`)
- Optionally: `gnat/review/` configured with a `ReviewQueueStore` for HITL flows
- Optionally: XSOAR connector configured for critical action notifications

---

## Check and Enforce Permissions

```python
from gnat.agents.governor import AgentGovernor, AgentPermissionDenied
from gnat.policy.models import AgentActionType

governor = AgentGovernor()

# Check silently
can_enrich = governor.can_act(
    agent_id="research-agent-1",
    action_type=AgentActionType.ENRICH,
    trust_level="semi_trusted",
)
print(can_enrich)  # True

# Raise on denial
try:
    governor.require_can_act(
        agent_id="otx-reader",
        action_type=AgentActionType.TRIGGER_PLAYBOOK,
        trust_level="untrusted_external",
    )
except AgentPermissionDenied as e:
    print(e)  # "otx-reader (trust='untrusted_external') denied trigger_playbook"
```

### Default permission matrix

| Trust Level | Allowed Actions |
|-------------|----------------|
| `trusted_internal` | All actions (read_stix, write_stix, delete_stix, enrich, ingest, export, trigger_playbook, manage_workspace, escalate, hypothesize) |
| `semi_trusted` | read_stix, write_stix, enrich, ingest, hypothesize, escalate |
| `untrusted_external` | read_stix, enrich, hypothesize |

---

## Apply Per-Agent Overrides

Override the default matrix at runtime or via config:

```python
# Allow a specific agent to trigger playbooks despite semi_trusted level
governor.set_policy_override(
    "high-fidelity-agent",
    AgentActionType.TRIGGER_PLAYBOOK,
    allowed=True,
)

# Deny an agent from deleting STIX objects even if trust would allow it
governor.set_policy_override(
    "read-only-agent",
    AgentActionType.DELETE_STIX,
    allowed=False,
)
```

Or via INI (loaded by `AgentGovernor.from_config(cfg)`):

```ini
[agent_policy]
high-fidelity-agent.trigger_playbook = true
read-only-agent.delete_stix          = false
```

---

## Rate Limiting

```python
from gnat.agents.governor import AgentGovernor, RateLimitExceeded

governor = AgentGovernor(max_calls_per_window=50, window_seconds=60)

for i in range(55):
    try:
        governor.rate_limit_check("bulk-agent")
    except RateLimitExceeded as e:
        print(f"Rate limit hit at call {i}: {e}")
        break
```

---

## Record Actions (Audit Trail)

```python
from gnat.agents.governor import AgentAction, AgentGovernor
from gnat.policy.models import AgentActionType

governor = AgentGovernor()

action = AgentAction(
    agent_id="threat-hunter-1",
    action_type=AgentActionType.ENRICH,
    target_ref="indicator--abc123",
    impact_level="low",
    context_id=ctx.context_id,  # link to ExecutionContext
)

governor.record_action(action)

# Query audit log
all_actions = governor.get_action_log()
agent_actions = governor.get_action_log("threat-hunter-1")
```

---

## HITL (Human-in-the-Loop) Gateway

For high or critical impact actions, submit them for human review before executing:

```python
from gnat.agents.hitl import HITLGateway
from gnat.agents.governor import AgentAction
from gnat.policy.models import AgentActionType
from gnat.review.service import ReviewService
from gnat.review.store import ReviewQueueStore

# Wire to existing review queue
store = ReviewQueueStore(db_url="sqlite:///~/.gnat/gnat.db")
store.create_all()
review_service = ReviewService(store=store)

gateway = HITLGateway(
    review_service=review_service,
    approval_timeout_seconds=3600,
)

action = AgentAction(
    agent_id="incident-responder",
    action_type=AgentActionType.TRIGGER_PLAYBOOK,
    target_ref="indicator--malicious-ip",
    impact_level="high",
)

approved, review_item = gateway.evaluate(action)

if approved:
    # low/medium: auto-approved, execute immediately
    print("Action auto-approved, executing...")
else:
    # high: blocking — wait for human review
    print(f"Awaiting approval. Review ID: {review_item.id}")

    # Later, poll for status
    from gnat.review.models import ReviewStatus
    status = gateway.check_approval_status(review_item.id)
    if status == ReviewStatus.APPROVED:
        print("Approved by analyst, executing...")
    elif status == ReviewStatus.REJECTED:
        print("Rejected, action cancelled.")
```

### Impact tiers

| Impact Level | Behaviour |
|-------------|-----------|
| `low` | Auto-approved immediately; logged only |
| `medium` | Auto-approved immediately; logged only |
| `high` | Submitted to ReviewService as PENDING; blocks execution |
| `critical` | PENDING + XSOAR notification fired via `XSOARClient.upsert_object()` |

---

## Add XSOAR Notification for Critical Actions

```python
from gnat.connectors.xsoar.client import XSOARClient
from gnat.agents.hitl import HITLGateway

xsoar = XSOARClient(host="https://xsoar.example.com", api_key="...")

gateway = HITLGateway(
    review_service=review_service,
    xsoar_client=xsoar,
    approval_timeout_seconds=1800,  # 30 minutes
)
```

---

## Use AgentTestHarness in Tests

The `AgentTestHarness` provides a fully deterministic test environment — all HITL
submissions are auto-approved and all rate limits are effectively unlimited:

```python
from gnat.testing import AgentTestHarness
from gnat.agents.governor import AgentPermissionDenied
from gnat.policy.models import AgentActionType

harness = AgentTestHarness()

# Run an action end-to-end (permission check + rate limit + HITL + audit)
approved, action = harness.run_action(
    agent_id="test-agent",
    action_type=AgentActionType.ENRICH,
    target_ref="indicator--abc",
    impact_level="low",
    trust_level="semi_trusted",
)

assert approved is True
assert action.status == "approved"
assert len(harness.recorded_actions) == 1

# Test permission denial
try:
    harness.run_action(
        agent_id="restricted-agent",
        action_type=AgentActionType.TRIGGER_PLAYBOOK,
        trust_level="untrusted_external",
    )
except AgentPermissionDenied:
    print("Correctly denied")
```

---

## See Also

- [ADR-0045 — Agent Governance Layer](../explanation/architecture/adrs/0045-ADR-agent-governance.md)
- [ADR-0046 — HITL Gateway](../explanation/architecture/adrs/0046-ADR-hitl-gateway.md)
- [ADR-0049 — Testing Framework](../explanation/architecture/adrs/0049-ADR-testing-framework.md)
- [Reference: Configuration](../reference/configuration.md) — `[agent_policy]` section

---

*Licensed under the Apache License, Version 2.0*

# ADR-0046 — Human-in-the-Loop Gateway (Phase 4D)

**Date:** 2026-04-09  
**Status:** Accepted  
**Deciders:** GNAT Platform Team

---

## Context

GNAT's AI agents can now be granted write, export, playbook-trigger, and
workspace-management permissions via `AgentGovernor` (ADR-0045).  For most
trust levels and action types the governor's permission matrix is sufficient:
either the action is allowed and it executes immediately, or it is denied
outright.

However, a subset of agent actions are high-impact enough that neither
automatic approval nor outright denial is the correct policy:

- Triggering an XSOAR playbook against a live environment carries irreversible
  side effects (firewall rule changes, endpoint isolation, ticket creation).
- Workspace deletions or bulk STIX deletions are difficult to roll back.
- Escalation decisions that route findings to an incident team should carry an
  auditable human sign-off.

Prior to this ADR there was no mechanism to **pause** an agent action and hold
it in a review queue until a human operator approved or rejected it.  The
existing `gnat/review/` module contained a fully implemented `ReviewService`
and `ReviewQueueStore`, but they were reachable only from the report lifecycle
(ADR-0034); agents had no bridge to that infrastructure.

The result was an all-or-nothing choice: either grant agents unrestricted
write access, or block the action class entirely.  Neither option is suitable
for production deployments where agents need occasional high-impact capability
under controlled conditions.

---

## Decision

Introduce **`HITLGateway`** (`gnat/agents/hitl.py`) as a thin policy bridge
between `AgentGovernor` and `gnat/review/service.py`.  Every agent action
evaluated by `AgentGovernor.require_can_act()` is additionally evaluated by
`HITLGateway.evaluate()` before it may execute.

### Impact Tier Classification

Impact level is a field on `AgentAction` (see ADR-0045) set by the agent at
action creation time.  `HITLGateway` routes on that field:

| Impact Level | Routing Policy | Review Queue Entry |
|---|---|---|
| `low` | Auto-approved, execution proceeds immediately | None (logged only) |
| `medium` | Auto-approved, execution proceeds immediately | None (logged only) |
| `high` | Blocked pending human approval via `ReviewService` | `PENDING` `ReviewItem` created |
| `critical` | Blocked pending human approval; XSOAR playbook notification sent | `PENDING` `ReviewItem` created + XSOAR alert |

### `HITLGateway` API

Located at `gnat/agents/hitl.py`:

```python
from gnat.agents.hitl import HITLGateway
from gnat.agents.governor import AgentAction, AgentActionType

gateway = HITLGateway()

# Primary entry point — called by AgentGovernor after permission check passes
approved, review_item = gateway.evaluate(action)
if not approved:
    # action is PENDING; agent should poll or await human decision
    print(f"Action {action.action_id} awaiting review: {review_item.id}")

# Submit a specific action to the review queue explicitly
review_item = gateway.submit_for_approval(action)

# Poll queue for a decision
from gnat.review.service import ReviewStatus
status = gateway.check_approval_status(review_item.id)
# status is one of ReviewStatus.PENDING, APPROVED, REJECTED

# Auto-approve (used in test harnesses and auto-escalation policies)
gateway.auto_approve_pending(review_item.id, reviewer="auto-policy")
```

### `evaluate()` Logic

```python
def evaluate(
    self, action: AgentAction
) -> tuple[bool, ReviewItem | None]:
    if action.impact_level in ("low", "medium"):
        self._log_auto_approved(action)
        return True, None

    review_item = self.submit_for_approval(action)

    if action.impact_level == "critical":
        self._notify_xsoar(action, review_item)

    return False, review_item
```

The action is **blocked** (returns `False`) for `high` and `critical` levels
regardless of the trust level of the agent.  Even a `trusted_internal` agent
must pause for a human reviewer if its action carries `impact_level="critical"`.

### `submit_for_approval()` — ReviewService Bridge

`submit_for_approval()` converts the `AgentAction` dataclass into a
STIX-compatible metadata dict and delegates to `ReviewService.submit()`:

```python
def submit_for_approval(self, action: AgentAction) -> ReviewItem:
    payload = {
        "type": "agent-action-review",
        "action_id": action.action_id,
        "agent_id": action.agent_id,
        "action_type": action.action_type.value,
        "target_ref": action.target_ref,
        "impact_level": action.impact_level,
        "context_id": action.context_id,
        "submitted_at": action.submitted_at.isoformat(),
    }
    return self._review_service.submit(
        item_type="agent_action",
        payload=payload,
        submitter=action.agent_id,
        priority="high" if action.impact_level == "critical" else "normal",
    )
```

No new storage is introduced — `ReviewItem` and `ReviewQueueStore` from
`gnat/review/` are used as-is.

### Approval Timeout

`check_approval_status()` enforces a configurable timeout:

```python
def check_approval_status(self, review_id: str) -> ReviewStatus:
    item = self._review_service.get(review_id)
    elapsed = (datetime.utcnow() - item.submitted_at).total_seconds()
    if (
        item.status == ReviewStatus.PENDING
        and elapsed > self._approval_timeout_seconds
    ):
        self._review_service.reject(
            review_id,
            reason="auto-rejected: approval timeout exceeded",
            reviewer="hitl-gateway",
        )
        return ReviewStatus.REJECTED
    return item.status
```

Default `approval_timeout_seconds` is `3600` (one hour).  Configurable via the
`[agents]` INI section:

```ini
[agents]
hitl_approval_timeout_seconds = 3600
hitl_xsoar_playbook_id = P-GNAT-AGENT-ALERT
```

### XSOAR Notification for Critical Actions

For `critical` impact actions, `HITLGateway` calls the XSOAR connector's
`upsert_object()` with a pre-formed STIX `incident` custom object:

```python
def _notify_xsoar(
    self, action: AgentAction, review_item: ReviewItem
) -> None:
    incident = {
        "type": "x-gnat-incident",
        "name": f"HITL Review Required: {action.action_type.value}",
        "severity": "high",
        "agent_id": action.agent_id,
        "action_id": action.action_id,
        "review_id": review_item.id,
        "target_ref": action.target_ref,
    }
    try:
        self._xsoar_client.upsert_object(incident)
    except Exception as exc:
        # Notification failure must never block the review queue entry
        logger.warning("XSOAR notification failed: %s", exc)
```

The XSOAR client is a `trusted_internal` connector instance constructed from
the INI `[xsoar]` section.  If XSOAR is not configured, the notification is
skipped and a warning is logged; the `ReviewItem` is still created.

### Sequence Diagram

```
Agent                  AgentGovernor          HITLGateway          ReviewService
  |                         |                      |                     |
  |── require_can_act() ──► |                      |                     |
  |                         |── evaluate(action) ► |                     |
  |                         |                      |── submit() ────────►|
  |                         |                      |◄── ReviewItem ──────|
  |                         |                      |                     |
  |                         |  [critical only]      |                     |
  |                         |                      |── _notify_xsoar()   |
  |                         |                      |   (XSOARClient)     |
  |                         |◄── (False, item) ────|                     |
  |◄── AgentActionPending ──|                      |                     |
  |                         |                      |                     |
  |   [human approves]      |                      |                     |
  |── check_approval() ─────────────────────────► |── get(review_id) ──►|
  |◄── APPROVED ─────────────────────────────────── |◄── ReviewStatus ───|
```

---

## Consequences

### Positive

- **No runaway high-impact actions:** agents cannot execute playbook triggers,
  workspace deletions, or bulk STIX writes without a human in the loop,
  regardless of their trust level.
- **Zero new storage infrastructure:** the review queue already existed in
  `gnat/review/`.  `HITLGateway` is a pure orchestration layer with no new
  tables or persistence concerns.
- **XSOAR users receive actionable alerts:** operators who rely on XSOAR as
  their SOAR console see critical agent actions appear as incidents immediately,
  without requiring a separate notification integration.
- **Timeout prevents indefinite blocking:** auto-rejection after one hour
  ensures that a missed review does not permanently block an agent session.
- **Testable in isolation:** `HITLGateway` accepts a `review_service` and
  `xsoar_client` in its constructor, enabling full injection of test doubles.

### Negative / Trade-offs

- **Agents must poll or wait for approval:** there is no push-based callback
  mechanism.  Agents that need a fast response for `high`-impact actions must
  implement a polling loop or be designed to suspend and resume.
- **Timeout is process-local:** the timeout check runs inside
  `check_approval_status()`, which the agent must call.  If the agent process
  restarts, in-flight pending reviews are not automatically expired; a
  background sweep task is needed for production deployments (deferred).
- **Single XSOAR integration point:** critical notifications only reach XSOAR
  in this implementation.  Other SOAR platforms (Splunk SOAR, Palo Alto XSIAM)
  require additional notification adapters (deferred).

### Deferred

- Background sweep task to expire timed-out `PENDING` reviews independently of
  agent polling
- Multi-SOAR notification adapters (Splunk SOAR, Tines, Torq)
- Webhook-based push approval for non-XSOAR environments (e.g. Slack approval
  buttons via the Discord/Slack connectors)
- Role-based approval routing: routing `critical` actions to a named reviewer
  group rather than the global queue

---

## Alternatives Considered

### Rebuild a Dedicated HITL Queue

A purpose-built queue store separate from `gnat/review/` was considered to
avoid coupling agent governance to the report review subsystem.  Rejected
because `ReviewService` and `ReviewQueueStore` already implement exactly the
required semantics (item submission, status polling, approval/rejection,
timeout), and duplication would create two review mechanisms that diverge over
time.  The bridge pattern costs fewer than 120 lines of code.

### Email-Only Notification

Sending an email to a configured address for `high` and `critical` actions was
prototyped.  Rejected because email provides no structured approval path: the
reviewer has no UI from which to approve or reject the action back into the
system.  Notifications via XSOAR (and future adapters) provide a structured
approval workflow.

### Synchronous Approval via Long-Poll

Blocking the agent's calling thread in a long-poll loop until the review is
resolved was considered.  Rejected because it ties up a thread for the full
approval window (up to one hour by default) and makes the system unresponsive
to cancellation.  The asynchronous poll-or-suspend model is more appropriate
for an embedded agent runtime.

### Trust-Level Exemption for `trusted_internal`

A proposal to exempt `trusted_internal` agents from HITL checks for `high`
impact actions was considered.  Rejected on security grounds: trust level
reflects the provenance of the agent code, not the risk of the target action.
Even a fully trusted agent should not autonomously trigger a production SOAR
playbook without a human sign-off.

---

*Licensed under the Apache License, Version 2.0*

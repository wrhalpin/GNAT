# ConfirmationBroker: Human-in-the-Loop Control Flow Gates

## Overview

The **ConfirmationBroker** is a framework for pausing sensitive or irreversible agent actions before they execute, waiting for analyst approval, and recording the decision.

It answers: *"This action is important. Should I really do it?"*

### ConfirmationBroker vs ConfidenceFilter

Both are gates on agent output, but they operate at different levels:

| Aspect | ConfidenceFilter | ConfirmationBroker |
|--------|---|---|
| **Gate type** | Data-flow | Control-flow |
| **When** | Before export/promotion | Before action execution |
| **Trigger** | Confidence score | Scope + policy |
| **Example** | "Skip exporting this if confidence < 70%" | "Pause before publishing report" |

A single action can trigger both gates:
1. Action executes → generates STIX objects
2. Objects checked against ConfidenceFilter (data gate)
3. If promoted → ConfirmationBroker checks (control gate)

## Key Concepts

### Scopes

Scopes are **dotted identifiers** that name sensitive actions:

```
library.promote              Promote research from workspace to library
report.publish              Publish report (irreversible state change)
connector.write.<key>        Write to a specific connector
connector.delete.<key>       Delete from a specific connector
dissemination.taxii.publish Make intelligence visible in TAXII
dissemination.webhook.<name> Outbound webhook notification
huntgnat.deploy             Deploy a hunt package
```

Scopes use prefix matching with `.*` wildcard:
- `connector.write.*` matches `connector.write.threatq`, `connector.write.aws`, etc.
- `dissemination.webhook.*` matches any webhook target

### Policies

A **policy** maps a scope to an **action**. Policies are defined in `config.ini`:

```ini
[confirmation.policies]
; Irreversible actions always require lift
report.publish = prompt
huntgnat.deploy = prompt
connector.delete.* = prompt
library.promote = prompt

; Pre-approved for development workflows
agent.research.run = auto_approve
rules.engine.run = auto_approve

; Explicitly deny (should never reach broker)
connector.delete.gnat_remote = auto_deny
```

**Actions:**
- `auto_approve` — Execute without human lift
- `auto_deny` — Block immediately
- `prompt` — Wait for human decision; timeout = denial
- `prompt_timeout_approve` — Wait for human; timeout = approval
- `prompt_timeout_deny` — Wait for human; timeout = denial (default, safe)

First matching policy wins. If no policy matches, fall back to `default_action` (default: `prompt_timeout_deny`).

### Principal Context

Requests carry a `principal_type` (analyst vs system):

```python
# Interactive analyst session
req = ConfirmationRequest(
    scope="library.promote",
    principal_type="analyst",  # User at terminal
    ...
)

# Scheduled job
req = ConfirmationRequest(
    scope="agent.research.run",
    principal_type="system",  # Cron / background task
    ...
)
```

Policies can distinguish: e.g., `agent.research.run = auto_approve` for system, but `prompt` for analyst.

## Broker Workflow

```
request(req)
    │
    ├─→ PolicyEngine.decide(req)
    │   ├─ Matches auto_approve? → Return AUTO_APPROVED
    │   ├─ Matches auto_deny? → Return AUTO_DENIED
    │   └─ Matches prompt*? → Continue to backend
    │
    ├─→ Log request to audit trail
    │
    ├─→ Backend.prompt(req)  [if not auto-decided]
    │   ├─ CLIBackend: Interactive terminal prompt
    │   ├─ DashboardBackend: Web UI / REST+WebSocket
    │   └─ RecordingBackend: Test fixture (no actual prompt)
    │
    ├─→ Wrap outcome in ConfirmationDecision
    │
    ├─→ Log decision to audit trail
    │
    └─→ Return decision
       (or raise ConfirmationDenied if denied)
```

## Audit Trail

All requests and decisions are logged to an append-only JSONL file:

```json
{"event": "requested", "timestamp": "2026-05-04T14:30:00", "request_id": "...", "scope": "library.promote", "agent": "ResearchAgent", "workspace": "apt29-q2", "risk": "medium", ...}
{"event": "decided", "timestamp": "2026-05-04T14:30:15", "request_id": "...", "outcome": "approved", "decided_by": "analyst", "note": "Q2 promotion pass"}
```

Query the audit log:
```python
audit_log = ConfirmationAuditLog("~/.gnat/confirmation_audit.jsonl")
events = audit_log.get_workspace_history("apt29-q2")
for event in events:
    print(f"{event['event']}: {event}")
```

## Backend Implementations

### AutoApproveBackend

Auto-approves all requests. **Test/CI only** — refuses to load if `GNAT_ENV` is not `test`, `ci`, or `dev`.

```python
# In tests
os.environ["GNAT_ENV"] = "test"
backend = AutoApproveBackend()
broker = ConfirmationBroker(policy_engine, backend, audit_log)
# All requests approved; still audited
```

### NullBackend

Denies all requests. **Safe default** if backend can't be loaded.

### CLIBackend

Interactive prompt at the terminal. Useful for development and scheduled jobs running interactively.

```
[CONFIRM] ResearchAgent wants to: promote
  Workspace:  apt29-q2
  Scope:      library.promote
  Risk:       medium
  Reason:     Promote workspace to library
  Subject:    {"topic": "APT29", "object_count": 12}
  Timeout:    300s
[a]pprove / [d]eny / [n]ote-and-approve / [N]ote-and-deny: a
```

### DashboardBackend

Web-based confirmation via REST + WebSocket. Stores pending requests in memory; web handler resolves via `/api/confirmations/{request_id}/decide` endpoint.

Synchronous `prompt()` blocks on an `asyncio.Future` until the analyst decides or timeout elapses.

### RecordingBackend

Test fixture that records all prompts without actually prompting. Returns a configurable outcome (APPROVED or DENIED).

```python
backend = RecordingBackend(ConfirmationOutcome.APPROVED)
broker.request(req)
backend.assert_requested("library.promote")
```

## Integration Points

### @requires_confirmation Decorator

Gate any function with a single decorator:

```python
from gnat.agents.confirmation import requires_confirmation

@requires_confirmation(
    scope="library.promote",
    risk="medium",
    subject_from=lambda args, kw: {"topic": kw["topic"]},
    reason="Promoting to library",
    workspace=lambda args, kw: kw["workspace"].name,
)
def promote(self, workspace, topic, researcher, note=""):
    ...

# Calling promote() will:
# 1. Build a ConfirmationRequest
# 2. Check ConfirmationBroker
# 3. If denied, raise ConfirmationDenied
# 4. If approved, proceed
```

Works with both sync and async functions.

### ResearchLibrary.promote()

```python
lib.promote(
    workspace=my_ws,
    topic="APT29",
    researcher="analyst1",
    note="C2 infra + CVEs",
)
# Blocked by broker if policy requires lift
```

### ReportService.publish()

```python
service.publish(report_id, changed_by="analyst@example.com")
# State transition APPROVED → PUBLISHED requires confirmation
```

### Future: BaseClient.call(allow_write=True)

```python
client.call("upsert_object", "indicator", payload, allow_write=True)
# write-classified calls checked against connector.write.* scopes
```

## Configuration

### INI File Template

```ini
[confirmation]
backend = cli
default_action = prompt_timeout_deny
default_timeout_seconds = 300
audit_log_path = ~/.gnat/confirmation_audit.jsonl

[confirmation.policies]
; Require lift for irreversible actions
report.publish = prompt
huntgnat.deploy = prompt
connector.delete.* = prompt
library.promote = prompt

; Pre-approved for development
agent.research.run = auto_approve
rules.engine.run = auto_approve

; Explicitly deny (safety net)
connector.delete.gnat_remote = auto_deny
```

### Backend Selection

- `backend = cli` — Interactive terminal prompt
- `backend = dashboard` — Web UI (requires FastAPI integration)
- `backend = auto` — Auto-approve (test/ci only)
- `backend = null` — Auto-deny (safe default if missing)

## Error Handling

### ConfirmationDenied

Raised when a request is denied:

```python
from gnat.agents.confirmation import ConfirmationDenied

try:
    lib.promote(ws, topic="APT29", researcher="analyst1")
except ConfirmationDenied as e:
    print(f"Denied: {e.decision.note}")
    print(f"Outcome: {e.decision.outcome.value}")
    # Agent can log, retry, or escalate
```

### ConfirmationTimeout

Raised when backend doesn't respond in time:

```python
from gnat.agents.confirmation import ConfirmationTimeout

try:
    broker.request(req)
except ConfirmationTimeout:
    # Timeout policy determines outcome (deny by default)
```

## Design Rationale

- **Single analyst per workspace** — No RBAC, no delegation. Simpler model, adequate for analyst-owned workflows.
- **Per-workspace config** — Policies live in INI, same loading path as connector credentials. No additional system.
- **Append-only audit** — Immutable log for compliance. External logrotate handles retention.
- **Pluggable backends** — Same backend pattern as SecretsBroker. Easy to add new prompt mechanisms (Slack, email, etc.).
- **Mirrors SecretsBroker design** — Consistency across agent layer infrastructure.
- **Fail closed by default** — Unknown scopes timeout and deny, forcing explicit policy edits.
- **No bypass mechanism** — Even emergencies go through AutoApproveBackend and get audited.

## What v1 Does NOT Do

- No multi-principal approval chains
- No persistence of pending requests across process restart (timeout = denial)
- No GUI for policy editing (edit INI, restart broker)
- No batched approvals ("approve all 12 in this run")
- No external IdP integration (Okta / Entra)
- No rate limiting on prompts
- No automatic policy learning

These are candidates for v2.

## See Also

- [How to Configure Confirmation Policies](../how-to/configure-confirmation-policies.md)
- [ConfirmationBroker API Reference](../../reference/confirmation-broker.md)

# How to Configure Confirmation Policies

## Quick Start

Add a `[confirmation]` section to `~/.gnat/config.ini`:

```ini
[confirmation]
backend = cli
audit_log_path = ~/.gnat/confirmation_audit.jsonl

[confirmation.policies]
library.promote = prompt
report.publish = prompt
connector.delete.* = prompt
```

Then restart the broker and sensitive actions will pause for analyst approval.

## Step 1: Choose Your Backend

The backend handles how prompts are presented to analysts.

### For Development

Use `cli` (terminal prompt):

```ini
[confirmation]
backend = cli
```

Analysts see an interactive prompt:
```
[CONFIRM] ResearchAgent wants to: promote
  Workspace:  my-workspace
  Scope:      library.promote
  [a]pprove / [d]eny / [n]ote-and-approve: 
```

### For Web Users

Use `dashboard` (REST + WebSocket):

```ini
[confirmation]
backend = dashboard
```

Pending requests appear in the web dashboard at `/api/confirmations/pending`.

### For Tests/CI

Use `auto` (auto-approve):

```ini
[confirmation]
backend = auto
```

All requests are approved automatically; still audited.

## Step 2: Define Policies

Under `[confirmation.policies]`, map scope patterns to actions:

```ini
[confirmation.policies]
; Exact match: library.promote scope only
library.promote = prompt

; Wildcard: all connector deletes
connector.delete.* = prompt

; Auto-approve for development
agent.research.run = auto_approve

; Auto-deny as safety net
connector.delete.gnat_remote = auto_deny
```

**Actions:**
- `prompt` — Wait for human decision (timeout = deny)
- `prompt_timeout_approve` — Wait; timeout = approve
- `prompt_timeout_deny` — Wait; timeout = deny
- `auto_approve` — Always approve without asking
- `auto_deny` — Always deny immediately

## Step 3: Set Defaults

If a scope doesn't match any policy, fall back to `default_action`:

```ini
[confirmation]
backend = cli
default_action = prompt_timeout_deny    ; Safe: unknown scopes deny on timeout
```

Options: `auto_approve`, `auto_deny`, `prompt*`

## Complete Example

### Development Workflow

```ini
[confirmation]
backend = cli
default_action = prompt_timeout_deny
default_timeout_seconds = 300
audit_log_path = ~/.gnat/confirmation_audit.jsonl

[confirmation.policies]
; Always require lift for irreversible actions
report.publish = prompt
huntgnat.deploy = prompt
connector.delete.* = prompt
library.promote = prompt

; Pre-approve for development workflows
agent.research.run = auto_approve
rules.engine.run = auto_approve

; Safety net: explicitly deny risky scopes
connector.delete.production_api = auto_deny
dissemination.taxii.publish = prompt
```

### Production Workflow

```ini
[confirmation]
backend = dashboard
default_action = prompt_timeout_deny
default_timeout_seconds = 600
audit_log_path = /var/log/gnat/confirmation_audit.jsonl

[confirmation.policies]
; Everything irreversible requires web dashboard lift
report.publish = prompt
library.promote = prompt
connector.delete.* = prompt
connector.write.* = prompt
dissemination.taxii.publish = prompt
huntgnat.deploy = prompt

; Only auto-approve low-risk agent operations
agent.research.run = auto_approve

; Nothing else auto-approves in production
```

### Testing

```ini
[confirmation]
backend = auto
default_action = auto_approve

[confirmation.policies]
; All policies must be explicit in tests; no wildcards
library.promote = auto_approve
report.publish = auto_approve
connector.write.test = auto_approve
```

## Common Patterns

### Staged Approval

Require lift for public dissemination but not internal research:

```ini
[confirmation.policies]
; Internal — pre-approve
library.promote = auto_approve
agent.research.run = auto_approve

; External — require lift
dissemination.taxii.publish = prompt
dissemination.webhook.* = prompt
report.publish = prompt
```

### Connector-Specific Gates

Different policies for different connectors:

```ini
[confirmation.policies]
; Trusted connectors: auto-approve writes
connector.write.internal_api = auto_approve
connector.write.threatq = auto_approve

; External connectors: require lift
connector.write.virustotal = prompt
connector.delete.* = prompt    ; All deletes require lift
```

### Safe Default with Exceptions

Auto-approve most things, but gate sensitive operations:

```ini
[confirmation]
default_action = auto_approve    ; Default: no lift needed

[confirmation.policies]
; Exceptions: these require lift
connector.delete.* = prompt
report.publish = prompt
dissemination.taxii.publish = prompt
huntgnat.deploy = prompt
```

## Audit Trail

All confirmations are logged to `audit_log_path` (default: `~/.gnat/confirmation_audit.jsonl`):

```json
{"event": "requested", "timestamp": "2026-05-04T14:30:00", "request_id": "abc123", "scope": "library.promote", "agent": "ResearchAgent", "workspace": "apt29", ...}
{"event": "decided", "timestamp": "2026-05-04T14:30:15", "request_id": "abc123", "outcome": "approved", "decided_by": "analyst", "note": "Verified IOCs"}
```

Query the audit log:

```python
from gnat.agents.confirmation import ConfirmationAuditLog

log = ConfirmationAuditLog("~/.gnat/confirmation_audit.jsonl")

# All decisions for a workspace
events = log.get_workspace_history("apt29")
for evt in events:
    print(f"{evt['event']}: {evt['outcome']}")

# Summary for compliance
summary = log.get_audit_summary("apt29")
print(f"Approved: {summary['approved']}, Denied: {summary['denied']}")
```

External tools (Splunk, datadog, etc.) can ingest the JSONL directly.

## Timeout Behavior

Timeouts are determined by the action in the matched policy:

| Action | Timeout Behavior |
|--------|---|
| `prompt` | Timeout = DENIED |
| `prompt_timeout_approve` | Timeout = APPROVED |
| `prompt_timeout_deny` | Timeout = DENIED |
| `auto_approve` | No timeout (auto-approved immediately) |
| `auto_deny` | No timeout (auto-denied immediately) |

Default timeout is 300 seconds. Override per scope if needed (TODO: per-scope timeout configuration):

```ini
[confirmation]
default_timeout_seconds = 600
```

## Troubleshooting

### "Confirmation timed out"

Backend didn't respond within `timeout_seconds`. Common causes:
- Analyst was away
- Analyst closed terminal / lost WebSocket connection
- System overload

Check audit trail to see when requested / decided.

### "Confirmation denied"

Action was explicitly denied by policy or analyst. Options:
- Update policy if this is a false positive
- Add analyst note via dashboard to understand reason
- Escalate to administrator

### "Configuration not found"

Broker defaults to NullBackend (deny-all) if `[confirmation]` section is missing. Add it to `config.ini`.

### Policy isn't matching

Remember:
- Scope patterns use prefix matching only: `connector.write.*` matches `connector.write.threatq` but not `connector.writeable`.
- Policies are evaluated top-to-bottom; first match wins.
- If no policy matches, `default_action` is used.

Debug by checking what scope is actually being requested:

```python
from gnat.agents.confirmation import ConfirmationAuditLog

log = ConfirmationAuditLog("~/.gnat/confirmation_audit.jsonl")
events = log.read_events()
for evt in events:
    if evt['event'] == 'requested':
        print(f"Scope: {evt['scope']}, Matched action: ?")
```

## Testing

Use RecordingBackend in tests:

```python
from gnat.agents.confirmation.backends.recording import RecordingBackend
from gnat.agents.confirmation import ConfirmationBroker, ConfirmationOutcome
from gnat.agents.confirmation.policy import PolicyEngine
from gnat.agents.confirmation.audit import ConfirmationAuditLog
import tempfile

backend = RecordingBackend(ConfirmationOutcome.APPROVED)
policies = {"library.promote": "prompt"}
engine = PolicyEngine(policies)
audit = ConfirmationAuditLog(tempfile.mktemp())
broker = ConfirmationBroker(engine, backend, audit)

# Exercise code that calls broker
lib.promote(ws, topic="APT29", researcher="analyst1")

# Assert what was requested
backend.assert_requested("library.promote", action="promote")
```

Or use AutoApproveBackend for full integration tests:

```python
import os
os.environ["GNAT_ENV"] = "test"

# Broker will use AutoApproveBackend
lib.promote(ws, topic="APT29", researcher="analyst1")
# Test passes
```

## Next Steps

- Review the [ConfirmationBroker explanation](../explanation/confirmation-broker.md)
- Check audit logs regularly: `tail -f ~/.gnat/confirmation_audit.jsonl`
- Adjust policies based on analyst workflows

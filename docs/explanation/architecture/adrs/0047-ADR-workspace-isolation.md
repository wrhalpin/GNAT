# ADR-0047 — Workspace Trust Boundary Enforcement (Phase 4E)

**Date:** 2026-04-09  
**Status:** Accepted  
**Deciders:** GNAT Platform Team

---

## Context

GNAT workspaces are the primary isolation unit for multi-tenant and
multi-classification deployments.  Each workspace holds a set of STIX objects,
an enrichment log, and configuration for the connectors that may interact with
it.

Prior to this ADR, workspace isolation was **logical only**: the workspace ID
scoped database queries, but there was no enforcement mechanism preventing a
connector from writing into a workspace that it was not supposed to touch.  The
following scenarios had no protection:

1. An `untrusted_external` connector loading community threat feeds writes
   enriched indicators into a `trusted_internal` workspace that holds
   classified government-sourced intelligence.  The commingling contaminates
   the provenance chain.

2. An MSSP deployment with multiple customer tenants assigns each tenant their
   own workspace.  A connector instance shared across tenants (e.g. a VirusTotal
   client configured with the MSSP's API key) reads objects from workspace A and
   enriches them into workspace B.

3. A `semi_trusted` plugin agent (ADR-0045) is granted `write_stix` permission
   but should only write to a sandbox workspace, not to the production
   workspace.  There is no way to express this constraint.

Connector trust levels are declared as class-level attributes (`TRUST_LEVEL`)
since ADR-0039, and agent trust levels are registered with `AgentGovernor`
since ADR-0045.  The missing piece was a mechanism to declare, on the
**workspace** side, which trust levels and connector identities are permitted
to interact with it.

---

## Decision

Extend the `workspaces` database table and `Workspace` ORM class with two new
fields that declare the workspace's trust boundary, then enforce that boundary
at connector access time.

### Database Schema Extension

Alembic migration `0007_add_workspace_trust_boundary.py` adds two columns to
the existing `workspaces` table:

| Column | Type | Default | Notes |
|---|---|---|---|
| `trust_boundary` | `VARCHAR(50)` | `'semi_trusted'` | Minimum trust level required to access this workspace |
| `allowed_connector_refs` | `TEXT` | `'[]'` | JSON array of permitted connector class names; empty list means all connectors at or above `trust_boundary` are permitted |

Both columns are nullable at the database level for backward compatibility with
existing rows; application code treats `NULL` as the defaults shown above.

```sql
-- Migration 0007 (excerpt)
ALTER TABLE workspaces
    ADD COLUMN trust_boundary VARCHAR(50) NOT NULL DEFAULT 'semi_trusted';

ALTER TABLE workspaces
    ADD COLUMN allowed_connector_refs TEXT NOT NULL DEFAULT '[]';

CREATE INDEX ix_workspaces_trust_boundary ON workspaces (trust_boundary);
```

### `Workspace` ORM Changes

`WorkspaceModel` (SQLAlchemy) gains the two mapped columns.  The `Workspace`
domain class gains corresponding attributes and one new method:

```python
@dataclass
class Workspace:
    # ... existing fields ...
    trust_boundary: str = "semi_trusted"
    allowed_connector_refs: list[str] = field(default_factory=list)

    def check_connector_trust(self, connector: object) -> None:
        """
        Raise PermissionError if `connector` is not permitted to access
        this workspace.

        Checks two conditions in order:
        1. The connector's TRUST_LEVEL rank must be >= trust_boundary rank.
        2. If allowed_connector_refs is non-empty, the connector's class name
           must appear in the list.

        Parameters
        ----------
        connector : object
            Any connector instance that has a TRUST_LEVEL class variable.

        Raises
        ------
        PermissionError
            If the connector does not satisfy the workspace trust boundary.
        """
        connector_trust = getattr(type(connector), "TRUST_LEVEL", "untrusted_external")
        if _trust_rank(connector_trust) < _trust_rank(self.trust_boundary):
            self._log_violation(connector, "trust_level_insufficient")
            raise PermissionError(
                f"Connector '{type(connector).__name__}' has trust level "
                f"'{connector_trust}', but workspace '{self.workspace_id}' "
                f"requires '{self.trust_boundary}' or higher."
            )
        if self.allowed_connector_refs:
            connector_name = type(connector).__name__
            if connector_name not in self.allowed_connector_refs:
                self._log_violation(connector, "connector_not_in_allowlist")
                raise PermissionError(
                    f"Connector '{connector_name}' is not in the allowlist "
                    f"for workspace '{self.workspace_id}'."
                )
```

### Trust Rank Ordering

```python
_TRUST_RANK: dict[str, int] = {
    "untrusted_external": 0,
    "semi_trusted":       1,
    "trusted_internal":   2,
}

def _trust_rank(level: str) -> int:
    return _TRUST_RANK.get(level, 0)
```

The ordering is: `trusted_internal` > `semi_trusted` > `untrusted_external`.
A workspace with `trust_boundary = "trusted_internal"` rejects connectors at
`semi_trusted` or `untrusted_external` even if those connectors are otherwise
granted `write_stix` by `AgentGovernor`.

### Enforcement Points

`check_connector_trust()` is called in two locations:

1. **`Workspace._init_store()`** — at workspace initialisation, when a
   connector is bound to the workspace for the first time.
2. **`IngestPipeline.run()`** — immediately before the first `upsert_object()`
   call, after `ExecutionContext` has been established.

Both call sites catch `PermissionError`, log the violation to `execution_log`
as a `security_event` row (see ADR-0039), and re-raise.

### Configuring Workspace Trust Boundaries

Workspace trust boundaries are set at workspace creation time via the `Workspace`
API or the CLI:

```python
from gnat.context.workspace import Workspace

# Create a high-trust workspace that only accepts VirusTotal and CrowdStrike
ws = Workspace.create(
    name="classified-intel",
    trust_boundary="trusted_internal",
    allowed_connector_refs=["VirusTotalClient", "CrowdStrikeClient"],
)

# Update an existing workspace's trust boundary
ws = Workspace.load("production")
ws.trust_boundary = "semi_trusted"
ws.allowed_connector_refs = []   # any semi_trusted or higher connector is fine
ws.save()
```

CLI equivalent:

```bash
gnat workspace create classified-intel \
    --trust-boundary trusted_internal \
    --allow-connector VirusTotalClient \
    --allow-connector CrowdStrikeClient

gnat workspace set-trust production --trust-boundary semi_trusted
```

### Violation Logging

Every `PermissionError` raised by `check_connector_trust()` is written to the
`execution_log` table as a `security_event`:

```python
def _log_violation(self, connector: object, reason: str) -> None:
    self._ctx_store.append_event(
        context_id=self._active_context_id,
        event_type="security_event",
        metadata={
            "violation": "workspace_trust_boundary",
            "workspace_id": self.workspace_id,
            "trust_boundary": self.trust_boundary,
            "connector": type(connector).__name__,
            "connector_trust": getattr(type(connector), "TRUST_LEVEL", "unknown"),
            "allowed_connector_refs": self.allowed_connector_refs,
            "reason": reason,
        },
    )
```

These rows are queryable alongside all other execution context events, making
boundary violations visible in the same audit trail as agent permission denials
(ADR-0045) and data lineage events (ADR-0038).

### Default Behaviour (Backward Compatibility)

Existing workspaces that do not have `trust_boundary` set receive
`'semi_trusted'` from the migration default.  This means all `semi_trusted`
and `trusted_internal` connectors continue to work without any configuration
change.  `untrusted_external` connectors (community feed readers, OSINT
scrapers) are blocked from existing workspaces unless the boundary is
explicitly lowered to `'untrusted_external'`.

This is a deliberate, slightly breaking default: if any existing deployment
uses an `untrusted_external` connector to write into a workspace, it will begin
receiving `PermissionError` after the migration.  The operator must explicitly
set `trust_boundary = "untrusted_external"` for those workspaces to restore
prior behaviour.  This is the correct security posture: the old behaviour was
unintentionally permissive.

---

## Consequences

### Positive

- **Trust-aware workspace isolation:** the workspace itself declares what it
  trusts, rather than relying solely on the permission matrix in
  `AgentGovernor`.  This enables a defence-in-depth model where both the action
  policy and the target resource enforce trust constraints independently.
- **Zero-trust workspaces are possible:** a workspace with
  `trust_boundary = "trusted_internal"` and a non-empty `allowed_connector_refs`
  list will reject every connector that is not explicitly named — suitable for
  classified or high-value intelligence stores.
- **MSSP tenancy is enforceable:** each customer workspace can be given an
  allowlist of their specific connector instances, preventing cross-tenant
  write-through.
- **Violations are auditable:** every blocked access is logged as a
  `security_event` in `execution_log`, giving operators a clear record of
  attempted boundary crossings.
- **Backward-compatible default:** the `'semi_trusted'` default preserves
  existing behaviour for the vast majority of deployments.

### Negative / Trade-offs

- **Slightly breaking for `untrusted_external` connectors:** deployments that
  rely on community feed connectors writing directly to default workspaces will
  require a one-time configuration update after the migration.
- **`allowed_connector_refs` is a class name string:** it compares against
  `type(connector).__name__`, which means it is case-sensitive and does not
  survive connector class renames.  A more robust connector identity mechanism
  (e.g. a `CONNECTOR_ID` class constant) is deferred.
- **Enforcement is at the GNAT application layer:** database-level row-security
  policies (e.g. PostgreSQL RLS) are not implemented.  A connector that
  bypasses the GNAT application layer and writes directly to the database is
  not constrained.

### Deferred

- `CONNECTOR_ID` class constant on `BaseClient` to decouple allowlist entries
  from class names
- Database-level row security (PostgreSQL RLS) for multi-process deployments
  where multiple GNAT workers share a database
- TUI workspace inspector showing trust boundary configuration and recent
  violation events
- Per-workspace read boundary (currently `check_connector_trust()` is called
  on write paths only; read-path enforcement is deferred)

---

## Alternatives Considered

### Separate Database Schema Per Tenant

Each tenant workspace would live in a separate database schema or database
instance, providing hard isolation at the storage layer.  Rejected because it
requires database-level provisioning for each workspace, complicates migrations,
and makes cross-workspace queries (e.g. correlation across tenants for MSSP
analytics) impossible without a federation layer.  The application-level trust
boundary model achieves the required isolation for the current threat model at
far lower operational cost.

### TLP-Only Filtering

Restrict connector write access based on the TLP marking of the STIX objects
rather than the trust level of the connector.  Rejected because TLP controls
*dissemination* of intelligence (who may see it), not *provenance* (who may
write it).  A `semi_trusted` connector should not be allowed to inject objects
into a workspace designated for `trusted_internal` sources even if the objects
carry TLP:WHITE markings.

### Policy Engine Allowlist (ADR-0037)

The existing policy engine (ADR-0037) could be extended to express workspace
trust boundaries as policy rules rather than workspace attributes.  Rejected
for this phase because workspace trust is a stable property of the workspace
itself, not a dynamic rule that should be evaluated against arbitrary
conditions.  The policy engine is a better home for complex, contextual
decisions (e.g. "allow if the object's confidence score exceeds 80"); workspace
boundary enforcement is simpler and benefits from being collocated with the
workspace model.

### Connector-Level Workspace Declarations

Each connector class could carry a list of workspace IDs it is permitted to
access (inverting the relationship — connector declares targets instead of
workspace declaring sources).  Rejected because workspace configuration is
the correct authority for workspace-scoped policy.  Distributing access
control across 99 connector class definitions would be operationally unwieldy.

---

*Licensed under the Apache License, Version 2.0*

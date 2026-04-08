# ADR-0027: Multi-Tenant Workspace Isolation

**Decision:** Transparent name prefixing (`{tenant_id}::name`) over per-tenant databases.

**Why name prefixing over separate databases:**
- Zero schema migration required — works with existing SQLite and FlatFile stores.
- A single `WorkspaceManager` instance serves all tenants; no per-tenant connection pools.
- Isolation is enforced at the API layer, not the storage layer, which keeps the persistence
  backend simple and testable.

**`WorkspaceManager.for_tenant(tenant_id)`:**
Returns a `TenantWorkspaceManager` that intercepts all workspace names and applies the
prefix before delegating to the underlying `WorkspaceManager`. Existing workspaces that
have no prefix are implicitly in the `"default"` tenant.

**`TenantRegistry`:**
Stores tenant metadata (display name, optional per-tenant config path). Per-tenant
config allows different Claude API keys, sector aliases, or EDL targets per tenant —
critical for MSP deployments.

**CLI:**
`gnat tenant list/create/info/workspaces/delete` — all standard CRUD; `--yes` flag
required for destructive operations.

---

*Licensed under the Apache License, Version 2.0*

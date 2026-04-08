# ADR-0037 — Policy Engine (RBAC)

**Date:** 2026-04-08  
**Status:** Accepted  
**Deciders:** GNAT Platform Team

---

## Context

GNAT's dissemination API used a single, coarse access-control mechanism: a
TLP level embedded in each Bearer token.  An *amber* key could read amber
reports, a *red* key could also manage API keys.  This worked for simple
deployments but broke down as the platform matured:

1. All *red* key holders automatically became admins — no way to give an
   analyst RED access without also giving them key-management rights.
2. There was no concept of "who can submit a report for review" vs "who can
   approve it" — both required a manual code check.
3. The investigation API (Phase 3B) needs per-route permission enforcement
   that cannot be expressed with TLP levels alone.
4. Enterprise deployments need audit trails that identify *who* did *what*,
   not just *which token* was used.

---

## Decision

Introduce a **thin role-based access control (RBAC) layer** orthogonal to the
existing TLP system:

### Role enum (`gnat.policy.models.Role`)

Five roles, ordered from lowest to highest privilege:

| Role | Value |
|------|-------|
| VIEWER | `"viewer"` |
| ANALYST | `"analyst"` |
| SENIOR_ANALYST | `"senior_analyst"` |
| REVIEWER | `"reviewer"` |
| ADMIN | `"admin"` |

### Permission enum (`gnat.policy.models.Permission`)

Ten granular permissions:

| Permission | Granted to |
|-----------|-----------|
| `read_investigations` | VIEWER+ |
| `write_investigations` | ANALYST+ |
| `read_reports` | VIEWER+ |
| `submit_reports` | SENIOR_ANALYST+ |
| `approve_reports` | REVIEWER+ |
| `publish_reports` | ADMIN only |
| `export_red` | ADMIN only |
| `manage_keys` | ADMIN only |
| `manage_plugins` | ADMIN only |
| `write_taxii` | SENIOR_ANALYST+ |

The matrix is a static `dict[Role, set[Permission]]` in
`gnat.policy.models.ROLE_PERMISSIONS`.  ADMIN receives the full set
(`set(Permission)`).

### PolicyEngine (`gnat.policy.engine`)

- `evaluate(subject, permission) → bool` — resolves the subject's role
  (reads `subject.role`, coerces string → `Role`, falls back to
  `default_role`), then checks the permission matrix.
- `require(permission, key_store, allow_none) → Callable` — returns a
  FastAPI `Depends`-compatible callable that reads the `Authorization`
  header, resolves the `APIKey`, checks the permission, and raises HTTP
  401/403 on failure.  Gracefully falls back to a no-op callable when
  FastAPI is not installed.
- `audit(subject, permission, resource, granted)` — emits a structured
  `policy_decision` event on the `HookBus` for audit trail integration.

### APIKey integration

`APIKey.role: str = "viewer"` field added to the dataclass.  The field is
a plain string so the auth module has no hard import on `gnat.policy`.
`PolicyEngine.evaluate()` performs the string → `Role` coercion lazily.

`APIKeyStore.add_key()` and `generate_key()` gain a `role=` keyword
argument (default `"viewer"`).

### Middleware (`gnat.policy.middleware`)

`build_audit_middleware(key_store)` returns a Starlette `BaseHTTPMiddleware`
subclass that:
1. Times every request.
2. Resolves the actor from the Bearer token.
3. Emits a structured log line: `actor`, `method`, `path`, `status`,
   `elapsed_ms`.
4. Emits an `api_request` event on the `HookBus`.

### Gateway integration

`build_gateway_router()` now accepts an optional `policy_engine` parameter.
The three `/admin/keys` endpoints use
`engine.require(Permission.MANAGE_KEYS, key_store=key_store)` as their
`Depends`.  The old TLP-rank hard-check (`_require_admin`) is removed.

---

## Consequences

### Positive

- **Fine-grained control:** roles and permissions are independent of TLP
  level — a SENIOR_ANALYST key can be GREEN TLP but still submit reports.
- **FastAPI-native:** `engine.require()` slots in as a standard `Depends`
  decorator; no framework wrappers needed.
- **Orthogonal to TLP:** existing TLP enforcement in TAXII and export
  unchanged.  Both checks apply independently.
- **Audit trail:** every access decision can be logged and forwarded via
  `HookBus`.
- **Zero new dependencies:** plain Python + optional FastAPI (already a
  `[serve]` extra).

### Negative / Trade-offs

- **Static matrix:** permissions are hardcoded; dynamic ACLs (per-report,
  per-investigation) require subclassing `PolicyEngine`.
- **In-memory roles:** roles live on the `APIKey` object; persisting them to
  a database requires implementing a custom `APIKeyStore`.

### Deferred

- Attribute-based access control (ABAC) — per-resource permission overrides.
- Database-backed `APIKeyStore` with role persistence.
- UI for role management.

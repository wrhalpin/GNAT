# ADR-0056: Unified API Key Authentication

**Status:** Accepted

**Date:** 2026-04-24

## Context

GNAT has two independent API key mechanisms that evolved separately:

1. **Serve layer** (`gnat/serve/auth.py`) — `APIKeyAuth` accepts a single
   `X-Api-Key` header string.  The key is compared with
   `hmac.compare_digest` against one configured value.  There is no
   concept of multiple keys, expiry, revocation, or identity.

2. **Dissemination layer** (`gnat/dissemination/api/auth.py`) —
   `APIKeyStore` manages multiple `APIKey` objects with TLP levels,
   RBAC roles, labels, expiry, and enable/disable.  Keys are validated
   via `Authorization: Bearer` headers.

The result is:

- The serve layer cannot issue per-consumer keys, track which key is
  used, or revoke a single integration without rotating the global key.
- The dissemination layer stores keys in memory only — restarts lose
  all registered keys.
- Addon tools (SandGNAT, SenseGNAT, RedGNAT) authenticate as service
  accounts via the serve layer, but there is no way to distinguish
  which addon made a request or to apply per-addon TLP restrictions.
- The header scheme is inconsistent: `X-Api-Key` in serve, `Bearer` in
  dissemination.  Consumers must know which layer they are talking to.
- `APIKey.tenant_id` is accessed via a `__getattr__` fallback into the
  `metadata` dict, which is fragile and invisible to tooling.
- The SSE endpoint (`/api/stream`) compares the key value with `==`
  instead of `hmac.compare_digest`, creating a timing side-channel.
- There is no key rotation workflow — replacing a key requires
  coordinated downtime across all consumers.

Requirements:

1. One key store, one auth scheme, usable by both serve and
   dissemination layers.
2. Multiple keys with per-key identity (label, role, TLP, tenant).
3. Both `Authorization: Bearer` and `X-Api-Key` headers accepted for
   backward compatibility.
4. Persistent storage option (database-backed).
5. Key rotation with grace period so old and new keys overlap.
6. CLI management of keys (`gnat key generate/list/revoke/rotate`).
7. Constant-time comparison everywhere.
8. Addon tools continue using API keys as service accounts.
9. SSO/OIDC not required now but must not be precluded.

## Decision

### 1. Consolidate on `APIKeyStore` as the single auth backend

Both the serve layer and dissemination layer use the same
`APIKeyStore` instance (from `gnat.dissemination.api.auth`).  The
serve-layer `APIKeyAuth` dependency accepts an `APIKeyStore` instead
of a single string.  It resolves the incoming token against the store
and returns the matched `APIKey` object, giving downstream handlers
access to the key's label, role, TLP level, and tenant.

A single-string convenience constructor is retained for minimal
deployments:

```python
auth = APIKeyAuth(api_key="legacy-single-key")  # wraps in a one-key store
auth = APIKeyAuth(key_store=store)               # multi-key
```

### 2. Promote `tenant_id` to a first-class field on `APIKey`

Add `tenant_id: str | None = None` as an explicit dataclass field on
`APIKey`, with a default of `None`.  Remove the prior pattern of
stashing it in `metadata` and relying on `__getattr__` fallback.
Include `tenant_id` in `to_dict()` output.

### 3. Standardize on `Authorization: Bearer` with `X-Api-Key` as deprecated alias

The canonical header is `Authorization: Bearer <token>`.  The serve
auth dependency also accepts `X-Api-Key: <token>` for backward
compatibility, but new documentation and generated client code use
`Authorization: Bearer`.  When both headers are present,
`Authorization` takes precedence.

### 4. Add `SQLAlchemyKeyStore` for persistent storage

A new `gnat.dissemination.api.key_store_db.SQLAlchemyKeyStore`
subclasses `APIKeyStore` and persists keys in a SQL database.  It
follows the same pattern as
`gnat.analysis.investigations.storage.InvestigationStore`:

- Core model (`APIKey`) is a pure Python dataclass — no ORM coupling.
- SQLAlchemy model (`APIKeyModel`) lives only in the storage module.
- Guard import with `try/except ImportError`.
- Serialize key metadata as JSON in a text column.
- Indexed columns for `token_hash`, `tenant_id`, `enabled`.

The in-memory `APIKeyStore` remains the default for tests and
single-process deployments.

### 5. Add CLI key management

New `gnat key` subcommand with operations:

| Command | Description |
|---------|-------------|
| `gnat key generate` | Create a new key; print token once |
| `gnat key list` | List keys (shows hash prefix, label, TLP, tenant, status) |
| `gnat key revoke <hash-prefix>` | Disable a key |
| `gnat key rotate <hash-prefix>` | Generate replacement key with grace period |

### 6. Key rotation with configurable grace period

`APIKeyStore.rotate_key(token, grace_hours=24)` generates a new key
with the same label, role, TLP, and tenant.  The old key's `expires_at`
is set to `now + grace_hours`.  During the grace period both keys are
valid.  After the grace period the old key expires naturally via the
existing `is_valid()` check.

### 7. Fix SSE timing side-channel

All token comparison paths — including the SSE endpoint — use
`hmac.compare_digest`.  The consolidated `APIKeyAuth` dependency
handles this uniformly, eliminating the per-endpoint comparison.

### 8. Addon tools use API keys as service accounts

SandGNAT, SenseGNAT, and RedGNAT authenticate with dedicated API
keys that carry appropriate labels (e.g. `"sandgnat-service"`),
roles, and TLP levels.  This is consistent with ADR-0055 (cross-tool
investigation context).  API keys are the right mechanism for
machine-to-machine service accounts.

### 9. SSO/OIDC deferred to future release

Human user authentication via SSO/OIDC is deferred.  When
implemented it will live behind an optional `gnat[sso]` extra to
avoid pulling in heavy dependencies (e.g. `authlib`, `python-jose`).
The `APIKeyAuth` dependency will be extended with an `or`-chain that
accepts either a valid API key or a valid OIDC token.  This ADR does
not constrain the OIDC design — it only ensures the API key path
does not preclude it.

## Consequences

**Positive:**

- Single auth code path for both serve and dissemination layers
  reduces maintenance burden and eliminates inconsistencies.
- Per-key identity enables audit logging ("which integration made this
  request") and per-consumer revocation without global rotation.
- `tenant_id` as a first-class field is visible to type checkers and
  IDE autocompletion, eliminating a class of `AttributeError` bugs.
- `SQLAlchemyKeyStore` survives process restarts, which is required
  for production multi-key deployments.
- Grace-period rotation eliminates coordinated downtime during key
  changes.
- Constant-time comparison everywhere closes the SSE timing
  side-channel.
- CLI key management gives operators a self-service workflow without
  editing config files.

**Negative:**

- The `X-Api-Key` deprecated alias adds a small amount of header
  parsing complexity.  This is bounded and will be removed in a
  future major version.
- `SQLAlchemyKeyStore` adds an optional dependency on SQLAlchemy
  (already available via `gnat[persist]`), but the in-memory store
  remains zero-dependency.
- Key rotation grace periods mean a compromised key remains valid for
  up to `grace_hours` after rotation.  Operators can set
  `grace_hours=0` for immediate revocation when compromise is
  confirmed.

**Neutral:**

- Addon tools are unaffected — they continue to send a bearer token.
  The only change is that the token now resolves to a richer `APIKey`
  object on the server side.
- Existing single-key deployments continue to work via the
  convenience constructor.  No config migration is required.

---

Related: ADR-0027 (Multi-Tenant Workspace Isolation — tenant scoping)
Related: ADR-0055 (Cross-Tool Investigation Context — addon service accounts)

---

*Licensed under the Apache License, Version 2.0*

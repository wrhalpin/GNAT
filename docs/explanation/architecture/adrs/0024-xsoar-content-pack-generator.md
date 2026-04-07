# ADR-0024: XSOAR Content Pack Generator

**Decision:** Introspect any `ConnectorMixin` via `capabilities()` and generate a complete XSOAR 6 content pack zip.

**Why introspection over templates:**
- Hardcoded templates would need manual updates every time a connector grows new methods.
- `capabilities()` already has the method signatures, docstrings, and classification
  (`read` / `write` / `helper`). The generator maps these directly to XSOAR command YAML.

**Pack layout:**
```
<Name>/
  pack_metadata.json         # Version, author, description
  Integrations/<Name>/
    <Name>.yml               # Command manifest (write methods flagged dangerous: true)
    <Name>.py                # Delegating script — calls ConnectorMixin.call()
  ReleaseNotes/
    1_0_0.md
```

**Auth detection:**
Auth type is inferred from the connector constructor signature (`client_id`/`client_secret`
→ `oauth2`; `api_token`/`api_key` → `api_key`; `username`/`password` → `basic`).
Overrideable via `--auth` flag.

**Write safety:**
Write-classified methods are flagged `dangerous: true` in the YAML. The generated
Python script calls `ConnectorMixin.call(method, allow_write=False)` by default —
XSOAR operators must explicitly set `allow_write=True` per-command.

---

*Licensed under the Apache License, Version 2.0*

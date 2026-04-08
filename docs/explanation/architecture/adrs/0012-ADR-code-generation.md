# ADR-0012: Code Generation

**Decision:** OpenAPI spec → connector scaffold, not a full auto-implementation.

**What the generator does:**
- Parses OpenAPI 3.x or Swagger 2.x (JSON or YAML with PyYAML)
- Detects CRUD-like endpoints by HTTP method and path pattern
- Infers `stix_type_map` from schema names heuristically
- Selects auth scaffold from `--auth oauth2|api_key|basic`
- Writes `client.py` with all methods stubbed and `# TODO` comments
- Writes full pytest scaffold with all required test classes

**What you still need to implement:**
- `to_stix(native)` — map platform fields to STIX 2.1
- `from_stix(stix_dict)` — map STIX to platform request payload
- `health_check()` — replace `GET /health` stub with real endpoint
- Verify `_resolve_resource()` paths match actual API endpoints

**Registration after generation:**
```python
# gnat/clients/__init__.py
from gnat.connectors.myplatform.client import MyplatformClient
CLIENT_REGISTRY["myplatform"] = MyplatformClient

# gnat/async_client/connectors.py — add async mirror
# gnat/async_client/client.py — add to _build_async_registry()
```

---

*Licensed under the Apache License, Version 2.0*

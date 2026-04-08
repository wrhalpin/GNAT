# ADR-0005: Context System — Global and Local

**Decision:** Multiple global contexts, separate relationship objects for
enrichment (not merged scores).

**Multiple globals rationale:**
Different platforms serve different roles — ThreatQ as system of record,
Recorded Future as enrichment-only, CrowdStrike as endpoint context.
Forcing a single global would either lose platform provenance or require
complex merge logic.

**`GlobalContextRegistry` priority:**
Lower integer = higher priority. Default write target is the lowest-priority
non-read-only context. Override with `registry.set_default("name")`.

**INI config format for multiple globals:**
```ini
[global]
default = threatq_prod

[global.threatq_prod]
target        = threatq
host          = https://threatq.example.com
client_id     = ...
client_secret = ...

[global.recorded_future]
target    = recordedfuture
host      = https://api.recordedfuture.com
api_token = ...
read_only = true
priority  = 20
```

**`GlobalContextRegistry.from_clients()` for programmatic setup:**
```python
registry = GlobalContextRegistry.from_clients(
    {"tq": tq_cli, "rf": rf_cli, "cs": cs_cli},
    default="tq",
    read_only=["rf"],
)
```

**Enrichment strategies — choose based on use case:**

| Strategy | Effect | Use when |
|---|---|---|
| `create_relationships` | New STIX SDO + Relationship added; original untouched | **Default.** Preserves full provenance. Multiple platforms can enrich the same object without collision. |
| `merge_extensions` | `x_` fields merged into original; original marked dirty | You want a single enriched indicator rather than a graph of objects. Loses individual platform provenance. |
| `tag_only` | `x_enrichment_tags` list updated; nothing else changes | Lightweight "was checked" marking. No data persisted. |

**`create_relationships` is the correct default for your requirement**
("preserve both as separate relationships"). RF risk score and CS
endpoint data become separate nodes in the graph, linked to the
original indicator. `diff()` and `commit()` will pick them up as new
objects.

---

*Licensed under the Apache License, Version 2.0*

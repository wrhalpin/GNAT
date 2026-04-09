# How-to: Use the Reasoning Engine

GNAT's reasoning layer lets you score and rank STIX observables by evidence quality,
track analyst hypotheses with structured evidence links, and suppress redundant connector
queries using negative evidence records.

---

## Prerequisites

- GNAT installed (`pip install gnat`)
- A `WorkspaceManager` configured (see [How-to: Use Workspaces](use-workspaces.md))
- Optionally: Solr search sidecar running (see `[search]` config section)

---

## Score Observables with ReasoningEngine

`ReasoningEngine.prioritize()` assigns a composite score in `[0.0, 1.0]` to each
observable based on:

| Signal | Weight | Description |
|--------|--------|-------------|
| Connector trust weight | 40% | `trusted_internal`→0.9, `semi_trusted`→0.6, `untrusted_external`→0.3 |
| Object age factor | 30% | 1.0 decaying by 5% per day from `modified` timestamp |
| Cross-connector corroboration | 30% | Solr hit count × 0.05, capped at 0.25 |
| Negative evidence penalty | −50% | min(0.3 × fresh NegativeEvidenceRecord count, 0.6) |

```python
from gnat.reasoning.engine import ReasoningEngine
from gnat.core.context import ExecutionContext
from gnat.context.workspace import WorkspaceManager

manager = WorkspaceManager.default()

# Create a context from your connector (sets trust_level automatically)
from gnat.connectors.crowdstrike.client import CrowdStrikeClient
cs = CrowdStrikeClient(host="...", client_id="...", client_secret="...")
ctx = ExecutionContext.from_connector(cs, domain="analysis", workspace_id="my-ws")

engine = ReasoningEngine(manager=manager, workspace_name="my-ws")

# Load observables from the workspace
ws = manager.open("my-ws")
observables = list(ws.objects.values())

results = engine.prioritize(observables, context=ctx, store_notes=True)

for observable, score, explanation in results:
    print(f"{score:.2f}  {observable.id}")
    print(f"  {explanation['summary']}")
```

### Read the structured explanation

The `explanation` dict is machine-readable:

```python
_, score, explanation = results[0]

print(explanation["observable_id"])    # STIX ID
print(explanation["score"])            # 0.0 – 1.0

trust_info = explanation["components"]["trust_weight"]
print(trust_info["trust_level"])       # "semi_trusted"
print(trust_info["weight"])            # 0.6

age = explanation["components"]["age_factor"]
print(f"age factor: {age:.2f}")        # 0.85 (17 days old at 5%/day decay)

neg = explanation["components"]["negative_evidence"]
print(f"{neg['count']} fresh neg records, penalty={neg['penalty']:.2f}")

corr = explanation["components"]["corroboration"]
print(f"{corr['hits']} Solr hits, bonus={corr['bonus']:.2f}")
```

### Stored STIX notes

When `store_notes=True` (default), the engine writes a STIX `note` object to the
workspace for each scored observable.  The note contains the full JSON explanation so
analysts can review it later.

---

## Propose and Evaluate Hypotheses

```python
from gnat.reasoning.hypothesis import HypothesisEngine
from gnat.context.workspace import WorkspaceManager

manager = WorkspaceManager.default()
engine = HypothesisEngine(manager=manager, workspace_name="apt29-investigation")

# 1. Propose a hypothesis
h = engine.propose(
    statement="192.0.2.1 is a Lazarus Group C2 server.",
    initial_evidence=["relationship--abc123"],  # STIX relationship IDs
    confidence=0.2,   # low initial confidence
)
print(h._properties["status"])      # "pending"
print(h._properties["confidence"])  # 0.2

# 2. Evaluate — queries Solr for corroborating evidence
h = engine.evaluate(h.id)
print(h._properties["confidence"])  # updated based on evidence + Solr hits
print(h._properties["status"])      # "pending" | "confirmed" | "refuted"

# 3. Add more evidence manually
h.add_supporting_evidence("relationship--def456")
h.add_refuting_evidence("relationship--ghi789")

# 4. Close with a verdict
h = engine.close(h.id, verdict="confirmed")
print(h._properties["status"])  # "confirmed"
```

### List all hypotheses

```python
all_hypotheses = engine.list_all()
for h in all_hypotheses:
    print(h._properties["statement"][:60], "→", h._properties["status"])
```

---

## Track Negative Evidence

`NegativeEvidenceRecord` suppresses redundant connector re-queries within a configurable TTL.

```python
from gnat.stix.sdos.negative_evidence import NegativeEvidenceRecord
from gnat.context.workspace import WorkspaceManager

manager = WorkspaceManager.default()
ws = manager.open("my-ws")

indicator_id = "indicator--abc123"

# Check for a fresh negative record before querying
neg_records = [
    obj for obj in ws.objects.values()
    if getattr(obj, "stix_type", "") == "x-gnat-negative-evidence"
    and obj._properties.get("target_ref") == indicator_id
    and not obj.is_expired()   # within TTL
]

if neg_records:
    print("Skipping re-query — connector returned no results within TTL")
else:
    # Query connector
    result = vt_client.get(f"/api/v3/files/{indicator_id}")

    if not result:
        # Write negative evidence record
        rec = NegativeEvidenceRecord(
            target_ref=indicator_id,
            queried_connector="VirusTotalClient",
            ttl_seconds=3600,  # suppress re-queries for 1 hour
        )
        ws._add_object(rec.to_dict(), mark_dirty=True)
```

Check TTL status:

```python
rec = NegativeEvidenceRecord(target_ref="indicator--abc", queried_connector="VT", ttl_seconds=3600)
print(rec.is_expired())          # False immediately after creation
print(rec.seconds_remaining())   # ~3600
```

---

## Attach Solr for Corroboration

When Solr is running, the reasoning engine uses it for cross-connector corroboration.
Configure via `[search]` in `~/.gnat/config.ini`:

```ini
[search]
solr_url   = http://localhost:8983/solr/gnat
enabled    = true
batch_size = 100
```

Then pass it explicitly:

```python
from gnat.search.index import SolrSearchIndex, SolrSearchConfig
from gnat.reasoning.engine import ReasoningEngine

config = SolrSearchConfig(solr_url="http://localhost:8983/solr/gnat")
index = SolrSearchIndex(config)

engine = ReasoningEngine(
    manager=manager,
    workspace_name="my-ws",
    search_index=index,
)
```

Without Solr, the engine falls back to `NullSearchIndex` — all scores work but
the corroboration bonus is always 0.0.

---

## See Also

- [ADR-0042 — Hypothesis Engine](../explanation/architecture/adrs/0042-ADR-hypothesis-engine.md)
- [ADR-0043 — Negative Evidence](../explanation/architecture/adrs/0043-ADR-negative-evidence.md)
- [ADR-0044 — Reasoning Engine](../explanation/architecture/adrs/0044-ADR-reasoning-engine.md)
- [How-to: Use Workspaces](use-workspaces.md)
- [How-to: Build Investigations](build-investigations.md)

---

*Licensed under the Apache License, Version 2.0*

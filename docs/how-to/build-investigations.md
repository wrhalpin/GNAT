# How-to: Build Cross-Platform Investigations

Use `gnat.investigations` to collect, normalise, correlate, and persist
evidence from multiple connected platforms into a unified GNAT workspace.

---

## Overview

`InvestigationBuilder` runs a **five-step pipeline**:

| Step | What happens |
|------|-------------|
| 1. Seed expansion | Queries each platform for indicators, incidents, cases, and events matching the seed values |
| 2. Incident expansion | Fetches constituent evidence (alerts, tasks, observables, timeline) for every discovered incident |
| 3. Normalisation | Translates every raw platform record into a common `EvidenceNode` |
| 4. Correlation | Adds cross-platform edges (same IOC, same host, same user, same campaign, same ticket) between nodes from different platforms |
| 5. Materialisation | Writes nodes + edges into a GNAT workspace as STIX objects and `Relationship` SROs |

---

## Basic usage

```python
from gnat.investigations import InvestigationBuilder, Seed, SeedType, materialize

# Provide any subset of your connected platform clients
builder = InvestigationBuilder({
    "xsoar":      xsoar_client,
    "greymatter": gm_client,
    "threatq":    tq_client,
})

# Build the evidence graph from one or more seeds
graph = builder.build(
    seeds=[
        Seed("185.220.101.5", SeedType.IP),
        Seed("INC-4892",      SeedType.CASE_ID, hint_platform="xsoar"),
    ],
    title = "Ransomware triage – 2026-04-05",
)

# Print a summary
print(graph.summary())

# Persist into a GNAT workspace
ws = materialize(graph, workspace_manager, workspace_name="ransomware-apr-2026")
```

---

## Seed types

| `SeedType` | Typical value | Platforms queried |
|-----------|--------------|------------------|
| `IP` | `"185.220.101.5"` | All platforms with indicator search |
| `DOMAIN` | `"evil-corp.com"` | All platforms with indicator search |
| `HASH` | `"d41d8cd98f00b204e9800998ecf8427e"` | All platforms with indicator search |
| `EMAIL` | `"phish@bad.actor"` | TIPs, SOAR, email security platforms |
| `URL` | `"https://evil.example/payload"` | All platforms with indicator search |
| `HOSTNAME` | `"ws-12.corp.example.com"` | SOAR, EDR, SIEM, asset management |
| `USERNAME` | `"jsmith@corp.example.com"` | SOAR, EDR, identity platforms |
| `ALERT_ID` | `"alert-001"` | SOAR, SIEM platforms |
| `CASE_ID` | `"INC-4892"` | SOAR platforms (XSOAR, TheHive, ServiceNow) |
| `TICKET_REF` | `"JIRA-1234"` | Jira, ServiceNow |

Use `hint_platform` to direct a seed exclusively at one connector:

```python
Seed("INC-4892", SeedType.CASE_ID, hint_platform="xsoar")
```

---

## Working with the evidence graph

```python
from gnat.investigations import EvidenceGraph, EvidenceNode, EvidenceEdge, NodeType

# Iterate nodes
for node_id, node in graph.nodes.items():
    print(f"{node.node_type.value} [{node.platform}] {node.title or node.value}")

# Iterate edges
for edge in graph.edges:
    print(f"{edge.source_id} --{edge.edge_type}--> {edge.target_id}")

# Filter by node type
incidents = [n for n in graph.nodes.values() if n.node_type == NodeType.INCIDENT]
observables = [n for n in graph.nodes.values() if n.node_type == NodeType.OBSERVABLE]

# Summary counts
print(graph.summary())
# "EvidenceGraph: 47 nodes across 3 platforms, 31 edges"
```

Node types: `INCIDENT`, `OBSERVABLE`, `ASSET`, `IDENTITY`, `FINDING`,
`TASK`, `DECISION`, `ARTIFACT`, `TIMELINE_EVENT`.

---

## Materialising into a workspace

Once the graph is built, `materialize()` writes every node to the workspace
as a STIX object and creates `Relationship` SROs for the edges:

```python
from gnat.investigations import materialize

ws = materialize(
    graph            = graph,
    workspace_manager = workspace_manager,
    workspace_name   = "ransomware-apr-2026",
)

# The workspace now contains STIX objects sourced from all platforms
for stix_obj in ws.list_all():
    print(stix_obj.stix_type, stix_obj.id)
```

---

## Multi-platform investigation example

```python
builder = InvestigationBuilder({
    "xsoar":             xsoar_client,
    "greymatter":        gm_client,
    "threatq":           tq_client,
    "thehive":           hive_client,
    "servicenow_secops": sn_client,
    "cortex_xdr":        xdr_client,
})

graph = builder.build(
    seeds=[
        Seed("blackcat-ransomware", SeedType.IOC_VALUE),
        Seed("185.220.101.5",       SeedType.IP),
        Seed("evil-corp.com",       SeedType.DOMAIN),
        Seed("INC-4892",            SeedType.CASE_ID, hint_platform="xsoar"),
    ],
    title = "BLACKCAT Ransomware Campaign — Apr 2026",
)

print(graph.summary())
ws = materialize(graph, workspace_manager, "blackcat-apr-2026")
```

---

## Combining with the analysis layer

After building the evidence graph you can run correlation, gap detection,
and timeline reconstruction from `gnat.analysis`:

```python
from gnat.analysis.graph import GraphQuery
from gnat.analysis.timeline import TimelineBuilder
from gnat.analysis.copilot.gap_detector import GapDetector

# Graph pivoting
gq      = GraphQuery(graph)
context = gq.pivot("xsoar::incident::INC-4892", hops=2)
print(f"{context.node_count} related nodes")

# Timeline
builder = TimelineBuilder()
events  = builder.from_evidence_graph(graph)
for e in events:
    print(f"{e.timestamp.isoformat()}  {e.title}")

# Gap detection (after linking graph findings to an Investigation)
from gnat.analysis.investigations import InvestigationService
service = InvestigationService(store)
inv     = service.create(title="BLACKCAT", created_by="analyst@example.com")
service.add_hypothesis(inv.id, "BLACKCAT used spear-phishing for initial access.",
                       created_by="analyst@example.com")

detector = GapDetector()
gaps     = detector.detect_all(service.get(inv.id))
for gap in gaps:
    print(f"[{gap.severity}] {gap.description}")
```

---

## See Also

- [How-to: Use the Analysis Layer](use-analysis-layer.md)
- [How-to: Create Intelligence Reports](create-intelligence-reports.md)
- [How-to: Use Workspaces](use-workspaces.md)
- [Explanation: Analysis Layer Architecture](../explanation/architecture/adrs/0031-ADR-analysis-layer-architecture.md)

---

*Licensed under the Apache License, Version 2.0*

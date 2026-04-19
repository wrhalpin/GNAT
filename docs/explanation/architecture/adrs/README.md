# GNAT Architecture Decision Records

A single reference for every design decision made during development,
including tradeoffs, alternatives considered, and implementation notes.
Use this when testing, implementing new connectors, or extending existing
subsystems.

## Table of Contents

1. [ADR-0001: HTTP Client Layer](0001-ADR-http-client-layer.md)
2. [ADR-0002: ORM / STIX Compatibility](0002-ADR-orm-stix-compatibility.md)
3. [ADR-0003: Connector Architecture](0003-ADR-connector-architecture.md)
4. [ADR-0004: Ingestion Framework](0004-ADR-ingestion-framework.md)
5. [ADR-0005: Context System — Global and Local](0005-ADR-context-system.md)
6. [ADR-0006: Workspace Persistence](0006-ADR-workspace-persistence.md)
7. [ADR-0007: Async Client](0007-ADR-async-client.md)
8. [ADR-0008: Visualization — Tabular](0008-ADR-visualization-tabular.md)
9. [ADR-0009: Visualization — Graph](0009-ADR-visualization-graph.md)
10. [ADR-0010: Visualization — Grafana vs Power BI](0010-ADR-visualization-grafana-vs-power-bi.md)
11. [ADR-0011: CLI Design](0011-ADR-cli-design.md)
12. [ADR-0012: Code Generation](0012-ADR-code-generation.md)
13. [ADR-0013: Configuration](0013-ADR-configuration.md)
14. [ADR-0014: Testing Strategy](0014-ADR-testing-strategy.md)
15. [ADR-0015: Packaging and Extras](0015-ADR-packaging-and-extras.md)
16. [ADR-0016: Feed Scheduling](0016-ADR-feed-scheduling.md)
17. [ADR-0017: Export / Integration Pipeline](0017-ADR-export-integration-pipeline.md)
18. [ADR-0018: AI Agent Layer](0018-ADR-ai-agent-layer.md)
19. [ADR-0019: Shared Research Library](0019-ADR-shared-research-library.md)
20. [ADR-0020: NLP Query Layer](0020-ADR-nlp-query-layer.md)
21. [ADR-0021: Rust Native Extension (`gnat-core`)](0021-ADR-rust-native-extension.md)
22. [ADR-0022: Web Dashboard (`gnat/serve/`)](0022-ADR-web-dashboard.md)
23. [ADR-0023: Terminal UI — Textual](0023-ADR-terminal-ui.md)
24. [ADR-0024: XSOAR Content Pack Generator](0024-ADR-xsoar-content-pack-generator.md)
25. [ADR-0025: Upstream Contribution Pipeline](0025-ADR-upstream-contribution-pipeline.md)
26. [ADR-0026: Connector Health Monitor](0026-ADR-connector-health-monitor.md)
27. [ADR-0027: Multi-Tenant Workspace Isolation](0027-ADR-multi-tenant-workspace-isolation.md)
28. [ADR-0028: TAXII 2.1 Server](0028-ADR-taxii-21-server.md)
29. [ADR-0029: Docker Containerization](0029-ADR-docker-containerization.md)
30. [ADR-0030: Use Diátaxis and ADRs](0030-ADR-use-diataxis-and-adrs.md)
31. [ADR-0031: Analysis Layer Architecture](0031-ADR-analysis-layer-architecture.md)
32. [ADR-0032: STIX Custom Objects](0032-ADR-stix-custom-objects.md)
33. [ADR-0033: Confidence Scoring](0033-ADR-confidence-scoring.md)
34. [ADR-0034: Report Lifecycle](0034-ADR-report-lifecycle.md)
35. [ADR-0035: Quality Agents](0035-ADR-quality-agents.md)
36. [ADR-0036: Security Agents Phase B](0036-ADR-security-agents-phaseb.md)
37. [ADR-0037: Adopt Responsible Disclosure, DCO, and Apache 2.0 Compliance](0037-ADR-adopt-responsible-disclosure-dco-and-apache-2.0-compliance.md)
38. [ADR-0038: Data Lineage Tracking](0038-data-lineage.md)

### Phase 4 — Control, Reasoning, Safety

39. [ADR-0039: Unified Execution Context](0039-ADR-execution-context.md)
40. [ADR-0040: Connector Trust Model](0040-ADR-connector-trust-model.md)
41. [ADR-0041: Idempotency and Schema Evolution](0041-ADR-idempotency-schema-evolution.md)
42. [ADR-0042: Hypothesis Engine](0042-ADR-hypothesis-engine.md)
43. [ADR-0043: Negative Evidence Tracking](0043-ADR-negative-evidence.md)
44. [ADR-0044: Reasoning Engine](0044-ADR-reasoning-engine.md)
45. [ADR-0045: Agent Governance](0045-ADR-agent-governance.md)
46. [ADR-0046: HITL Gateway](0046-ADR-hitl-gateway.md)
47. [ADR-0047: Workspace Isolation and Trust Boundaries](0047-ADR-workspace-isolation.md)
48. [ADR-0048: Query Budget and Cost Model](0048-ADR-query-budget.md)
49. [ADR-0049: Testing Framework — Simulation and Replay](0049-ADR-testing-framework.md)

### Detection, Attribution & Telemetry

50. [ADR-0050: HuntGNAT — Detection Rule Translation](0050-ADR-huntgnat-detection-translation.md)
51. [ADR-0051: Attribution & Campaign Tracking](0051-ADR-attribution-campaign-tracking.md)
52. [ADR-0052: Telemetry Ingestion](0052-ADR-telemetry-ingestion.md)
53. [ADR-0053: Infrastructure Graph Labels](0053-ADR-infrastructure-graph-labels.md)
54. [ADR-0054: Analysis Rule Engine](0054-ADR-analysis-rule-engine.md)

---

## Quick Reference: Adding a New Connector

```bash
# 1. Generate scaffold
gnat-codegen --spec platform-openapi.json --name myplatform --auth oauth2

# 2. Implement in gnat/connectors/myplatform/client.py
#    - authenticate()
#    - to_stix(native) → dict with type, id, created, modified
#    - from_stix(stix_dict) → platform-native payload
#    - health_check()
#    - get_object(), list_objects(), upsert_object(), delete_object()

# 3. Register sync connector
# gnat/clients/__init__.py:
CLIENT_REGISTRY["myplatform"] = MyplatformClient

# 4. Add async mirror
# gnat/async_client/connectors.py: add AsyncMyplatformClient
# gnat/async_client/client.py: add to _build_async_registry()

# 5. Add INI section to config/config.ini.example

# 6. Add [global.myplatform] block to ADR-0013 (0013-ADR-configuration.md)

# 7. Run tests
pytest tests/unit/connectors/ -v
```

## Quick Reference: Adding a New Ingest Source

```python
# SourceReader subclass
class MyReader(SourceReader):
    def _iter_records(self) -> Iterator[RawRecord]:
        # yield plain dicts

# RecordMapper subclass
class MyMapper(RecordMapper):
    def map(self, record: RawRecord) -> Iterator[STIXBase]:
        # yield STIXBase objects using self._client, self.tlp_marking, self.confidence

# Register in:
# gnat/ingest/sources/__init__.py
# gnat/ingest/mappers/__init__.py
# gnat/__init__.py (both __all__ and import)
```

## Quick Reference: Workspace Investigation Workflow

```python
from gnat import GNATClient
from gnat.context import WorkspaceManager, GlobalContextRegistry

# Setup (once per session)
tq = GNATClient().connect("threatq")
rf = GNATClient().connect("recordedfuture")  # read-only
cs = GNATClient().connect("crowdstrike")

manager = WorkspaceManager.from_clients(
    {"threatq": tq, "rf": rf, "crowdstrike": cs},
    default="threatq",
    read_only=["rf"],
)

# Investigation
ws = manager.get_or_create("campaign-name")
ws.load("indicator", filters={"tags": "apt28"})

ws.enrich(
    sources=["rf", "crowdstrike"],
    strategy="create_relationships",  # preserves provenance
    confidence_floor=60,
)

print(ws.diff())            # what changed
result = ws.commit()        # write back to ThreatQ
print(result)

# Visualize
from gnat.viz import TabularView, GraphView
TabularView(ws).show()
GraphView(ws).to_html("graph.html")  # auto-selects sigma.js at scale
```

---

*Licensed under the Apache License, Version 2.0*

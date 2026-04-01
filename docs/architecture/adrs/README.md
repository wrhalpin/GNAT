# GNAT Architecture Decision Records

A single reference for every design decision made during development,
including tradeoffs, alternatives considered, and implementation notes.
Use this when testing, implementing new connectors, or extending existing
subsystems.

## Table of Contents

1. [ADR-0001: HTTP Client Layer](0001-http-client-layer.md)
2. [ADR-0002: ORM / STIX Compatibility](0002-orm-stix-compatibility.md)
3. [ADR-0003: Connector Architecture](0003-connector-architecture.md)
4. [ADR-0004: Ingestion Framework](0004-ingestion-framework.md)
5. [ADR-0005: Context System — Global and Local](0005-context-system.md)
6. [ADR-0006: Workspace Persistence](0006-workspace-persistence.md)
7. [ADR-0007: Async Client](0007-async-client.md)
8. [ADR-0008: Visualization — Tabular](0008-visualization-tabular.md)
9. [ADR-0009: Visualization — Graph](0009-visualization-graph.md)
10. [ADR-0010: Visualization — Grafana vs Power BI](0010-visualization-grafana-vs-power-bi.md)
11. [ADR-0011: CLI Design](0011-cli-design.md)
12. [ADR-0012: Code Generation](0012-code-generation.md)
13. [ADR-0013: Configuration](0013-configuration.md)
14. [ADR-0014: Testing Strategy](0014-testing-strategy.md)
15. [ADR-0015: Packaging and Extras](0015-packaging-and-extras.md)
16. [ADR-0016: Feed Scheduling](0016-feed-scheduling.md)
17. [ADR-0017: Export / Integration Pipeline](0017-export-integration-pipeline.md)
18. [ADR-0018: AI Agent Layer](0018-ai-agent-layer.md)
19. [ADR-0019: Shared Research Library](0019-shared-research-library.md)
20. [ADR-0020: NLP Query Layer](0020-nlp-query-layer.md)
21. [ADR-0021: Rust Native Extension (`gnat-core`)](0021-rust-native-extension.md)
22. [ADR-0022: Web Dashboard (`gnat/serve/`)](0022-web-dashboard.md)
23. [ADR-0023: Terminal UI — Textual](0023-terminal-ui.md)
24. [ADR-0024: XSOAR Content Pack Generator](0024-xsoar-content-pack-generator.md)
25. [ADR-0025: Upstream Contribution Pipeline](0025-upstream-contribution-pipeline.md)
26. [ADR-0026: Connector Health Monitor](0026-connector-health-monitor.md)
27. [ADR-0027: Multi-Tenant Workspace Isolation](0027-multi-tenant-workspace-isolation.md)
28. [ADR-0028: TAXII 2.1 Server](0028-taxii-21-server.md)
29. [ADR-0029: Docker Containerization](0029-docker-containerization.md)

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

# 6. Add [global.myplatform] block to ADR-0013 (0013-configuration.md)

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

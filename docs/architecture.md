# GNAT High-Level Architecture

GNAT (CTM Toolkit) is a production-ready Python library providing a unified client interface for security and threat-intelligence platforms. This document describes the overall system architecture and links to the individual Architecture Decision Records (ADRs) that capture the rationale behind each major design choice.

> **Visual diagrams:**
> - [Architectural Diagrams](explanation/architecture/diagrams.md) — system overview, connector architecture, AI agent layer, ingestion pipeline (PNG, generated with the `diagrams` library)
> - [Workflow Diagrams](explanation/architecture/workflow-diagrams.md) — sequence and flow diagrams for ingestion, analysis, export, scheduling, and AI agent request flows (Mermaid, compatible with [Grafly](https://grafly.io/))

---

## Layers at a Glance

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CLI / Web Dashboard                          │
│          gnat/cli/  ·  gnat/serve/  ·  gnat/viz/tui.py             │
├─────────────────────────────────────────────────────────────────────┤
│              Dissemination  (gnat/dissemination/)                   │
│     ExportService · WebhookNotifier · TAXII 2.1 · REST Gateway      │
├────────────────────┬────────────────────┬───────────────────────────┤
│   Analysis Layer   │   Reporting Layer  │   Investigation Builder   │
│   gnat/analysis/   │   gnat/reporting/  │   gnat/investigations/    │
│ Confidence · TLP   │ Report lifecycle   │ 5-step evidence graph     │
│ Correlation        │ STIX SDO export    │ Cross-platform pipeline   │
│ Timeline · Graph   │ AI drafting assist │ Workspace materialisation │
├────────────────────┴────────────────────┴───────────────────────────┤
│                         GNATClient facade                           │
│                          gnat/client.py                             │
├────────────────────┬────────────────────┬───────────────────────────┤
│   Ingest Pipeline  │  AI Agent Layer    │  Research Library         │
│   gnat/ingest/     │  gnat/agents/      │  gnat/research/           │
├────────────────────┴────────────────────┴───────────────────────────┤
│                     STIX 2.1 ORM  (gnat/orm/)                       │
├──────────────────────────────────┬──────────────────────────────────┤
│  158 Platform Connectors         │  Export Pipeline                 │
│   gnat/connectors/               │  gnat/export/                   │
├──────────────────────────────────┴──────────────────────────────────┤
│          HTTP Client Layer  (gnat/clients/  ·  gnat/async_client/)  │
│            urllib3 (sync)  ·  httpx (async)                         │
├─────────────────────────────────────────────────────────────────────┤
│   Context & Workspace  │  Scheduling    │  Search Sidecar           │
│   gnat/context/        │  gnat/schedule/│  gnat/search/ (Solr)      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Core Subsystems

### HTTP Client Layer
All network I/O is handled by a thin wrapper around `urllib3.PoolManager` for synchronous work and `httpx.AsyncClient` for async work. The layer provides connection pooling, configurable retries, and a uniform `GNATClientError` exception that carries HTTP status and body.

→ [ADR-0001: HTTP Client Layer](explanation/architecture/adrs/0001-http-client-layer.md)
→ [ADR-0007: Async Client](explanation/architecture/adrs/0007-async-client.md)

---

### STIX 2.1 ORM
`STIXBase` is a pure Python class — not a SQLAlchemy model or Pydantic model. Core STIX fields are real instance attributes; all other properties live in a `_properties` dict exposed via `__getattr__`/`__setattr__`. Serialisation is done via `to_dict()` / `from_dict()` / `to_stix_bundle()`. Non-standard extension fields use the `x_` prefix per STIX 2.1.

→ [ADR-0002: ORM / STIX Compatibility](explanation/architecture/adrs/0002-orm-stix-compatibility.md)

---

### Analysis Layer
The `gnat.analysis` package is the analyst-facing layer that transforms ingested CTI data into
intelligence products. It provides:

- **Confidence scoring** — `ConfidenceScore` combines the NATO Admiralty Scale (source reliability
  A–F, information credibility 1–6) with a STIX 2.1 numeric confidence value (0–100).
- **TLP 2.0 classification** — `TLPLevel` enum covering WHITE/CLEAR/GREEN/AMBER/AMBER+STRICT/RED,
  shared across the analysis, reporting, and dissemination layers.
- **Analyst investigations** — `Investigation` objects with a four-state lifecycle (OPEN →
  IN_PROGRESS → REVIEW → CLOSED), hypothesis tracking, analyst notes, tasks, and artifact linking.
  `InvestigationService` enforces transitions; `InvestigationStore` persists via SQLAlchemy.
- **Correlation engine** — `EntityResolver` deduplicates IOCs across platforms; `RelationshipScorer`
  scores co-occurrence; `ClusterDetector` groups related indicators; `EnrichmentDispatcher` fans out
  enrichment queries best-effort.
- **Timeline reconstruction** — `TimelineBuilder` assembles chronological event sequences from
  investigations, evidence graphs, or raw platform records.
- **Graph queries** — `GraphQuery` provides BFS pivot/expand/filter over `EvidenceGraph` objects
  without a separate graph database.
- **Analyst assistance** — `GapDetector` surfaces missing evidence via rule-based gap analysis;
  `ReportDraftingAssistant` generates LLM-backed executive summaries and key-findings narratives.

→ [ADR-0031: Analysis Layer Architecture](explanation/architecture/adrs/0031-ADR-analysis-layer-architecture.md)
→ [ADR-0033: Confidence Scoring Model](explanation/architecture/adrs/0033-ADR-confidence-scoring.md)
→ [How-to: Use the Analysis Layer](how-to/use-analysis-layer.md)

---

### Investigation Builder
`gnat.investigations.InvestigationBuilder` orchestrates a five-step cross-platform evidence
collection pipeline: seed expansion → incident expansion → normalisation → correlation →
materialisation. It translates raw platform records into a unified `EvidenceGraph` of
`EvidenceNode` and `EvidenceEdge` objects, then writes them to a GNAT workspace as STIX objects
and `Relationship` SROs. Works with any subset of connected platform clients.

→ [ADR-0031: Analysis Layer Architecture](explanation/architecture/adrs/0031-ADR-analysis-layer-architecture.md)
→ [How-to: Build Cross-Platform Investigations](how-to/build-investigations.md)

---

### Reporting Layer
`gnat.reporting` provides first-class intelligence report objects with a formal five-state
lifecycle (DRAFT → REVIEW → APPROVED → PUBLISHED → ARCHIVED). `ReportService` enforces the state
machine and generates a STIX 2.1 `report` SDO bundle automatically on `publish()`. Published
reports are immutable; revisions create a new draft linked via `parent_report_id`. Distinct from
`gnat.reports` (operational PDF/DOCX generator) — this layer produces structured, traceable
finished intelligence.

→ [ADR-0034: Report Lifecycle](explanation/architecture/adrs/0034-ADR-report-lifecycle.md)
→ [ADR-0032: STIX Custom Objects](explanation/architecture/adrs/0032-ADR-stix-custom-objects.md)
→ [How-to: Create Intelligence Reports](how-to/create-intelligence-reports.md)

---

### Dissemination Layer
`gnat.dissemination` handles the outbound delivery of finished intelligence:

- **`ExportService`** — serialises published `Report` objects to STIX 2.1 bundle, JSON, or PDF.
- **`WebhookNotifier`** — fans out HTTP POST notifications to registered subscribers, with
  TLP-based filtering and optional HMAC-SHA256 request signing.
- **TAXII 2.1 router** — `build_taxii_router()` returns a FastAPI router exposing full TAXII 2.1
  Discovery / Collections / Objects endpoints.
- **REST gateway** — `build_gateway_router()` exposes report listing, export download, and API
  key administration; bearer-token auth with TLP-restricted key scopes.

→ [ADR-0028: TAXII 2.1 Server](explanation/architecture/adrs/0028-taxii-21-server.md)
→ [ADR-0031: Analysis Layer Architecture](explanation/architecture/adrs/0031-ADR-analysis-layer-architecture.md)
→ [How-to: Disseminate Intelligence](how-to/disseminate-intelligence.md)

---

### Connector Architecture
Each connector uses dual inheritance — `BaseClient` (HTTP) and `ConnectorMixin` (STIX contract). Every connector must implement `authenticate()`, `to_stix()`, `from_stix()`, `health_check()`, and the four CRUD methods. Connectors are registered in `CLIENT_REGISTRY` in `gnat/clients/__init__.py`. The library ships with 158 connectors covering SIEM, XDR, TIP, ASM, OT/IoT, vulnerability management, sandboxes, MDR, identity/ITDR, email security, insider risk/UEBA, BAS, DFIR, certificate transparency, bug bounty, and AI platforms.

→ [ADR-0003: Connector Architecture](explanation/architecture/adrs/0003-connector-architecture.md)

---

### Ingestion Framework
Three composable abstractions form the ingest pipeline:

| Abstraction | Role |
|---|---|
| `SourceReader` | Reads raw records from any source (file, API, TAXII, RSS, SQL…) |
| `RecordMapper` | Converts raw records into `STIXBase` objects |
| `IngestPipeline` | Wires reader → mapper → dedup → connector write |

14 built-in readers and 12 built-in mappers cover the most common formats. Custom readers and mappers can be dropped in by subclassing.

→ [ADR-0004: Ingestion Framework](explanation/architecture/adrs/0004-ingestion-framework.md)

---

### Context and Workspace
A `GlobalContextRegistry` tracks named connector instances and their read/write permissions. `WorkspaceManager` creates and manages investigation workspaces, each with its own object graph and diff/commit lifecycle. Workspaces are serialised to JSON for persistence; optional SQLAlchemy back-end available via the `persist` extra.

→ [ADR-0005: Context System](explanation/architecture/adrs/0005-context-system.md)
→ [ADR-0006: Workspace Persistence](explanation/architecture/adrs/0006-workspace-persistence.md)
→ [ADR-0027: Multi-Tenant Workspace Isolation](explanation/architecture/adrs/0027-multi-tenant-workspace-isolation.md)

---

### Visualization
Three rendering targets are supported out of the box:

| Target | Module | Best for |
|---|---|---|
| Tabular (pandas / rich) | `gnat/viz/tabular.py` | CLI output, quick review |
| Graph (sigma.js / pyvis) | `gnat/viz/graph.py` | Relationship exploration |
| Grafana / Power BI export | `gnat/viz/` | Operational dashboards |

→ [ADR-0008: Visualization — Tabular](explanation/architecture/adrs/0008-visualization-tabular.md)
→ [ADR-0009: Visualization — Graph](explanation/architecture/adrs/0009-visualization-graph.md)
→ [ADR-0010: Visualization — Grafana vs Power BI](explanation/architecture/adrs/0010-visualization-grafana-vs-power-bi.md)

---

### CLI
The CLI (`gnat/cli/main.py`) uses `argparse` subcommands with no framework dependency. It surfaces ingest, export, scheduling, workspaces, connectors, reports, and code generation as top-level subcommands.

→ [ADR-0011: CLI Design](explanation/architecture/adrs/0011-cli-design.md)
→ [ADR-0023: Terminal UI — Textual](explanation/architecture/adrs/0023-terminal-ui.md)

---

### Code Generation
`gnat/codegen/` scaffolds new connector packages from an OpenAPI specification. It generates the directory layout, `__init__.py`, `client.py` stub with the full `ConnectorMixin` contract, unit test skeleton, INI example block, and ADR stub.

→ [ADR-0012: Code Generation](explanation/architecture/adrs/0012-code-generation.md)
→ [ADR-0024: XSOAR Content Pack Generator](explanation/architecture/adrs/0024-xsoar-content-pack-generator.md)

---

### Configuration
INI-based configuration via stdlib `configparser`. Search order: `GNAT_CONFIG` env var → `~/.gnat/config.ini` → `./gnat.ini`. Each platform gets its own section; shared settings live in `[global]`. No external config library is used.

→ [ADR-0013: Configuration](explanation/architecture/adrs/0013-configuration.md)

---

### Testing Strategy
Unit tests live in `tests/unit/` and mock at the HTTP layer via `mock_pool_manager`. Integration tests in `tests/integration/` are gated behind `@pytest.mark.integration` and the `--run-integration` pytest flag; they require live credentials in `GNAT_CONFIG`. Minimum coverage is 70 %.

→ [ADR-0014: Testing Strategy](explanation/architecture/adrs/0014-testing-strategy.md)

---

### Packaging and Extras
GNAT uses setuptools extras so users install only what they need. The core package requires only `urllib3`. Optional feature groups (`yaml`, `taxii`, `ingest`, `async`, `persist`, `schedule`, `reports`, `viz`, `serve`) are installed on demand. The `all` extra pulls everything.

→ [ADR-0015: Packaging and Extras](explanation/architecture/adrs/0015-packaging-and-extras.md)

---

### Feed Scheduling
`FeedJob` wraps a `(SourceReader, RecordMapper, connector)` triple with a cron expression. `FeedScheduler` runs jobs via `croniter`, tracks `last_success`, and passes a `JobRunContext` to each reader factory so incremental fetches work correctly.

→ [ADR-0016: Feed Scheduling](explanation/architecture/adrs/0016-feed-scheduling.md)

---

### Export Pipeline
The export layer converts `STIXBase` objects to delivery-ready formats. Built-in targets include EDL (plain-text IP/domain/URL block lists) and Netskope CE. A filter chain (`ConfidenceFilter`, `TLPFilter`, `SectorFilter`) gates what reaches each target.

→ [ADR-0017: Export / Integration Pipeline](explanation/architecture/adrs/0017-export-integration-pipeline.md)

---

### AI Agent Layer
`ResearchAgent` (a `SourceReader`) and `ParsingAgent` (a `RecordMapper`) drop directly into the existing `IngestPipeline` and `FeedJob` infrastructure. They call the Claude API using stdlib `urllib` (no `anthropic` SDK dependency). Every AI-extracted STIX object is capped at `ai_confidence_ceiling` (default 60) and tagged `x_source_type: "ai_extracted"` to require human review before high-stakes propagation. `CopilotReader` connects to Microsoft 365 via the Bot Framework DirectLine v3 API.

→ [ADR-0018: AI Agent Layer](explanation/architecture/adrs/0018-ai-agent-layer.md)

---

### Research Library
`ResearchLibrary` provides a curated, searchable store of threat reports, news, and analyst notes. `CurationJob` automates ingestion from monitored RSS/web sources. The library integrates with the AI agent layer for AI-assisted summarisation and with the Solr search sidecar for full-text search.

→ [ADR-0019: Shared Research Library](explanation/architecture/adrs/0019-shared-research-library.md)

---

### NLP Query Layer
A natural-language query interface sits in front of workspace objects and the research library. Queries are translated to structured filters by the AI agent layer, allowing analysts to ask questions like "show me all ransomware indicators added this week" without writing code.

→ [ADR-0020: NLP Query Layer](explanation/architecture/adrs/0020-nlp-query-layer.md)

---

### Rust Native Extension
An optional Rust extension module (`gnat._core`) accelerates hot-path IOC operations: classify, defang, refang, extract pattern value, and batch classify. The Python shim (`gnat/ingest/_ioc_classifier.py`) detects whether the compiled extension is available and falls back to the pure-Python implementation transparently.

→ [ADR-0021: Rust Native Extension](explanation/architecture/adrs/0021-rust-native-extension.md)

---

### Web Dashboard
`gnat/serve/` exposes a FastAPI-based web dashboard for browsing workspaces, running queries, and reviewing AI-extracted objects. It is an optional component installed via the `serve` extra (`fastapi` + `uvicorn`).

→ [ADR-0022: Web Dashboard](explanation/architecture/adrs/0022-web-dashboard.md)

---

### Upstream Contribution Pipeline
A pipeline that formats GNAT-curated intelligence as pull requests or API submissions to open-source threat-intel communities (MISP galaxies, OpenCTI, TAXII 2.1 servers). Governed by configurable confidence thresholds and TLP markings.

→ [ADR-0025: Upstream Contribution Pipeline](explanation/architecture/adrs/0025-upstream-contribution-pipeline.md)

---

### Connector Health Monitor
A background service that polls each registered connector's `health_check()` endpoint on a configurable interval, records latency and availability metrics, and surfaces connector status in the web dashboard and CLI.

→ [ADR-0026: Connector Health Monitor](explanation/architecture/adrs/0026-connector-health-monitor.md)

---

### TAXII 2.1 Server
An embedded TAXII 2.1 server (`gnat/serve/taxii/`) allows GNAT to act as a threat-intel distribution point. Collections map to connector namespaces or workspace snapshots. Requires the `serve` extra.

→ [ADR-0028: TAXII 2.1 Server](explanation/architecture/adrs/0028-taxii-21-server.md)

---

### Docker Containerisation
Official Docker images and a `docker-compose.yml` ship with the repository. The compose stack includes the GNAT API server, Solr (search sidecar), and a scheduler container. Configuration is injected via environment variables that map to INI keys.

→ [ADR-0029: Docker Containerization](explanation/architecture/adrs/0029-docker-containerization.md)

---

## Architecture Decision Records Index

All ADRs are stored in [`docs/explanation/architecture/adrs/`](explanation/architecture/adrs/) and listed in the [ADR README](explanation/architecture/adrs/README.md).

| # | Title | Topic |
|---|-------|-------|
| [0001](explanation/architecture/adrs/0001-http-client-layer.md) | HTTP Client Layer | Infrastructure |
| [0002](explanation/architecture/adrs/0002-orm-stix-compatibility.md) | ORM / STIX Compatibility | Data model |
| [0003](explanation/architecture/adrs/0003-connector-architecture.md) | Connector Architecture | Integration |
| [0004](explanation/architecture/adrs/0004-ingestion-framework.md) | Ingestion Framework | Data pipeline |
| [0005](explanation/architecture/adrs/0005-context-system.md) | Context System | State management |
| [0006](explanation/architecture/adrs/0006-workspace-persistence.md) | Workspace Persistence | State management |
| [0007](explanation/architecture/adrs/0007-async-client.md) | Async Client | Infrastructure |
| [0008](explanation/architecture/adrs/0008-visualization-tabular.md) | Visualization — Tabular | UX |
| [0009](explanation/architecture/adrs/0009-visualization-graph.md) | Visualization — Graph | UX |
| [0010](explanation/architecture/adrs/0010-visualization-grafana-vs-power-bi.md) | Visualization — Grafana vs Power BI | UX |
| [0011](explanation/architecture/adrs/0011-cli-design.md) | CLI Design | UX |
| [0012](explanation/architecture/adrs/0012-code-generation.md) | Code Generation | Developer experience |
| [0013](explanation/architecture/adrs/0013-configuration.md) | Configuration | Infrastructure |
| [0014](explanation/architecture/adrs/0014-testing-strategy.md) | Testing Strategy | Quality |
| [0015](explanation/architecture/adrs/0015-packaging-and-extras.md) | Packaging and Extras | Distribution |
| [0016](explanation/architecture/adrs/0016-feed-scheduling.md) | Feed Scheduling | Data pipeline |
| [0017](explanation/architecture/adrs/0017-export-integration-pipeline.md) | Export / Integration Pipeline | Data pipeline |
| [0018](explanation/architecture/adrs/0018-ai-agent-layer.md) | AI Agent Layer | Intelligence |
| [0019](explanation/architecture/adrs/0019-shared-research-library.md) | Shared Research Library | Intelligence |
| [0020](explanation/architecture/adrs/0020-nlp-query-layer.md) | NLP Query Layer | Intelligence |
| [0021](explanation/architecture/adrs/0021-rust-native-extension.md) | Rust Native Extension | Performance |
| [0022](explanation/architecture/adrs/0022-web-dashboard.md) | Web Dashboard | UX |
| [0023](explanation/architecture/adrs/0023-terminal-ui.md) | Terminal UI — Textual | UX |
| [0024](explanation/architecture/adrs/0024-xsoar-content-pack-generator.md) | XSOAR Content Pack Generator | Developer experience |
| [0025](explanation/architecture/adrs/0025-upstream-contribution-pipeline.md) | Upstream Contribution Pipeline | Integration |
| [0026](explanation/architecture/adrs/0026-connector-health-monitor.md) | Connector Health Monitor | Operations |
| [0027](explanation/architecture/adrs/0027-multi-tenant-workspace-isolation.md) | Multi-Tenant Workspace Isolation | State management |
| [0028](explanation/architecture/adrs/0028-taxii-21-server.md) | TAXII 2.1 Server | Integration |
| [0029](explanation/architecture/adrs/0029-docker-containerization.md) | Docker Containerization | Operations |
| [0030](explanation/architecture/adrs/0030-use-diataxis-and-adrs.md) | Adopt Diátaxis and ADRs | Documentation |
| [0031](explanation/architecture/adrs/0031-ADR-analysis-layer-architecture.md) | Analysis Layer Architecture | Intelligence |
| [0032](explanation/architecture/adrs/0032-ADR-stix-custom-objects.md) | STIX Custom Objects | Data model |
| [0033](explanation/architecture/adrs/0033-ADR-confidence-scoring.md) | Confidence Scoring Model | Intelligence |
| [0034](explanation/architecture/adrs/0034-ADR-report-lifecycle.md) | Report Lifecycle State Machine | Intelligence |
| [0035](explanation/architecture/adrs/0035-ADR-quality-agents.md) | Quality Agents | Quality |
| [0036](explanation/architecture/adrs/0036-ADR-security-agents-phaseb.md) | Security Agents (Phase B) | Quality |
| [0037](explanation/architecture/adrs/0037-ADR-adopt-responsible-disclosure-dco-and-apache-2.0-compliance.md) | Responsible Disclosure, DCO, and Apache 2.0 Compliance | Governance |

---

## Key Design Principles

| Principle | Rationale |
|---|---|
| **urllib3 over requests** | Direct control, no extra abstraction layer, compatible with async path |
| **Pure-Python ORM** | STIX objects are not DB-bound; serialise to JSON, not sessions |
| **`ConnectorMixin` contract** | Every connector exposes the same CRUD + STIX surface; no special casing in pipelines |
| **Extras-based packaging** | Users pay only for the dependencies they actually use |
| **AI confidence ceiling** | AI-extracted intel requires human review before high-stakes propagation |
| **INI configuration** | Zero external config library; works everywhere `configparser` works |
| **Diátaxis docs** | Each document has one purpose — tutorial, how-to, reference, or explanation |

---

*Licensed under the Apache License, Version 2.0*

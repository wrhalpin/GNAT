# Changelog

All notable changes to GNAT are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Detailed per-version release notes are available in [`docs/releases/`](docs/releases/).

---

## [Unreleased]

### Added — Analysis Layer (Phase 0 + 1 + 2)

**`gnat.analysis` — Analyst-facing foundation**
- `gnat/analysis/tlp.py`: `TLPLevel` enum implementing TLP 2.0 (WHITE/CLEAR/GREEN/AMBER/AMBER+STRICT/RED) with STIX marking definition IDs, hex colours, rank ordering, and human-readable labels
- `gnat/analysis/confidence.py`: `ConfidenceScore` dataclass combining the NATO Admiralty Scale (source reliability A–F, information credibility 1–6) with a STIX 2.1 numeric confidence value (0–100); `ConfidenceLevel` convenience bands (HIGH/MEDIUM/LOW); convenience factories `ConfidenceScore.high/medium/low()`

**`gnat.analysis.investigations` — Investigation lifecycle**
- `Investigation` dataclass: top-level analyst workspace with status state machine (OPEN → IN_PROGRESS → REVIEW → CLOSED), TLP classification, scope constraints, hypothesis tracking, analyst notes, tasks, and artifact linking
- `Hypothesis`, `AnalystNote`, `InvestigationTask`, `InvestigationScope` dataclasses
- `InvestigationStore`: SQLAlchemy-backed persistence (`sqlite:///:memory:` for tests, shared engine support); follows existing `WorkspaceStore` JSON-serialization pattern; zero-migration `create_all()` schema init
- `InvestigationService`: enforces state machine transitions, owns all mutation operations (create/get/list/delete/transition, add_note/task/hypothesis, link_indicators/observables/threat_actors, add_tags, summary)
- `InvestigationError` for invalid operations

**`gnat.reporting` — Intelligence product lifecycle**
- `Report` dataclass: structured intelligence product with five-state lifecycle (DRAFT → REVIEW → APPROVED → PUBLISHED → ARCHIVED), versioning with `parent_report_id` linkage, TLP classification, evidence binding, attribution, STIX export
- `Finding`, `EvidenceLink`, `Attribution`, `ReportSection`, `ChangelogEntry` dataclasses
- `ReportType` enum: INCIDENT_REPORT / THREAT_ACTOR_PROFILE / CAMPAIGN_ANALYSIS / DAILY_BRIEF / VULNERABILITY_ADVISORY / FINISHED_INTELLIGENCE
- `ReportStore`: SQLAlchemy-backed persistence with same zero-migration pattern as `InvestigationStore`
- `ReportService`: enforces lifecycle transitions; `publish()` auto-generates STIX bundle and sets `stix_report_ref`; `create_revision()` creates new draft from published version with incremented version
- `report_to_stix_bundle()`: serialises a `Report` to a STIX 2.1 bundle (report SDO + identity SDO + threat-actor SDO if attribution set + attributed-to relationship); TLP `object_marking_refs`; `x_gnat_*` extension fields
- Three report templates (YAML): `incident_report.yaml`, `threat_actor_profile.yaml`, `campaign_analysis.yaml`
- `[analysis]` and `[reporting]` optional dependency extras (both require `sqlalchemy>=2.0`)

**Architecture Decision Records**
- ADR-0031: Analysis Layer Architecture — layered consumer model; `WorkspaceStore` pattern for new tables; no new storage backend
- ADR-0032: STIX Custom Objects — `x-gnat-investigation` SDO schema; `investigates` custom relationship verb; standard `report` SDO for finished intelligence
- ADR-0033: Confidence Scoring Model — rationale for Admiralty Scale; STIX numeric confidence for interoperability; HIGH/MEDIUM/LOW bands aligned with ATT&CK convention
- ADR-0034: Report Lifecycle — five-state machine with reject path; immutability on PUBLISHED; versioning model; STIX bundle triggered on publish

**Tests**
- `tests/unit/analysis/test_confidence.py`: 16 tests covering TLP ordering, STIX marking IDs, confidence bands, Admiralty Scale, serialization roundtrips, bounds validation
- `tests/unit/analysis/test_investigations.py`: 24 tests covering model roundtrips, state machine valid/invalid transitions, full service lifecycle (create/get/transition/note/task/hypothesis/link/delete/list/summary)
- `tests/unit/reporting/test_reports.py`: 30 tests covering report model, evidence links, attribution, full DRAFT→PUBLISHED lifecycle, immutability enforcement, STIX bundle structure and field correctness, revision creation

**Bug fixes**
- `gnat/investigations/builder.py`: CASE_ID seed expansion passed a list to `normalize()` instead of iterating it (fixed in previous session)
- `gnat/investigations/normalizer.py`: Missing `("threatq", "incident")` dispatch alias — ThreatQ Events are the investigation container but the builder calls `normalize(platform, "incident", ...)` for all CASE_ID seeds
- `gnat/investigations/workspace.py`: `_node_to_stix_base` and Relationship tagging used `obj["key"] = value` item assignment; `STIXBase` only supports `obj.key = value` attribute access — fixed, workspace now materialises all nodes correctly (was 0 nodes materialised)

**Example**
- `examples/investigation_xsoar_tq_gm_powerbi.py`: End-to-end cross-platform investigation script (XSOAR + ThreatQ + GreyMatter → EvidenceGraph → workspace → Power BI xlsx); `--mock` flag for dry runs without live credentials; completeness check verifying 14 investigation methods across 3 platforms

### Added — Analysis Layer (Phase 3: Correlation Engine + Analyst Assistance)

**`gnat.analysis.correlation` — Cross-platform indicator correlation**
- `EntityResolver`: deduplicates indicators across platforms by canonical value; normalises IPv4 (strips /32), IPv6 (compressed), domain (lowercase, trailing dot stripped), URL (scheme+host lowercase), email, MD5/SHA1/SHA256 hashes, hostname, and ASN; groups cross-platform aliases into `EntityGroup` objects
- `IndicatorRecord`: lightweight dataclass for platform-sourced IOC records with platform, ioc_type, value, confidence, tags, and first/last seen timestamps
- `EntityGroup`: aggregated view of cross-platform aliases; exposes `platforms`, `is_cross_platform`, `max_confidence`, `all_tags` properties
- `RelationshipScorer`: scores entity-to-entity relationships using co-occurrence (0/0/15/30/45 pts for 1–4+ platforms), recency (≤7d=25pts, ≤30d=15pts, ≤90d=5pts), and source-reliability bonus (+10 if all ≥ B_USUALLY_RELIABLE); output is a `ConfidenceScore`
- `ClusterDetector`: rule-based heuristic clustering of `EntityGroup` objects via shared /24 subnet, shared tags, platform co-occurrence, and timing proximity (72-hour window); BFS connected-component grouping; `Cluster` dataclass with member IDs, signals list, and confidence score
- `EnrichmentDispatcher`: fan-out enrichment across registered connectors; tries `search_indicators_by_value` → `search_observables_by_value` → `list_objects` in priority order; fully best-effort (errors logged, never raised); returns `EnrichmentResult` dict per platform

**`gnat.analysis.timeline` — Chronological event reconstruction**
- `TimelineBuilder`: reconstructs investigation timelines from `Investigation` objects (opened/notes/tasks/closed), `EvidenceGraph` nodes (via `time_window` and `stix` metadata), and raw records (arbitrary timestamp + title fields)
- `TimelineEvent`: dataclass with timestamp, event_type, title, source, description, and linked_artifacts
- `TimelineEventType` enum: 14 event types covering incident/investigation lifecycle, analyst actions, and observables

**`gnat.analysis.graph` — Evidence graph querying**
- `GraphQuery`: adjacency-index BFS pivot/expand/filter over `EvidenceGraph` objects; supports N-hop pivoting, cross-node expansion, and multi-dimensional filtering (confidence, platform set, date range, node types)
- `GraphContext`: results container with nodes dict, edges list, seed_ids; `platforms()`, `node_count`, `edge_count` properties; `to_dict()` for API serialisation
- `GraphQuery.shortest_path()`: BFS shortest-path between any two nodes

**`gnat.analysis.copilot` — Analyst assistance**
- `GapDetector`: 8 rule-based evidence gap detection rules (no-evidence/CRITICAL, lateral-movement-no-host/HIGH, exfiltration-no-network/HIGH, attribution-no-ttp/HIGH, ransomware-no-hash/MEDIUM, phishing-no-email-or-domain/MEDIUM, c2-no-network-ioc/HIGH, no-campaign-linkage/LOW); `detect()` per hypothesis, `detect_all()` across all hypotheses, `summary()` counts by severity
- `GapRecommendation`: dataclass with rule_id, severity, description, suggested_action
- `ReportDraftingAssistant`: LLM-backed executive summary and key-findings narrative drafting; graceful fallback (placeholder text + warning) when no LLM configured; two-call `draft_full()` for merged results; configurable prompt templates; evidence capped at 20 links to avoid token explosion
- `DraftResult`: output dataclass with executive_summary, key_findings_narrative, model, prompt/completion token counts, and warnings

### Added — Dissemination Layer (Phase 4)

**`gnat.dissemination.export` — Report export**
- `ExportService`: exports published intelligence reports to STIX 2.1 bundle, GNAT JSON, or PDF; uses cached `stix_bundle_json` when available; SHA-256 checksum on all outputs
- `ExportFormat` enum: STIX / JSON / PDF
- `ExportResult`: dataclass with report_id, format, path, size_bytes, checksum (SHA-256 hex), exported_at
- `export_stix_bundle()`: in-memory STIX bundle retrieval without disk write
- PDF export via `gnat.reports.renderers.PDFRenderer`; falls back to plain-text if reportlab not installed

**`gnat.dissemination.taxii` — TAXII 2.1 server**
- `TAXIICollection`: TAXII 2.1 collection backed by GNAT report store; deterministic UUIDs (uuid5); TLP rank-based `is_accessible()` access control
- `COLLECTIONS`: four built-in collections (tlp-white/green/amber/red) with cumulative TLP filtering
- `build_taxii_router()`: FastAPI router implementing all six TAXII 2.1 read-only endpoints (Discovery, API Root, Collections list/metadata, Objects, Manifest); offset-based pagination with base64 cursor; `application/taxii+json;version=2.1` content type
- ADR-0035: FastAPI over dedicated TAXII library; TLP-based collection model; single-process TAXII+API mount

**`gnat.dissemination.notify` — Webhook notifications**
- `WebhookNotifier`: fan-out HTTP POST notifications to registered subscribers; TLP-level access control per subscriber; HMAC-SHA256 `X-GNAT-Signature` header when secret configured; best-effort delivery (errors logged, never raised)
- `WebhookSubscription`: dataclass with id, url, min_tlp, secret, events list, timeout
- `DeliveryReceipt`: per-delivery outcome with status_code, success flag, error message, attempted_at

**`gnat.dissemination.api` — REST gateway and API key management**
- `APIKey`: API key dataclass with TLP access level, label, expiry, enabled flag, SHA-256 token hash property
- `APIKeyStore`: in-memory bearer token store with add/generate/revoke/delete/list operations; `generate_key()` produces cryptographically random 32-byte tokens
- `build_gateway_router()`: FastAPI router for report listing/metadata/export (STIX/JSON/PDF) and admin key management; TLP-filtered report responses; PDF via `FileResponse` with background cleanup

**Optional extras**
- `gnat[taxii-server]`: FastAPI + uvicorn for TAXII 2.1 server
- `gnat[dissemination]`: FastAPI + uvicorn + SQLAlchemy for full dissemination layer

**Tests**: 142 new unit tests across `tests/unit/analysis/test_correlation.py`, `test_timeline.py`, `test_graph.py`, `test_copilot.py`, `tests/unit/dissemination/test_export.py`, `test_taxii.py`, `test_notify.py`

---

## [v1.3.0] — Unreleased

9 new platform connectors (AWS Security Hub/GuardDuty, Cribl Stream, Datadog, Dragos, HIBP, SecurityScorecard, Synapse, Tanium, Trend Micro Vision One). Unified multi-LLM client (`LLMClient`) with Claude, OpenAI, and Grok backends and automatic fallback. Deprecated `PENDING_ITEMS.md` — release notes, ADRs, and the architecture implementation plan now supersede it.

→ [Full release notes](docs/releases/v1.3.0.md)

---

## [v1.2.0] — 2026-03-30

25 new platform connectors across three batches (Censys, ServiceNow SecOps, Darktrace, ExtraHop, Lansweeper, Vectra, Sophos, Trellix, BitSight, Flashpoint, HudsonRock, Intel 471, UpGuard, Carbon Black, CortexXDR, Dragos, FortiEDR, FortiSIEM, FortiSOAR, Google Chronicle, GreyNoise, LogRhythm, Nozomi, Prisma Cloud, Shodan). CISA KEV connector. 89 new unit tests for previously untested connectors. Mass lint cleanup (4,647 auto-fixed issues + 141 manual fixes).

→ [Full release notes](docs/releases/v1.2.0.md)

---

## [v1.1.0] — 2026-03-30

13 new connectors (Armis, Axonius, Cortex Xpanse, CyCognito, DefectDojo, Greenbone, Group-IB, Orca, Qualys, SentinelOne, Tenable One, Wiz, ZeroFox). Optional Rust-accelerated IOC processing (`gnat-core`). Web dashboard, Textual TUI, TAXII 2.1 server, NLP query engine, STIX pattern validator, multi-tenant workspace isolation, XSOAR content pack generator, upstream contribution pipeline, connector health monitor, Solr/Grafana observability, Docker integration test harness, Jira connector, and numerous connector additions and fixes.

→ [Full release notes](docs/releases/v1.1.0.md)

---

## [v1.0.0] — 2026-03-28

First stable release. 29 platform connectors including SIEM/IDS/IPS platforms (Elastic, Graylog, MISP, OpenCTI, OSSIM, QRadar, Security Onion, Sentinel, Snort, Suricata, Wazuh, Zeek, ControlUp DEX, AlienVault OTX). Solr search sidecar. Report generation pipeline (PDF, HTML, DOCX, Markdown) with AI narration. AI agents (ResearchAgent, ParsingAgent, CopilotReader). Research Library with curation workflow.

→ [Full release notes](docs/releases/v1.0.0.md)

---

## [v0.9.0] — 2025-09-15

Research Library three-tier knowledge base (personal / staging / library workspaces) with TTL-based curation and INI configuration.

→ [Full release notes](docs/releases/v0.9.0.md)

---

## [v0.8.0] — 2025-07-01

AI agent integration: ResearchAgent (Claude-powered threat synthesis), ParsingAgent (unstructured text → STIX), and CopilotReader (Microsoft Copilot DirectLine). Config via `[claude]` INI section.

→ [Full release notes](docs/releases/v0.8.0.md)

---

## [v0.7.0] — 2025-05-15

Export pipeline with fluent builder API. 11 filter types (TypeFilter, ConfidenceFilter, TLPFilter, SectorFilter, etc.), EDL and Netskope CE transforms, and multiple delivery targets including EDLServer (FastAPI).

→ [Full release notes](docs/releases/v0.7.0.md)

---

## [v0.6.0] — 2025-04-01

Feed scheduling layer: `FeedScheduler`, `FeedJob`, `IngestJob`, cron expression support via croniter, and `gnat schedule` CLI subcommands.

→ [Full release notes](docs/releases/v0.6.0.md)

---

## [v0.3.0] — 2025-03-20

Async client (`AsyncGNATClient` on httpx). Full CLI (`gnat ping`, `query`, `list`, `ingest`, `codegen`, `config`). Visualization layer (TabularView, GraphView with sigma.js WebGL for 1000+ nodes, GrafanaServer, PowerBIExporter). Context system (GlobalContext, Workspace, WorkspaceManager, FlatFileStore/WorkspaceStore). Sphinx documentation. GitHub Actions CI/CD.

→ [Full release notes](docs/releases/v0.3.0.md)

---

## [v0.1.0] — 2025-03-19

Initial release. Core client layer (`GNATClient`, `BaseClient`, `CLIENT_REGISTRY`). STIX 2.1 ORM (`STIXBase` + 12 domain/observable types). 6 platform connectors (ThreatQ, CrowdStrike, Proofpoint, Netskope, XSOAR, Recorded Future). Ingestion framework with 14 source readers and 12 record mappers. OpenAPI code generator. Full unit and integration test scaffold.

→ [Full release notes](docs/releases/v0.1.0.md)

---

[Unreleased]: https://github.com/your-org/gnat/compare/v1.2.0...HEAD
[v1.3.0]: https://github.com/your-org/gnat/compare/v1.2.0...v1.3.0
[v1.2.0]: https://github.com/your-org/gnat/compare/v1.1.0...v1.2.0
[v1.1.0]: https://github.com/your-org/gnat/compare/v1.0.0...v1.1.0
[v1.0.0]: https://github.com/your-org/gnat/compare/v0.9.0...v1.0.0
[v0.9.0]: https://github.com/your-org/gnat/compare/v0.8.0...v0.9.0
[v0.8.0]: https://github.com/your-org/gnat/compare/v0.7.0...v0.8.0
[v0.7.0]: https://github.com/your-org/gnat/compare/v0.6.0...v0.7.0
[v0.6.0]: https://github.com/your-org/gnat/compare/v0.3.0...v0.6.0
[v0.3.0]: https://github.com/your-org/gnat/compare/v0.1.0...v0.3.0
[v0.1.0]: https://github.com/your-org/gnat/releases/tag/v0.1.0

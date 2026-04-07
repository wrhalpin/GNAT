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

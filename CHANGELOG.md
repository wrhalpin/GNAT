# Changelog

All notable changes to GNAT are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Detailed per-version release notes are available in [`docs/releases/`](docs/releases/).

---

## [Unreleased]

### Added — Analyst OS Layer (Phase 3)

**Database Migrations (`alembic/`)**
- `alembic.ini` + `alembic/env.py`: Alembic 1.13 setup; URL resolved from `GNAT_DB_URL` env var → `[database]` INI section → `alembic.ini` default; unified metadata via `gnat.migrations.get_combined_metadata()`
- `alembic/versions/0001_init_all_tables.py`: initial schema (investigations, reports, workspaces, workspace_objects, enrichment_log, context_globals)
- `alembic/versions/0002_add_lineage_events.py`: `lineage_events` table with composite index on (object_id, timestamp)
- `alembic/versions/0003_add_metrics_events.py`: `metrics_events` table with index on (metric_type, timestamp)
- `gnat/migrations/__init__.py`: `get_combined_metadata()` aggregates all `_Base` objects for Alembic auto-detection
- `gnat/migrations/cli.py`: `gnat-db` CLI entry point with upgrade/downgrade/current/history/check/revision/stamp subcommands
- New extras: `[migrations]` (alembic + sqlalchemy); `[orchestration]` (sqlalchemy)
- New script: `gnat-db = "gnat.migrations.cli:main"` in pyproject.toml

**Plugin System (`gnat/plugins/`)**
- `GNATPlugin` ABC: `name`, `version`, `capabilities`, `description`; requires `register(registry)` implementation
- `PluginCapability` enum: CONNECTOR | READER | MAPPER | AGENT | REPORTER | HOOK
- `HookBus` singleton: thread-safe pub/sub with `on()` decorator, `register/unregister/emit/clear/handlers()`; 14 built-in `KNOWN_EVENTS`; async handler support; exceptions in handlers are caught and logged, never propagated
- `PluginRegistry`: load/unload/get/list/list_by_capability; entry_points discovery (`gnat.plugins` group); filesystem discovery via `GNAT_PLUGIN_DIRS`; `register_connector/reader/mapper()` wraps existing registries
- `load_plugins()`: reads `[plugins]` INI section + `GNAT_PLUGIN_DIRS` env var
- `[project.entry-points."gnat.plugins"]` section in pyproject.toml for third-party plugin declaration
- ADR-0036: Plugin Architecture — entry_points + filesystem discovery; HookBus pub/sub; backward-compatible connector/reader/mapper registration

**Policy Engine (`gnat/policy/`)**
- `Role` enum (VIEWER → ADMIN) + `Permission` enum (10 permissions) + static `ROLE_PERMISSIONS` matrix
- `PolicyEngine`: `evaluate(subject, permission)`, `evaluate_role(role, permission)`, `require(permission, key_store)` FastAPI `Depends` factory, `audit()` emits `policy_decision` HookBus event
- `build_audit_middleware(key_store)`: Starlette `BaseHTTPMiddleware` that times requests, resolves actor, emits structured log + `api_request` HookBus event
- `APIKey.role: str = "viewer"` field added; `APIKeyStore.add_key/generate_key()` gain `role=` kwarg
- `APIKey.to_dict()` now includes `role` field
- `build_gateway_router()` gains optional `policy_engine=` parameter; admin endpoints use `engine.require(Permission.MANAGE_KEYS)` instead of raw TLP check; old `_require_admin()` removed
- ADR-0037: Policy Engine — RBAC orthogonal to TLP, static permission matrix, FastAPI-native Depends integration

**TAXII 2.1 Write Endpoints**
- `TAXIICollection.can_write = True` for TLP:AMBER and TLP:RED collections
- POST `/taxii2/{api-root}/collections/{id}/objects/`: push STIX 2.1 bundle; requires `WRITE_TAXII` permission; validates `type=bundle`; routes `report` objects to `store.ingest_stix()`; returns TAXII 2.1 status record (202)
- DELETE `/taxii2/{api-root}/collections/{id}/objects/{stix-id}`: soft-delete by STIX ID; tries `store.delete_by_stix_id()` first, falls back to scan+delete; returns 404 on not found
- `build_taxii_router()` gains optional `policy_engine=` parameter
- `_ingest_stix_objects()` and `_soft_delete_object()` helpers (testable independently)
- Updated module docstring to document all 8 endpoints (6 read + 2 write)

**Investigation Query DSL (`gnat/analysis/query.py`)**
- `InvestigationQuery` dataclass: `status` list, `created_by`, `assigned_to`, `tags` list (ANY match), `classification` list, `date_from`/`date_to`, `text` (title substring), `has_hypothesis`, `has_linked_report`, `page`, `page_size`, `sort_by`, `sort_desc`
- `InvestigationStore.list()` now accepts `query: InvestigationQuery` with full filter → SQLAlchemy WHERE chain; `has_hypothesis`/`has_linked_report` post-filtered from JSON blob; legacy kwargs preserved for backward compatibility
- `InvestigationService.list()` accepts `InvestigationQuery` and passes it through
- SQL injection protection: `safe_sort_by` property validates against allowlist

**Serve Routers (`gnat/serve/routers/`)**
- `gnat/serve/routers/investigations.py`: 11 REST endpoints — list (full `InvestigationQuery` filter params), create, get, update, transition, add note, add task, update task, add hypothesis, link artifacts, summary
- `gnat/serve/routers/analysis.py`: 7 REST endpoints — graph/pivot, graph/filter, graph/shortest-path, copilot/gaps, copilot/draft, reports/{id}/export/stix, metrics/investigations, metrics/enrichment
- `gnat/serve/app.py`: `create_app()` and `run()` gain `investigation_service`, `graph_query`, `gap_detector`, `report_drafting_assistant`, `export_service`, `metrics_aggregator` parameters; new routers registered with `_api_deps`

**Agent Orchestration (`gnat/agents/`)**
- `gnat/agents/workflow.py`: `Workflow`, `WorkflowContext`, `WorkflowStep`, `WorkflowResult` — sequential DAG executor with `on_success`/`on_failure` routing, cycle detection, elapsed timing
- `gnat/agents/steps.py`: built-in step factories — `enrich_step`, `correlate_step`, `gap_detect_step`, `draft_report_step`, `transition_step`, `fn_step`; all accept `None` components for no-op/test mode
- `gnat/agents/workflows/phishing_triage.py`: 5-step pre-built phishing triage workflow (enrich → correlate → gap_detect → draft_report → transition IN_PROGRESS)
- `gnat/agents/workflows/incident_response.py`: 5-step incident response workflow (enrich → correlate → gap_detect → draft_report → transition REVIEW)

**Data Lineage (`gnat/lineage/`)**
- `LineageEventType` enum: INGESTED | ENRICHED | NORMALIZED | LINKED | EXPORTED | REPORTED | DELETED
- `LineageEvent` dataclass: immutable append-only record with UUID4 id, timestamp, object_id, actor, source, metadata dict
- `LineageStore` (SQLAlchemy): `lineage_events` table; `append()`, `query(object_id)`, `query_by_type()`, `query_by_actor()`, `count()`; composite index on (object_id, timestamp)
- `LineageTracker`: convenience wrapper with one `record_*` method per event type; `store=None` → silent no-op; exceptions never propagate to callers
- ADR-0038: Data Lineage Tracking — append-only event log; zero new runtime dependencies; optional deployment

**Analyst Metrics (`gnat/metrics/`)**
- `MetricType` enum: 9 types covering investigation lifecycle, enrichment effectiveness, report publishing, gap detection, false positives
- `MetricEvent` dataclass with metric_type, value, labels dict, timestamp
- `MetricsCollector`: thread-safe ring-buffer (configurable max_size); `record()`, `snapshot()`, `since(cutoff)`, `clear()`
- `MetricsAggregator`: `investigation_summary(days)`, `enrichment_effectiveness(platform, days)`, `gap_frequency(days)`, `false_positive_rate(days)` — all return structured dicts

**Architecture Decision Records**
- ADR-0036: Plugin Architecture
- ADR-0037: Policy Engine (RBAC)
- ADR-0038: Data Lineage Tracking

**Tests**
- `tests/unit/test_plugins.py`: 13 tests covering capabilities, ABC enforcement, registry lifecycle, HookBus events/routing/error-swallowing, connector registration
- `tests/unit/test_policy.py`: 13 tests covering role/permission matrix, engine evaluation (by role, subject, fallback), audit hook emission, APIKey role field, init exports
- `tests/unit/test_taxii_write.py`: 12 tests covering collection write flags, ingest helper, soft-delete helper (direct API + fallback scan), router construction
- `tests/unit/agents/test_workflow.py`: 18 tests covering context/step/workflow construction, success/failure/routing runs, all step factories, pre-built workflows
- `tests/unit/test_lineage.py`: 16 tests covering event model, store append/query/count, tracker convenience methods, no-op mode
- `tests/unit/test_metrics.py`: 17 tests covering model, collector (ring buffer, thread safety, snapshot filtering, since), aggregator (investigation summary, enrichment effectiveness, gap frequency, false positive rate)
- `tests/unit/analysis/test_investigation_query.py`: 13 tests covering dataclass helpers (offset/limit/safe_sort_by), full InvestigationStore.list() integration (all filters, pagination, legacy kwargs)

### Added — Integration & CLI Hardening (Phase 4)

**CLI Subcommands (`gnat/cli/main.py`)**
- `gnat investigation` subcommand group: `list` (--status, --created-by, --tag, --text, --page, --page-size), `create` (--title, --created-by, --description, --tlp, --tags), `get <id>`, `transition <id> <status>` (--note, --author), `note <id>` (--content, --author), `link <id>` (--indicators, --reports)
- `gnat plugins` subcommand group: `list` (loads entry_points + env dirs, tabulates all registered plugins), `load <directory>` (on-demand directory scan)
- `gnat db` subcommand group: `upgrade`, `downgrade` (-1), `current`, `history`, `revision` (-m, --autogenerate), `stamp <revision>` — all delegated to `gnat.migrations.cli.run_db_command()`
- `gnat tui` now accepts `investigations` as a screen choice
- DB URL resolved from `GNAT_DB_URL` env var (default `sqlite:///gnat.db`) for investigation subcommand
- Graceful ImportError handling: missing SQLAlchemy → exit 1 with install hint; missing Alembic → exit 1 with install hint

**Data Lineage Wiring**
- `IngestPipeline.with_lineage(tracker)`: fluent builder that sets `_lineage`; after each `obj.save()` emits `tracker.record_ingest()` — exceptions never propagate
- `ExportPipeline.with_lineage(tracker)`: fluent builder on `gnat.export.base.ExportPipeline`; after successful delivery emits `tracker.record_export()` for each delivered object
- `ReportService.__init__` gains optional `lineage=` parameter; `publish()` emits `tracker.record_report()` after STIX bundle generation

**MetricsCollector HookBus Bridge (`gnat/metrics/hooks.py`)**
- `register_metrics_hooks(collector)`: registers closures on `HookBus.instance()` for `investigation_opened`, `investigation_closed` (+ INVESTIGATION_DURATION from `duration_seconds`), `report_published`, `gap_detected`
- `unregister_metrics_hooks()`: removes all previously registered closures for clean test teardown
- Exported from `gnat.metrics.__init__`

**TUI Investigations Panel (`gnat/tui/screens/investigations.py`)**
- `InvestigationsScreen(Screen)` with F5 / Ctrl+R / Ctrl+N bindings
- `compose()`: Header, search Input, status Select, Refresh/New buttons, DataTable (id/title/status/tlp/created_by/updated), detail pane with transition Select
- `_init_service()`: creates `InvestigationStore` + `InvestigationService` from `GNAT_DB_URL`; graceful ImportError + DB error handling with status message
- `_load_investigations(status_filter, text)`: builds `InvestigationQuery`, populates DataTable
- `on_data_table_row_selected()`: shows detail pane with full investigation metadata
- `_apply_transition()`: calls `service.transition()`, refreshes table
- `GNATApp` gains `db_url=` parameter; F5 binding added; Investigations TabPane wired into `compose()`; `run()` and `_cmd_tui()` updated

**Tests**
- `tests/unit/test_cli_phase4.py`: 25 tests — parser registration (investigation/plugins/db), investigation list/create/transition (success + error paths, missing SQLAlchemy), plugins list/load (empty + populated + error), db subcommand (upgrade/downgrade/-1/current/revision with message and autogenerate/stamp/missing alembic/runtime error)
- `tests/unit/test_lineage.py` (extended): `with_lineage()` fluent API, IngestPipeline + ExportPipeline + ReportService lineage emission
- `tests/unit/test_metrics.py` (extended): `register_metrics_hooks` / `unregister_metrics_hooks` — investigation_opened, investigation_closed + duration, report_published, gap_detected, unregister stops capture
- `tests/unit/test_tui.py` (extended): InvestigationsScreen import, `db_url=` param, F5 binding, 5-tab assertion, `investigations` screen CLI choice

---

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

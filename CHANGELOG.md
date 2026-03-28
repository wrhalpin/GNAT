# Changelog

All notable changes to GNAT are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- `CopilotReader`: DirectLine token exchange and auto-refresh (`use_token_exchange = true` in `[copilot]` INI section). Exchanges secret for short-lived token via `POST /tokens/generate`; refreshes automatically before expiry via `POST /tokens/refresh`. Falls back to secret on failure. 20 unit tests.

### Fixed
- `BaseClient.__init__`: cast `timeout` to `float` so INI string values work with `urllib3.Timeout`
- `AgeFilter._get()`: reads `_properties` exclusively so auto-defaulted ORM `created`/`modified` core attributes do not shadow explicitly-set timestamps
- `AgeFilter._timestamp()`: ensure timezone-awareness for naive ISO datetimes
- `LogDelivery.deliver()`: catch `TypeError` from non-JSON-serializable payloads, fall back to `str()`
- `Workspace.commit()`: fix `list & set` `TypeError` in deletion handling
- `_TOPIC_KEYWORDS` ordering: check `threat_actor` before `campaign` so "Volt Typhoon campaign" → `threat_actor`
- `FeedJob.next_run_at()`: return `_utcnow()` when no history (job is immediately due)
- `FeedScheduler.run_all_now()`: include disabled jobs as `status="skipped"` entries in result dict
- `RunRecord`: add `run_count` field; `CurationJob.execute()` now populates it
- `ParsingAgent._common_fields()`: apply `ai_confidence_ceiling` so STIX objects inherit the cap
- `GraphView._render_intent()`: intent methods always use sigma.js for consistent `GRAPH_DATA` output
- `GraphView._timeline_layout()`: `_parse_ts` reads only `_properties` so auto-set ORM core timestamps are not treated as explicit values
- `SplunkClient`: refactored to `BaseClient + ConnectorMixin`; accepts `host`, `api_token`, `username`, `password` keyword args; adds `authenticate()`, `to_stix()`, `from_stix()`

### Planned
- STIX 2.1 pattern validator integration
- Docker-based integration test harness
- ThreatQ sector/industry field name verification (see PENDING_ITEMS.md §1)
- Solr search UI / Grafana dashboard integration for `gnat/search` sidecar

---

## [1.0.0] — 2026-03-28

### Added

#### 29 Platform Connectors
- **AlienVault OTX** — API key, pulse/IOC queries, STIX `Indicator` mapping
- **Elastic SIEM** — API key/Basic, ECS document queries, Kibana alert/rule/case management
- **Graylog** — API key/Basic, stream alerts and search, STIX `Indicator` mapping
- **MISP** — API key, full event/attribute/feed/galaxy/sighting/tag CRUD, STIX ↔ MISP translation
- **OpenCTI** — API key, GraphQL-based connector scaffold
- **OSSIM** — Basic auth, AlienVault SIEM event queries, STIX mapping
- **IBM QRadar** — API token, Ariel search, offenses, assets, reference data, rules
- **Security Onion** — API key, alert/hunt queries, STIX `Indicator` mapping
- **Microsoft Sentinel** — OAuth2/Azure AD, incidents, alerts, analytic rules, watchlists, hunting
- **Snort IDS** — File/Syslog, rule parsing, alert log reading, STIX mapping
- **Suricata IDS/IPS** — File/Syslog, EVE JSON log consumption, STIX mapping
- **Wazuh SIEM/XDR** — API key/Basic, agents, alerts, rules, syscheck, active response, vuln data
- **Zeek Network Monitor** — File/Syslog, conn/dns/http/ssl log parsing, STIX mapping
- **ControlUp DEX** — Bearer token, device/session/alert/vulnerability STIX translation

#### Search Sidecar (`gnat/search/`)
- `GNATIndexer` — Solr 9.x document indexing, querying, and batch management
- `SearchMixin` — drop-in connector mixin that auto-indexes on `upsert_object()`
- ORM integration helpers (`orm_with_mixin.py`) — mixin-enhanced STIX objects
- Ingest pipeline patch (`pipeline_patch.py`) — routes records through Solr post-map
- ResearchLibrary patch (`library_patch.py`) — search-backed cross-source lookups
- `solr_schema_gnat.xml` — Solr 9.x schema for GNAT threat intel fields
- Configure via `[search]` section: `solr_url`, `enabled`, `batch_size`

#### Reports (`gnat/reports/`)
- `ReportGenerator` — pluggable pipeline: aggregate → AI narrate → render → deliver
- `DataAggregator` — volume, IOC breakdown, threat actors, CVEs, sectors, sources,
  confidence distribution, time series, period-over-period delta
- Four renderers: `MarkdownRenderer`, `HTMLRenderer`, `PDFRenderer` (reportlab),
  `DOCXRenderer` (python-docx, pure Python — no Node.js required)
- `ReportJob` — scheduled report via `FeedScheduler`; configurable via INI `[report.*]`
- `AIMode` — `DISABLED` / `ASSISTED` / `FULL` per-report AI involvement
- Email delivery (`EmailDelivery`) and SharePoint delivery (`SharePointDelivery`)
- `SectorFilter` moved to `gnat/export/filters.py` — available in both export
  and report layers; re-exported from `gnat/reports/base.py` for backwards compatibility

#### CLI additions
- `gnat report list` — list configured `[report.*]` profiles from ini
- `gnat report run --config <name>` — generate a report on demand;
  supports `--formats`, `--output-dir`, `--no-ai` overrides

#### AI Agents (`gnat/agents/`)
- `ResearchAgent` — topic-driven and feed-driven AI threat research via Claude API
- `ParsingAgent` — extract structured STIX from unstructured text (IOCs, TTPs, CVEs)
- `CopilotReader` — Microsoft Copilot via DirectLine for M365/SharePoint content
- Config via `[claude]` INI section: `api_key`, `model`, `ai_confidence_ceiling`

#### Research Library (`gnat/research/`)
- `ResearchLibrary` — three-tier knowledge base: personal workspaces → staging → library
- `CurationJob` — scheduled promotion from staging to library with TTL enforcement
- `ResearchEntry` — typed entry with category, freshness, confidence, and source tracking
- `WorkspaceManager.default()` — zero-config factory (SQLite or FlatFileStore fallback)

### Changed
- `DOCXRenderer` replaced Node.js/npm subprocess implementation with pure-Python
  `python-docx`; `python-docx>=1.1` added to `[reports]` and `[all]` extras
- `SectorFilter` canonical location moved to `gnat.export.filters`; `gnat.reports.base`
  re-exports it for backwards compatibility

---

## [0.9.0] — 2025-09-15

### Added

#### Research Library (`gnat/research/`)
- `ResearchLibrary` three-tier knowledge base (personal / staging / library workspaces)
- `ResearchEntry` — typed entry: category, status, TTL, confidence, source, narrative
- `CurationJob` — scheduled promotion, TTL expiry, staged→library gating
- `ResearchLibrary.default()` / `from_manager()` factory methods
- INI configuration: `[research]` section with `staging_name`, `library_name`,
  TTL overrides per category (`ttl_threat_actor`, `ttl_vulnerability`, etc.)

---

## [0.8.0] — 2025-07-01

### Added

#### AI Agents (`gnat/agents/`)
- `ResearchAgent` — topic-driven synthesis and feed-driven monitoring via Claude API
  (`web_search` tool, configurable topic list, confidence ceiling)
- `ParsingAgent` — unstructured text → STIX objects (IOCs, TTPs, actors, CVEs)
  with `x_source_type = "ai_extracted"` and confidence ≤ `ai_confidence_ceiling`
- `CopilotReader` — Microsoft Copilot DirectLine source reader; polls
  SharePoint, mailboxes, and Teams channels for threat content
- `ClaudeClient` — thin wrapper around Claude API with retry and token tracking
- Config: `[claude]` INI section — `api_key`, `model` (default `claude-sonnet-4-6`),
  `ai_confidence_ceiling` (default 60)

---

## [0.7.0] — 2025-05-15

### Added

#### Export pipeline (`gnat/export/`)
- `ExportPipeline` — fluent builder: `.read_from()`, `.filter_with()`,
  `.transform_with()`, `.deliver_to()`, `.run()`
- `ExportJob` — scheduled export via `FeedScheduler`; `pipeline_factory` pattern
- `ExportResult`, `TransformResult`, `DeliveryResult` — typed outcome dataclasses
- **Filters:** `TypeFilter`, `ConfidenceFilter`, `TLPFilter`, `TagFilter`,
  `AgeFilter`, `PatternFilter`, `IOCTypeFilter`, `LimitFilter`,
  `DeduplicateFilter`, `FunctionFilter`, `SectorFilter`
- **Transforms:** `EDLTransform` (plaintext IOC lists), `NetskopeCETransform`
  (Netskope CE API payload format)
- **Delivery targets:** `FileDelivery`, `HTTPDelivery`, `EDLServer` (FastAPI,
  per-type endpoint, poll-based firewall integration), `PlatformDelivery`,
  `EmailDelivery`

---

## [0.6.0] — 2025-04-01

### Added

#### Feed scheduling (`gnat/schedule/`)
- `FeedScheduler` — APScheduler/Celery-compatible job runner;
  `add()`, `remove()`, `start()`, `stop()`, `statuses()`, context manager
- `FeedJob` — typed job: `job_id`, `pipeline_factory`, `interval_seconds`,
  `cron_expr`, `max_retries`, `on_success`/`on_error` callbacks
- `IngestJob` — convenience subclass that wires `IngestPipeline` into scheduler
- CLI: `gnat schedule list`, `gnat schedule run [--job JOB_ID]`,
  `gnat schedule crontab`
- New optional extra: `pip install "gnat[schedule]"` (installs croniter)

---

## [0.1.0] — 2025-03-19

### Added

#### Core client layer
- `SAKClient` top-level facade with `connect()`, `disconnect()`, `ping()`
- `SAKConfig` INI-file loader with env-var and default-path fallback
- `BaseClient` — urllib3 `PoolManager` with retry/back-off, auth header injection,
  JSON encoding, and structured `SAKClientError`
- `CLIENT_REGISTRY` mapping target names to connector classes

#### ORM layer (STIX 2.1)
- `STIXBase` — abstract base with `to_dict()`, `from_dict()`, `to_stix_bundle()`,
  `select()`, `save()`, `delete()`, `refresh()`, and `__getattr__`/`__setattr__`
  property bag
- Domain objects: `Indicator`, `ThreatActor`, `Malware`, `Vulnerability`,
  `AttackPattern`, `Relationship`
- Cyber Observables: `Observable`, `IPv4Address`, `DomainName`, `URL`,
  `FileObject`, `EmailAddress`

#### Connectors
- **ThreatQ** — OAuth2 client-credentials, full CRUD, STIX ↔ ThreatQ translation
- **CrowdStrike** — OAuth2, IOC CRUD via Falcon API
- **Proofpoint** — HTTP Basic, TAP v2 read-only
- **Netskope** — API token, URL list CRUD
- **XSOAR 6** — API key (+ MSSP auth-id), indicator search/edit/delete
- **Recorded Future** — API token, read-only Connect API
- `ConnectorMixin` abstract contract: `to_stix()`, `from_stix()`, `get_object()`,
  `list_objects()`, `upsert_object()`, `delete_object()`, `health_check()`

#### Ingestion framework
- `SourceReader` / `RecordMapper` abstract base classes with context-manager support
- `IngestPipeline` — fluent builder: `.read_from()`, `.map_with()`, `.write_to()`,
  `.deduplicate()`, `.filter()`, `.transform()`, `.run()` / `.iter_objects()`
- `IngestResult` summary dataclass; `DeduplicationCache` with configurable key fields

**Source readers (14):**
`PlainTextReader`, `CSVReader`, `JSONReader`, `JSONLReader`,
`STIXBundleReader`, `TAXIICollectionReader`, `SQLReader`,
`MISPReader`, `SyslogReader` (syslog/CEF/LEEF), `RSSReader`,
`EmailReader`, `OpenIOCReader`, `SplunkReader`, `ElasticReader`

**Mappers (12):**
`FlatIOCMapper`, `STIXPassthroughMapper`, `MISPAttributeMapper`,
`CEFMapper`, `SQLRowMapper`, `CSVIndicatorMapper`, `RSSEntryMapper`,
`EmailIOCMapper`, `OpenIOCMapper`, `SplunkResultMapper`,
`ElasticResultMapper`, `NVDCVEMapper`

#### Code generation
- `openapi_generator.py` — CLI (`gnat-codegen`) and Python API
- Parses OpenAPI 3.x / Swagger 2.x specs (JSON or YAML)
- Generates connector package, `__init__.py`, and full pytest scaffold
- Detects CRUD endpoints, schema fields, auth type; scaffolds `to_stix` / `from_stix`

#### Utilities
- `stix_helpers`: `make_bundle()`, `extract_objects()`, `filter_by_type()`,
  `validate_stix_id()`

#### Tests
- `tests/unit/test_orm.py` — 40+ assertions: all ORM types, serialisation, CRUD guards
- `tests/unit/test_client.py` — `SAKConfig`, `SAKClient` (all 6 targets), `BaseClient`
  HTTP layer
- `tests/unit/connectors/test_connectors.py` — auth, CRUD, translation for all 6 connectors
- `tests/unit/ingest/test_ingest.py` — 300+ assertions: all readers, mappers, pipeline
  features, edge cases, error handling
- `tests/integration/test_integration.py` — live API scaffold (opt-in)
- Shared `conftest.py` with minimal INI config fixture

#### Configuration
- `config/config.ini.example` — annotated template for all six platforms

#### Packaging
- `pyproject.toml` with optional extras: `yaml`, `taxii`, `rss`, `ingest`, `dev`, `all`
- `MANIFEST.in`, `LICENSE` (MIT), `py.typed` marker (PEP 561)
- `Makefile` with `test`, `lint`, `typecheck`, `build`, `clean` targets
- `.gitignore` tuned for Python + security tooling

[Unreleased]: https://github.com/your-org/gnat/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/your-org/gnat/releases/tag/v0.1.0

---

## [0.3.0] — 2025-03-20

### Added

#### Async client (`gnat/async_client/`)
- `AsyncBaseClient` on `httpx` with retry transport, async context manager
- `AsyncSAKClient` — async mirror of `SAKClient` supporting `async with` and `asyncio.gather` concurrent multi-platform queries
- `AsyncSTIXBase` — awaitable `select()`, `save()`, `delete()`, `refresh()`
- Async connectors for all six platforms: `AsyncThreatQClient`, `AsyncCrowdStrikeClient`, `AsyncProofpointClient`, `AsyncNetskopeClient`, `AsyncXSOARClient`, `AsyncRecordedFutureClient`
- New optional extra: `pip install "gnat[async]"` (installs httpx)

#### CLI (`gnat/cli/`, entry point `gnat`)
- `gnat ping` — connectivity check
- `gnat query` — fetch single object by id with `--output json|table|stix`
- `gnat list` — paginated object listing with `--filter KEY=VALUE`
- `gnat ingest` — file-to-platform with 8 format options, `--dry-run`, `--tlp`, `--confidence`, `--deduplicate`
- `gnat codegen` — wraps the OpenAPI generator
- `gnat config --show|--validate|--init` — config management
- ANSI color output with `--no-color` fallback; `--debug` flag for trace logging

#### Sphinx documentation (`docs/`)
- `furo` theme with dark/light mode
- `autodoc`, `napoleon` (NumPy docstrings), `viewcode`, `intersphinx`, `sphinx-copybutton`
- Full `index.rst` TOC, API autosummary stubs for all modules
- `docs/requirements.txt`, `docs/Makefile`; `make docs` target in root `Makefile`

#### GitHub Actions (`.github/workflows/`)
- `ci.yml`: lint → test matrix (Python 3.9–3.12 × Linux + macOS + Windows on 3.12) → coverage → async tests → build check → Sphinx build → Bandit SAST
- `release.yml`: PyPI publish via OIDC trusted publishing on version tags



#### Graph visualization — performance rewrite for 1000+ nodes

**Layout algorithms** (pure Python, no numpy/scipy):

| Algorithm | Complexity | Trigger |
|---|---|---|
| Fruchterman-Reingold (networkx) | O(n²) | ≤ 200 nodes |
| Barnes-Hut ForceAtlas2 | O(n log n) | 200–1000 nodes |
| Type-cluster (Fibonacci spiral) | O(n) | > 1000 nodes |

Barnes-Hut uses a custom pure-Python quad-tree with centre-of-mass approximation (theta=0.8).  Measured: n=2000 in 2.2s, n=5000 in 4.4s.  Type-cluster layout: n=3000 in 0.003s.

**Rendering** — tiered by graph size:
- ≤ 300 nodes: **Plotly 3D** (unchanged, Jupyter-native)
- > 300 nodes: **sigma.js WebGL** via unpkg CDN — handles 100K nodes; self-contained HTML with search, type filter, edge toggle, hover tooltips, zoom/pan, dark theme
- sigma.js HTML: ~200KB for 400 nodes, loads in < 0.2s

**New methods**: `to_graph_json()` (sigma.js data format for Grafana graph panel); `to_html(renderer=sigma|plotly3d)` explicit renderer selection; `show(max_nodes=N)` caps by degree centrality; `show(cluster_threshold=N)` override per-call

**Grafana graph panel integration**: `GrafanaServer` now exposes `/graph-json/<workspace>` endpoint returning sigma.js-compatible node/edge data for live dashboard graphs
#### Visualization layer (`gnat/viz/`)
- **`TabularView`** — filterable tables: rich terminal (ANSI color), Jupyter inline, self-contained sortable dark-theme HTML, CSV, Excel/Power BI (openpyxl, freeze-panes, auto-widths, alternating rows)
- **`GraphView`** — 3D force-directed STIX relationship graph via Plotly; spring layout (networkx, ≤800 nodes) with Fibonacci sphere fallback; nodes colored + sized by confidence/risk score; edges grouped by relationship type; `to_html()`, `to_json()`, `to_networkx()`, `summary()`
- **`GrafanaServer`** — FastAPI SimpleJSON datasource server; endpoints: `/search`, `/query` (table + timeseries), `/annotations` (enrichment events), `/tag-keys`, `/tag-values`; `run_in_background()` for notebooks
- **`PowerBIExporter`** — multi-sheet Excel workbook with Relationships + EnrichmentLog + Summary sheets; `to_model_json()` Power BI data model descriptor with auto-generated table relationships
- **`grafana_dashboard` / `save_grafana_dashboard`** — pre-built Grafana dashboard JSON: object-type bar chart, RF risk-score timeline, CVSS timeline, confidence gauge, indicator table, relationship table, enrichment annotations
- New CLI subcommand tree: `gnat viz table`, `graph`, `serve`, `dashboard`, `powerbi`
- New optional extras: `pip install gnat[viz]` (plotly + networkx + openpyxl), `gnat[serve]` (fastapi + uvicorn)
#### Context system (`gnat/context/`)
- **`GlobalContext`** — wraps a `SAKClient`, adds read-only flag and priority
- **`GlobalContextRegistry`** — manages multiple global contexts; `from_config()` and `from_clients()` factories; default write target, `writable()` / `read_only_contexts()` helpers
- **`Workspace`** — analyst working set with:
  - `load(stix_type, filters, source)` — pull from global context
  - `add(obj)` / `remove(stix_id)` — direct object management
  - `enrich(sources, strategy)` / `aenrich(...)` — concurrent async fan-out enrichment
  - Three enrichment strategies: `create_relationships` (default), `merge_extensions`, `tag_only`
  - `diff()` — shows added/modified/deleted since last load or commit
  - `commit(target, dry_run)` — write dirty objects back to any writable global
  - `export_bundle()` — full STIX 2.1 bundle export
  - Immediate persistence on every mutation
- **`WorkspaceManager`** — factory: `create()`, `open()`, `get_or_create()`, `list()`, `delete()`; `from_clients()` for programmatic setup
- **`CommitResult`** — typed summary with `written`, `deleted`, `errors`, `would_write`, `success`
- **`WorkspaceStore`** (SQLAlchemy) — SQLite (WAL mode) or PostgreSQL; schema: `workspaces`, `workspace_objects` (with dirty tracking + soft delete), `enrichment_log`, `context_globals`
- **`FlatFileStore`** — zero-dependency JSON flat-file fallback; one file per object, JSONL enrichment log, STIX bundle export; auto-selected when SQLAlchemy is not installed
- Transparent backend switching: `WorkspaceStore` preferred, falls back to `FlatFileStore`
- New optional extra: `pip install "gnat[persist]"` (installs sqlalchemy)

# Changelog

All notable changes to CTM-SAK are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- Async client variant (`asyncio` / `httpx`)
- STIX 2.1 pattern validator integration
- CLI entry point (`ctm-sak query`, `ctm-sak ingest`)
- Docker-based integration test harness
- Sphinx API documentation

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
- `openapi_generator.py` — CLI (`ctm-sak-codegen`) and Python API
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

[Unreleased]: https://github.com/your-org/ctm-sak/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/your-org/ctm-sak/releases/tag/v0.1.0

---

## [0.3.0] — 2025-03-20

### Added

#### Async client (`ctm_sak/async_client/`)
- `AsyncBaseClient` on `httpx` with retry transport, async context manager
- `AsyncSAKClient` — async mirror of `SAKClient` supporting `async with` and `asyncio.gather` concurrent multi-platform queries
- `AsyncSTIXBase` — awaitable `select()`, `save()`, `delete()`, `refresh()`
- Async connectors for all six platforms: `AsyncThreatQClient`, `AsyncCrowdStrikeClient`, `AsyncProofpointClient`, `AsyncNetskopeClient`, `AsyncXSOARClient`, `AsyncRecordedFutureClient`
- New optional extra: `pip install "ctm-sak[async]"` (installs httpx)

#### CLI (`ctm_sak/cli/`, entry point `ctm-sak`)
- `ctm-sak ping` — connectivity check
- `ctm-sak query` — fetch single object by id with `--output json|table|stix`
- `ctm-sak list` — paginated object listing with `--filter KEY=VALUE`
- `ctm-sak ingest` — file-to-platform with 8 format options, `--dry-run`, `--tlp`, `--confidence`, `--deduplicate`
- `ctm-sak codegen` — wraps the OpenAPI generator
- `ctm-sak config --show|--validate|--init` — config management
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
#### Visualization layer (`ctm_sak/viz/`)
- **`TabularView`** — filterable tables: rich terminal (ANSI color), Jupyter inline, self-contained sortable dark-theme HTML, CSV, Excel/Power BI (openpyxl, freeze-panes, auto-widths, alternating rows)
- **`GraphView`** — 3D force-directed STIX relationship graph via Plotly; spring layout (networkx, ≤800 nodes) with Fibonacci sphere fallback; nodes colored + sized by confidence/risk score; edges grouped by relationship type; `to_html()`, `to_json()`, `to_networkx()`, `summary()`
- **`GrafanaServer`** — FastAPI SimpleJSON datasource server; endpoints: `/search`, `/query` (table + timeseries), `/annotations` (enrichment events), `/tag-keys`, `/tag-values`; `run_in_background()` for notebooks
- **`PowerBIExporter`** — multi-sheet Excel workbook with Relationships + EnrichmentLog + Summary sheets; `to_model_json()` Power BI data model descriptor with auto-generated table relationships
- **`grafana_dashboard` / `save_grafana_dashboard`** — pre-built Grafana dashboard JSON: object-type bar chart, RF risk-score timeline, CVSS timeline, confidence gauge, indicator table, relationship table, enrichment annotations
- New CLI subcommand tree: `ctm-sak viz table`, `graph`, `serve`, `dashboard`, `powerbi`
- New optional extras: `pip install ctm-sak[viz]` (plotly + networkx + openpyxl), `ctm-sak[serve]` (fastapi + uvicorn)
#### Context system (`ctm_sak/context/`)
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
- New optional extra: `pip install "ctm-sak[persist]"` (installs sqlalchemy)

# GNAT Architecture Decisions

A single reference for every design decision made during development,
including tradeoffs, alternatives considered, and implementation notes.
Use this when testing, implementing new connectors, or extending existing
subsystems.

---

## Table of Contents

1. [HTTP Client Layer](#1-http-client-layer)
2. [ORM / STIX Compatibility](#2-orm--stix-compatibility)
3. [Connector Architecture](#3-connector-architecture)
4. [Ingestion Framework](#4-ingestion-framework)
5. [Context System — Global and Local](#5-context-system--global-and-local)
6. [Workspace Persistence](#6-workspace-persistence)
7. [Async Client](#7-async-client)
8. [Visualization — Tabular](#8-visualization--tabular)
9. [Visualization — Graph](#9-visualization--graph)
10. [Visualization — Grafana vs Power BI](#10-visualization--grafana-vs-power-bi)
11. [CLI Design](#11-cli-design)
12. [Code Generation](#12-code-generation)
13. [Configuration](#13-configuration)
14. [Testing Strategy](#14-testing-strategy)
15. [Packaging and Extras](#15-packaging-and-extras)

---

## 1. HTTP Client Layer

**Decision:** `urllib3.PoolManager` as the sync base, `httpx.AsyncClient` for async.

**Why urllib3 over requests:**
- `requests` wraps `urllib3` but adds overhead and its own abstraction.
  Since we need connection pooling, retry logic, and raw control over
  headers/encoding, going to `urllib3` directly is cleaner and has zero
  additional dependencies.
- `requests` sessions do not compose well with async; urllib3 does not
  create this problem.

**Why httpx for async:**
- `httpx` provides the same API surface as `requests`-style but is
  natively async with `AsyncClient`.
- It has built-in retry transport (`AsyncHTTPTransport(retries=N)`).
- Alternative considered: `aiohttp`. Rejected because its API is more
  divergent from the sync path, making connector mirroring harder.

**Retry configuration:**
```python
Retry(
    total=3,
    backoff_factor=0.5,
    status_forcelist={429, 500, 502, 503, 504},
    allowed_methods={"GET", "POST", "PUT", "PATCH", "DELETE"},
)
```
Note: `allowed_methods` (not `method_whitelist`) — urllib3 ≥ 2.0 API.

**`GNATClientError` carries `status` and `body`:**
Always check `exc.status` in connector tests — 401 vs 403 vs 429 all
need different handling.

---

## 2. ORM / STIX Compatibility

**Decision:** `STIXBase` is a pure Python class. It is **not** a SQLAlchemy
model, not a Pydantic model, not a dataclass.

**Why not SQLAlchemy inheritance:**
Coupling the STIX domain model to a DB session lifecycle would mean:
- Objects carry DB session state everywhere
- `async def` methods would require async sessions throughout
- Tests need a DB to instantiate any object
- STIX serialisation becomes entangled with ORM session expiry

The chosen pattern — serialize to JSON via `to_dict()`, store in DB,
deserialize via `from_dict()` — keeps the two layers fully decoupled.

**`__getattr__` / `__setattr__` property bag:**
- Core STIX fields (`id`, `spec_version`, `created`, `modified`) are
  stored as real instance attributes.
- All other properties land in `self._properties` dict.
- `__getattr__` reads from `_properties` on attribute miss.
- This means `obj.confidence = 80` and `obj._properties["confidence"] = 80`
  are equivalent. **Always access via attribute syntax in application code.**

**`x_` prefix convention:**
All non-standard extension fields use `x_` prefix per STIX 2.1 spec
(e.g. `x_rf_risk_score`, `x_tlp`, `x_enrichment_source`). This keeps
the wire format valid.

**`from_dict` class method:**
Returns the most specific ORM class based on `type` field. Unknown types
return bare `STIXBase`. The `_from_dict` helper in `workspace.py` uses
a hardcoded map — update it when adding new ORM types.

---

## 3. Connector Architecture

**Decision:** Dual inheritance — `BaseClient` + `ConnectorMixin`.

```python
class MyConnector(BaseClient, ConnectorMixin):
    stix_type_map = {"indicator": "ioc", ...}
    def authenticate(self): ...
    def to_stix(self, native): ...
    def from_stix(self, stix_dict): ...
    def get_object(self, stix_type, object_id): ...
    def list_objects(self, stix_type, filters, page, page_size): ...
    def upsert_object(self, stix_type, payload): ...
    def delete_object(self, stix_type, object_id): ...
    def health_check(self): ...
```

**`stix_type_map`:**
Maps STIX type strings to platform-native resource names/codes.
Used by `_resolve_resource()` helpers. Must be populated at class level.

**Authentication patterns implemented:**
| Pattern | Platforms | Implementation |
|---|---|---|
| OAuth2 client-credentials | ThreatQ, CrowdStrike, GreyMatter | `post("/token", data={grant_type, client_id, client_secret})` |
| API token header | Netskope, Recorded Future, Feedly, Splunk | Set `_auth_headers` in `authenticate()` |
| HTTP Basic | Proofpoint, RiskRecon | `base64.b64encode(f"{user}:{pass}")` |
| API key header | XSOAR, Whistic | Direct header injection |

**`authenticate()` is called lazily:**
`_authenticated` flag ensures it runs exactly once per client instance.
The first HTTP request triggers it. Tests must either mock `authenticate()`
or set `client._authenticated = True` to bypass it.

**`to_stix()` contract:**
Must return a dict with at minimum:
```python
{"type": "<stix-type>", "id": "<stix-type>--<uuid>", "created": "...", "modified": "..."}
```
Use `x_` prefix for platform-specific extension fields.

**Read-only connectors:**
Platforms that don't support writes (Recorded Future, Proofpoint, Feedly)
should raise `GNATClientError` from `upsert_object` and `delete_object`
with a clear "read-only" message. The `GlobalContextRegistry` marks them
with `read_only=True` which prevents `Workspace.commit()` targeting them.

**`CLIENT_REGISTRY` in `gnat/clients/__init__.py`:**
Must be updated for every new connector. Keys are lowercase, hyphens
replaced with underscores (e.g. `"greymatter"`, `"riskrecon"`).

---

## 4. Ingestion Framework

**Decision:** Three composable abstractions — `SourceReader`, `RecordMapper`,
`IngestPipeline`.

**`SourceReader` contract:**
- Implement `_iter_records(self) -> Iterator[RawRecord]`
- Override `open()` / `close()` for resources with connection lifecycle
- Support context manager (`with reader:`) — auto-calls `open`/`close`
- `batch_size` param for paginated sources (SQL, Elasticsearch)

**`RecordMapper` contract:**
- Implement `map(self, record: RawRecord) -> Iterator[STIXBase]`
- May yield 0 objects (filtered), 1 (normal), or N (MISP events with many attrs)
- Use `self._client`, `self.tlp_marking`, `self.confidence`

**Critical dedup bug fixed in v0.1:**
`DeduplicationCache.__len__` returning `0` on empty cache made
`if self._dedup and ...` evaluate to `False` before the first item was
seen — the entire dedup was silently skipped. Fix: always use
`if self._dedup is not None and ...`. This applies everywhere you guard
on an object with a `__len__` that can be zero.

**IOC auto-classification in `PlainTextReader`:**
Pattern order matters — SHA-256 checked before SHA-1 before MD5 (by
hash length). IPv4 checked before domain to avoid misclassifying IPs
as domains.

**Defang handling:**
`PlainTextReader` strips `[.]`, `hxxp://`, `hxxps://` before
classification. Connectors receiving IOC values from the ingestion
pipeline will see clean values.

---

## 5. Context System — Global and Local

**Decision:** Multiple global contexts, separate relationship objects for
enrichment (not merged scores).

**Multiple globals rationale:**
Different platforms serve different roles — ThreatQ as system of record,
Recorded Future as enrichment-only, CrowdStrike as endpoint context.
Forcing a single global would either lose platform provenance or require
complex merge logic.

**`GlobalContextRegistry` priority:**
Lower integer = higher priority. Default write target is the lowest-priority
non-read-only context. Override with `registry.set_default("name")`.

**INI config format for multiple globals:**
```ini
[global]
default = threatq_prod

[global.threatq_prod]
target        = threatq
host          = https://threatq.example.com
client_id     = ...
client_secret = ...

[global.recorded_future]
target    = recordedfuture
host      = https://api.recordedfuture.com
api_token = ...
read_only = true
priority  = 20
```

**`GlobalContextRegistry.from_clients()` for programmatic setup:**
```python
registry = GlobalContextRegistry.from_clients(
    {"tq": tq_cli, "rf": rf_cli, "cs": cs_cli},
    default="tq",
    read_only=["rf"],
)
```

**Enrichment strategies — choose based on use case:**

| Strategy | Effect | Use when |
|---|---|---|
| `create_relationships` | New STIX SDO + Relationship added; original untouched | **Default.** Preserves full provenance. Multiple platforms can enrich the same object without collision. |
| `merge_extensions` | `x_` fields merged into original; original marked dirty | You want a single enriched indicator rather than a graph of objects. Loses individual platform provenance. |
| `tag_only` | `x_enrichment_tags` list updated; nothing else changes | Lightweight "was checked" marking. No data persisted. |

**`create_relationships` is the correct default for your requirement**
("preserve both as separate relationships"). RF risk score and CS
endpoint data become separate nodes in the graph, linked to the
original indicator. `diff()` and `commit()` will pick them up as new
objects.

---

## 6. Workspace Persistence

**Decision:** SQLAlchemy stores serialized STIX JSON alongside indexed metadata
columns. Objects are **not** SQLAlchemy models.

**Backend selection:**
```
WorkspaceStore (SQLAlchemy) ← preferred
    └── SQLite (WAL mode)   ← default, single-file, zero-config
    └── PostgreSQL           ← team-shared contexts

FlatFileStore               ← zero-dependency fallback
    └── Auto-selected when SQLAlchemy is not installed
    └── One JSON file per object in ~/.gnat/workspaces/<name>/objects/
    └── JSONL enrichment log per workspace
```

**SQLite WAL mode** is set on every connection via `PRAGMA journal_mode=WAL`.
This allows concurrent readers without blocking writers — important for
notebook workflows where multiple cells read the workspace simultaneously.

**Dirty tracking:**
`is_dirty=True` in the DB + `stix_id in ws.dirty` in memory.
`mark_clean()` clears both after a successful `commit()`.
`soft_delete` sets `is_deleted=True` rather than removing rows — the
object stays in the DB for audit purposes, just not returned by
`get_objects()`.

**Snapshot vs. objects:**
- `ws._snapshot` holds STIX dicts as they were at load time (from platform).
- `ws.objects` holds live Python objects.
- `diff()` compares them — objects NOT in snapshot are "added", objects
  IN snapshot with changed fields are "modified".
- **Key rule:** `_add_object(mark_dirty=False)` → goes into snapshot.
  `_add_object(mark_dirty=True)` → does NOT go into snapshot (so `diff()`
  shows it as "added").

**Live object reference bug (fixed):**
`_add_object()` creates a new Python object via `_from_dict()`. The
original reference passed to `add()` is not the same object as
`ws.objects[id]`. All enrichment strategies (`merge_extensions`,
`tag_only`) must operate on `self.objects.get(original.id, original)`,
not on `original` directly.

---

## 7. Async Client

**Decision:** `AsyncBaseClient` on `httpx`, not a wrapper around the sync client.

**Why a separate implementation:**
Wrapping sync calls with `asyncio.run_in_executor` would work but defeats
the purpose — you'd be running sync urllib3 on a thread pool rather than
truly async I/O. The platforms that benefit most from async (ThreatQ,
CrowdStrike) support proper HTTP/2 keep-alive which httpx uses natively.

**`authenticate()` is async:**
Means token refresh can be non-blocking. Proofpoint and Netskope auth is
header injection (synchronous in effect) but declared async for
interface consistency.

**`translation methods stay synchronous:**
`to_stix()` and `from_stix()` are CPU-bound JSON manipulation — there is
no benefit to making them async, and it would complicate callers.

**Concurrent multi-platform queries:**
```python
async with AsyncGNATClient() as tq, AsyncGNATClient() as rf:
    await asyncio.gather(tq.connect("threatq"), rf.connect("recordedfuture"))
    tq_res, rf_res = await asyncio.gather(
        tq.client.get_object("indicator", ioc_id),
        rf.client.get_object("indicator", ioc_id),
    )
```
This is the primary reason to use the async client — fan-out enrichment
across 5 platforms takes the same wall-clock time as the slowest single
platform.

---

## 8. Visualization — Tabular

**Decision:** Five output targets from one `TabularView` class.

**Format selection logic:**
- `view.show()` → terminal (`rich` if installed, plain ASCII fallback)
- `view.display()` → Jupyter `IPython.display(HTML(...))`
- `view.to_html(path)` → self-contained dark-theme HTML, sortable columns
- `view.to_csv(path)` → UTF-8-BOM CSV (Power BI-compatible)
- `view.to_excel(path)` → openpyxl, one sheet per STIX type

**Column definitions in `_COLUMNS` dict:**
Maps STIX type → list of fields to display. Update this when adding new
ORM types or important `x_` extension fields. The `_default` key is the
fallback for unknown types.

**Sort order for numeric fields:**
`_sort()` negates numeric values so they sort descending by default.
Confidence 90 appears before confidence 10.

**Power BI Excel compatibility notes:**
- Column types are inferred by Power BI from cell values — ensure numeric
  fields (`confidence`, `x_cvss_score`) contain actual numbers, not strings.
- The `Relationships` sheet uses `source_ref`/`target_ref` columns that
  Power BI's graph visual maps to from/to node ids. Do not rename these.
- `to_model_json()` generates the data model descriptor with foreign key
  relationships pre-wired.

---

## 9. Visualization — Graph

**Decision:** Tiered renderer + tiered layout based on node count.

### Layout algorithm selection

| Node count | Algorithm | Complexity | Approx. time |
|---|---|---|---|
| ≤ 200 | Fruchterman-Reingold (networkx) | O(n²) | < 0.1s |
| 200–1000 | Barnes-Hut ForceAtlas2 (pure Python) | O(n log n) | 0.1–2s |
| > 1000 | Type-cluster (Fibonacci spiral) | O(n) | < 0.01s |

**Barnes-Hut implementation details:**
- Custom `_QuadTree` class — no scipy, no numpy
- `theta=0.8` is the accuracy parameter. Lower = more accurate, slower.
  0.5 gives near-exact results; 1.2 is fast but visually coarser.
  0.8 is the sweet spot for threat intel graphs.
- `kr=10.0` (repulsion), `ka=0.1` (attraction), `gravity=0.5`
  These can be tuned if your workspace has highly variable node degrees.
- Step size decays by `step_ratio=0.95` per iteration — simulated annealing.

**Type-cluster layout tradeoff:**
At 1000+ nodes, type-cluster sacrifices topological accuracy for speed.
You see *where types are* but not *how individual nodes relate*. If the
relationship structure is the signal (e.g., tracing a specific campaign),
override: `GraphView(ws, cluster_threshold=5000).to_html(...)` to force
Barnes-Hut even at large scale.

### Renderer selection

| Node count | Renderer | Technology | Notes |
|---|---|---|---|
| ≤ 300 | Plotly 3D | WebGL (Plotly) | 3D, Jupyter-native, ~3MB JS |
| > 300 | sigma.js | WebGL (sigma) | 2D, 100K node capacity, ~50KB JS |

**sigma.js HTML features:**
- Real-time label search (filters nodes by name substring)
- Type filter dropdown (hides/shows entire STIX types)
- Edge toggle (show/hide all edges)
- Hover tooltips (all `x_` attributes displayed)
- Camera reset button
- Legend with clickable type rows
- Dark theme matching the tabular HTML report

**`to_graph_json()` format:**
```json
{
  "nodes": [
    {"key": "indicator--abc", "label": "evil.com", "x": 1.2, "y": -0.8,
     "size": 12, "color": "#4ea8de", "type": "indicator",
     "attributes": {"confidence": 80, "x_rf_risk_score": 90}}
  ],
  "edges": [
    {"key": "e-0", "source": "indicator--abc", "target": "malware--xyz",
     "label": "indicates", "color": "#4ea8de"}
  ]
}
```
Use this to feed the Grafana Node Graph panel or build custom sigma.js apps.

**Intent-driven rendering API — primary user-facing interface:**

The five intent methods remove the need to know layout algorithms or renderer names.
Each one encodes "what you want to see" and configures everything automatically:

| Method | Primary question | Layout | Renderer | Edges |
|---|---|---|---|---|
| `render_relationship_graph()` | How are objects connected? | Barnes-Hut (always) | sigma/Plotly | Prominent (opacity 0.7) |
| `render_type_graph()` | What types are in this workspace? | Type-cluster (always) | sigma/Plotly | Secondary (opacity 0.25) |
| `render_campaign_graph()` | What connects to these seeds? | Barnes-Hut + BFS ego | sigma/Plotly | Standard (0.65) |
| `render_timeline_graph()` | How did this evolve over time? | X=timestamp, Y=type lane | sigma only | Standard |
| `render_risk_heatmap()` | What has high risk vs low confidence? | X=field, Y=field (value-driven) | sigma only | None |

**Key design decisions in intent methods:**

`render_relationship_graph` overrides `cluster_threshold` to `n+1` so Barnes-Hut
is used at any scale — type-cluster would hide the relational topology that is the
entire point of this view.

`render_type_graph` overrides `cluster_threshold` to `0` so type-cluster is always
used — and sets `uniform_node_size=True` so visual density reflects object counts
rather than score distribution.

`render_campaign_graph` uses BFS from seed nodes. Auto-seeds to top-3 by degree
centrality if no `seed_ids` given. Result is always a strict subgraph of the
workspace — never shows disconnected objects.

`render_timeline_graph` places objects at X = (timestamp - min) / range × 20,
Y = type-lane index × 4 + jitter. Objects without a parseable timestamp get X = -5
(visibly outside the axis, not hidden). Uses sigma always because timelines can be
very wide.

`render_risk_heatmap` places objects at X = x_field/10, Y = y_field/10.
Objects missing either field get random jitter near origin — they cluster visibly
at (0,0) so the "coverage gap" is itself informative. No edges drawn.

**Plotly fallback in `_render_intent`:**
If plotly is not installed and the graph is below `plotly_threshold`, the intent
methods automatically fall back to sigma.js rather than raising ImportError.
The low-level `figure()` method still raises ImportError as documented.

**`max_nodes` caps by degree centrality:**
Keeps the most-connected nodes. For large workspaces this means hub
indicators (seen by many sources) survive the cap; isolated singletons
are dropped. Run `view.summary()` first to understand the graph before capping.

---

## 10. Visualization — Grafana vs Power BI

**Decision:** Grafana as live dashboard, Power BI as static export.

**Why not a live Power BI API connector:**
- Power BI streaming datasets are POST-only with no query capability.
- Push datasets require a workspace ID + Azure AD token refresh.
- DirectQuery requires a gateway or Azure-hosted source.
- The net result is more authentication plumbing than threat intel value.

**Grafana advantages for this use case:**
- SimpleJSON protocol = 6 HTTP endpoints, ~150 lines to implement fully.
- Node Graph panel is purpose-built for relationship visualization.
- Self-hostable, open source, no per-seat licensing.
- Annotation support maps the enrichment log to timeline markers.

**SimpleJSON query target format:**
`<workspace_name>/<stix_type>` → table data
`<workspace_name>/<stix_type>/<field>` → time-series of numeric field
`<workspace_name>/summary` → object-count bar chart

**Running the Grafana server:**
```bash
gnat viz serve --port 3001
# In Grafana: Add data source → SimpleJSON → http://localhost:3001
```

**Power BI import workflow:**
1. `gnat viz powerbi --workspace apt28 --file workspace.xlsx`
2. Power BI Desktop → Get Data → Excel → select `workspace.xlsx`
3. Load all sheets. Relationships sheet auto-creates the graph visual.
4. `to_model_json()` optional — auto-wires foreign keys if imported via
   Power BI Desktop's "Transform Data" flow.

---

## 11. CLI Design

**Decision:** `argparse` subcommand tree, no external CLI framework.

**Why not Click or Typer:**
- Click adds a dependency.
- Typer adds Click + type annotation reflection.
- argparse is stdlib, zero overhead, sufficient for this command surface.

**`gnat` entry point tree:**
```
gnat
├── ping    --target NAME
├── query   --target NAME --type STIX_TYPE --id OBJECT_ID
├── list    --target NAME --type STIX_TYPE [--limit N] [--filter K=V ...]
├── ingest  --target NAME --source PATH --format FORMAT [--dry-run]
│           formats: plaintext csv json jsonl stix-bundle misp cef openioc nvd
├── codegen --spec PATH --name NAME [--auth oauth2|api_key|basic]
├── config  --show | --validate | --init
└── viz
    ├── table     --workspace NAME [--type TYPE] [--file out.html|.csv|.xlsx]
    ├── graph     --workspace NAME [--file out.html] [--types TYPE ...]
    ├── serve     [--port 3001] [--host 0.0.0.0]
    ├── dashboard --workspace NAME [--file dashboard.json]
    └── powerbi   --workspace NAME [--file workspace.xlsx]
```

**Global flags apply to all subcommands:**
`--config PATH`, `--output json|table|stix`, `--quiet`, `--no-color`, `--debug`

**`--dry-run` on ingest:**
Maps objects and prints/returns them without calling `write_to()` on any
client. Use for validating format mappings before committing.

**Exit codes:**
- `0` — success
- `1` — error (exception, missing config, unknown target)
- `2` — partial success (ingest completed with some errors)

---

## 12. Code Generation

**Decision:** OpenAPI spec → connector scaffold, not a full auto-implementation.

**What the generator does:**
- Parses OpenAPI 3.x or Swagger 2.x (JSON or YAML with PyYAML)
- Detects CRUD-like endpoints by HTTP method and path pattern
- Infers `stix_type_map` from schema names heuristically
- Selects auth scaffold from `--auth oauth2|api_key|basic`
- Writes `client.py` with all methods stubbed and `# TODO` comments
- Writes full pytest scaffold with all required test classes

**What you still need to implement:**
- `to_stix(native)` — map platform fields to STIX 2.1
- `from_stix(stix_dict)` — map STIX to platform request payload
- `health_check()` — replace `GET /health` stub with real endpoint
- Verify `_resolve_resource()` paths match actual API endpoints

**Registration after generation:**
```python
# gnat/clients/__init__.py
from gnat.connectors.myplatform.client import MyplatformClient
CLIENT_REGISTRY["myplatform"] = MyplatformClient

# gnat/async_client/connectors.py — add async mirror
# gnat/async_client/client.py — add to _build_async_registry()
```

---

## 13. Configuration

**INI file search order:**
1. Explicit `config_path=` parameter
2. `GNAT_CONFIG` environment variable
3. `~/.gnat/config.ini`
4. `./gnat.ini`

**Section naming:**
- `[DEFAULT]` — inherited by all sections
- `[threatq]`, `[crowdstrike]`, etc. — single-platform sections
- `[global]` — context system default name
- `[global.<name>]` — named global context configs

**Required keys per platform:**

| Platform | Required keys |
|---|---|
| threatq | `host`, `client_id`, `client_secret` |
| crowdstrike | `host`, `client_id`, `client_secret` |
| proofpoint | `host`, `service_principal`, `secret` |
| netskope | `host`, `api_token` |
| xsoar | `host`, `api_key` |
| recordedfuture | `host`, `api_token` |
| greymatter | `host`, `client_id`, `client_secret` |
| whistic | `host`, `api_key` |
| riskrecon | `host`, `client_id`, `client_secret` |
| feedly | `host`, `api_token` |
| splunk | `host`, `api_token` (or `username`+`password`) |

**Override at runtime:**
Any INI key can be overridden by passing it to `connect()`:
```python
cli.connect("threatq", client_secret="runtime-secret")
```

---

## 14. Testing Strategy

**Unit test structure:**
```
tests/unit/
├── test_orm.py          # 40+ assertions: STIXBase + all domain types
├── test_client.py       # GNATConfig, GNATClient (6 targets), BaseClient HTTP
├── connectors/
│   └── test_connectors.py   # auth, CRUD, to_stix/from_stix for all connectors
├── ingest/
│   └── test_ingest.py       # 300+ assertions: all readers, mappers, pipeline
├── context/
│   └── test_context.py      # store, registry, workspace, enrichment, commit
└── viz/
    └── test_viz.py          # tabular, graph, export, Grafana server
```

**Mock pattern for connectors:**
```python
def _authenticated(connector_cls, **kwargs):
    c = connector_cls(host="https://fake.example.com", **kwargs)
    c._authenticated = True   # bypass authenticate()
    return c
```

**Mock pattern for HTTP layer:**
```python
monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [...]}))
```
Never mock `_request()` directly — mock the public HTTP methods (`get`,
`post`, `put`, `delete`) so retry/header logic is still exercised.

**`to_stix` contract assertion (use in every connector test):**
```python
def _assert_stix_contract(stix_dict):
    assert isinstance(stix_dict, dict)
    assert "type" in stix_dict
    assert "id" in stix_dict
    assert "--" in stix_dict["id"]  # valid STIX id format
```

**Integration tests opt-in:**
```bash
GNAT_CONFIG=/path/to/real.ini pytest tests/integration/ --run-integration -v
```
Never run in CI without real credentials. The GitHub Actions `ci.yml`
does not include `--run-integration`.

**`DeduplicationCache` truthiness:**
An empty cache is falsy via `__len__`. Always guard with
`if cache is not None` not `if cache`. This is a known footgun.

---

## 15. Packaging and Extras

**Optional dependency groups:**

| Extra | Installs | Required for |
|---|---|---|
| `yaml` | `pyyaml` | YAML OpenAPI specs in codegen |
| `taxii` | `taxii2-client` | TAXII 2.x feed ingestion |
| `rss` | `feedparser` | RSS/Atom feed ingestion |
| `ingest` | `taxii2-client`, `feedparser` | All ingest extras |
| `async` | `httpx` | Async client |
| `persist` | `sqlalchemy` | SQLAlchemy workspace store |
| `viz` | `plotly`, `networkx`, `openpyxl` | Graph + Excel |
| `serve` | `fastapi`, `uvicorn` | Grafana datasource server |
| `dev` | all of the above + `pytest`, `ruff`, `mypy` | Development |
| `all` | everything except dev tools | Full install |

**Install for development:**
```bash
pip install -e ".[dev]" httpx
```

**`py.typed` marker:**
Present at `gnat/py.typed` — signals mypy and other type checkers
that the package provides inline types (PEP 561).

**Entry points:**
```
gnat        → gnat.cli.main:main
gnat-codegen → gnat.codegen.openapi_generator:_main
```

**OIDC PyPI publishing:**
`release.yml` uses `pypa/gh-action-pypi-publish` with `id-token: write`
permission. No API token needed — configure trusted publishing in PyPI
project settings under the repo name.

**Version bump workflow:**
1. Update `version` in `pyproject.toml`
2. Add `## [X.Y.Z]` section to `CHANGELOG.md`
3. `git tag vX.Y.Z && git push --tags`
4. Release workflow fires automatically

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

# 6. Add [global.myplatform] block to ARCHITECTURE_DECISIONS.md §13

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

## 16. Scheduling

**Decision:** Built-in threading scheduler (`FeedScheduler`) as the primary
path, with export adapters for APScheduler and Celery.

### Why not just APScheduler

APScheduler is excellent but adds a dependency and a learning curve for a
feature analysts need to configure on day one. The built-in scheduler covers
the common case (interval + cron) in ~200 lines. Teams that already have
APScheduler or Celery can use the export adapters.

### Reader factory pattern — the key to correct incremental ingestion

The `reader_factory` callable receives a `JobRunContext` on every run. This
is the correct place to construct time-windowed readers:

```python
def make_taxii_reader(ctx):
    return TAXIICollectionReader(
        collection,
        added_after=ctx.last_success_iso or "2024-01-01T00:00:00Z",
    )
```

`ctx.last_success_iso` is `None` on the first run (full backfill) and the
ISO timestamp of the last successful completion on all subsequent runs.
This means incremental ingestion is automatic — readers only fetch new data.

**Why factory and not instance:** Readers are not reusable across runs —
they may hold open connections, carry file pointers, or depend on the
`added_after` computed from the previous run. A factory produces a fresh
reader each time with the correct parameters.

### FeedJob state machine

```
enabled=False → always "skipped"
overlap=skip, lock unavailable → "skipped"
reader/pipeline raises → "failed", on_failure callback
result.errors non-empty → "partial", on_failure callback
all clear → "success", on_success callback, last_success_at updated
```

`consecutive_failures` counts backwards through history and resets to 0
on the first "success" or "partial" result. Use it for alerting thresholds:
fire a PagerDuty alert when `job.consecutive_failures >= 3`.

### Drift-corrected timing

The scheduler computes `next_trigger = last_scheduled_at + interval` rather
than `time.time() + interval`. This means a 1-hour feed that takes 5 minutes
to run still fires at the next hour mark, not 65 minutes after the last run.
If the process was down and the next trigger is already in the past, it fires
immediately without trying to backfill the missed runs.

### Threading model

One daemon thread per job. Threads sleep in 1-second increments (not one
long sleep) so `stop()` responds within ~1 second regardless of interval.
`start(run_immediately=True)` is the right choice for startup backfill — it
fires all jobs once before entering the normal schedule loop.

### Overlap policy

`"skip"` (default): if a run is still executing when the next trigger fires,
the new run is logged as "skipped". Best for feeds where missing one run is
acceptable and you don't want a backlog of queued runs.

`"queue"`: the new run waits for the current one to finish. Use for feeds
where every run must complete, but beware that a slow source can cause
unlimited queueing.

### Config extras

`pip install "gnat[schedule]"` adds `croniter` for cron expression
support. Interval-based jobs work with no extras. APScheduler and Celery
adapters require those packages installed separately.

### Quick-reference: adding a scheduled feed

```python
from gnat.schedule import FeedJob, FeedScheduler
from gnat.ingest.sources.readers import PlainTextReader, TAXIICollectionReader
from gnat.ingest.mappers.mappers import FlatIOCMapper, STIXPassthroughMapper

# Stateless feed (blocklist)
blocklist = FeedJob(
    job_id="blocklist-hourly",
    reader_factory=lambda ctx: PlainTextReader("https://example.com/ips.txt"),
    mapper_factory=lambda ctx: FlatIOCMapper(confidence=70, tlp_marking="white"),
    interval_seconds=3600,
    client=tq_client,
)

# Incremental TAXII feed
taxii = FeedJob(
    job_id="taxii-daily",
    reader_factory=lambda ctx: TAXIICollectionReader(
        collection,
        added_after=ctx.last_success_iso or "2024-01-01T00:00:00Z",
    ),
    mapper_factory=lambda ctx: STIXPassthroughMapper(client=tq_client),
    cron="0 2 * * *",   # 02:00 daily — requires pip install "gnat[schedule]"
    client=tq_client,
    on_failure=lambda rec: logger.error("TAXII feed failed: %s", rec.error),
)

scheduler = FeedScheduler()
scheduler.add(blocklist)
scheduler.add(taxii)
scheduler.start(run_immediately=True)   # backfill on startup

# Health check
for status in scheduler.statuses():
    if not status["is_healthy"]:
        print(f"UNHEALTHY: {status['job_id']} — {status['last_run_status']}")
```

---

## 17. Export / Integration Pipeline

**Decision:** A separate push-oriented pipeline (Filter → Transform → Deliver)
distinct from the pull-oriented ingestion pipeline (Reader → Mapper → Pipeline).

### Why separate from ingestion

Ingestion is incremental — you fetch new records since last run and add them.
Export is often idempotent and authoritative — a firewall EDL must contain the
*current complete list*, not a diff. This fundamental difference in semantics
means the same pipeline abstraction doesn't fit both.

### Three-stage composable pipeline

```
ExportFilter → ExportTransform → ExportDelivery
```

All three are protocol classes. Filters are lazy generators (composable via `&`).
Transforms produce a `TransformResult` with named payloads (one per output file).
Delivery targets receive the full `TransformResult` and push each payload.

**Multiple outputs from one transform:** `EDLTransform` produces separate files
per IOC type (`indicators-ipv4.txt`, `indicators-domain.txt`, etc.) because
firewalls need to assign each type to the appropriate security policy — you can't
mix IPs and domains in a single EDL entry.

### Filter design decisions

All filters are lazy generators — they don't materialise intermediate lists.
Composable via `&` operator: `TypeFilter("indicator") & ConfidenceFilter(70)`.

`IOCTypeFilter` inspects the STIX pattern string rather than a separate IOC
type field because STIX patterns are the canonical representation. The type is
inferred from the observable keyword (`ipv4-addr`, `domain-name`, etc.).

`TLPFilter` defaults unlabelled objects to `"white"` — the most permissive
default. Override with `default_tlp="amber"` for strict environments that
should block unlabelled objects from leaving.

`AgeFilter` uses `modified` then `created` then the custom `time_field` in
fallback order. Missing timestamps default to "pass through" (`drop_missing=False`)
so old or partial objects aren't silently dropped — use `drop_missing=True` to
enforce freshness strictly.

### EDL transform — atomic file replace

`FileDelivery` uses write-to-temp-then-rename (atomic replace) so firewalls that
poll the EDL file via HTTP never see a partially-written file. The temp file is
created in the same directory as the destination to ensure both are on the same
filesystem (rename is atomic only within one filesystem).

### EDLServer — built-in HTTP server

`EDLServer` runs a background daemon thread serving EDL files directly.
Firewalls point to `http://<host>:8080/indicators-ipv4.txt`. On each export
pipeline run, the in-memory files are updated atomically (under a lock) and the
server immediately serves the new version on the next poll. No file system I/O
or nginx configuration needed for the most common case.

### ExportJob — bridges export to scheduling

`ExportJob` inherits from `FeedJob` and overrides `execute()` to call the
pipeline factory instead of the reader/mapper/ingest pipeline. This means
all scheduling features — drift-corrected timing, overlap prevention, history,
callbacks, APScheduler/Celery export — apply to export jobs automatically.

The `pipeline_factory(ctx) -> ExportPipeline` pattern allows the pipeline to
incorporate per-run context. A common pattern: filter objects modified since
`ctx.last_success_iso` so only newly-updated indicators are exported:

```python
def factory(ctx):
    filters = [TypeFilter("indicator"), ConfidenceFilter(70)]
    if ctx.last_success_iso:
        filters.append(AgeFilter(max_age_days=1, time_field="modified"))
    return (ExportPipeline("incremental")
            .read_from(workspace)
            .filter_with(*filters)
            .transform_with(NetskopeCETransform())
            .deliver_to(HTTPDelivery(url=NETSKOPE_CE_URL, headers=AUTH)))
```

### ThreatQ → Netskope CE → EDL reference workflow

This is the exact workflow from the design brief:

```python
from gnat.export import ExportPipeline
from gnat.export.filters import TypeFilter, ConfidenceFilter, IOCTypeFilter
from gnat.export.transforms.netskope import NetskopeCETransform
from gnat.export.delivery.targets import HTTPDelivery, MultiDelivery, FileDelivery, EDLServer
from gnat.export.jobs import ExportJob
from gnat.schedule import FeedScheduler

# ThreatQ workspace (populated by ingestion pipeline or direct load)
ws = manager.open("threat-intel")

# Build the delivery stack
edl_server = EDLServer(port=8080)   # started on first deliver()

def tq_to_netskope(ctx):
    return (
        ExportPipeline("tq-to-netskope-ce")
        .read_from(ws)
        .filter_with(TypeFilter("indicator"))
        .filter_with(ConfidenceFilter(min_confidence=60))
        .filter_with(IOCTypeFilter(["domain", "url", "sha256"]))
        .transform_with(NetskopeCETransform(
            source_label="ThreatQ",
            default_reputation=60,
        ))
        .deliver_to(HTTPDelivery(
            url="https://netskope-ce.example.com/api/plugin/threatintel/pushData",
            headers={"Authorization": "Bearer <token>"},
        ))
    )

def tq_to_edl(ctx):
    return (
        ExportPipeline("tq-to-palo-alto")
        .read_from(ws)
        .filter_with(TypeFilter("indicator"))
        .filter_with(ConfidenceFilter(min_confidence=70))
        .filter_with(IOCTypeFilter(["ipv4", "domain", "url"]))
        .transform_with(EDLTransform(
            ioc_types=["ipv4", "domain", "url"],
            max_per_file=100_000,
        ))
        .deliver_to(MultiDelivery(
            FileDelivery("/var/www/edl/"),   # nginx serves these
            edl_server,                      # also served live on :8080
        ))
    )

scheduler = FeedScheduler()
scheduler.add(ExportJob(
    job_id="tq-to-netskope-hourly",
    pipeline_factory=tq_to_netskope,
    interval_seconds=3600,
    on_failure=lambda rec: alert(f"Netskope sync failed: {rec.error}"),
))
scheduler.add(ExportJob(
    job_id="tq-to-edl-hourly",
    pipeline_factory=tq_to_edl,
    interval_seconds=3600,
))

scheduler.start(run_immediately=True)   # backfill on startup
# Firewalls poll http://<host>:8080/indicators-ipv4.txt on their own schedule
```

Netskope CE's sharing rules then push the received indicators to tenant URL/domain/IP
lists, which push to perimeter firewall EDLs. GNAT's role is the authoritative
push from ThreatQ into CE — everything downstream is Netskope's responsibility.

---

## 17. AI Agent Layer

**Decision:** Agents implement the existing `SourceReader` / `RecordMapper`
interfaces so they drop directly into `IngestPipeline` and `FeedJob` without
any special casing.

### Two agent types, one interface

`ResearchAgent` is a `SourceReader` — it yields `RawRecord` dicts.
`ParsingAgent` is a `RecordMapper` — it consumes `RawRecord` dicts and yields
`STIXBase` objects. `CopilotReader` is a `SourceReader` — it yields `RawRecord`
dicts from M365 sources. The pipeline chain is:

```
ResearchAgent / CopilotReader (SourceReader)
    → ParsingAgent (RecordMapper)
    → existing mappers (optional)
    → connectors / EDLs
```

This means scheduling, deduplication, error handling, and delivery all reuse
the existing `FeedJob` / `IngestPipeline` infrastructure with zero new code.

### Claude API key in INI, not environment

```ini
[claude]
api_key               = sk-ant-...
model                 = claude-sonnet-4-6
max_tokens            = 4096
timeout               = 120
ai_confidence_ceiling = 60
```

The `ClaudeClient` uses stdlib `urllib` only — no `anthropic` SDK dependency.
This keeps the `agents` extra dependency-free (no new pip installs required).

### Confidence ceiling — the most important design decision

Every STIX object produced by `ParsingAgent` is capped at
`AgentConfig.ai_confidence_ceiling` (default 60) and tagged
`x_source_type: "ai_extracted"`. This means:

- AI-extracted intel can never reach EDLs at high confidence without analyst review
- Filters like `ConfidenceFilter(min_confidence=70)` in export pipelines
  will exclude AI intel by default unless explicitly lowered
- The tag allows analysts to find and review all AI-extracted objects:
  `ws.objects` filtered by `x_source_type == "ai_extracted"`

**Never raise the ceiling to 100.** Claude can hallucinate slightly wrong IPs
or malformed hashes. The ceiling exists to require human review before high-stakes
propagation.

### Reader factory pattern for incremental research

The feed-driven `ResearchAgent` and `CopilotReader` both support `newer_than`
via the `JobRunContext` pattern:

```python
FeedJob(
    reader_factory=lambda ctx: ResearchAgent(
        config=cfg,
        monitored_sources=[...],
        newer_than=ctx.last_success_iso,  # None on first run (full backfill)
    ),
    ...
)
```

On the first run `newer_than` is `None` and Claude fetches everything relevant.
On subsequent runs it's the ISO timestamp of the last successful completion.

### Topic-driven vs. feed-driven — when to use each

| Mode | Use when | Output |
|---|---|---|
| Topic-driven | Targeted research ("what do we know about APT29?") | One synthesis per topic |
| Feed-driven | Monitoring sources on schedule | One record per new article found |
| CopilotReader | M365 content (emails, SharePoint, Teams) | One record per content item |

Topic-driven is better for on-demand analyst queries. Feed-driven is better for
recurring monitoring jobs. Both can be combined in the same `IngestPipeline`.

### max_calls_per_run prevents runaway cost

Topic-driven mode makes one Claude API call per topic. Feed-driven makes one
call per batch of 10 sources. `max_calls_per_run` (default 20) caps total calls
per `_iter_records` invocation. For a feed with 100 monitored sources:
`100 / 10 = 10 batches < 20 limit` — fine. For a topic list of 50 topics, set
`max_calls_per_run=50` explicitly or the last 30 will be silently skipped with
a warning log.

### Prompts are centralised in prompts.py

All Claude system and user prompt templates live in `gnat/agents/prompts.py`.
This is intentional — prompt engineering is iterative and keeping prompts
separate from logic means they can be reviewed, versioned, and tuned without
touching agent code. The JSON schema embedded in `PARSING_SYSTEM` is the
contract between Claude and `ParsingAgent._to_stix_objects`. Field names must
match exactly.

### CopilotReader uses DirectLine v3 (sync urllib)

Copilot is accessed via Bot Framework DirectLine v3 API. The reader uses
stdlib `urllib` (not the async `httpx` client from `async_client.base`) because
`SourceReader._iter_records` is synchronous. The polling pattern (2s interval,
30 attempts max) handles Copilot's variable response time when querying M365 Graph.

The prose fallback in `_parse_reply` handles cases where Copilot returns a
natural-language "no results" message instead of JSON — this is common when
the M365 source has no new content matching the query.

---

## 18. Shared Research Library

**Decision:** Three-tier model (personal → staging → library) with all access
through `ResearchLibrary`. No direct workspace manipulation by analysts.

### Why three tiers, not two

A flat shared workspace has two failure modes: analysts write garbage directly
to the shared space, or concurrent writes from multiple analysts corrupt entries.
The staging tier absorbs both. Analysts write to staging freely — it's an inbox,
not a source of truth. The curation job is the only thing that writes to the
library, so the library is never in an inconsistent state from concurrent analyst
activity.

### Deduplication: most recent wins

When multiple analysts research the same topic and promote to staging, the
curation job keeps the entry with the latest `promoted_at` timestamp and
archives the rest. Archived entries remain in storage — nothing is deleted —
so the history of who researched what is preserved for audit. The `entry_id`
is a SHA-256 fingerprint of `(topic_key, promoted_at)` so it's deterministic
and collision-resistant.

### TTL categories

| Category | Default | Rationale |
|---|---|---|
| `indicator` | 24h | IOCs rotate or get sinkholed quickly |
| `vulnerability` | 72h | Exploitability status changes within days |
| `campaign` | 14d | Campaign activity evolves over weeks |
| `threat_actor` | 30d | Actor TTPs and infrastructure change slowly |
| `other` | 7d | Conservative fallback |

All overridable in `[research_library]` INI section. The TTL is set at
*curation time*, not promotion time — so the clock starts when the entry
enters the library, not when the analyst finished their research.

### check-before-research pattern

```python
lib = ResearchLibrary.default()

if lib.is_fresh("APT29"):
    # Use cached research — load into workspace, save API costs
    lib.load_into_workspace("APT29", my_workspace)
else:
    # Run agents, review, then promote
    # ... research ...
    lib.promote(my_workspace, topic="APT29", researcher="analyst1",
                note="New C2 infra confirmed by Unit42 and Mandiant.")
```

`is_fresh` returns `True` only for curated (library) entries within their TTL.
Pending staging entries are invisible to `is_fresh` and `get`. This means
analysts always see curator-reviewed data, never raw staging entries.

### The optional note field

`lib.promote(..., note="...")` is deliberately optional. Making it required
adds friction that reduces promotion rates. Making it optional means analysts
who want to share context can do so; those in a hurry can skip it. The note
appears in `list_entries()` and `search()` output, so a descriptive note
increases discoverability by colleagues.

### CurationJob scheduling

```python
from gnat.research import ResearchLibrary, CurationJob
from gnat.schedule import FeedScheduler

lib  = ResearchLibrary.default()
job  = CurationJob(lib, interval_seconds=4 * 3600)   # every 4 hours

with FeedScheduler() as sched:
    sched.add(job)
```

Four hours is a reasonable default — staging entries don't sit unreviewed for
long, but the curation job doesn't run so frequently that it becomes noisy in
the scheduler status output. For teams that need faster promotion, `cron="0 * * * *"`
(hourly) works equally well.

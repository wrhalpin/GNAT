# GNAT Pending Items

Tracked outstanding implementation tasks, normalization work, and
known gaps. Update this file as items are completed or new ones are
identified.

---

## HIGH PRIORITY

### 1. ThreatQ Sector / Industry Field Normalization — ✅ COMPLETE

**File:** `gnat/connectors/threatq/client.py`

**Implemented:**
Research confirmed that ThreatQ stores sector/industry as entries in a
generic `attributes` array (never as top-level fields), only present when
`?with=attributes` is appended to the request. The attribute `name` strings
are free-form and deployment-configurable — there is no platform-wide
controlled vocabulary.

Changes made:
- `get_object()` and `list_objects()` now include `attributes` in the
  `?with=` parameter.
- Added `_extract_sectors()` static helper: iterates `attributes[]`,
  matches `name` case-insensitively against known variants
  (`"Targeted Industry"`, `"Target Industry"`, `"Targeted Sector"`,
  `"Target Sector"`, `"Sector"`, `"Targets"`, `"Victim Industry"`),
  and collects `value` strings.
- `to_stix()` calls `_extract_sectors()` and writes results to
  `x_target_sectors` when non-empty.
- Added `get_attribute_types()` method: calls `GET /api/attribute_types`
  to let operators discover the exact names used in their deployment.
- 11 new unit tests covering all attribute name variants, case
  insensitivity, multiple attrs, unrelated attrs ignored, and the
  `get_attribute_types()` / `?with=attributes` request behaviour.

**Other connectors — all now complete:**
- `recordedfuture/client.py` ✅ — `relatedEntities[type=Industry]` → `x_target_sectors`
- `crowdstrike/client.py` ✅ — `target_industries[]` → `x_target_sectors`
- `virustotal/client.py` ✅ — `popular_threat_category` → `x_target_sectors`
- `shadowserver/client.py` ✅ — `sector` → `x_target_sectors`
- `nucleus/client.py` ✅ — `asset.industry` + tags → `x_target_sectors`

---

### 2. VirusTotal Connector

**File:** `gnat/connectors/virustotal/client.py`  
**Status:** ✅ COMPLETE — API key auth, file/URL/IP/domain lookups, `to_stix()` maps VT reputation to `Indicator` with confidence scoring.

---

### 3. ShadowServer Connector

**File:** `gnat/connectors/shadowserver/client.py`  
**Status:** ✅ COMPLETE — API key auth, reports/scan/asn queries, `to_stix()` maps scan results to `Indicator`/`Vulnerability`.

---

### 4. Rapid7 InsightVM/IDR Connector

**File:** `gnat/connectors/rapid7/client.py`  
**Status:** ✅ COMPLETE — API key auth, vulnerability and asset queries, `to_stix()` maps CVEs to `Vulnerability` with CVSS.

---

### 5. Nucleus Connector

**File:** `gnat/connectors/nucleus/client.py`  
**Status:** ✅ COMPLETE — API key auth, asset/vuln/finding queries, `to_stix()` maps findings to `Vulnerability` with sector tagging placeholder.

---

## MEDIUM PRIORITY

### 6. DOCX Renderer — Node.js npm dependency

**File:** `gnat/reports/renderers.py` — `DOCXRenderer`

**Status:** ✅ COMPLETE — Replaced Node.js/npm `docx` implementation with
pure-Python `python-docx`. No subprocess, no temp files, no Node.js required.
`python-docx>=1.1` added to `[reports]` and `[all]` extras in `pyproject.toml`.

---

### 7. Report Email Body HTML

**File:** `gnat/reports/delivery.py` — `EmailDelivery`

**Status:** ✅ COMPLETE — `ReportGenerator._extract_email_body_html()` reads
the rendered `.html` file and passes its full content as `body_html` when an
HTML output was rendered. For PDF/DOCX-only deliveries it falls back to an
HTML snippet built from the first 2000 chars of the Executive Summary section
narrative. `_deliver_email()` now passes the result to `EmailDelivery.from_ini()`.
4 unit tests added in `TestEmailBodyHTML`.

---

### 8. Report Yearly Scheduling

**File:** `gnat/reports/generator.py` — `ReportJob`

**Status:** ✅ COMPLETE — `ReportJob` now defaults yearly reports to
`cron="0 6 1 1 *"` (06:00 UTC January 1st) instead of the 365-day interval,
preventing drift after server restarts. `config/config.ini.example` documents
recommended cron expressions for daily (`0 6 * * *`), weekly trends
(`0 6 * * 1`), and yearly (`0 6 1 1 *`) report types. 3 unit tests added
in `TestReportJob`.

---

### 9. Research Library — WorkspaceManager.default() method

**File:** `gnat/context/workspace.py`

**Status:** ✅ COMPLETE — `WorkspaceManager.default()` exists and is fully
implemented. Builds a `GlobalContextRegistry` from config and a SQLite
`WorkspaceStore` (falls back to `FlatFileStore` if SQLAlchemy unavailable).
`ResearchLibrary.default()` chains through it correctly. Added 3 unit tests
to `TestWorkspaceManager` covering the happy path, missing config error, and
return type.

---

### 10. AI Agent — Copilot DirectLine Token Refresh

**File:** `gnat/agents/copilot.py`

**Status:** ✅ COMPLETE — Added `use_token_exchange` flag (INI: `use_token_exchange = true`).
When enabled, `_ensure_token()` exchanges the DirectLine secret for a 30-minute
token via `POST /tokens/generate` on first use, and refreshes automatically via
`POST /tokens/refresh` when fewer than 5 minutes remain. `_bearer()` returns the
current token (or secret as fallback). `_query_source` calls `_ensure_token()`
before opening each conversation. 20 unit tests added.

---

## LOW PRIORITY / NICE TO HAVE

### 11. CLI — `gnat report` subcommand

**File:** `gnat/cli/main.py`

**Status:** ✅ COMPLETE — Added `gnat report list` and `gnat report run`.
`run` accepts `--config <name>`, `--formats`, `--output-dir`, `--no-ai`.

### 12. Export Pipeline — `SectorFilter` integration

**File:** `gnat/export/filters.py`

**Status:** ✅ COMPLETE — `SectorFilter` moved to `gnat/export/filters.py`
as a proper `ExportFilter` subclass (composable via `&`). Re-exported from
`gnat/reports/base.py` with `apply()` and `from_config()` helpers for
backwards compatibility. Available as `gnat.export.SectorFilter`.

### 13. CHANGELOG.md — versions 0.6.0 through 1.0.0

**File:** `CHANGELOG.md`

**Status:** ✅ COMPLETE — Added entries for 0.6.0 (FeedScheduler),
0.7.0 (ExportPipeline + filters), 0.8.0 (AI Agents), 0.9.0 (ResearchLibrary),
and 1.0.0 (Reports, 29 connectors, search sidecar, CLI report subcommand,
python-docx DOCXRenderer, SectorFilter move).

### 14. pyproject.toml — `[project.optional-dependencies]` for new connectors

✅ COMPLETE — No new pip dependencies required. VirusTotal, ShadowServer,
Rapid7, and Nucleus connectors use only Python stdlib (`hashlib`, `hmac`,
`json`) plus GNAT's own `BaseClient` (urllib3). All existing extras groups
in `pyproject.toml` remain correct.

---

## NORMALIZATION REFERENCE

| Platform        | Native Field / Path                          | Maps to              | Status    |
|-----------------|----------------------------------------------|----------------------|-----------|
| ThreatQ         | `attributes[].name` ∈ sector variants, `attributes[].value` | `x_target_sectors` | ✅ DONE |
| Recorded Future | `relatedEntities[type=Industry].entity.name` | `x_target_sectors`   | ✅ DONE   |
| CrowdStrike     | `target_industries[]` (adversary objects)    | `x_target_sectors`   | ✅ DONE   |
| VirusTotal      | `popular_threat_category{}.value`            | `x_target_sectors`   | ✅ DONE   |
| ShadowServer    | `sector` (top-level report field)            | `x_target_sectors`   | ✅ DONE   |
| Nucleus         | `asset.industry` + `asset.tags[]`            | `x_target_sectors`   | ✅ DONE   |

**Canonical field:** `x_target_sectors` — list of strings on any STIX object.
**Alias config:** `[sector_aliases]` section in `config.ini`.
**Filter class:** `gnat/export/filters.py::SectorFilter` (re-exported from `gnat/reports/base.py`).

---

## ROADMAP — NEW ITEMS (evaluated 2026-03-28)

Items below were accepted after design review. Each requires a plan pass
before any code changes. Ordered by implementation dependency / priority.

---

### 15. Connector Structure Audit — ✅ COMPLETE

**Priority:** HIGH — prerequisite for items 16, 19, 20

**Implemented:** Items #16 (incident linking), #19 (capability reflection), and #20
(batch 2 connectors) all shipped successfully, validating that the connector
contract was sound. `ComplianceMatrix` in `gnat/codegen/contribute.py` (item #25)
now provides a programmatic audit of all 8 required `ConnectorMixin` methods plus
test coverage for any registered connector, replacing the manual audit pass.

---

### 16. Incident Linking: XSOAR / ServiceNow / GreyMatter

**Priority:** HIGH — depends on #15 audit confirming current connector state

**Status:** ✅ COMPLETE

**Implemented:**
- **XSOAR:** `XSOARClient.link_incident(incident_id, stix_obj)` — calls
  `POST /incident/{id}/linkedIncidents`. `upsert_object()` now accepts
  `incident_id` kwarg; automatically links on write when provided. 4 unit tests.
- **ServiceNow:** New `ServiceNowClient` (`gnat/connectors/servicenow/`) —
  `BaseClient + ConnectorMixin` for `sn_si_incident` Table API. Basic auth
  (username+password) and Bearer token. `annotate_incident(sys_id, stix_obj)`
  appends a structured work note via `PUT /api/now/table/sn_si_incident/{sys_id}`.
  Registered in `CLIENT_REGISTRY` and `config.ini.example`. 13 unit tests.
- **GreyMatter:** `GreyMatterClient.link_investigation(case_id, stix_obj)` —
  calls `POST /v1/incidents/{case_id}/linked_observables`; infers observable
  type from STIX pattern. `upsert_object()` now accepts `linked_cases` list
  kwarg merged into request payload. 4 unit tests.

---

### 17. Jira + ServiceNow Connectors

**Priority:** MEDIUM

**Status:** ✅ COMPLETE

**Implemented:**
- **ServiceNow** ✅ — completed in item #16.
- **Jira** (`gnat/connectors/jira/client.py`): `BaseClient + ConnectorMixin`
  for Jira REST API v3 (Cloud + Server/DC). Basic auth (email + API token)
  or Bearer token. `list_objects()` via JQL (`POST /rest/api/3/issue/search`);
  `upsert_object()` create/update; `to_stix()` maps issues to `note` /
  `course-of-action`; `from_stix()` builds JQL; `annotate_ticket()` posts
  ADF-formatted comment; `search_by_label()` helper. Registered in
  `CLIENT_REGISTRY`, `[jira]` section in `config.ini.example`. 15 unit tests.

---

### 18. NLP Query Interface

**Status:** ✅ Complete — `gnat/nlp/` package, `GNATClient.natural_language_query()`, `gnat nlq` CLI, 46 unit tests.

**Priority:** MEDIUM

**What:** Natural-language query layer on top of `GNATClient.list_objects()`.
"Give me everything on APT-128 from the last 30 days" → structured query
dispatched to one or all connectors.

**Architecture:** New `gnat/nlp/` package:

```
gnat/nlp/
├── __init__.py          # exports: NLPQueryEngine
├── parser.py            # NLPQueryEngine — dispatches to backend
├── builtin.py           # BuiltinParser — rule-based, no AI deps
│                        #   extracts: entity names, time ranges,
│                        #   IOC types, platform filters via regex + keywords
└── claude_backend.py    # ClaudeParser — structured extraction via Claude API
                         #   returns same QuerySpec as BuiltinParser
```

**QuerySpec** (internal dataclass):
```python
@dataclass
class QuerySpec:
    entities: list[str]           # APT-128, Cobalt Strike, ...
    ioc_types: list[str]          # ip, domain, hash, ...
    since: datetime | None
    until: datetime | None
    platforms: list[str]          # connector names to query, empty = all
    limit: int
```

**Config:**
```ini
[nlp]
backend = builtin          # builtin | claude
model   = claude-sonnet-4-6
```

**GNATClient API:**
```python
client.natural_language_query("Get all IPs related to Lazarus Group since January")
# → list[STIXBase]
```

**Extras:** `[nlp]` group; built-in backend has no new deps; Claude backend
uses existing `[agents]` Claude client.

---

### 19. Client Capability Reflection

**Priority:** MEDIUM

**Status:** ✅ COMPLETE

**Implemented:**
- `ConnectorMixin.capabilities()` (`gnat/connectors/base_connector.py`):
  MRO walk returns all public, non-plumbing methods with `signature`,
  `doc`, `type` (`auth`/`read`/`write`/`helper`), and `platform_specific`
  flag. Private, HTTP-plumbing (`get`, `post`, etc.), and meta methods
  (`capabilities`, `call`) excluded.
- `ConnectorMixin.call(method_name, *args, allow_write=False, **kwargs)`:
  whitelist-only dispatch; write-type methods require `allow_write=True`.
- CLI: `gnat client capabilities --platform <name>` (colour table + JSON);
  `gnat client call --platform <name> --method <m> --args KEY=VALUE ...`
  with `--allow-write` guard.
- 31 unit tests in `tests/unit/test_capabilities.py`.

---

### 20. Additional Connectors (Batch 2)

**Status:** ✅ Complete — all 11 connectors implemented and tested.

**Priority:** MEDIUM — depends on #15 audit to ensure consistent baseline

Eleven new connectors in priority order. Each follows the standard
`BaseClient + ConnectorMixin` pattern established in CLAUDE.md.

| # | Platform | Auth | Primary Value | Notes |
|---|----------|------|---------------|-------|
| 1 | ThreatConnect | OAuth2 / API token | Major enterprise TI platform | TC Exchange API v3 |
| 2 | Mandiant | OAuth2 (client_credentials) | APT/malware intel feeds | Mandiant Advantage API |
| 3 | MS Defender Threat Intelligence | OAuth2 (Azure AD) | Azure shop TI; MSTI API | Same auth as Sentinel |
| 4 | TheHive | API key | SOAR/case management; STIX-native | TheHive 5.x API |
| 5 | ThreatStream (Anomali) | API key + username | Enterprise TI aggregation | OPTIC API v2 |
| 6 | Stellar Cyber | API key | XDR/open XDR platform | Starlight API |
| 7 | FLARE | API key | Google/Mandiant sandbox enrichment | Flare Systems API |
| 8 | SOCRadar | API key | CTI + attack surface mgmt | SOCRadar TI API |
| 9 | PulseDive | API key | Community TI enrichment | PulseDive API v1 |
| 10 | Yeti | API key | FOSS TI (STIX-native) | Yeti REST API |
| 11 | CloudSEK | API key | ASM / digital risk | CloudSEK XVigil API |

**Per-connector deliverables:**
- `gnat/connectors/<platform>/client.py` — full `BaseClient + ConnectorMixin`
- `gnat/connectors/<platform>/__init__.py`
- `CLIENT_REGISTRY` entry in `gnat/clients/__init__.py`
- `[<platform>]` section in `config/config.ini.example`
- Minimum 5 unit tests per connector
- `CHANGELOG.md` entry

**Implement one at a time**; each gets its own commit.

---

### 21. XSOAR Content Pack Generator

**Priority:** MEDIUM-LOW

**Status:** ✅ COMPLETE

**Implemented:**
- `gnat/codegen/xsoar_generator.py` — `generate_xsoar_pack(connector_name,
  output_dir, version, auth_type, overwrite)`. Introspects any registered
  connector via `capabilities()`, maps methods to XSOAR command defs, and
  writes a valid XSOAR 6 content pack zip. Write methods flagged
  `dangerous: true`; auth type auto-detected from constructor signature.
- Pack layout: `pack_metadata.json`, `Integrations/<Name>/<Name>.yml`,
  `Integrations/<Name>/<Name>.py`, `ReleaseNotes/<ver>.md`.
- `gnat codegen` restructured to `openapi`/`xsoar` sub-subcommands.
  CLI: `gnat codegen xsoar --connector threatq --output ./packs/`.
- Platform-specific helpers (`link_incident`, `link_investigation`,
  `annotate_incident`) auto-surface as XSOAR commands.
- 40 unit tests in `tests/unit/test_xsoar_generator.py`.

---

### 22. Docker Containerization

**Priority:** MEDIUM-LOW

**Status:** ✅ COMPLETE

**Implemented:**
- `docker/scheduler/Dockerfile`, `docker/edl/Dockerfile`,
  `docker/monitor/Dockerfile` — slim Python 3.11 images with targeted
  extras; workspace bind-mounted via named volume `gnat-workspace`.
- `docker-compose.yml` — orchestrates scheduler, edl (port 8080), monitor
  (port 8090) with health-checks and `restart: unless-stopped`.
- `.env.example` — `GNAT_CONFIG_DIR`, `EDL_PORT`, `MONITOR_PORT` vars.
- `.dockerignore` — excludes secrets, test artifacts, Rust build products.
- `.devcontainer/devcontainer.json` — VS Code / Codespaces dev container;
  Rust toolchain + Docker-in-Docker + Ruff extension.
- `Makefile` — added `docker-build`, `docker-up`, `docker-down`,
  `docker-logs` targets.

---

### 23a. Terminal UI (Textual) — Workstation / SSH Analyst Tool

**Status:** ✅ Complete — `gnat/tui/` package, 4 screens, 2 widgets, `gnat tui` CLI, 38 unit tests.

**Priority:** LOW

**What:** Interactive terminal UI for analysts running GNAT on a local
workstation or over SSH. Built with [Textual](https://github.com/Textualize/textual)
— a modern TUI framework from the `rich` authors. Zero browser required;
works on any terminal, including remote sessions.

**Why Textual over tkinter:**
- Works over SSH (no display server needed) — same binary on workstation
  and server
- Modern look (colors, panels, tables, input widgets) vs tkinter's dated
  appearance
- Pure Python, pip-installable; one new dependency vs zero for tkinter, but
  the UX difference is significant
- `rich` is already a de facto standard in Python tooling

**Scope (MVP views):**
1. **NLP query bar** — type a natural language query (item #18), results
   displayed in a scrollable STIX object table
2. **Research library browser** — search, filter by topic/TLP/date, view
   STIX object detail, promote/reject staging entries
3. **Scheduler status** — live-updating job table (last run, next run,
   status, error count); trigger job manually
4. **Report list** — list generated reports with metadata; open rendered
   HTML in system browser via `webbrowser.open()`

**Architecture:** `gnat/tui/` package:
```
gnat/tui/
├── __init__.py
├── app.py          # GNATApp(textual.App) — root, screen routing
├── screens/
│   ├── query.py    # NLP query screen
│   ├── library.py  # Research library browser
│   ├── scheduler.py# Scheduler status / control
│   └── reports.py  # Report list
└── widgets/
    ├── stix_table.py   # Reusable STIX object DataTable
    └── job_table.py    # Scheduler job DataTable
```

**Launch:**
```bash
gnat tui          # launch interactive TUI
gnat tui query    # launch directly on query screen
```

**Extras group:** `[tui]` → `textual>=0.60`

**INI config:** None required beyond existing GNAT config — TUI reads
the same `GNAT_CONFIG` the library uses.

**Depends on:** #18 (NLP query) for the query screen; gracefully degrades
to structured filter input if NLP not configured.

---

### 23b. Web UI (FastAPI) — Server / Dashboard

**Status:** ✅ Complete — `gnat/serve/` package, 3 API routers, embedded single-page dashboard, `gnat serve` CLI, 54 unit tests.

**Priority:** LOW

**What:** Browser-based dashboard for server deployments. FastAPI
(already in `[serve]` extras) serves a lightweight app accessible over
the network for teams sharing a central GNAT instance.

**Scope (MVP):**
1. **Research library browser** — search, filter by topic/TLP/date, view
   STIX object detail, promote/demote staging entries
2. **Report viewer** — list generated reports, serve rendered HTML inline
3. **Scheduler status** — job list, last run time, next run, error counts;
   manual trigger button

**Security requirements (non-negotiable):**
- API key auth (`X-Api-Key` header) — no unauthenticated access
- Bind to `localhost` by default; nginx+TLS for external exposure
- No config/credentials visible in any API response
- Input validation on all query parameters
- Rate limiting on all endpoints (100 req/min per key)

**Architecture:** `gnat/serve/` (FastAPI app) + `gnat/serve/static/`
(minimal JS, no build step — vanilla JS or htmx).

**INI config:**
```ini
[webui]
enabled = true
bind    = 127.0.0.1
port    = 8088
api_key = <random 32-char hex>
```

**Relationship to 23a:** Both TUI and web UI share the same backend logic
(`gnat/context/`, `gnat/research/`, `gnat/schedule/`). The TUI calls
Python objects directly; the web UI calls FastAPI endpoints that call the
same objects. No duplication of business logic.

**Note:** Pyramid was considered and rejected — FastAPI is already a
declared dependency and is a better fit for a JSON API + minimal HTML server.

---

### 24. Connector Health + Drift Monitoring Agent (3a)

**Status:** ✅ Complete — `gnat/agents/health_monitor.py`, `ConnectorHealthJob`, `SchemaSnapshot`, `DriftReport`, `gnat health` CLI, 74 unit tests.

**Priority:** LOW

**What:** A new `FeedJob` subclass (`ConnectorHealthJob`) that periodically:
1. Calls `health_check()` on all configured connectors
2. Compares response schema shape (field presence, type) against a stored
   baseline snapshot
3. Reports drift (new fields, missing fields, type changes) as structured
   alerts
4. Optionally posts a summary to a configured Slack webhook or email

**Implementation:** `gnat/agents/health_monitor.py` — `ConnectorHealthJob`
extends `FeedJob`; `SchemaSnapshot` persists baseline to workspace JSON.

**Config:**

```ini
[health_monitor]
enabled          = true
interval_minutes = 60
alert_webhook    = https://hooks.slack.com/...   # optional
drift_threshold  = 0.2                           # 20% field change triggers alert
```

---

### 25. Upstream Contribution Pipeline (3b) — ✅ COMPLETE

**Priority:** LOW — opt-in only

**Implemented:** `gnat/codegen/contribute.py` — `ContributionPipeline`, `ComplianceMatrix`,
`ContributeConfig`, `SubprocessRunner`. `gnat contribute` CLI subcommand in `gnat/cli/main.py`.
47 unit tests in `tests/unit/test_contribute.py`.

**What:** Opt-in workflow that packages a new/updated GNAT connector as a
GitHub pull request against the upstream `wrhalpin/GNAT` repository.

**CLI:**

```bash
gnat contribute --connector myplatform --message "Add MyPlatform connector"
# → validates connector structure (#15 compliance matrix)
# → runs unit tests (aborts on failure)
# → creates a branch contribute/{platform}-{timestamp}, commits, pushes to fork
# → opens a draft PR via GitHub API (requires PAT config)

gnat contribute --connector myplatform --dry-run   # compliance check only, no git ops
gnat contribute --connector myplatform --no-pr     # push branch but skip PR creation
```

**Config:**
```ini
[contribute]
enabled          = false       # explicit opt-in
github_token     = ghp_...     # PAT with repo scope on user's fork
fork_remote      = origin
upstream_remote  = upstream
draft_pr         = true        # always draft; human must mark ready
```

**Safety rules:**
- `draft_pr = true` is not overridable (hardcoded in `ContributeConfig.from_ini()`)
- Runs full test suite before creating branch; aborts on failure
- Never pushes directly to `main` or `master` (`_PROTECTED_BRANCHES` guard)
- Connector must pass the compliance matrix before PR is allowed

---

### 26. TAXII 2.1 Server — ✅ COMPLETE

**Priority:** MEDIUM — standard threat intelligence sharing protocol

**Implemented:** `gnat/serve/taxii/__init__.py`, `gnat/serve/taxii/app.py` — full TAXII 2.1 server;
`gnat taxii` CLI subcommand in `gnat/cli/main.py`. 44 unit tests in
`tests/unit/test_taxii_server.py`.

**What:** FastAPI application implementing the TAXII 2.1 protocol. Each GNAT workspace is exposed
as a TAXII collection under a single `gnat` API root. Clients can discover collections, fetch
STIX bundles with filtering and pagination, and POST new STIX objects directly into workspaces.

**Endpoints:**
```
GET  /taxii2/                                           Discovery (no auth)
GET  /taxii2/roots/gnat/                                API root info (no auth)
GET  /taxii2/roots/gnat/collections/                    List collections (auth)
GET  /taxii2/roots/gnat/collections/{id}/               Collection detail (auth)
GET  /taxii2/roots/gnat/collections/{id}/objects/       Get bundle (auth, paginated)
POST /taxii2/roots/gnat/collections/{id}/objects/       Add bundle (auth)
GET  /taxii2/roots/gnat/collections/{id}/manifest/      Object manifest (auth)
GET  /taxii2/roots/gnat/collections/{id}/objects/{oid}/ Single object (auth)
GET  /taxii2/roots/gnat/collections/{id}/objects/{oid}/versions/  Versions (auth)
```

**CLI:**
```bash
gnat taxii --port 8090 --api-key s3cr3t
gnat taxii --title "Acme TAXII" --contact admin@acme.com --port 9000
```

**Requires:** `gnat[serve]` (FastAPI + uvicorn)


---

### 27. STIX 2.1 Pattern Validator — ✅ COMPLETE

**Priority:** MEDIUM — core data quality for Indicator objects

**Implemented:** `gnat/stix/__init__.py`, `gnat/stix/pattern_validator.py`. 87 unit tests in
`tests/unit/test_stix_validator.py`. `gnat validate` CLI subcommand in `gnat/cli/main.py`.
`Indicator.__init__` gains `validate=True` kwarg. `pyproject.toml` gains `[stix-validate]` extra.

**What:** Two-tier STIX 2.1 Indicator pattern validator. Tier 1 is a pure-Python recursive
descent parser (no deps). Tier 2 uses the official `stix2-patterns` ANTLR grammar when
`pip install "gnat[stix-validate]"` is present.

**CLI:**
```bash
gnat validate pattern "[ipv4-addr:value = '1.2.3.4']"
gnat validate bundle indicators.json --fail-fast
gnat validate bundle indicators.json --strict   # uses stix2-patterns if installed
```

**Python API:**
```python
from gnat.stix import validate_pattern, PatternValidationError

result = validate_pattern("[ipv4-addr:value = '1.2.3.4']")
assert result.valid

validate_pattern("[bad", raise_on_error=True)  # raises PatternValidationError

# ORM integration (non-breaking, opt-in):
from gnat.orm.indicator import Indicator
ind = Indicator(pattern="[ipv4-addr:value = '1.2.3.4']", validate=True)
```

---

### 28. Multi-Tenant Workspace Isolation — ✅ COMPLETE

**Priority:** MEDIUM — MSP deployments with multiple client tenants

**Implemented:** `gnat/context/tenant.py` — `Tenant`, `TenantRegistry`, `TenantWorkspaceManager`.
`WorkspaceManager.for_tenant()` in `gnat/context/workspace.py`. `gnat/context/__init__.py` updated.
`gnat tenant` CLI subcommand in `gnat/cli/main.py`. 63 unit tests in `tests/unit/test_tenant.py`.

**What:** Complete tenant isolation layer for multi-tenant MSP deployments. Each tenant gets an
isolated workspace namespace using transparent name prefixing (`{tenant_id}::name`). No schema
migration required — works with existing SQLite and FlatFile stores. Existing workspaces are
implicitly in the "default" tenant.

**Python API:**

```python
from gnat.context import WorkspaceManager, TenantRegistry, TenantWorkspaceManager

# Register tenants
registry = TenantRegistry()
registry.register("acme", display_name="Acme Corp", config_path="/etc/gnat/acme.ini")
registry.register("beta", display_name="Beta Ltd")

# Scope a manager to a tenant
manager = WorkspaceManager.default()
acme = manager.for_tenant("acme")
ws = acme.create("apt28-investigation")  # stored as "acme::apt28-investigation"

beta = manager.for_tenant("beta")
ws2 = beta.create("apt28-investigation")  # "beta::apt28-investigation" — no collision

print(acme.list())  # [{"name": "apt28-investigation", "tenant_id": "acme", ...}]
print(beta.list())  # [{"name": "apt28-investigation", "tenant_id": "beta", ...}]
```

**CLI:**

```bash
gnat tenant list
gnat tenant create acme --display-name "Acme Corp" --config /etc/gnat/acme.ini
gnat tenant info acme
gnat tenant workspaces acme
gnat tenant delete acme --yes
```

---

### 30. Solr/Grafana Observability Integration — ✅ COMPLETE

**Priority:** MEDIUM — live search index dashboards for ops teams

**Implemented:**

- `gnat/viz/grafana/search_endpoints.py` — `/solr/` FastAPI sub-router exposing Solr index data as a Grafana SimpleJSON datasource. Targets: `stats/total`, `stats/type_counts`, `stats/platform_counts`, `timeseries/ingest`, `facet/<field>`, `search/<query>`. Zero new dependencies (stdlib `urllib.request`).
- `GrafanaServer` extended with optional `search_index` param; mounts `/solr/` router when provided.
- `solr_dashboard()` / `save_solr_dashboard()` in `gnat/viz/export.py` — 7-panel dashboard JSON.
- `gnat viz serve --with-solr` and `gnat viz solr-dashboard` CLI subcommands.
- `docker/grafana/provisioning/` — auto-provisioned GNAT + GNAT-Solr datasources; bundled dashboard JSON files.
- `docker-compose.yml` — `solr` (profile: `search`/`full`) + `grafana` (profile: `monitoring`/`full`) services; `make docker-search`, `make docker-full`.
- 44 unit tests in `tests/unit/test_grafana_searchi.py`.

**Usage:**

```bash
# Start Grafana + Solr sidecar via Docker Compose
make docker-full      # or: docker compose --profile full up -d

# Run GrafanaServer locally with Solr endpoints
gnat viz serve --with-solr --port 3001

# Export the Solr dashboard JSON (import into any Grafana instance)
gnat viz solr-dashboard --file solr_dashboard.json
```

---

### 29. Docker Integration Test Harness — ✅ COMPLETE

**Priority:** MEDIUM — reproducible CI integration tests without live credentials

**Implemented:**
- `docker/test/docker-compose.test.yml` — test-only Elasticsearch 8.13.4 + Solr 9.6 containers on non-conflicting ports (19200, 18983).
- `docker/test/gnat.test.ini` — minimal GNAT config for test containers.
- `tests/integration/conftest_docker.py` — session-scoped fixtures: `docker_services` (compose lifecycle), `elasticsearch_url`, `solr_url` (health-poll), `gnat_taxii_server` (subprocess TAXII server on a free port). `--run-docker` flag; `@pytest.mark.docker` marker.
- `tests/integration/test_docker_taxii.py` — 20 TAXII 2.1 round-trip integration tests.
- `tests/integration/test_docker_elastic.py` — 14 Elasticsearch + ElasticConnector integration tests.
- `tests/integration/test_docker_solr.py` — 14 Solr + GNATIndexer integration tests.
- `Makefile`: `test-docker-up`, `test-docker-down`, `test-docker` targets.
- `pyproject.toml`: `docker` pytest marker registered.

**Usage:**

```bash
make test-docker           # Up → run suite → down (automated)
make test-docker-up        # Start containers only
pytest tests/integration/ --run-docker -v
make test-docker-down      # Teardown + remove volumes
```

**No new dependencies** — uses stdlib `subprocess`, `urllib.request`, `socket` only.

---

### 30. Solr/Grafana Observability Integration — ✅ COMPLETE

**Priority:** MEDIUM — live search index dashboards for ops teams

**Implemented:**
- `gnat/viz/grafana/search_endpoints.py` — `/solr/` FastAPI sub-router exposing Solr index data as a Grafana SimpleJSON datasource. Targets: `stats/total`, `stats/type_counts`, `stats/platform_counts`, `timeseries/ingest`, `facet/<field>`, `search/<query>`. Zero new dependencies (stdlib `urllib.request`).
- `GrafanaServer` extended with optional `search_index` param; mounts `/solr/` router when provided.
- `solr_dashboard()` / `save_solr_dashboard()` in `gnat/viz/export.py` — 7-panel dashboard JSON.
- `gnat viz serve --with-solr` and `gnat viz solr-dashboard` CLI subcommands.
- `docker/grafana/provisioning/` — auto-provisioned GNAT + GNAT-Solr datasources; bundled dashboard JSON files.
- `docker-compose.yml` — `solr` (profile: `search`/`full`) + `grafana` (profile: `monitoring`/`full`) services; `make docker-search`, `make docker-full`.
- 44 unit tests in `tests/unit/test_grafana_search.py`.

**CLI:**

```bash
gnat validate pattern "[ipv4-addr:value = '1.2.3.4']"
gnat validate bundle indicators.json --fail-fast
gnat validate bundle indicators.json --strict   # uses stix2-patterns if installed
```

**Python API:**

```python
from gnat.stix import validate_pattern, PatternValidationError

result = validate_pattern("[ipv4-addr:value = '1.2.3.4']")
assert result.valid

validate_pattern("[bad", raise_on_error=True)  # raises PatternValidationError

# ORM integration (non-breaking, opt-in):
from gnat.orm.indicator import Indicator
ind = Indicator(pattern="[ipv4-addr:value = '1.2.3.4']", validate=True)
```

---

### 26. TAXII 2.1 Server — ✅ COMPLETE

**Priority:** MEDIUM — standard threat intelligence sharing protocol

**Implemented:** `gnat/serve/taxii/__init__.py`, `gnat/serve/taxii/app.py` — full TAXII 2.1 server;
`gnat taxii` CLI subcommand in `gnat/cli/main.py`. 44 unit tests in
`tests/unit/test_taxii_server.py`.

**What:** FastAPI application implementing the TAXII 2.1 protocol. Each GNAT workspace is exposed
as a TAXII collection under a single `gnat` API root. Clients can discover collections, fetch
STIX bundles with filtering and pagination, and POST new STIX objects directly into workspaces.

**Endpoints:**
```
GET  /taxii2/                                           Discovery (no auth)
GET  /taxii2/roots/gnat/                                API root info (no auth)
GET  /taxii2/roots/gnat/collections/                    List collections (auth)
GET  /taxii2/roots/gnat/collections/{id}/               Collection detail (auth)
GET  /taxii2/roots/gnat/collections/{id}/objects/       Get bundle (auth, paginated)
POST /taxii2/roots/gnat/collections/{id}/objects/       Add bundle (auth)
GET  /taxii2/roots/gnat/collections/{id}/manifest/      Object manifest (auth)
GET  /taxii2/roots/gnat/collections/{id}/objects/{oid}/ Single object (auth)
GET  /taxii2/roots/gnat/collections/{id}/objects/{oid}/versions/  Versions (auth)
```
**Usage:**
```bash
# Start Grafana + Solr sidecar via Docker Compose
make docker-full      # or: docker compose --profile full up -d

# Run GrafanaServer locally with Solr endpoints
gnat viz serve --with-solr --port 3001

# Export the Solr dashboard JSON (import into any Grafana instance)
gnat viz solr-dashboard --file solr_dashboard.json
```
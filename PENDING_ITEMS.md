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

### 15. Connector Structure Audit

**Priority:** HIGH — prerequisite for items 16, 19, 20

**What:** Audit all 29 connectors against the standard `BaseClient + ConnectorMixin`
contract. Produce a compliance matrix covering: auth, `get_object`, `list_objects`,
`upsert_object`, `delete_object`, `to_stix`, `from_stix`, `health_check`, unit test
coverage, and correct test placement (all connector tests in
`tests/unit/connectors/test_connectors.py`).

**Deliverables:**
- Compliance matrix (29 rows × 9 columns)
- List of gaps per connector
- Moved/added tests where needed
- Updated `IMPLEMENTATION_PLAN.md` connector map

**Scope:** Read-only audit pass first; fixes in a second commit.

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

**What:** Two new `BaseClient + ConnectorMixin` connectors for IT service
management / ticketing:

**Jira** (`gnat/connectors/jira/`):
- Auth: API token (Basic with email + token), OAuth2 supported
- `get_object(issue_key)` → `GET /rest/api/3/issue/{key}`
- `list_objects(jql)` → `POST /rest/api/3/issue/search` with JQL
- `upsert_object(stix_obj)` → `POST /rest/api/3/issue` (create) or
  `PUT /rest/api/3/issue/{key}` (update); maps STIX to Jira fields
- `annotate_ticket(key, stix_obj)` → `POST /rest/api/3/issue/{key}/comment`
- `to_stix()` → maps Jira issue to STIX `note` or `course-of-action` SDO
- `from_stix()` → builds JQL from STIX fields

**ServiceNow** (`gnat/connectors/servicenow/`):
- Auth: Basic (username + password) or OAuth2
- `get_object(sys_id)` → `GET /api/now/table/sn_si_incident/{sys_id}`
- `list_objects(query)` → `GET /api/now/table/sn_si_incident?sysparm_query=...`
- `upsert_object(stix_obj)` → create/update security incident
- `annotate_ticket(sys_id, stix_obj)` → add work note
- `to_stix()` → maps SI record to STIX `observed-data` or `course-of-action`

**Config sections:** `[jira]` and `[servicenow]` in `config.ini.example`.

---

### 18. NLP Query Interface

**Priority:** MEDIUM

**What:** Natural-language query layer on top of `SAKClient.list_objects()`.
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

**SAKClient API:**
```python
client.natural_language_query("Get all IPs related to Lazarus Group since January")
# → list[STIXBase]
```

**Extras:** `[nlp]` group; built-in backend has no new deps; Claude backend
uses existing `[agents]` Claude client.

---

### 19. Client Capability Reflection

**Priority:** MEDIUM

**What:** `ConnectorMixin` gains a `capabilities()` method that returns a
structured inventory of available operations, combining:
1. The standard 7-method interface (always present)
2. Any public extra methods on the connector subclass (platform-specific)
3. Metadata: method signatures, docstrings, read/write classification

**API:**
```python
caps = client.capabilities()
# → {
#     "authenticate": {"signature": "...", "type": "auth"},
#     "list_objects": {"signature": "...", "type": "read"},
#     "get_indicators": {"signature": "...", "type": "read", "platform_specific": True},
#     ...
# }

# Dynamic dispatch (safe — no eval, no arbitrary attr chains):
result = client.call("get_indicators", limit=100, since="2026-01-01")
```

**Safety rules for `call()`:**
- Only dispatches to methods in `capabilities()` (whitelist, not blacklist)
- Read-only by default; write methods require `allow_write=True` kwarg
- No recursion, no chained attribute access

**CLI integration:** `gnat client capabilities --platform threatq` prints
the capability table.

**Scope:** Changes to `gnat/connectors/base_connector.py` +
`gnat/clients/__init__.py` + CLI subcommand.

---

### 20. Additional Connectors (Batch 2)

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

**What:** `gnat codegen xsoar --connector <name>` generates a valid XSOAR
content pack zip from an existing GNAT connector. Promotes code reuse for
shops that run XSOAR natively and want a native integration without
maintaining two separate codebases.

**XSOAR content pack structure:**
```
MyConnector/
├── pack_metadata.json
├── Integrations/
│   └── MyConnector/
│       ├── MyConnector.yml      # integration definition (commands, args, outputs)
│       └── MyConnector.py       # Python script wrapping GNAT client methods
└── ReleaseNotes/
    └── 1_0_0.md
```

**Generator logic** (in `gnat/codegen/xsoar_generator.py`):
1. Introspect connector class via `capabilities()` (see item #19)
2. Map GNAT method signatures → XSOAR command definitions in YAML
3. Render `MyConnector.py` that imports the GNAT client and delegates
4. Render `pack_metadata.json` from connector metadata
5. Zip the output

**CLI:** `gnat codegen xsoar --connector threatq --output ./packs/`

**Depends on:** #19 (capability reflection provides introspection input)

---

### 22. Docker Containerization

**Priority:** MEDIUM-LOW

**What:** Package GNAT's three operational services as Docker containers
with a `docker-compose.yml` for single-host deployment. No change to
application code — pure infrastructure.

**Files to create:**
```
docker/
├── scheduler/Dockerfile     # gnat-scheduler service
├── edl/Dockerfile           # gnat-edl server
├── monitor/Dockerfile       # gnat-monitor health endpoint
docker-compose.yml            # orchestrates all three + named volumes
.env.example                  # GNAT_CONFIG path, port bindings
.dockerignore
```

**Service design:**
```yaml
services:
  scheduler:
    build: docker/scheduler
    volumes:
      - ./config:/etc/gnat:ro
      - workspace:/var/gnat/workspace
    restart: unless-stopped

  edl:
    build: docker/edl
    ports: ["8080:8080"]
    volumes:
      - workspace:/var/gnat/workspace:ro
    restart: unless-stopped
    depends_on: [scheduler]

  monitor:
    build: docker/monitor
    ports: ["8090:8090"]
    volumes:
      - workspace:/var/gnat/workspace:ro
    restart: unless-stopped

volumes:
  workspace:
```

**Dev container:** `.devcontainer/devcontainer.json` for VS Code / Codespaces,
includes Rust toolchain (for `make build-rust`).

**Makefile targets added:** `make docker-build`, `make docker-up`,
`make docker-down`, `make docker-logs`.

---

### 23a. Terminal UI (Textual) — Workstation / SSH Analyst Tool

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

### 25. Upstream Contribution Pipeline (3b)

**Priority:** LOW — opt-in only

**What:** Opt-in workflow that packages a new/updated GNAT connector as a
GitHub pull request against the upstream `wrhalpin/GNAT` repository.

**CLI:**
```bash
gnat contribute --connector myplatform --message "Add MyPlatform connector"
# → validates connector structure (item #15 compliance matrix)
# → runs unit tests
# → creates a branch, commits, pushes to configured fork
# → opens a draft PR via GitHub API (opt-in, requires PAT config)
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
- `draft_pr = true` is not overridable via CLI (only draft PRs created)
- Runs full test suite before creating branch; aborts on failure
- Never pushes directly to `main` or `master`
- Connector must pass the #15 compliance matrix before PR is allowed

# GNAT Implementation and Architecture Plan

**GNAT** — Universal Cyber Threat Management Library 
Version 1.0.0 | Architecture as of March 2026

---

## Overview

GNAT is a universal Python client and STIX 2.1 ORM library providing a
single abstracted interface across multiple security platforms. It solves the
platform proliferation problem: security teams typically maintain point-to-point
integrations between every combination of tools, each with its own auth model,
data format, and API quirks. GNAT replaces that web of bespoke integrations
with one library, one configuration file, and one operational model.

---

## Architecture

### Layer model

```
┌─────────────────────────────────────────────────────────────────┐
│  Application Layer                                               │
│  (analysts, scheduled jobs, report generation, export pipelines) │
├─────────────────────────────────────────────────────────────────┤
│  Orchestration Layer                                             │
│  FeedScheduler · FeedJob · ExportJob · ReportJob · CurationJob  │
├──────────────────────────────────┬──────────────────────────────┤
│  Intelligence Layer              │  AI Agent Layer               │
│  ResearchLibrary · Workspace     │  ResearchAgent · ParsingAgent │
│  GlobalContextRegistry           │  CopilotReader                │
├──────────────────────────────────┴──────────────────────────────┤
│  Pipeline Layer                                                  │
│  IngestPipeline · ExportPipeline · ReportGenerator               │
│  SourceReaders · RecordMappers · ExportFilters · Transforms      │
├─────────────────────────────────────────────────────────────────┤
│  Abstraction Layer (the middle layer)                            │
│  STIX 2.1 ORM · ConnectorMixin · BaseClient                      │
├─────────────────────────────────────────────────────────────────┤
│  Connector Layer                                                 │
│  ThreatQ · CrowdStrike · Splunk · Netskope · XSOAR ·             │
│  RecordedFuture · VirusTotal · ShadowServer · Rapid7 · Nucleus · │
│  GreyMatter · Whistic · RiskRecon · Feedly · Proofpoint          │
└─────────────────────────────────────────────────────────────────┘
```

### The abstraction layer is the value

Every connector implements the same five-method interface:
`authenticate()`, `get_object()`, `list_objects()`, `upsert_object()`,
`delete_object()` — plus `to_stix()` and `from_stix()` for data translation.
Code written against this interface works with any connector. A pipeline
that ingests from ThreatQ works identically against CrowdStrike or VirusTotal
by changing one string in the config file.

---

## Package Structure

```
gnat/
├── orm/                    STIX 2.1 ORM (Indicator, ThreatActor, Vulnerability, ...)
├── clients/                BaseClient (urllib3), CLIENT_REGISTRY
├── connectors/             95 platform connectors
├── ingest/                 SourceReaders (14), RecordMappers (12), IngestPipeline
├── export/                 ExportFilters, Transforms (EDL, Netskope), Delivery, ExportJob
├── schedule/               FeedJob, FeedScheduler, APScheduler/Celery adapters
├── context/                Workspace, WorkspaceManager, GlobalContextRegistry, stores
│   └── tenant.py           Multi-tenant workspace isolation (TenantRegistry)
├── search/                 Solr search sidecar (GNATIndexer, SearchMixin, ORM/pipeline integration)
├── agents/                 ResearchAgent, ParsingAgent, CopilotReader, ClaudeClient
│   └── health_monitor.py   ConnectorHealthJob — periodic health + API schema drift detection
├── research/               ResearchLibrary, ResearchEntry, CurationJob
├── reports/                ReportGenerator, ReportJob, 4 renderers, 2 delivery targets
├── viz/                    TabularView, GraphView (3 layout algorithms), GrafanaServer, sigma.js
├── nlp/                    NLPQueryEngine, QuerySpec, builtin + Claude backends
├── tui/                    GNATApp (Textual 8.x), 4 screens, STIXTable/JobTable widgets
├── serve/                  Web dashboard (FastAPI, X-Api-Key auth, rate limiting)
│   └── taxii/              TAXII 2.1 server (workspaces as collections)
├── stix/                   STIX pattern validator (validate_pattern, PatternValidationError)
├── async_client/           AsyncBaseClient, AsyncGNATClient (httpx)
└── codegen/                OpenAPI connector scaffold + XSOAR content pack generator
    └── contribute.py       ContributionPipeline (7-step gate + draft PR)
```

---

## Connector Map

| Platform            | Module            | Auth          | Read | Write | Status  |
|---------------------|-------------------|---------------|------|-------|---------|
| ThreatQ             | threatq           | OAuth2        | ✓    | ✓     | Stable  |
| CrowdStrike         | crowdstrike       | OAuth2        | ✓    | ✓     | Stable  |
| Splunk              | splunk            | Token/Basic   | ✓    | ✓     | Stable  |
| Netskope            | netskope          | API key       | ✓    | ✓     | Stable  |
| XSOAR               | xsoar             | API key       | ✓    | ✓     | Stable  |
| Recorded Future     | recordedfuture    | API token     | ✓    | —     | Stable  |
| GreyMatter          | greymatter        | OAuth2        | ✓    | ✓     | Stable  |
| Whistic             | whistic           | API key       | ✓    | —     | Stable  |
| RiskRecon           | riskrecon         | OAuth2        | ✓    | —     | Stable  |
| Feedly              | feedly            | Bearer/API key| ✓    | —     | Stable  |
| Proofpoint TAP      | proofpoint        | Basic auth    | ✓    | —     | Stable  |
| VirusTotal          | virustotal        | API key       | ✓    | —     | Stable  |
| ShadowServer        | shadowserver      | HMAC          | ✓    | —     | Stable  |
| Rapid7              | rapid7            | API key       | ✓    | Partial| Stable |
| Nucleus             | nucleus           | API key       | ✓    | ✓     | Stable  |
| ControlUp DEX       | controlup         | Bearer        | ✓    | —     | Stable  |
| AlienVault OTX      | alienvault        | API key       | ✓    | —     | Stable  |
| Elastic SIEM        | elastic           | API key/Basic | ✓    | ✓     | Stable  |
| Graylog             | graylog           | Basic auth    | ✓    | —     | Stable  |
| MISP                | misp              | API key       | ✓    | ✓     | Stable  |
| OpenCTI             | opencti           | API key       | ✓    | ✓     | Stable  |
| OSSIM               | ossim             | API key       | ✓    | —     | Stable  |
| IBM QRadar          | qradar            | API token     | ✓    | —     | Stable  |
| Security Onion      | security_onion    | Bearer        | ✓    | —     | Stable  |
| MS Sentinel         | sentinel          | OAuth2/AAD    | ✓    | ✓     | Stable  |
| Snort IDS           | snort             | File/Syslog   | ✓    | —     | Stable  |
| Suricata            | suricata          | File/EVE JSON | ✓    | —     | Stable  |
| Wazuh               | wazuh             | API key/Basic | ✓    | —     | Stable  |
| Zeek                | zeek              | File/TSV-JSON | ✓    | —     | Stable  |
| ServiceNow          | servicenow        | Basic/Bearer  | ✓    | ✓     | Stable  |
| Jira                | jira              | Basic/Bearer  | ✓    | ✓     | Stable  |
| ThreatConnect       | threatconnect     | API key       | ✓    | ✓     | Stable  |
| Mandiant            | mandiant          | API key       | ✓    | —     | Stable  |
| Defender TI         | defenderti        | OAuth2/AAD    | ✓    | —     | Stable  |
| TheHive             | thehive           | API key       | ✓    | ✓     | Stable  |
| ThreatStream        | threatstream      | API key       | ✓    | ✓     | Stable  |
| SOCRadar            | socradar          | API key       | ✓    | —     | Stable  |
| Pulsedive           | pulsedive         | API key       | ✓    | —     | Stable  |
| Flare               | flare             | API key       | ✓    | —     | Stable  |
| Stellar Cyber       | stellarcyber      | API key       | ✓    | —     | Stable  |
| YETI                | yeti              | API key       | ✓    | ✓     | Stable  |
| CloudSEK            | cloudsek          | API key       | ✓    | —     | Stable  |
| Grok AI             | grok              | API key       | ✓    | —     | LLM     |
| Google Gemini       | gemini            | API key       | ✓    | —     | LLM     |
| MS Copilot Security | copilot           | DirectLine    | ✓    | —     | LLM     |
| OpenAI ChatGPT      | chatgpt           | API key       | ✓    | —     | LLM     |
| Cyble Vision        | cyble_vision      | API key       | ✓    | —     | Stable  |
| Armis               | armis             | Secret key    | ✓    | —     | Stable  |
| Axonius             | axonius           | API key+Secret| ✓    | —     | Stable  |
| Cortex Xpanse       | cortex_xpanse     | API key       | ✓    | —     | Stable  |
| CyCognito           | cycognito         | Bearer        | ✓    | —     | Stable  |
| DefectDojo          | defectdojo        | API token     | ✓    | ✓     | Stable  |
| Greenbone/OpenVAS   | greenbone         | GMP user/pass | ✓    | —     | Stable  |
| Group-IB            | group_ib          | API token     | ✓    | —     | Stable  |
| Orca Security       | orca              | Bearer        | ✓    | —     | Stable  |
| Qualys VMDR         | qualys            | Basic auth    | ✓    | —     | Stable  |
| SentinelOne         | sentinelone       | API token     | ✓    | —     | Stable  |
| Tenable One         | tenable_one       | X-ApiKeys     | ✓    | —     | Stable  |
| Wiz CNAPP           | wiz               | OAuth2        | ✓    | —     | Stable  |
| ZeroFox             | zerofox           | Bearer        | ✓    | —     | Stable  |

*Status legend:* **Stable** = full ConnectorMixin interface implemented and tested.
**LLM** = LLM assistant connector; wraps an AI API rather than a security platform; read-only, no STIX write-back.

---

## Deployment Architecture

### Recommended: Single Azure B2ms VM, three systemd services

**Why single VM:**
All workloads are I/O-bound (network calls to APIs, file writes). CPU
is idle 95%+ of the time. A B2ms (2 vCPU, 8GB RAM) handles 30+ scheduled
feeds, export pipelines, and daily reports without contention.

**Three services:**

```
Service 1: gnat-scheduler.service
  — FeedScheduler running all ingest, export, curation, and report jobs
  — Restarts automatically on failure (missed one run = acceptable)

Service 2: gnat-edl.service
  — EDLServer on port 8080 (or behind nginx)
  — Reads pre-written files; completely independent of scheduler
  — Firewalls poll this; uptime matters more than scheduler uptime

Service 3: gnat-monitor.service (optional)
  — Lightweight HTTP endpoint returning scheduler.summary() as JSON
  — Azure Monitor or simple ping check hooks into this
```

**Why separate the EDL server:**
If the scheduler crashes and restarts (e.g. after a failed API call),
the EDL server continues serving the last-written files. Firewalls never
see a gap. Keeping them as separate services provides the only fault
isolation that actually matters.

### Azure specifics

- **VM size:** B2ms or B4ms — burstable, accumulates CPU credits while idle
- **Storage:** Premium SSD P6 (64GB) for OS + workspace store + report output
- **Networking:** Private endpoint preferred — firewalls reach EDL server via
  Azure VNet private IP, eliminating public IP costs and outbound transfer costs
- **Cost estimate:** B2ms (~$70/mo) + P6 disk (~$10/mo) + private IP = ~$80/mo
- **Scaling path:** If AI agent workloads grow, offload research jobs to
  Azure Container Instances (per-job cost) rather than upsizing the VM

### systemd service template

```ini
# /etc/systemd/system/gnat-scheduler.service
[Unit]
Description=GNAT Feed Scheduler
After=network.target

[Service]
Type=simple
User=ctmsak
WorkingDirectory=/opt/gnat
ExecStart=/opt/gnat/venv/bin/python -m gnat.scheduler_main
Restart=on-failure
RestartSec=30
Environment=GNAT_CONFIG=/etc/gnat/config.ini

[Install]
WantedBy=multi-user.target
```

---

## Data Flow

### Ingest flow

```
External Source (ThreatQ, RF, Feedly, TAXII, CSV, ...)
  ↓  SourceReader._iter_records()
  ↓  RawRecord (dict)
  ↓  RecordMapper.map()
  ↓  STIXBase objects
  ↓  DeduplicationCache (optional)
  ↓  Workspace.add() or GNATClient.upsert_object()
  ↓  IngestResult (total_records, written_objects, errors)
```

### Export flow

```
Workspace or GNATClient
  ↓  ExportFilter.apply() (type, confidence, TLP, sector, ...)
  ↓  ExportTransform.transform() (EDL text, Netskope CE JSON, STIX bundle, CSV)
  ↓  ExportDelivery.deliver() (file, HTTP, EDL server, platform, email, SP)
  ↓  DeliveryResult
```

### AI research flow

```
Topic / Monitored URL list
  ↓  ResearchAgent._iter_records() [Claude + web search]
  ↓  RawRecord {text, url, topic, metadata}
  ↓  ParsingAgent.map() [Claude structured extraction]
  ↓  STIXBase objects (confidence ≤ 60, x_source_type=ai_extracted)
  ↓  Workspace → analyst review
  ↓  ResearchLibrary.promote() → staging
  ↓  CurationJob → library
```

### Report generation flow

```
Workspace / Library
  ↓  DataAggregator.run() — pure data, no AI
  ↓  ReportAggregates (counts, distributions, top-N lists)
  ↓  ReportSynthesizer.synthesize() — one Claude call per section
  ↓  ReportDocument (ordered sections: data + narrative)
  ↓  Renderer (Markdown → HTML → PDF → DOCX)
  ↓  Delivery (email SMTP, SharePoint Graph API)
```

---

## Key Design Decisions

### 1. urllib3 foundation, no requests

`BaseClient` uses urllib3 directly. No third-party HTTP library dependency
beyond urllib3 (already a transitive dep of most Python environments).
Connection pooling, retry/backoff, and SSL verification all handled at
the BaseClient level — connectors inherit this transparently.

### 2. STIX as lingua franca

All cross-platform data passes through STIX 2.1 objects. `to_stix()` converts
native platform data to STIX; `from_stix()` converts back. This means a
workflow like "pull from CrowdStrike, enrich with Recorded Future, push to
ThreatQ" requires no platform-specific logic in the pipeline — just
connector configuration.

### 3. INI configuration, no code for deployment changes

Every parameter that varies between deployments (hosts, credentials, TTLs,
sectors, report schedules) lives in `config.ini`. Operators can reconfigure
the system without touching Python code. Connector targets can be swapped
by editing one line.

### 4. FeedJob / FeedScheduler threading model

One daemon thread per job. Threads sleep in 1-second increments (not one
long sleep) so `stop()` responds within ~1 second. Drift-corrected timing
keeps hourly jobs at hourly intervals even when runs take variable time.
`overlap_policy="skip"` (default) prevents queue buildup on slow sources.

### 5. AI confidence ceiling

All AI-extracted objects carry `confidence ≤ ai_confidence_ceiling` (default 60)
and `x_source_type="ai_extracted"`. This means:
- `ConfidenceFilter(min_confidence=70)` in export pipelines excludes AI intel
  by default — analyst review required before it reaches EDLs
- The tag lets analysts find and verify AI-extracted objects
- Never raise the ceiling to 100 without a review process in place

### 6. Research library three-tier model

Personal workspaces → staging → curated library. Analysts never write
directly to the library. The `CurationJob` is the only thing that promotes
staging entries to the library, providing a consistent curation gate.
Deduplication keeps the library pruned to one authoritative entry per topic
(most recent wins). TTLs per category ensure stale research is clearly flagged.

### 7. Report generation two-pass model

Aggregation (pure data, no AI) runs first. AI synthesis receives compact
structured aggregates, not raw STIX blobs. This keeps prompts small and
focused, makes individual section failures recoverable, and ensures reports
can be generated with `ai_mode=NONE` without any API dependency.

---

## Sector / Industry Normalization (PENDING)

The canonical field for sector data across all GNAT objects is
`x_target_sectors` — a list of strings on any STIX object.

**Status:** Placeholder in ThreatQ connector. Connector needs updating
once ThreatQ field names are verified (see `PENDING_ITEMS.md`).

**Architecture:**

```
ThreatQ API response
  ↓  ThreatQClient.to_stix()
  ↓  x_target_sectors = [normalize(v) for v in tq_industries + tq_sectors]

[sector_aliases] in config.ini
  "healthcare = Healthcare, Health, Medical, H-ISAC, ..."
  ↓  SectorFilter._matches_sector()
  ↓  Alias-expanded matching across all platforms
```

---

## Testing

Test suite: 784 unit tests across 25 test files.

```bash
# Run all tests
pytest tests/

# Run by module
pytest tests/unit/connectors/
pytest tests/unit/ingest/
pytest tests/unit/export/
pytest tests/unit/schedule/
pytest tests/unit/agents/
pytest tests/unit/research/
pytest tests/unit/reports/

# Run with coverage
pytest --cov=gnat tests/
```

All tests use `unittest.mock` — no live API calls, no network required.
New connectors follow the pattern in `tests/unit/connectors/test_connectors.py`.

---

## Dependencies

### Core (no extras required)

- Python 3.9+
- `urllib3` — HTTP client foundation
- Standard library only for: STIX ORM, INI config, schedule, HMAC signing,
  JSON handling, email delivery

### Optional extras

```bash
pip install "gnat[async]"      # httpx — AsyncGNATClient
pip install "gnat[taxii]"      # taxii2-client — TAXIICollectionReader
pip install "gnat[ingest]"     # taxii2-client + feedparser — full ingest pipeline
pip install "gnat[persist]"    # sqlalchemy — WorkspaceStore (SQLite/PostgreSQL)
pip install "gnat[viz]"        # plotly, networkx, openpyxl — GraphView, TabularView
pip install "gnat[schedule]"   # croniter — cron expression scheduling
pip install "gnat[reports]"    # reportlab + python-docx — PDF and DOCX rendering
pip install "gnat[serve]"      # fastapi, uvicorn — Web dashboard + TAXII server
pip install "gnat[tui]"        # textual — Terminal UI
pip install "gnat[nlp]"        # NLP query interface (builtin backend; zero extra deps)
pip install "gnat[all]"        # All of the above
pip install "gnat[dev]"        # All + dev tools (ruff, mypy, pytest, bandit)
```

### Full install

```bash
pip install "gnat[all]"
```

---

## Roadmap

### Completed ✅

All near-term and medium-term roadmap items have shipped:

| Item | Status |
|------|--------|
| ThreatQ / RF / CrowdStrike sector normalization | ✅ Done |
| `SectorFilter` moved to `gnat/export/filters.py` | ✅ Done |
| `gnat report run` CLI subcommand | ✅ Done |
| Web UI — research library, scheduler, report viewer | ✅ Done (#23b) |
| Terminal UI — 4 screens, NLP query bar | ✅ Done (#23a) |
| Connector health + drift monitoring agent | ✅ Done (#24) |
| Upstream contribution pipeline | ✅ Done (#25) |
| DOCX rendering (python-docx, no Node.js) | ✅ Done |
| Docker containerization (`docker/`, `docker-compose.yml`) | ✅ Done (#22) |
| XSOAR content pack generator | ✅ Done (#21) |
| NLP query interface | ✅ Done (#18) |
| Client capability reflection | ✅ Done (#19) |
| TAXII 2.1 server (`gnat/serve/taxii/`) | ✅ Done |
| STIX pattern validator (`gnat/stix/`) | ✅ Done |
| Docker-based integration test harness | ✅ Done |
| Solr/Grafana observability (`gnat/viz/grafana/`) | ✅ Done |
| Multi-tenant workspace isolation (`gnat/context/tenant.py`) | ✅ Done |
| Rust native extension (`rust_core/`, `gnat[fast]`) | ✅ Done |

### In progress / Near term
- All near-term items have shipped. See completed list above.

### Medium term
- STIX 2.1 full object-level validation against official spec
- Analyst workflow UI — structured review/approval queue before promoting
  AI-extracted intel to production workspaces

### Long term
- Federated multi-GNAT deployments with cross-instance workspace sync

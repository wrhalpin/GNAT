# CLAUDE.md — GNAT AI Assistant Guide

This file provides context for AI assistants (Claude Code and similar) working in this repository.

---

## Project Overview

**GNAT** (CTM Toolkit) is a production-ready Python library providing:
- A unified client interface for 158 security/threat intelligence platforms
- A STIX 2.1-compatible ORM for threat intelligence objects
- Ingestion, export, scheduling, visualization, and reporting pipelines
- AI agent integration (Claude, OpenAI, Grok via unified LLMClient)
- A fully featured CLI and TUI

**Package name on PyPI:** `gnat`
**Import root:** `gnat`
**Version:** 1.5.0
**Python support:** 3.9, 3.10, 3.11, 3.12, 3.13
**License:** Apache-2.0

---

## Repository Layout

```
gnat/                        # Main Python package
├── __init__.py              # Public API surface (GNATClient, ORM types, connectors)
├── client.py                # GNATClient — top-level facade
├── config.py                # INI-based configuration management
├── orm/                     # STIX 2.1 ORM (STIXBase + 8 object types)
├── stix/                    # STIX pattern validation (stix2-patterns integration)
├── clients/                 # HTTP client layer (urllib3 BaseClient + CLIENT_REGISTRY)
├── connectors/              # 158 platform connectors (ThreatQ, CrowdStrike, Splunk, etc.)
├── ingest/                  # Multi-source ingestion pipeline (14 readers, 12 mappers)
│   └── telemetry/           # High-volume sensor ingestion (Kafka reader, Redis dedup, campaign auto-link)
├── export/                  # Export pipeline (EDL, Netskope CE delivery targets)
├── cli/                     # CLI entry point (gnat/cli/main.py)
├── tui/                     # Terminal UI (Textual-based interactive interface)
├── schedule/                # Feed scheduling (FeedJob, FeedScheduler, croniter)
├── reports/                 # Report generation (PDF + DOCX via ReportLab/python-docx, AI-assisted)
├── research/                # Research library (ResearchLibrary, CurationJob)
├── agents/                  # AI agent integration (LLMClient: Claude, OpenAI, Grok)
├── nlp/                     # NLP/IOC extraction (builtin + Claude backend)
├── context/                 # Global context + workspace persistence
├── viz/                     # Visualization (Tabular, Graph, Grafana, Power BI)
├── codegen/                 # OpenAPI → connector scaffolding
├── async_client/            # Async variant (httpx)
├── analysis/attribution/    # Campaign tracking, Diamond Model, kill-chain, infrastructure classification, attribution hypotheses
├── plugins/huntgnat/        # STIX → detection rule translation (Sigma, YARA, Suricata, Snort), hunt packages, ATT&CK coverage, validation
├── serve/                   # FastAPI HTTP server + TAXII endpoint
├── search/                  # Solr full-text search sidecar (SearchMixin, indexer, ORM integration)
└── utils/                   # Misc helpers (stix_helpers.py)

tests/
├── conftest.py              # Shared fixtures (mock HTTP, test config)
├── unit/                    # Unit tests mirroring gnat/ layout
└── integration/             # Live API tests (opt-in)

docs/                        # Documentation (explanation, how-to, reference, tutorials; Sphinx HTML → docs/sphinx-html/)
config/config.ini.example    # Configuration template
Makefile                     # Dev targets (test, lint, build, docs, docker, rust)
pyproject.toml               # Build config, deps, tool configs
rust_core/                   # Optional Rust extension (gnat._core accelerator)
docker-compose.yml           # Docker services (core, search sidecar, Grafana)
```

---

## Development Workflow

### Setup

```bash
python -m venv .venv && source .venv/bin/activate
make install        # pip install -e ".[dev]" + httpx
```

### Common Make Targets

| Target | Command | Description |
|--------|---------|-------------|
| `make test` | `pytest tests/unit/ -v` | Run unit tests |
| `make coverage` | pytest + coverage | HTML report at `htmlcov/` |
| `make integration` | pytest with `--run-integration` | Requires `GNAT_CONFIG` env var |
| `make lint` | ruff check + format check | Lint the codebase |
| `make fmt` | ruff format | Auto-format code |
| `make typecheck` | mypy | Type-check public APIs |
| `make check` | lint + typecheck | Full static analysis |
| `make docs` | sphinx-build | Build HTML docs (output: `docs/sphinx-html/`) |
| `make build` | setuptools | Build sdist + wheel |
| `make clean` | | Remove all build artifacts |
| `make build-rust` | maturin build --release | Build + install Rust native extension |
| `make build-rust-dev` | maturin develop | Build Rust extension in dev mode |
| `make docker-build` | docker compose build | Build all Docker service images |
| `make docker-up` | docker compose up -d | Start core services (detached) |
| `make docker-search` | docker compose --profile search | Start core + Solr search sidecar |
| `make docker-full` | docker compose --profile full | Start all services including Grafana |
| `make docker-down` | docker compose down | Stop all services |
| `make test-docker` | docker integration suite | Run Docker integration tests |

### Running Tests

```bash
pytest tests/unit/ -v --tb=short          # All unit tests
pytest tests/unit/connectors/ -v          # Connector tests only
pytest tests/integration/ --run-integration -v  # Integration (needs live creds)
pytest tests/integration/ --run-docker -v       # Docker-based integration tests
```

**Minimum coverage requirement:** 70% (enforced by `fail_under = 70` in pyproject.toml)

**Test markers:**
- `@pytest.mark.integration` — requires live credentials, opt-in with `--run-integration`
- `@pytest.mark.docker` — requires Docker daemon, opt-in with `--run-docker`
- `@pytest.mark.slow` — tests taking >5s, can be excluded

### Configuration

GNAT uses INI-based configuration. Search order:
1. `GNAT_CONFIG` environment variable (path to file)
2. `~/.gnat/config.ini`
3. `./gnat.ini`

Copy `config/config.ini.example` to get started. Each platform gets its own section:

```ini
[threatq]
host = https://threatq.example.com
client_id = ...
client_secret = ...
auth_type = oauth2
```

---

## Code Conventions

### Style & Linting

- **Formatter/linter:** Ruff (configured in `pyproject.toml` under `[tool.ruff]`)
- **Type checking:** mypy at Python 3.9 target
- **Docstrings:** NumPy-style on all public classes and methods
- **Imports:** Ruff `I` rule (isort-compatible); stdlib → third-party → local

Always run `make fmt && make lint` before committing.

### Error Handling

- Raise `GNATClientError` (from `gnat.clients.base`) for HTTP-level failures — includes `status` and `body`.
- Never use bare `except Exception` — log or re-raise with context.
- Use the connector's custom exception subclass when a platform-specific error is meaningful.

### Adding a New Connector

1. Create `gnat/connectors/<platform>/` package.
2. Subclass `ConnectorMixin` from `gnat/connectors/base_connector.py`.
3. Implement the required methods:
   - `authenticate()` — set up auth headers/tokens
   - `health_check()` — lightweight ping
   - `to_stix(obj)` / `from_stix(stix_obj)` — bidirectional STIX conversion
   - `get_object()`, `list_objects()`, `upsert_object()`, `delete_object()`
4. Register it in `gnat/clients/__init__.py` (`CLIENT_REGISTRY`).
5. Add tests in `tests/unit/connectors/test_connectors.py`.
6. Document credentials in `config/config.ini.example`.

Alternatively, use the code generator:

```bash
gnat codegen openapi --spec path/to/openapi.yaml --target myplatform
```

### Adding an Ingest Reader or Mapper

- **Reader:** Subclass `SourceReader` from `gnat/ingest/base.py`; implement `read() -> Iterator[dict]`.
- **Mapper:** Subclass `RecordMapper` from `gnat/ingest/base.py`; implement `map(record: dict) -> STIXBase`.
- Register in `gnat/ingest/sources/__init__.py` or `gnat/ingest/mappers/__init__.py`.
- Add tests in `tests/unit/ingest/test_ingest.py`.

### ORM Patterns

All ORM objects inherit from `STIXBase` (`gnat/orm/base.py`):
- Core STIX fields are explicit attributes; extras go into `_properties` dict.
- `__getattr__`/`__setattr__` provide transparent access to `_properties`.
- Use `to_dict()` / `from_dict()` for serialization; `to_stix_bundle()` for STIX bundles.
- ORM objects are not bound to a database — persistence is handled by the context/workspace layer.

---

## Key Architecture Decisions

See `docs/explanation/architecture/adrs/` for the full rationale (individual ADR files). Key choices:

| Decision | Choice | Reason |
|----------|--------|--------|
| HTTP client | `urllib3` (sync), `httpx` (async) | Fine-grained control, minimal overhead |
| ORM | Pure Python (not SQLAlchemy/Pydantic) | Avoid unnecessary coupling |
| Data model | STIX 2.1 property bag | Flexible schema for threat intel |
| Config | INI (configparser) | Zero dependencies, simple |
| Packaging | Extras groups | Pay-for-what-you-use dependency model |
| CLI | argparse subcommands | No framework dependency |
| Performance | Optional Rust extension (`gnat._core`) | Accelerates IOC classify/defang/refang/extract; install via `gnat-core` wheel |

---

## Testing Conventions

**Fixtures (tests/conftest.py):**
- `mock_http_response()` — Factory for fake `urllib3.HTTPResponse` objects (no real HTTP)
- `mock_pool_manager()` — Patches `urllib3.PoolManager` at the process level
- `minimal_config()` — Writes a temporary INI config file; returns its path
- `sak_client()` — Returns a `GNATClient` pre-loaded from the test config

**Integration tests** are gated by `@pytest.mark.integration` and the `--run-integration` flag. They require real credentials in `GNAT_CONFIG`.

**Slow tests** use `@pytest.mark.slow` for optional exclusion.

Prefer mocking at the HTTP layer (`mock_pool_manager`) rather than patching individual connector methods, so tests exercise the full request/response cycle.

---

## Git & Branch Conventions

- **`main`** — stable, releasable branch
- **Feature branches** — `claude/<description>-<id>` for AI-authored work, `feature/<name>` for human-authored
- Commit messages: imperative mood, concise summary line, optional body
- Semantic versioning: `MAJOR.MINOR.PATCH` tracked in `pyproject.toml` and `CHANGELOG.md`
- Keep `CHANGELOG.md` updated: add entries under `[Unreleased]` for every meaningful change

---

## Supported Platforms (Connectors)

| Platform | Module | Auth |
|----------|--------|------|
| AlienVault OTX | `gnat/connectors/alienvault/` | API key |
| Armis Centrix (IT/OT/IoT) | `gnat/connectors/armis/` | API secret key |
| AWS Security Hub / GuardDuty | `gnat/connectors/aws_security/` | AWS SigV4 (access key + secret) |
| Axonius | `gnat/connectors/axonius/` | API key + secret |
| BitSight Security Ratings | `gnat/connectors/bitsight/` | API token |
| VMware Carbon Black Cloud | `gnat/connectors/carbon_black/` | API key + connector ID |
| Censys Internet Intelligence / ASM | `gnat/connectors/censys/` | API ID + secret |
| OpenAI ChatGPT | `gnat/connectors/chatgpt/` | API key |
| CISA KEV Catalog | `gnat/connectors/cisa/` | None (public) |
| Cisco Umbrella (Investigate / Enforcement / Management) | `gnat/connectors/cisco_umbrella/` | Multiple API keys (Investigate, Enforcement, Management) |
| Claroty Platform (OT/IoT) | `gnat/connectors/claroty/` | Username/password |
| CloudSEK Digital Risk Protection | `gnat/connectors/cloudsek/` | Bearer |
| Microsoft Copilot for Security | `gnat/connectors/copilot/` | DirectLine / Bearer |
| Palo Alto Cortex XDR / XSIAM | `gnat/connectors/cortex_xdr/` | API key pair (HMAC-signed) |
| Cortex Xpanse (External ASM) | `gnat/connectors/cortex_xpanse/` | API key |
| Cribl Stream | `gnat/connectors/cribl/` | Bearer |
| CrowdStrike Falcon | `gnat/connectors/crowdstrike/` | OAuth2 |
| Cyble Vision | `gnat/connectors/cyble_vision/` | API key |
| CyCognito ASM | `gnat/connectors/cycognito/` | Bearer |
| Darktrace Enterprise Immune System | `gnat/connectors/darktrace/` | HMAC public/private key |
| Datadog Cloud SIEM | `gnat/connectors/datadog/` | API key + App key |
| DefectDojo Vulnerability Management | `gnat/connectors/defectdojo/` | API token |
| Microsoft Defender Threat Intelligence | `gnat/connectors/defenderti/` | OAuth2 (Azure AD) |
| Discord | `gnat/connectors/discord/` | Bot token |
| Dragos Platform (OT/ICS) | `gnat/connectors/dragos/` | Basic (API key + secret) |
| Elastic SIEM | `gnat/connectors/elastic/` | API key/Basic |
| ExtraHop Reveal(x) NDR | `gnat/connectors/extrahop/` | API key / OAuth2 |
| Feedly Threat Intelligence | `gnat/connectors/feedly/` | OAuth2/API key |
| Flare (Darknet/Threat Exposure) | `gnat/connectors/flare/` | Bearer |
| Flashpoint Underground / Dark Web CTI | `gnat/connectors/flashpoint/` | Bearer |
| Fortinet FortiEDR | `gnat/connectors/fortiedr/` | Username/password |
| Fortinet FortiSIEM | `gnat/connectors/fortisiem/` | Username/password |
| Fortinet FortiSOAR | `gnat/connectors/fortisoar/` | JWT / Basic |
| Google Gemini | `gnat/connectors/gemini/` | API key |
| Google Chronicle (SecOps SIEM) | `gnat/connectors/google_chronicle/` | Service account / API key |
| Graylog | `gnat/connectors/graylog/` | API key/Basic |
| Greenbone / OpenVAS | `gnat/connectors/greenbone/` | GMP username/password |
| GreyMatter | `gnat/connectors/greymatter/` | API key |
| GreyNoise | `gnat/connectors/greynoise/` | API key |
| Grok AI | `gnat/connectors/grok/` | API key |
| Group-IB Threat Intelligence | `gnat/connectors/group_ib/` | API key |
| Have I Been Pwned (HIBP) | `gnat/connectors/hibp/` | API key |
| Hudson Rock Breach Intelligence | `gnat/connectors/hudsonrock/` | API key |
| Intel 471 Cybercrime Intelligence | `gnat/connectors/intel471/` | Bearer |
| Atlassian Jira | `gnat/connectors/jira/` | Basic / Bearer |
| JupiterOne (CAASM / Cyber Asset Graph) | `gnat/connectors/jupiterone/` | Bearer (API key) |
| Lansweeper IT Asset Management | `gnat/connectors/lansweeper/` | OAuth2 / Bearer |
| LogRhythm NextGen SIEM | `gnat/connectors/logrhythm/` | Bearer / OAuth2 |
| Mandiant Advantage | `gnat/connectors/mandiant/` | OAuth2 |
| MISP Threat Sharing Platform | `gnat/connectors/misp/` | API key |
| Netskope SASE / SSE | `gnat/connectors/netskope/` | API token |
| Nozomi Networks Guardian / Vantage (OT/IoT) | `gnat/connectors/nozomi/` | API token / Basic |
| Nucleus Security | `gnat/connectors/nucleus/` | API key |
| OpenCTI | `gnat/connectors/opencti/` | API key |
| Generic OSINT Feed (TAXII / STIX-JSON) | `gnat/connectors/osint_feed/` | None / Basic / API key / Bearer / OAuth2 |
| Orca Security (Agentless CNAPP) | `gnat/connectors/orca/` | Bearer |
| OSSIM | `gnat/connectors/ossim/` | Basic auth |
| Palo Alto Prisma Cloud (CSPM/CNAPP) | `gnat/connectors/prisma_cloud/` | Access key + secret (JWT) |
| Proofpoint TAP | `gnat/connectors/proofpoint/` | Basic auth |
| PulseDive | `gnat/connectors/pulsedive/` | API key |
| IBM QRadar | `gnat/connectors/qradar/` | API token |
| Qualys VMDR | `gnat/connectors/qualys/` | Basic |
| Rapid7 InsightVM/IDR | `gnat/connectors/rapid7/` | API key |
| Recorded Future | `gnat/connectors/recordedfuture/` | API key |
| RiskRecon | `gnat/connectors/riskrecon/` | OAuth2 |
| Security Onion | `gnat/connectors/security_onion/` | Bearer |
| SecurityScorecard Security Ratings | `gnat/connectors/securityscorecard/` | API token |
| Microsoft Sentinel | `gnat/connectors/sentinel/` | OAuth2 (Azure AD) |
| SentinelOne Singularity XDR | `gnat/connectors/sentinelone/` | API token |
| ServiceNow ITSM / SecOps | `gnat/connectors/servicenow/` | Basic / Bearer |
| ServiceNow SecOps (SIR + VR + TIARA) | `gnat/connectors/servicenow_secops/` | Basic / Bearer |
| Shadowserver Foundation | `gnat/connectors/shadowserver/` | API key |
| Shodan | `gnat/connectors/shodan/` | API key |
| Snort IDS | `gnat/connectors/snort/` | File/Syslog |
| SOCRadar Extended Threat Intelligence | `gnat/connectors/socradar/` | API key |
| Sophos Central | `gnat/connectors/sophos/` | OAuth2 |
| Splunk | `gnat/connectors/splunk/` | Basic/token |
| Stellar Cyber Open XDR | `gnat/connectors/stellarcyber/` | API key |
| Suricata IDS/IPS | `gnat/connectors/suricata/` | File/Syslog |
| Vertex Project Synapse | `gnat/connectors/synapse/` | API key / Bearer |
| Tanium Endpoint Management | `gnat/connectors/tanium/` | API token / session |
| Tenable One Exposure Management | `gnat/connectors/tenable_one/` | X-ApiKeys |
| TheHive Security Incident Response | `gnat/connectors/thehive/` | API key |
| ThreatConnect | `gnat/connectors/threatconnect/` | OAuth2 / API token |
| ThreatQ | `gnat/connectors/threatq/` | OAuth2 |
| Anomali ThreatStream (OPTIC) | `gnat/connectors/threatstream/` | API key + username |
| Trellix XDR / ePolicy Orchestrator | `gnat/connectors/trellix/` | OAuth2 |
| Trend Micro Vision One XDR | `gnat/connectors/trendmicro_visionone/` | Bearer token |
| UpGuard Vendor Risk + CAASM + DRP | `gnat/connectors/upguard/` | API key |
| Vectra AI NDR | `gnat/connectors/vectra/` | API token |
| VirusTotal | `gnat/connectors/virustotal/` | API key |
| Wazuh SIEM/XDR | `gnat/connectors/wazuh/` | API key/Basic |
| Whistic (Vendor Risk) | `gnat/connectors/whistic/` | API key |
| Wiz CNAPP | `gnat/connectors/wiz/` | OAuth2 |
| Palo Alto XSOAR | `gnat/connectors/xsoar/` | API key |
| YETI (Your Everyday Threat Intelligence) | `gnat/connectors/yeti/` | API key |
| Zeek Network Monitor | `gnat/connectors/zeek/` | File/Syslog |
| ZeroFox Digital Risk Protection | `gnat/connectors/zerofox/` | Bearer |
| ControlUp DEX | `gnat/connectors/controlup/` | Bearer token |
| MITRE ATT&CK (TAXII 2.1) | `gnat/connectors/mitre_attack/` | None (public) |
| Abuse.ch (URLhaus/MalwareBazaar/ThreatFox/Feodo/SSLBL) | `gnat/connectors/abusech/` | Optional Auth-Key |
| OSV.dev (open-source vulnerabilities) | `gnat/connectors/osv/` | None (public) |
| VulnCheck (exploit intelligence) | `gnat/connectors/vulncheck/` | Bearer token |
| Cloudflare Threat Intelligence | `gnat/connectors/cloudflare_intel/` | Bearer token + account_id |
| GitGuardian (secret incidents) | `gnat/connectors/gitguardian/` | API key (`Authorization: Token`) |
| runZero (CAASM asset inventory) | `gnat/connectors/runzero/` | Organization Export token (Bearer) |
| SecurityTrails (passive DNS / WHOIS history) | `gnat/connectors/securitytrails/` | API key (`APIKEY` header) |
| DomainTools Iris (WHOIS / hosting history / pivoting) | `gnat/connectors/domaintools/` | API username + API key (query params) |
| Silent Push (future-attack infrastructure) | `gnat/connectors/silent_push/` | API key (`X-API-KEY` header) |
| Silverfort (ITDR runtime identity telemetry) | `gnat/connectors/silverfort/` | OAuth2 client credentials |
| Semperis DSP (AD / Entra posture + IoE/IoC) | `gnat/connectors/semperis/` | Bearer token |
| Abnormal Security (BEC / vendor impersonation) | `gnat/connectors/abnormal/` | Bearer token |
| Cofense Intelligence (human-verified phishing) | `gnat/connectors/cofense_intel/` | HTTP Basic (username + password) |
| TRM Labs (blockchain / crypto intel) | `gnat/connectors/trm_labs/` | API key (Basic auth, empty password) |
| Joe Sandbox Cloud (dynamic malware analysis) | `gnat/connectors/joe_sandbox/` | API key (form field) |
| ANY.RUN (interactive sandbox) | `gnat/connectors/any_run/` | API key (`API-Key` header) |
| Hybrid Analysis / Falcon Sandbox | `gnat/connectors/hybrid_analysis/` | API key + User-Agent header |
| VMRay (hypervisor-level analysis) | `gnat/connectors/vmray/` | API key (`api_key` header) |
| Intezer Analyze (binary DNA attribution) | `gnat/connectors/intezer/` | API key → JWT Bearer |
| Huntress Managed EDR / ITDR | `gnat/connectors/huntress/` | HTTP Basic (key id + secret) |
| Arctic Wolf MDR | `gnat/connectors/arctic_wolf/` | Bearer token (+ optional customer id) |
| Red Canary MDR | `gnat/connectors/red_canary/` | API key (`X-Api-Key` header) |
| SafeBreach (BAS) | `gnat/connectors/safebreach/` | `x-apitoken` + `x-accountid` headers |
| AttackIQ Security Optimization | `gnat/connectors/attackiq/` | Token header |
| Cymulate (BAS) | `gnat/connectors/cymulate/` | `x-token` header |
| Picus Security Validation | `gnat/connectors/picus/` | Refresh token → Bearer |
| Pentera automated validation | `gnat/connectors/pentera/` | Bearer (tenant JWT) |
| XM Cyber Attack Path Management | `gnat/connectors/xm_cyber/` | API key → session Bearer |
| Cisco Talos Intelligence | `gnat/connectors/talos/` | None (public reputation) |
| Fortinet FortiGuard Labs | `gnat/connectors/fortiguard/` | Optional Bearer (IOC service) |
| Kaspersky OpenTIP | `gnat/connectors/kaspersky_opentip/` | Optional `x-api-key` |
| ESET Threat Intelligence | `gnat/connectors/eset_ti/` | Bearer token |
| Bitdefender IntelliZone | `gnat/connectors/bitdefender_iz/` | `X-API-Key` header |
| Okta Identity Cloud | `gnat/connectors/okta/` | `Authorization: SSWS` |
| Microsoft Entra ID (Azure AD) | `gnat/connectors/entra_id/` | OAuth2 (Graph API) |
| Ping Identity (PingOne) | `gnat/connectors/ping_identity/` | OAuth2 client credentials |
| Mimecast email security | `gnat/connectors/mimecast/` | OAuth2 client credentials |
| IRONSCALES AI email security | `gnat/connectors/ironscales/` | Bearer + `X-Company-Id` header |
| Code42 Incydr (insider risk) | `gnat/connectors/code42/` | OAuth2 client credentials (Basic → Bearer) |
| DTEX InTERCEPT (behavioral insider threat) | `gnat/connectors/dtex/` | Bearer token |
| Gurucul UEBA | `gnat/connectors/gurucul/` | Bearer token |
| Exabeam Security Operations Platform | `gnat/connectors/exabeam/` | OAuth2 client credentials |
| Securonix cloud SIEM / UEBA | `gnat/connectors/securonix/` | Username/password → session token |
| Dataminr Pulse (real-time event intelligence) | `gnat/connectors/dataminr/` | OAuth2 client credentials → `Dmauth` token |
| Factal verified breaking-news intelligence | `gnat/connectors/factal/` | Bearer token |
| Samdesk global crisis detection | `gnat/connectors/samdesk/` | `X-Api-Key` header |
| HUMAN Security (bot defense / ATO) | `gnat/connectors/human_security/` | OAuth2 client credentials |
| AbuseIPDB community IP reputation | `gnat/connectors/abuseipdb/` | `Key` header |
| Project Honey Pot http:BL | `gnat/connectors/project_honey_pot/` | http:BL access key (DNS-based) |
| crt.sh public Certificate Transparency search | `gnat/connectors/crtsh/` | None (public) |
| Google Certificate Transparency log API | `gnat/connectors/google_ct/` | None (public; per-log path) |
| Velociraptor open-source DFIR | `gnat/connectors/velociraptor/` | Bearer token or mTLS cert/key |
| Magnet AXIOM Cyber (remote forensics) | `gnat/connectors/magnet_axiom/` | `X-API-Key` header |
| HackerOne (bug bounty / VDP) | `gnat/connectors/hackerone/` | HTTP Basic (username + token) |
| Bugcrowd (bug bounty / pentest) | `gnat/connectors/bugcrowd/` | `Authorization: Token` header |

---

## Search Sidecar (`gnat/search/`)

The `gnat/search/` package provides a Solr-backed full-text search sidecar for GNAT:

| File | Purpose |
|------|---------|
| `__init__.py` | Package exports (`SearchMixin`, `GNATIndexer`, `SolrSearchConfig`) |
| `index.py` | `GNATIndexer` — Solr document indexing and querying |
| `mixin.py` | `SearchMixin` — connector mixin that auto-indexes on write operations |
| `orm_with_mixin.py` | ORM integration helpers (mixin-enhanced STIX objects) |
| `pipeline_patch.py` | Ingest pipeline patch to route records through Solr indexer |
| `library_patch.py` | ResearchLibrary patch for search-backed lookups |
| `config_search_section.ini` | INI template for the `[search]` configuration section |
| `solr_schema_gnat.xml` | Solr 9.x schema definition for GNAT threat intel fields |

Configure via `[search]` section in gnat.ini:
```ini
[search]
solr_url    = http://localhost:8983/solr/gnat
enabled     = true
batch_size  = 100
```

---

## Ingest Sources & Mappers

**15 Source Readers:** PlainText, CSV, JSON, JSONL, STIXBundle, TAXIICollection, SQL, MISP, Syslog, RSS, Email, OpenIOC, Splunk, Elastic, Kafka (telemetry)

**13 Record Mappers:** FlatIOC, STIXPassthrough, MISP, CEF, SQLRow, CSV, RSSEntry, Email, OpenIOC, Splunk, Elastic, NVDCVE, Telemetry

---

## Dependency Extras

Install only what you need:

```bash
pip install gnat                        # Core only (urllib3)
pip install "gnat[yaml]"               # YAML support (pyyaml)
pip install "gnat[taxii]"              # TAXII reading (taxii2-client)
pip install "gnat[rss]"                # RSS feed reading (feedparser)
pip install "gnat[ingest]"             # TAXII + RSS (taxii2-client + feedparser)
pip install "gnat[async]"              # Async client (httpx)
pip install "gnat[persist]"            # DB persistence (sqlalchemy)
pip install "gnat[schedule]"           # Cron scheduling (croniter)
pip install "gnat[reports]"            # PDF + DOCX reports (reportlab + python-docx)
pip install "gnat[viz]"               # Visualization (plotly, networkx, openpyxl)
pip install "gnat[serve]"              # HTTP server (fastapi, uvicorn)
pip install "gnat[tui]"               # Terminal UI (textual)
pip install "gnat[nlp]"               # NLP/IOC extraction (builtin; claude backend reuses agents)
pip install "gnat[stix-validate]"      # Full STIX pattern validation (stix2-patterns ANTLR grammar)
pip install "gnat[telemetry]"         # High-volume sensor ingestion (kafka-python-ng + redis)
pip install "gnat[analysis]"          # Attribution & campaign tracking persistence (sqlalchemy)
pip install "gnat[fast]"              # Rust native extension (install gnat-core wheel separately)
pip install "gnat[all]"               # Everything
pip install "gnat[dev]"               # All + dev tools
```

---

## AI Agent Integration

The `gnat/agents/` package provides a unified multi-LLM framework for automated threat intelligence workflows:
- **LLMClient** (`gnat/agents/llm.py`) — unified facade supporting Claude, OpenAI, Grok (xAI), and Gemini backends with automatic fallback
- **ClaudeProvider** (`gnat/agents/claude.py`) — Anthropic Claude Messages API (urllib3-based, no requests)
- **ResearchAgent** (`gnat/agents/research.py`) — AI-assisted threat intelligence research; integrates as a `SourceReader`
- **ParsingAgent** — extracts structured STIX from unstructured text; integrates as a `RecordMapper`
- **quality/** — fixture coverage, normalization regression, and contract verification agents
- **repo_maintenance/** — automated connector discovery, repair, and registry maintenance
- **security/** — secrets hygiene and security scanning sub-agents

Config via `[claude]` section in INI: `api_key`, `model`, `ai_confidence_ceiling`. All providers can also be configured with their own INI sections.

The Claude model defaults to `claude-sonnet-4-6`. When modifying AI agent code, prefer the latest Claude models. See `EXAMPLES.md` for usage patterns.

---

## Documentation

| File | Purpose |
|------|---------|
| `README.md` | Feature overview, quickstart, platform table |
| `CHANGELOG.md` | Version history — update `[Unreleased]` for every change |
| `CONTRIBUTING.md` | Contributor guide, PR checklist |
| `docs/architecture.md` | Architecture overview |
| `docs/explanation/` | Concept explanations and design rationale |
| `docs/how-to/` | Task-oriented guides |
| `docs/reference/` | API reference documentation |
| `docs/tutorials/` | Step-by-step tutorials |
| `EXAMPLES.md` | Code snippets for all major features |
| `docs/source/` | Sphinx RST docs (build with `make docs`) |

---

## What NOT to Do

- Do not add `requests` as a dependency — the project deliberately uses `urllib3` directly.
- Do not introduce Pydantic or SQLAlchemy models for STIX objects — the property bag ORM is intentional.
- Do not bypass the `ConnectorMixin` contract when adding new connectors.
- Do not skip `CHANGELOG.md` updates for user-visible changes.
- Do not commit credentials or real API keys — only example values in `config/config.ini.example`.
- Do not add optional feature code to core imports — use the extras groups pattern.

---

*Licensed under the Apache License, Version 2.0*

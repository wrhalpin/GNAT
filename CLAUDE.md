# CLAUDE.md — GNAT AI Assistant Guide

This file provides context for AI assistants (Claude Code and similar) working in this repository.

---

## Project Overview

**GNAT** (Cybersecurity Threat Management Swiss Army Knife) is a production-ready Python library providing:
- A unified client interface for 15+ security/threat intelligence platforms
- A STIX 2.1-compatible ORM for threat intelligence objects
- Ingestion, export, scheduling, visualization, and reporting pipelines
- AI agent integration (Claude API)
- A fully featured CLI

**Package name on PyPI:** `gnat`
**Import root:** `gnat`
**Version:** 0.1.0
**Python support:** 3.9, 3.10, 3.11, 3.12
**License:** MIT

---

## Repository Layout

```
gnat/                        # Main Python package
├── __init__.py              # Public API surface (SAKClient, ORM types, connectors)
├── client.py                # SAKClient — top-level facade
├── config.py                # INI-based configuration management
├── orm/                     # STIX 2.1 ORM (STIXBase + 8 object types)
├── clients/                 # HTTP client layer (urllib3 BaseClient + CLIENT_REGISTRY)
├── connectors/              # 15 platform connectors (ThreatQ, CrowdStrike, Splunk, etc.)
├── ingest/                  # Multi-source ingestion pipeline (14 readers, 12 mappers)
├── export/                  # Export pipeline (EDL, Netskope CE delivery targets)
├── cli/                     # CLI entry point (gnat/cli/main.py — 27 KB)
├── schedule/                # Feed scheduling (FeedJob, FeedScheduler, croniter)
├── reports/                 # Report generation (PDF via ReportLab, AI-assisted)
├── research/                # Research library (ResearchLibrary, CurationJob)
├── agents/                  # AI agent integration (Claude API via CopilotReader)
├── context/                 # Global context + workspace persistence
├── viz/                     # Visualization (Tabular, Graph, Grafana, Power BI)
├── codegen/                 # OpenAPI → connector scaffolding
├── async_client/            # Async variant (httpx)
└── utils/                   # Misc helpers (stix_helpers.py)

tests/
├── conftest.py              # Shared fixtures (mock HTTP, test config)
├── unit/                    # Unit tests mirroring gnat/ layout
└── integration/             # Live API tests (opt-in)

docs/source/                 # Sphinx RST documentation
config/config.ini.example    # Configuration template
Makefile                     # Dev targets (test, lint, build, docs)
pyproject.toml               # Build config, deps, tool configs
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
| `make docs` | sphinx-build | Build HTML docs |
| `make build` | setuptools | Build sdist + wheel |
| `make clean` | | Remove build artifacts |

### Running Tests

```bash
pytest tests/unit/ -v --tb=short          # All unit tests
pytest tests/unit/connectors/ -v          # Connector tests only
pytest tests/integration/ --run-integration -v  # Integration (needs live creds)
```

**Minimum coverage requirement:** 70% (enforced by `fail_under = 70` in pyproject.toml)

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

- Raise `SAKClientError` (from `gnat.clients.base`) for HTTP-level failures — includes `status` and `body`.
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

See `ARCHITECTURE_DECISIONS.md` for the full rationale. Key choices:

| Decision | Choice | Reason |
|----------|--------|--------|
| HTTP client | `urllib3` (sync), `httpx` (async) | Fine-grained control, minimal overhead |
| ORM | Pure Python (not SQLAlchemy/Pydantic) | Avoid unnecessary coupling |
| Data model | STIX 2.1 property bag | Flexible schema for threat intel |
| Config | INI (configparser) | Zero dependencies, simple |
| Packaging | Extras groups | Pay-for-what-you-use dependency model |
| CLI | argparse subcommands | No framework dependency |

---

## Testing Conventions

**Fixtures (tests/conftest.py):**
- `mock_http_response()` — Factory for fake `urllib3.HTTPResponse` objects (no real HTTP)
- `mock_pool_manager()` — Patches `urllib3.PoolManager` at the process level
- `minimal_config()` — Writes a temporary INI config file; returns its path
- `sak_client()` — Returns a `SAKClient` pre-loaded from the test config

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
| ThreatQ | `gnat/connectors/threatq/` | OAuth2 |
| CrowdStrike Falcon | `gnat/connectors/crowdstrike/` | OAuth2 |
| Netskope | `gnat/connectors/netskope/` | API key |
| Proofpoint TAP | `gnat/connectors/proofpoint/` | Basic auth |
| Palo Alto XSOAR | `gnat/connectors/xsoar/` | API key |
| Recorded Future | `gnat/connectors/recordedfuture/` | API key |
| Splunk | `gnat/connectors/splunk/` | Basic/token |
| VirusTotal | `gnat/connectors/virustotal/` | API key |
| Shadowserver | `gnat/connectors/shadowserver/` | API key |
| Rapid7 InsightVM/IDR | `gnat/connectors/rapid7/` | API key |
| Nucleus | `gnat/connectors/nucleus/` | API key |
| GreyMatter | `gnat/connectors/greymatter/` | API key |
| Whistic | `gnat/connectors/whistic/` | API key |
| RiskRecon | `gnat/connectors/riskrecon/` | API key |
| Feedly | `gnat/connectors/feedly/` | OAuth2/API key |

---

## Ingest Sources & Mappers

**14 Source Readers:** PlainText, CSV, JSON, JSONL, STIXBundle, TAXIICollection, SQL, MISP, Syslog, RSS, Email, OpenIOC, Splunk, Elastic

**12 Record Mappers:** FlatIOC, STIXPassthrough, MISP, CEF, SQLRow, CSV, RSSEntry, Email, OpenIOC, Splunk, Elastic, NVDCVE

---

## Dependency Extras

Install only what you need:

```bash
pip install gnat                        # Core only (urllib3)
pip install "gnat[yaml]"               # YAML support (pyyaml)
pip install "gnat[taxii]"              # TAXII reading (taxii2-client)
pip install "gnat[ingest]"             # TAXII + RSS (taxii2-client + feedparser)
pip install "gnat[async]"              # Async client (httpx)
pip install "gnat[persist]"            # DB persistence (sqlalchemy)
pip install "gnat[schedule]"           # Cron scheduling (croniter)
pip install "gnat[reports]"            # PDF reports (reportlab)
pip install "gnat[viz]"               # Visualization (plotly, networkx, openpyxl)
pip install "gnat[serve]"              # HTTP server (fastapi, uvicorn)
pip install "gnat[all]"               # Everything
pip install "gnat[dev]"               # All + dev tools
```

---

## AI Agent Integration

The `gnat/agents/` package integrates with Claude API for automated threat intelligence workflows:
- **CopilotReader** (`gnat/agents/copilot.py`) — Claude API calls
- **ResearchAgent** (`gnat/agents/research.py`) — AI-assisted research analysis
- Config via `[claude]` section in INI: `api_key`, `model`, `ai_confidence_ceiling`

The Claude model defaults to `claude-sonnet-4-6`. When modifying AI agent code, prefer the latest Claude models. See `EXAMPLES.md` for usage patterns.

---

## Documentation

| File | Purpose |
|------|---------|
| `README.md` | Feature overview, quickstart, platform table |
| `CHANGELOG.md` | Version history — update `[Unreleased]` for every change |
| `CONTRIBUTING.md` | Contributor guide, PR checklist |
| `ARCHITECTURE_DECISIONS.md` | 15 documented design decisions with rationale |
| `IMPLEMENTATION_PLAN.md` | Project plan, layer diagram, roadmap |
| `EXAMPLES.md` | Code snippets for all major features |
| `PENDING_ITEMS.md` | Tracked outstanding tasks and TODOs |
| `docs/source/` | Sphinx RST docs (build with `make docs`) |

---

## What NOT to Do

- Do not add `requests` as a dependency — the project deliberately uses `urllib3` directly.
- Do not introduce Pydantic or SQLAlchemy models for STIX objects — the property bag ORM is intentional.
- Do not bypass the `ConnectorMixin` contract when adding new connectors.
- Do not skip `CHANGELOG.md` updates for user-visible changes.
- Do not commit credentials or real API keys — only example values in `config/config.ini.example`.
- Do not add optional feature code to core imports — use the extras groups pattern.

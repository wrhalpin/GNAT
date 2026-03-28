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

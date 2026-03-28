# GNAT Pending Items

Tracked outstanding implementation tasks, normalization work, and
known gaps. Update this file as items are completed or new ones are
identified.

---

## HIGH PRIORITY

### 1. ThreatQ Sector / Industry Field Normalization

**File:** `gnat/connectors/threatq/client.py` — `to_stix()` method

**Status:** Placeholder — needs field name verification

**Background:**
ThreatQ has Target Industry and Target Sector attributes on threat objects.
GNAT uses `x_target_sectors` as the canonical field for sector-based
filtering (used by `SectorFilter` in the reports layer and the export
pipeline). The ThreatQ connector's `to_stix()` method needs to read
ThreatQ's field names and write them to `x_target_sectors`.

**Action required:**
1. In ThreatQ, export a sample STIX bundle for an object with Target
   Industry and Target Sector values set.
2. Check the STIX export field names — likely something like
   `x_threatq_target_industries` or inside an `extensions` block.
3. Also check whether Target Industry and Target Sector are separate
   fields in the ThreatQ API response (`/api/types/`, `/api/indicators/`
   etc.) or combined.
4. Determine whether ThreatQ uses a controlled vocabulary (defined list)
   or free-form strings. Note: known values include "Healthcare",
   "Insurance", "Hospitals and Health Centers", "Opportunistic" — check
   if these are from a ThreatQ-defined list or user-entered.
5. Update `to_stix()` in `gnat/connectors/threatq/client.py`:

```python
# In ThreatQClient.to_stix() — fill in actual field names:
industries = native.get("x_threatq_target_industries")  # VERIFY field name
sectors    = native.get("x_threatq_target_sectors")      # VERIFY field name
if industries or sectors:
    combined = []
    if isinstance(industries, list): combined.extend(industries)
    elif isinstance(industries, str): combined.append(industries)
    if isinstance(sectors, list):    combined.extend(sectors)
    elif isinstance(sectors, str):   combined.append(sectors)
    stix_dict["x_target_sectors"] = combined
```

6. Add INI `[sector_aliases]` mappings if ThreatQ strings don't exactly
   match values from other sources (e.g., RF uses "health" vs ThreatQ
   "Healthcare").

**Other connectors to check (same pattern):**
- `recordedfuture/client.py` — RF tags sectors on its alerts/entities
- `crowdstrike/client.py` — CS Adversary profiles have target industries
- `splunk/client.py` — Depends on data in Splunk; may be in alert fields

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

**Status:** Plain-text email body only. The `body_html` parameter exists
but no HTML body is auto-generated from the report.

**Action required:**
- `ReportGenerator._deliver_email()` should pass the HTML report as the
  email body when an HTML output was rendered, rather than a generic
  plain-text message.
- Use the first 2000 chars of the executive summary as the email body
  for PDF/DOCX-only deliveries.

---

### 8. Report Yearly Scheduling

**File:** `gnat/reports/generator.py` — `ReportJob`

**Status:** Yearly reports default to `interval_seconds=365*86400` which
is a single large interval — fine for production but awkward for testing
and for cases where the server restarts.

**Action required:**
- Add support for calendar-anchored scheduling: "run on January 1st" via
  cron `"0 6 1 1 *"` rather than a 365-day interval.
- Document recommended cron expressions per report type in
  `config/config.ini.example`.

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

Once VirusTotal, ShadowServer, Rapid7, and Nucleus connectors are built,
add their pip dependencies (if any beyond stdlib + urllib3) to pyproject.toml.

---

## NORMALIZATION REFERENCE

Once ThreatQ field names are confirmed, update this table:

| Platform       | Native Field Name         | Maps to              | Status    |
|----------------|--------------------------|----------------------|-----------|
| ThreatQ        | TBD — verify in API      | `x_target_sectors`   | PENDING   |
| Recorded Future | `entities[].type`        | `x_target_sectors`   | PENDING   |
| CrowdStrike     | `adversary.target_industries` | `x_target_sectors` | PENDING |
| VirusTotal      | `popular_threat_category` | `x_target_sectors`  | PENDING   |
| ShadowServer    | `sector` (report field)  | `x_target_sectors`   | PENDING   |
| Nucleus         | `asset.industry`         | `x_target_sectors`   | PENDING   |

**Canonical field:** `x_target_sectors` — list of strings on any STIX object.  
**Alias config:** `[sector_aliases]` section in `config.ini`.  
**Filter class:** `gnat/reports/base.py::SectorFilter` (move to
`gnat/export/filters.py` — see item 12).

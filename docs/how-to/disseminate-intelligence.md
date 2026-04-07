# How-to: Disseminate Intelligence

Export finished intelligence, notify subscribers via webhooks, serve STIX 2.1
over TAXII, and expose a REST gateway — all via `gnat.dissemination`.

---

## Setup

```bash
pip install "gnat[serve]"   # FastAPI + uvicorn (for TAXII and REST gateway)
# or
pip install "gnat[all]"
```

```python
from gnat.dissemination import (
    ExportService,
    ExportFormat,
    ExportResult,
    WebhookNotifier,
    WebhookSubscription,
)
from gnat.dissemination.api import APIKeyStore, build_gateway_router
from gnat.dissemination.taxii import build_taxii_router
```

---

## Export reports to files or streams

`ExportService` serialises a published `Report` to STIX, JSON, or PDF.

```python
from gnat.dissemination import ExportService, ExportFormat

svc = ExportService(report_store)

# Export to STIX 2.1 bundle file
result: ExportResult = svc.export(
    report_id   = report.id,
    fmt         = ExportFormat.STIX,
    destination = "/var/exports/blackcat-apr-2026.json",
)
print(result.checksum)    # SHA-256 of the exported file
print(result.byte_count)  # file size in bytes

# Export as raw JSON
result = svc.export(report.id, ExportFormat.JSON, "/var/exports/blackcat.json")

# Export as PDF (requires gnat[reports])
result = svc.export(report.id, ExportFormat.PDF, "/var/exports/blackcat.pdf")
```

---

## Webhook notifications

`WebhookNotifier` fans out HTTP POST notifications to registered subscribers
when a report is published or updated.  Delivery is best-effort — failures are
logged, never raised.

```python
from gnat.dissemination import WebhookNotifier, WebhookSubscription
from gnat.analysis.tlp import TLPLevel

notifier = WebhookNotifier()

# Register subscribers
notifier.subscribe(WebhookSubscription(
    id      = "siem-hook",
    url     = "https://siem.example.com/webhook/gnat",
    min_tlp = TLPLevel.GREEN,                    # receives GREEN, AMBER, RED
    secret  = "hmac-shared-secret",              # HMAC-SHA256 signature header
))

notifier.subscribe(WebhookSubscription(
    id      = "partner-hook",
    url     = "https://partner.example.com/intel",
    min_tlp = TLPLevel.WHITE,                    # receives everything
    events  = ["report.published"],              # event filter (optional)
))

# Notify on publish (typically called from ReportService.publish())
receipts = notifier.notify(published_report)
for r in receipts:
    print(f"{r.subscription_id}: {'✓' if r.success else '✗'}  {r.status_code}")
```

The POST body is a JSON object containing report metadata and a STIX bundle
summary.  When `secret` is set, the notifier adds an `X-GNAT-Signature`
HMAC-SHA256 header so the subscriber can verify authenticity.

---

## TAXII 2.1 server

Serve GNAT workspaces as TAXII 2.1 collections inside a FastAPI application.

```python
from fastapi import FastAPI
from gnat.dissemination.taxii import build_taxii_router
from gnat.dissemination.api import APIKeyStore
from gnat.analysis.tlp import TLPLevel

app       = FastAPI(title="GNAT TAXII Server")
key_store = APIKeyStore()
key_store.add_key("my-bearer-token", min_tlp=TLPLevel.AMBER)

# Mount TAXII router (full TAXII 2.1 Discovery + Collection + Objects endpoints)
app.include_router(
    build_taxii_router(report_store, key_store),
    prefix = "/taxii2",
)
```

TAXII endpoints exposed:

| Endpoint | Description |
|----------|-------------|
| `GET /taxii2/` | Discovery (returns server metadata) |
| `GET /taxii2/collections/` | List all collections |
| `GET /taxii2/collections/{id}/` | Collection metadata |
| `GET /taxii2/collections/{id}/objects/` | Fetch STIX objects (paged) |
| `POST /taxii2/collections/{id}/objects/` | Ingest STIX objects |

---

## REST API gateway

`build_gateway_router` adds REST endpoints for report export, report listing,
and admin operations (API key management) to a FastAPI application.

```python
from fastapi import FastAPI
from gnat.dissemination.api import APIKeyStore, build_gateway_router
from gnat.dissemination import ExportService

app       = FastAPI(title="GNAT Gateway")
key_store = APIKeyStore()
key_store.add_key("analyst-token",  min_tlp=TLPLevel.AMBER)
key_store.add_key("external-token", min_tlp=TLPLevel.GREEN)

export_svc = ExportService(report_store)

app.include_router(
    build_gateway_router(export_svc, key_store, report_store),
    prefix = "/api/v1",
)
```

Gateway endpoints exposed:

| Endpoint | Description |
|----------|-------------|
| `GET  /api/v1/reports` | List published reports (TLP-filtered per API key) |
| `GET  /api/v1/reports/{id}` | Get report metadata |
| `GET  /api/v1/reports/{id}/export` | Download STIX / JSON / PDF |
| `POST /api/v1/admin/keys` | Add an API key (admin only) |
| `DELETE /api/v1/admin/keys/{id}` | Revoke an API key |

All requests require `Authorization: Bearer <token>`.

---

## Combined stack (TAXII + gateway)

```python
from fastapi import FastAPI
from gnat.dissemination import ExportService
from gnat.dissemination.api import APIKeyStore, build_gateway_router
from gnat.dissemination.taxii import build_taxii_router

app       = FastAPI(title="GNAT Intelligence Server")
key_store = APIKeyStore()
key_store.add_key("soc-token",     min_tlp=TLPLevel.AMBER)
key_store.add_key("partner-token", min_tlp=TLPLevel.GREEN)

export_svc = ExportService(report_store)

app.include_router(build_taxii_router(report_store, key_store), prefix="/taxii2")
app.include_router(build_gateway_router(export_svc, key_store, report_store), prefix="/api/v1")

# Run with: uvicorn myapp:app --host 0.0.0.0 --port 8000
```

---

## API key management

```python
from gnat.dissemination.api import APIKeyStore, APIKey
from gnat.analysis.tlp import TLPLevel

store = APIKeyStore()

# Add keys with TLP restrictions
store.add_key("internal-token", min_tlp=TLPLevel.AMBER)
store.add_key("partner-token",  min_tlp=TLPLevel.GREEN)
store.add_key("public-token",   min_tlp=TLPLevel.WHITE)

# Revoke a key
store.revoke("partner-token")

# Verify a key (returns APIKey or None)
key = store.verify("internal-token")
if key:
    print(f"Key authorized for TLP ≥ {key.min_tlp.label}")
```

---

## See Also

- [How-to: Create Intelligence Reports](create-intelligence-reports.md)
- [How-to: Export Indicators](export-indicators.md)
- [Explanation: TAXII 2.1 Server](../explanation/architecture/adrs/0028-ADR-taxii-21-server.md)
- [Explanation: Analysis Layer Architecture](../explanation/architecture/adrs/0031-ADR-analysis-layer-architecture.md)

---

*Licensed under the Apache License, Version 2.0*

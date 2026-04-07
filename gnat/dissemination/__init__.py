"""
gnat.dissemination
==================

Dissemination layer — export, TAXII 2.1 serving, webhooks, and REST gateway.

Sub-packages
------------
export
    :class:`~.export.ExportService` — STIX / JSON / PDF export with checksums.
taxii
    :func:`~.taxii.build_taxii_router` — TAXII 2.1 FastAPI router.
notify
    :class:`~.notify.WebhookNotifier` — best-effort HTTP POST fan-out.
api
    :func:`~.api.build_gateway_router` — REST gateway; :class:`~.api.APIKeyStore`.

Quick start::

    from gnat.dissemination import ExportService, ExportFormat
    from gnat.dissemination import WebhookNotifier, WebhookSubscription
    from gnat.dissemination.api import APIKeyStore, build_gateway_router
    from gnat.dissemination.taxii import build_taxii_router

    # Export
    svc    = ExportService(report_store)
    result = svc.export(report_id, ExportFormat.STIX, "/tmp/out.json")

    # Notify
    notifier = WebhookNotifier()
    notifier.subscribe(WebhookSubscription(id="s1", url="https://siem/hook",
                                            min_tlp=TLPLevel.AMBER))
    notifier.notify(report)

    # TAXII + Gateway (FastAPI app)
    key_store = APIKeyStore()
    key_store.add_key("secret", TLPLevel.AMBER)

    app.include_router(build_taxii_router(report_store, key_store), prefix="/taxii2")
    app.include_router(build_gateway_router(svc, key_store, report_store), prefix="/api/v1")
"""

from gnat.dissemination.export import ExportFormat, ExportResult, ExportService
from gnat.dissemination.notify import (
    DeliveryReceipt,
    WebhookNotifier,
    WebhookSubscription,
)

__all__ = [
    "ExportService",
    "ExportFormat",
    "ExportResult",
    "WebhookNotifier",
    "WebhookSubscription",
    "DeliveryReceipt",
]

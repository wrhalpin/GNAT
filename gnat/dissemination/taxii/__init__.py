"""
gnat.dissemination.taxii
=========================

TAXII 2.1 server and collection management.

Quick start::

    from gnat.dissemination.taxii import build_taxii_router, COLLECTIONS
    from gnat.dissemination.api.auth import APIKeyStore

    key_store = APIKeyStore()
    key_store.add_key("secret-token", TLPLevel.AMBER)

    router = build_taxii_router(report_store=store, key_store=key_store)
    app.include_router(router, prefix="/taxii2")
"""

from gnat.dissemination.taxii.collections import (
    COLLECTION_BY_ID,
    COLLECTIONS,
    TAXIICollection,
    collections_for_key,
    tlp_filter_for_collection,
)
from gnat.dissemination.taxii.server import build_taxii_router

__all__ = [
    "TAXIICollection",
    "COLLECTIONS",
    "COLLECTION_BY_ID",
    "collections_for_key",
    "tlp_filter_for_collection",
    "build_taxii_router",
]

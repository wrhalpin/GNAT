"""
gnat.dissemination.api
=======================

REST gateway and API key management for the GNAT dissemination layer.

Modules
-------
auth
    :class:`~.auth.APIKey` / :class:`~.auth.APIKeyStore` — bearer token store.
gateway
    :func:`~.gateway.build_gateway_router` — FastAPI router for report export
    and admin endpoints.
"""

from gnat.dissemination.api.auth import APIKey, APIKeyStore
from gnat.dissemination.api.gateway import build_gateway_router
from gnat.dissemination.api.investigations import build_investigation_router

__all__ = [
    "APIKey",
    "APIKeyStore",
    "build_gateway_router",
    "build_investigation_router",
]

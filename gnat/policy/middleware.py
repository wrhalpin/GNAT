"""
gnat.policy.middleware
=======================

Optional FastAPI middleware that logs every authenticated request and emits
a ``HookBus`` event for audit trail integration.

Usage::

    from fastapi import FastAPI
    from gnat.policy.middleware import PolicyAuditMiddleware
    from gnat.dissemination.api.auth import APIKeyStore

    app      = FastAPI()
    key_store = APIKeyStore()
    app.add_middleware(PolicyAuditMiddleware, key_store=key_store)
"""

from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


def build_audit_middleware(key_store: Any) -> type:
    """
    Build a Starlette ``BaseHTTPMiddleware`` subclass that audits requests.

    Parameters
    ----------
    key_store : APIKeyStore
        Used to resolve Bearer tokens to API key objects.

    Returns
    -------
    type
        A middleware class ready to pass to ``app.add_middleware()``.
    """
    try:
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.requests import Request
        from starlette.responses import Response
    except ImportError as exc:
        raise ImportError(
            "starlette is required for PolicyAuditMiddleware. "
            "Install it with: pip install 'gnat[serve]'"
        ) from exc

    class PolicyAuditMiddleware(BaseHTTPMiddleware):
        """Log every authenticated API request with timing."""

        async def dispatch(self, request: Request, call_next: Any) -> Response:
            start = time.monotonic()
            response = await call_next(request)
            elapsed_ms = (time.monotonic() - start) * 1000

            # Resolve actor from Authorization header
            actor = "anonymous"
            auth = request.headers.get("authorization", "")
            if auth.startswith("Bearer ") and key_store is not None:
                token = auth.removeprefix("Bearer ").strip()
                key   = key_store.get_key(token)
                if key is not None:
                    actor = getattr(key, "label", None) or f"key:{key.token_hash}"

            logger.info(
                "REQUEST: actor=%r method=%s path=%s status=%d elapsed=%.1fms",
                actor,
                request.method,
                request.url.path,
                response.status_code,
                elapsed_ms,
            )

            # Emit to HookBus for plugin handlers
            try:
                from gnat.plugins.hooks import HookBus
                HookBus.instance().emit(
                    "api_request",
                    actor       = actor,
                    method      = request.method,
                    path        = request.url.path,
                    status_code = response.status_code,
                    elapsed_ms  = elapsed_ms,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Policy audit middleware emit failed: %s", exc)

            return response

    return PolicyAuditMiddleware


# Alias for convenience
PolicyAuditMiddleware = None  # set lazily to avoid import error when starlette absent

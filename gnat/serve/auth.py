# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.serve.auth
===============
FastAPI dependency that enforces API key authentication.

Supports two header formats for backward compatibility:

- ``Authorization: Bearer <token>`` (preferred)
- ``X-Api-Key: <token>`` (deprecated, still accepted)

Usage::

    from gnat.dissemination.api.auth import APIKeyStore
    from gnat.serve.auth import APIKeyAuth

    store = APIKeyStore()
    store.generate_key(TLPLevel.AMBER, label="dashboard", role="admin")
    auth = APIKeyAuth(key_store=store)
    router = APIRouter(dependencies=[Depends(auth)])
"""

from __future__ import annotations

import hmac
from typing import Any

from fastapi import Header, HTTPException, Request, status


class APIKeyAuth:
    """Callable FastAPI dependency for API key authentication.

    Accepts keys via ``Authorization: Bearer`` or ``X-Api-Key`` headers.
    Validates against an :class:`~gnat.dissemination.api.auth.APIKeyStore`
    when one is provided, or falls back to single-key comparison for
    backward compatibility.

    Parameters
    ----------
    key_store : APIKeyStore, optional
        Multi-key store.  When provided, tokens are looked up and validated
        via ``key_store.get_key()``.
    api_key : str, optional
        Legacy single-key mode.  Compared using :func:`hmac.compare_digest`.
        Deprecated — use *key_store* instead.
    """

    def __init__(
        self,
        key_store: Any | None = None,
        api_key: str | None = None,
    ) -> None:
        self._store = key_store
        self._legacy_key: bytes | None = api_key.encode("utf-8") if api_key else None
        if key_store is None and api_key is None:
            raise ValueError("APIKeyAuth requires either key_store or api_key")

    def __call__(
        self,
        request: Request,
        authorization: str = Header(default=""),
        x_api_key: str = Header(default="", alias="X-Api-Key"),
    ) -> Any:
        """Validate the API key from request headers.

        Returns the :class:`~gnat.dissemination.api.auth.APIKey` object
        when using a key store, or the raw token string in legacy mode.

        Raises
        ------
        HTTPException
            ``401 Unauthorized`` when the key is missing or invalid.
        """
        token = ""
        if authorization.startswith("Bearer "):
            token = authorization.removeprefix("Bearer ").strip()
        elif x_api_key:
            token = x_api_key

        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing API key. Use Authorization: Bearer <token> "
                "or X-Api-Key header.",
            )

        if self._store is not None:
            key = self._store.get_key(token)
            if key is None or not key.is_valid():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired API key.",
                )
            return key

        if self._legacy_key is not None:
            try:
                provided = token.encode("utf-8")
            except AttributeError:
                provided = b""
            if not hmac.compare_digest(provided, self._legacy_key):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or missing API key",
                )
            return token

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication not configured.",
        )

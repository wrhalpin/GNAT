# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.serve.auth
===============
FastAPI dependency that enforces API key authentication with optional
OIDC fallback.

Supports two header formats for backward compatibility:

- ``Authorization: Bearer <token>`` (preferred)
- ``X-Api-Key: <token>`` (deprecated, still accepted)

When an :class:`~gnat.auth.oidc.OIDCProvider` is configured, bearer
tokens that are not found in the key store are validated as OIDC JWTs.
API key validation is always attempted first.

Usage::

    from gnat.dissemination.api.auth import APIKeyStore
    from gnat.serve.auth import APIKeyAuth

    store = APIKeyStore()
    store.generate_key(TLPLevel.AMBER, label="dashboard", role="admin")

    # API key only
    auth = APIKeyAuth(key_store=store)

    # API key + OIDC fallback
    from gnat.auth.oidc import OIDCProvider
    oidc = OIDCProvider(issuer="https://acme.okta.com", client_id="0oa...")
    auth = APIKeyAuth(key_store=store, oidc_provider=oidc)
"""

from __future__ import annotations

import hmac
from typing import Any

from fastapi import Header, HTTPException, Request, status


class APIKeyAuth:
    """Callable FastAPI dependency for API key + optional OIDC authentication.

    Accepts keys via ``Authorization: Bearer`` or ``X-Api-Key`` headers.
    Validates against an :class:`~gnat.dissemination.api.auth.APIKeyStore`
    when one is provided.  If an
    :class:`~gnat.auth.oidc.OIDCProvider` is also configured, bearer
    tokens that fail API key validation are tried as OIDC JWTs.

    Falls back to single-key comparison for backward compatibility when
    only *api_key* is given.

    Parameters
    ----------
    key_store : APIKeyStore, optional
        Multi-key store.
    api_key : str, optional
        Legacy single-key mode (deprecated).
    oidc_provider : OIDCProvider, optional
        OIDC token validator for SSO authentication.
    """

    def __init__(
        self,
        key_store: Any | None = None,
        api_key: str | None = None,
        oidc_provider: Any | None = None,
    ) -> None:
        self._store = key_store
        self._legacy_key: bytes | None = api_key.encode("utf-8") if api_key else None
        self._oidc = oidc_provider
        if key_store is None and api_key is None and oidc_provider is None:
            raise ValueError(
                "APIKeyAuth requires at least one of: key_store, api_key, oidc_provider"
            )

    def __call__(
        self,
        request: Request,
        authorization: str = Header(default=""),
        x_api_key: str = Header(default="", alias="X-Api-Key"),
    ) -> Any:
        """Validate the API key or OIDC token from request headers.

        Returns the :class:`~gnat.dissemination.api.auth.APIKey` object
        when validated via key store, an
        :class:`~gnat.auth.identity.OIDCIdentity` when validated via
        OIDC, or the raw token string in legacy mode.

        Raises
        ------
        HTTPException
            ``401 Unauthorized`` when all auth methods fail.
        """
        token = ""
        if authorization.startswith("Bearer "):
            token = authorization.removeprefix("Bearer ").strip()
        elif x_api_key:
            token = x_api_key

        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing API key. Use Authorization: Bearer <token> or X-Api-Key header.",
            )

        if self._store is not None:
            key = self._store.get_key(token)
            if key is not None and key.is_valid():
                return key

        if self._legacy_key is not None:
            try:
                provided = token.encode("utf-8")
            except AttributeError:
                provided = b""
            if hmac.compare_digest(provided, self._legacy_key):
                return token

        if self._oidc is not None:
            try:
                identity = self._oidc.validate_token(token)
                if identity is not None:
                    return identity
            except Exception:
                pass

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key.",
        )

"""
gnat.serve.auth
===============
FastAPI dependency that enforces ``X-Api-Key`` header authentication.

Usage::

    from gnat.serve.auth import APIKeyAuth

    auth = APIKeyAuth(api_key="secret")
    router = APIRouter(dependencies=[Depends(auth)])
"""

from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, status


class APIKeyAuth:
    """Callable FastAPI dependency for ``X-Api-Key`` header auth.

    Parameters
    ----------
    api_key : str
        The expected API key value.  Compared using :func:`hmac.compare_digest`
        to prevent timing attacks.
    """

    def __init__(self, api_key: str) -> None:
        self._key: bytes = api_key.encode("utf-8")

    def __call__(
        self,
        x_api_key: str = Header(..., alias="X-Api-Key"),
    ) -> str:
        """Validate the ``X-Api-Key`` request header.

        Raises
        ------
        HTTPException
            ``401 Unauthorized`` when the key is missing or wrong.
        """
        try:
            provided = x_api_key.encode("utf-8")
        except AttributeError:
            provided = b""
        if not hmac.compare_digest(provided, self._key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key",
            )
        return x_api_key

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.async_client.base
==========================

``httpx``-based async counterpart to :class:`~gnat.clients.base.BaseClient`.

All connector clients that need async support should subclass
:class:`AsyncBaseClient` instead of (or in addition to) the sync
:class:`~gnat.clients.base.BaseClient`.

Design
------
* Drop-in async mirror: same method signatures as the sync client,
  but all HTTP methods are ``async def`` and must be ``await``-ed.
* Shares the same :class:`~gnat.clients.base.GNATClientError` exception.
* Uses ``httpx.AsyncClient`` with a connection pool, retry middleware, and
  configurable timeouts.
* ``authenticate()`` is also ``async def`` — suited for platforms whose
  token endpoints must be awaited.

Usage::

    import asyncio
    import gnat.async_client as async_ctm

    async def main():
        cli = async_ctm.AsyncGNATClient()
        await cli.connect("threatq")

        ind = async_ctm.AsyncIndicator(client=cli,
                                       pattern="[ipv4-addr:value = '1.2.3.4']")
        await ind.select()
        print(ind.name)

        # Concurrent enrichment across platforms
        cs_cli  = async_ctm.AsyncGNATClient()
        rf_cli  = async_ctm.AsyncGNATClient()
        await asyncio.gather(
            cs_cli.connect("crowdstrike"),
            rf_cli.connect("recordedfuture"),
        )
        cs_ind, rf_ind = await asyncio.gather(
            cs_cli.client.get_object("indicator", "ioc-123"),
            rf_cli.client.get_object("indicator", "ioc-123"),
        )

    asyncio.run(main())
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urlencode, urljoin

from gnat.clients.base import GNATClientError

logger = logging.getLogger(__name__)


class AsyncBaseClient:
    """
    Async HTTP client base class using ``httpx.AsyncClient``.

    Parameters
    ----------
    host : str
        Base URL of the target API.
    verify_ssl : bool
        Verify TLS certificates.  Default ``True``.
    timeout : float
        Request timeout in seconds.  Default ``30``.
    max_retries : int
        Maximum retries on transient 429/5xx responses.  Default ``3``.
    config : dict, optional
        Raw config dict for subclass use.

    Notes
    -----
    ``httpx`` must be installed: ``pip install "gnat[async]"``

    Attributes
    ----------
    _auth_headers : dict
        Injected into every request after :meth:`authenticate` runs.
    """

    def __init__(
        self,
        host: str,
        verify_ssl: bool = True,
        timeout: float = 30.0,
        max_retries: int = 3,
        config: dict[str, Any] | None = None,
    ):
        self.host = host.rstrip("/")
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries
        self.config = config or {}
        self._auth_headers: dict[str, str] = {}
        self._authenticated = False
        self._http: Any = None  # httpx.AsyncClient, lazy-init in __aenter__

    # ------------------------------------------------------------------
    # Async context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> AsyncBaseClient:
        await self._init_http()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    async def _init_http(self) -> None:
        """Lazy-initialise the httpx AsyncClient."""
        try:
            import httpx
        except ImportError:
            raise ImportError("httpx is required for async support: pip install 'gnat[async]'")
        transport = httpx.AsyncHTTPTransport(retries=self.max_retries)
        self._http = httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=self.timeout,
            transport=transport,
        )

    async def aclose(self) -> None:
        """Close the underlying httpx session."""
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    # ------------------------------------------------------------------
    # Authentication (abstract)
    # ------------------------------------------------------------------

    async def authenticate(self) -> None:
        """
        Perform platform authentication and populate :attr:`_auth_headers`.

        Must be implemented by every connector subclass.

        Raises
        ------
        NotImplementedError
        """
        raise NotImplementedError("Async connector subclasses must implement authenticate()")

    # ------------------------------------------------------------------
    # Async HTTP helpers
    # ------------------------------------------------------------------

    async def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Async GET request."""
        return await self._request("GET", path, params=params, extra_headers=headers)

    async def post(
        self,
        path: str,
        json: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Async POST request."""
        return await self._request("POST", path, body=json, form_data=data, extra_headers=headers)

    async def put(
        self,
        path: str,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Async PUT request."""
        return await self._request("PUT", path, body=json, extra_headers=headers)

    async def patch(
        self,
        path: str,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Async PATCH request."""
        return await self._request("PATCH", path, body=json, extra_headers=headers)

    async def delete(
        self,
        path: str,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Async DELETE request."""
        return await self._request("DELETE", path, extra_headers=headers)

    # ------------------------------------------------------------------
    # Internal dispatcher
    # ------------------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        form_data: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> Any:
        if self._http is None:
            await self._init_http()

        if not self._authenticated:
            await self.authenticate()
            self._authenticated = True

        url = urljoin(self.host + "/", path.lstrip("/"))
        if params:
            url = f"{url}?{urlencode(params, doseq=True)}"

        req_headers: dict[str, str] = {"Accept": "application/json"}
        req_headers.update(self._auth_headers)
        if extra_headers:
            req_headers.update(extra_headers)

        content: bytes | None = None
        if body is not None:
            content = json.dumps(body).encode()
            req_headers["Content-Type"] = "application/json"
        elif form_data is not None:
            content = urlencode(form_data).encode()
            req_headers["Content-Type"] = "application/x-www-form-urlencoded"

        logger.debug("ASYNC %s %s", method, url)

        response = await self._http.request(method, url, content=content, headers=req_headers)

        if response.status_code >= 400:
            raise GNATClientError(
                f"HTTP {response.status_code} from {url}",
                status=response.status_code,
                body=response.text,
            )

        if not response.content:
            return None

        try:
            return response.json()
        except Exception:  # noqa: BLE001
            return response.text

    def __repr__(self) -> str:  # pragma: no cover
        return f"{type(self).__name__}(host={self.host!r}, authenticated={self._authenticated})"

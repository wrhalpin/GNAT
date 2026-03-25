"""
ctm_sak.async_client.client
============================

Async counterpart to :class:`~ctm_sak.client.SAKClient`.

:class:`AsyncSAKClient` exposes the same ``connect`` / ``disconnect`` / ``ping``
API but all I/O is non-blocking.  It is designed to be used as an async
context manager so ``httpx`` sessions are properly closed::

    async with AsyncSAKClient() as cli:
        await cli.connect("threatq")
        ...

It also enables concurrent multi-platform queries::

    async with AsyncSAKClient() as tq, AsyncSAKClient() as cs:
        await asyncio.gather(tq.connect("threatq"), cs.connect("crowdstrike"))
        tq_data, cs_data = await asyncio.gather(
            tq.client.get_object("indicator", ioc_id),
            cs.client.get_object("indicator", ioc_id),
        )
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from ctm_sak.config import SAKConfig
from ctm_sak.clients.base import SAKClientError
from ctm_sak.async_client.base import AsyncBaseClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Async connector registry (mirrors the sync CLIENT_REGISTRY)
# ---------------------------------------------------------------------------

def _build_async_registry() -> dict:
    """
    Build the async connector registry lazily.

    Each async connector wraps its sync counterpart's auth / translation
    logic in async-compatible form.  Where a platform has a dedicated async
    connector it is preferred; otherwise the sync connector is wrapped.
    """
    from ctm_sak.async_client.connectors import (
        AsyncThreatQClient,
        AsyncGreyMatterClient,
        AsyncWhisticClient,
        AsyncRiskReconClient,
        AsyncFeedlyClient,
        AsyncSplunkClient,
        AsyncCrowdStrikeClient,
        AsyncProofpointClient,
        AsyncNetskopeClient,
        AsyncXSOARClient,
        AsyncRecordedFutureClient,
    )
    return {
        "threatq":       AsyncThreatQClient,
        "crowdstrike":   AsyncCrowdStrikeClient,
        "proofpoint":    AsyncProofpointClient,
        "netskope":      AsyncNetskopeClient,
        "xsoar":         AsyncXSOARClient,
        "recordedfuture": AsyncRecordedFutureClient,
        "greymatter":     AsyncGreyMatterClient,
        "whistic":        AsyncWhisticClient,
        "riskrecon":      AsyncRiskReconClient,
        "feedly":         AsyncFeedlyClient,
        "splunk":         AsyncSplunkClient,
    }


ASYNC_CLIENT_REGISTRY: dict = {}   # populated on first use


class AsyncSAKClient:
    """
    Async universal security platform client.

    Parameters
    ----------
    config_path : str, optional
        Path to an INI configuration file (same as sync :class:`~ctm_sak.client.SAKClient`).

    Examples
    --------
    Single platform::

        async with AsyncSAKClient() as cli:
            await cli.connect("threatq")
            data = await cli.client.get_object("indicator", "123")

    Concurrent multi-platform enrichment::

        async def enrich(ioc_id: str) -> dict:
            async with AsyncSAKClient() as tq, AsyncSAKClient() as rf:
                await asyncio.gather(
                    tq.connect("threatq"),
                    rf.connect("recordedfuture"),
                )
                tq_res, rf_res = await asyncio.gather(
                    tq.client.get_object("indicator", ioc_id),
                    rf.client.get_object("indicator", ioc_id),
                )
            return {"threatq": tq_res, "recorded_future": rf_res}
    """

    def __init__(self, config_path: Optional[str] = None):
        self._config_path = config_path
        self._config: Optional[SAKConfig] = None
        self.client: Optional[AsyncBaseClient] = None
        self.target: Optional[str] = None

    # ------------------------------------------------------------------
    # Async context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "AsyncSAKClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.disconnect()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def connect(self, target: str, **overrides: Any) -> "AsyncSAKClient":
        """
        Connect to a security platform asynchronously.

        Parameters
        ----------
        target : str
            Target system name (same names as sync client).
        **overrides
            Override config values at runtime.

        Returns
        -------
        AsyncSAKClient
            ``self`` for optional chaining (``await cli.connect("tq")``).
        """
        global ASYNC_CLIENT_REGISTRY
        if not ASYNC_CLIENT_REGISTRY:
            ASYNC_CLIENT_REGISTRY.update(_build_async_registry())

        target = target.lower()
        if target not in ASYNC_CLIENT_REGISTRY:
            raise KeyError(
                f"Unknown async target {target!r}. "
                f"Available: {sorted(ASYNC_CLIENT_REGISTRY.keys())}"
            )

        cfg = self._load_config(target, overrides)
        connector_cls = ASYNC_CLIENT_REGISTRY[target]
        self.client = connector_cls(**cfg)
        await self.client.__aenter__()
        self.target = target
        return self

    async def disconnect(self) -> None:
        """Close the active connection and release resources."""
        if self.client is not None:
            await self.client.__aexit__(None, None, None)
            self.client = None
            self.target = None

    async def ping(self) -> bool:
        """Return ``True`` if the current connection is reachable."""
        if self.client is None:
            return False
        try:
            await self.client.health_check()
            return True
        except Exception:  # noqa: BLE001
            return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_config(self, target: str, overrides: dict) -> dict:
        cfg: dict = {}
        if self._config is None:
            try:
                self._config = SAKConfig(self._config_path)
            except FileNotFoundError:
                pass
        if self._config is not None:
            try:
                cfg.update(self._config.get(target))
            except KeyError:
                pass
        cfg.update({k: v for k, v in overrides.items() if v is not None})
        if not cfg.get("host"):
            raise SAKClientError(
                f"No 'host' found for async target {target!r}."
            )
        return cfg

    def __repr__(self) -> str:  # pragma: no cover
        return f"AsyncSAKClient(target={self.target!r}, connected={self.client is not None})"


# ---------------------------------------------------------------------------
# Async ORM base
# ---------------------------------------------------------------------------

class AsyncSTIXBase:
    """
    Async-capable ORM base — thin wrapper around
    :class:`~ctm_sak.orm.base.STIXBase` that exposes awaitable CRUD methods.

    Parameters
    ----------
    client : AsyncSAKClient, optional
        Bound async client.
    **kwargs
        STIX property values forwarded to the underlying sync ORM object.

    Examples
    --------
    ::

        ind = AsyncIndicator(client=cli, name="Evil IP",
                             pattern="[ipv4-addr:value = '1.2.3.4']")
        await ind.select()
        await ind.save()
        await ind.delete()
    """

    _sync_cls: Any = None   # set by concrete subclasses

    def __init__(self, client: Optional["AsyncSAKClient"] = None, **kwargs: Any):
        self._async_client = client
        # Instantiate the underlying sync ORM object (no client — async manages I/O)
        if self._sync_cls:
            self._obj = self._sync_cls(**kwargs)
        self.__dict__.update(self._obj.__dict__ if self._sync_cls else {})

    def __getattr__(self, name: str) -> Any:
        try:
            return getattr(self._obj, name)
        except AttributeError:
            raise AttributeError(f"{type(self).__name__} has no attribute {name!r}")

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_") or name in ("stix_type",):
            super().__setattr__(name, value)
        elif hasattr(self, "_obj"):
            setattr(self._obj, name, value)
        else:
            super().__setattr__(name, value)

    def _require_client(self) -> None:
        if self._async_client is None or self._async_client.client is None:
            raise RuntimeError(
                f"No async client bound to {type(self).__name__}. "
                "Pass client= when constructing or await AsyncSAKClient.connect() first."
            )

    async def select(self) -> "AsyncSTIXBase":
        """Async fetch this object from the platform by id."""
        self._require_client()
        data = await self._async_client.client.get_object(
            self._obj.stix_type, self._obj.id
        )
        translated = await asyncio.get_event_loop().run_in_executor(
            None, self._async_client.client.to_stix, data
        )
        self._obj._merge(translated)
        return self

    async def save(self) -> "AsyncSTIXBase":
        """Async create or update this object on the platform."""
        self._require_client()
        payload = self._async_client.client.from_stix(self._obj.to_dict())
        result = await self._async_client.client.upsert_object(
            self._obj.stix_type, payload
        )
        translated = self._async_client.client.to_stix(result)
        self._obj._merge(translated)
        return self

    async def delete(self) -> None:
        """Async delete this object from the platform."""
        self._require_client()
        await self._async_client.client.delete_object(
            self._obj.stix_type, self._obj.id
        )

    async def refresh(self) -> "AsyncSTIXBase":
        """Re-fetch and update from the platform."""
        return await self.select()

    def to_dict(self) -> dict:
        return self._obj.to_dict()

    def to_stix_bundle(self) -> dict:
        return self._obj.to_stix_bundle()

    def __repr__(self) -> str:  # pragma: no cover
        return f"Async{type(self).__name__}(id={self._obj.id!r})"

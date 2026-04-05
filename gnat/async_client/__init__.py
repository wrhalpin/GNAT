"""
gnat.async_client
====================

Async (httpx-based) client layer for GNAT.

Requires: ``pip install "gnat[async]"``

Quick start::

    import asyncio
    import gnat.async_client as async_ctm

    async def main():
        async with async_ctm.AsyncGNATClient() as cli:
            await cli.connect("threatq")
            print(await cli.ping())

    asyncio.run(main())
"""

from gnat.async_client.base import AsyncBaseClient
from gnat.async_client.client import AsyncGNATClient, AsyncSTIXBase
from gnat.async_client.connectors import (
    AsyncCrowdStrikeClient,
    AsyncFeedlyClient,
    AsyncGreyMatterClient,
    AsyncNetskopeClient,
    AsyncProofpointClient,
    AsyncRecordedFutureClient,
    AsyncRiskReconClient,
    AsyncSplunkClient,
    AsyncThreatQClient,
    AsyncWhisticClient,
    AsyncXSOARClient,
)

__all__ = [
    "AsyncBaseClient",
    "AsyncGNATClient",
    "AsyncSTIXBase",
    "AsyncThreatQClient",
    "AsyncCrowdStrikeClient",
    "AsyncProofpointClient",
    "AsyncNetskopeClient",
    "AsyncXSOARClient",
    "AsyncRecordedFutureClient",
    "AsyncGreyMatterClient",
    "AsyncWhisticClient",
    "AsyncRiskReconClient",
    "AsyncFeedlyClient",
    "AsyncSplunkClient",
]

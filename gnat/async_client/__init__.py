"""
gnat.async_client
====================

Async (httpx-based) client layer for GNAT.

Requires: ``pip install "gnat[async]"``

Quick start::

    import asyncio
    import gnat.async_client as async_ctm

    async def main():
        async with async_ctm.AsyncSAKClient() as cli:
            await cli.connect("threatq")
            print(await cli.ping())

    asyncio.run(main())
"""

from gnat.async_client.base import AsyncBaseClient
from gnat.async_client.client import AsyncSAKClient, AsyncSTIXBase
from gnat.async_client.connectors import (
    AsyncThreatQClient,
    AsyncCrowdStrikeClient,
    AsyncProofpointClient,
    AsyncNetskopeClient,
    AsyncXSOARClient,
    AsyncRecordedFutureClient,
    AsyncGreyMatterClient,
    AsyncWhisticClient,
    AsyncRiskReconClient,
    AsyncFeedlyClient,
    AsyncSplunkClient,
)

__all__ = [
    "AsyncBaseClient",
    "AsyncSAKClient",
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

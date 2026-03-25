"""
ctm_sak.async_client
====================

Async (httpx-based) client layer for CTM-SAK.

Requires: ``pip install "ctm-sak[async]"``

Quick start::

    import asyncio
    import ctm_sak.async_client as async_ctm

    async def main():
        async with async_ctm.AsyncSAKClient() as cli:
            await cli.connect("threatq")
            print(await cli.ping())

    asyncio.run(main())
"""

from ctm_sak.async_client.base import AsyncBaseClient
from ctm_sak.async_client.client import AsyncSAKClient, AsyncSTIXBase
from ctm_sak.async_client.connectors import (
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

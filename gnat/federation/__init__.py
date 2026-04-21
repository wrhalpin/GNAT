# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.federation
================

Federated multi-GNAT deployment layer.

Enables peer-to-peer (mesh) and hierarchical (parent/subsidiary)
sharing of STIX 2.1 threat intelligence between independent GNAT
instances using the TAXII 2.1 protocol.

Quick start
-----------
::

    from gnat.federation import PeerRegistry, PeerSyncService, FederationScheduler

    # Register a peer
    registry = PeerRegistry()
    registry.register(
        "acme-east",
        taxii_url="https://gnat-east.acme.com/taxii2/",
        api_key="Bearer your-token",
        max_tlp="amber",
        workspace_filter=["threats-2025"],
    )

    # Sync now (pull direction)
    svc = PeerSyncService()
    peer = registry.get("acme-east")
    result = svc.sync_from_peer(peer, added_after="2026-01-01T00:00:00Z")
    print(result)

    # Scheduled background sync
    scheduler = FederationScheduler(registry=registry, sync_service=svc)
    scheduler.start()
"""

from gnat.federation.peer import FederationPeer, PeerRegistry
from gnat.federation.scheduler import FederationScheduler
from gnat.federation.sync import FederationError, PeerSyncService, PullResult, PushResult
from gnat.federation.topology import FederationTopology

__all__ = [
    "FederationPeer",
    "PeerRegistry",
    "FederationError",
    "PeerSyncService",
    "PullResult",
    "PushResult",
    "FederationScheduler",
    "FederationTopology",
]

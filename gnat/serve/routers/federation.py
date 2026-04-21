# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.serve.routers.federation
==============================

FastAPI router for the federated multi-GNAT deployment layer.

Endpoints
---------
GET    /api/federation/peers                    list all peers with status
POST   /api/federation/peers                    register a new peer
DELETE /api/federation/peers/{peer_id}          remove a peer
GET    /api/federation/peers/{peer_id}/health   ping remote TAXII server
POST   /api/federation/peers/{peer_id}/sync     trigger an immediate sync
GET    /api/federation/topology                 mesh/hierarchy graph JSON

Registration
------------
Attach a :class:`~gnat.federation.peer.PeerRegistry` and
:class:`~gnat.federation.scheduler.FederationScheduler` via ``app.state``::

    from gnat.federation.peer import PeerRegistry
    from gnat.federation.sync import PeerSyncService
    from gnat.federation.scheduler import FederationScheduler
    from gnat.federation.topology import FederationTopology
    from gnat.serve.app import create_app

    registry  = PeerRegistry()
    sync_svc  = PeerSyncService()
    scheduler = FederationScheduler(registry=registry, sync_service=sync_svc)
    scheduler.start()

    app = create_app(
        api_key="secret",
        federation_registry=registry,
        federation_scheduler=scheduler,
    )
"""

from __future__ import annotations

import logging
from typing import Any

try:
    from fastapi import APIRouter, HTTPException, Request
    from fastapi.responses import JSONResponse
except ImportError:  # pragma: no cover
    raise ImportError('FastAPI is required. Run: pip install "gnat[serve]"')

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/federation", tags=["federation"])


# ---------------------------------------------------------------------------
# State helpers
# ---------------------------------------------------------------------------


def _registry(request: Request) -> Any:
    reg = getattr(request.app.state, "federation_registry", None)
    if reg is None:
        raise HTTPException(
            status_code=503,
            detail="Federation registry not configured on this server.",
        )
    return reg


def _scheduler(request: Request) -> Any:
    sched = getattr(request.app.state, "federation_scheduler", None)
    if sched is None:
        raise HTTPException(
            status_code=503,
            detail="Federation scheduler not configured on this server.",
        )
    return sched


# ---------------------------------------------------------------------------
# Peers — list / register / delete
# ---------------------------------------------------------------------------


@router.get("/peers")
def list_peers(request: Request, enabled_only: bool = False) -> Any:
    """List all registered federation peers with current sync status."""
    registry = _registry(request)
    peers = registry.list(enabled_only=enabled_only)
    return {
        "peers": [_peer_to_dict(p) for p in peers],
        "count": len(peers),
    }


@router.post("/peers")
def register_peer(request: Request, body: dict[str, Any]) -> Any:
    """
    Register a new federation peer.

    Body fields:

    - ``peer_id``               (str, required) — unique slug
    - ``taxii_url``             (str, required) — remote TAXII 2.1 base URL
    - ``api_key``               (str, required) — bearer token for remote
    - ``display_name``          (str, optional)
    - ``direction``             (str, optional, default ``"pull"``) — pull | push | both
    - ``max_tlp``               (str, optional, default ``"green"``)
    - ``parent_peer_id``        (str, optional) — declare hierarchy
    - ``sync_interval_seconds`` (int, optional, default ``3600``)
    - ``workspace_filter``      (list[str], optional) — explicit workspaces to sync
    - ``enabled``               (bool, optional, default ``True``)
    """
    from gnat.federation.peer import PeerRegistry

    registry: PeerRegistry = _registry(request)

    peer_id = body.get("peer_id", "")
    if not peer_id:
        raise HTTPException(status_code=400, detail="peer_id is required.")

    try:
        peer = registry.register(
            peer_id=peer_id,
            taxii_url=body.get("taxii_url", ""),
            api_key=body.get("api_key", ""),
            display_name=body.get("display_name", ""),
            direction=body.get("direction", "pull"),
            max_tlp=body.get("max_tlp", "green"),
            parent_peer_id=body.get("parent_peer_id"),
            sync_interval_seconds=int(body.get("sync_interval_seconds", 3600)),
            workspace_filter=body.get("workspace_filter", []),
            enabled=bool(body.get("enabled", True)),
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Wire into scheduler if it's running
    try:
        sched = getattr(request.app.state, "federation_scheduler", None)
        if sched is not None and peer.enabled:
            sched.add_peer(peer)
    except Exception:  # noqa: BLE001
        pass  # scheduler not running — peer still registered

    return JSONResponse(status_code=201, content=_peer_to_dict(peer))


@router.delete("/peers/{peer_id}")
def delete_peer(peer_id: str, request: Request) -> Any:
    """Remove a federation peer and cancel its sync job."""
    from gnat.federation.peer import PeerRegistry

    registry: PeerRegistry = _registry(request)

    peer = registry.get(peer_id)
    if peer is None:
        raise HTTPException(status_code=404, detail=f"Peer {peer_id!r} not found.")

    # Remove from scheduler first
    try:
        sched = getattr(request.app.state, "federation_scheduler", None)
        if sched is not None:
            sched.remove_peer(peer_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to remove peer %s from scheduler: %s", peer_id, exc)

    registry.delete(peer_id)
    return {"deleted": peer_id}


# ---------------------------------------------------------------------------
# Health check for a single peer
# ---------------------------------------------------------------------------


@router.get("/peers/{peer_id}/health")
def peer_health(peer_id: str, request: Request) -> Any:
    """
    Ping the remote TAXII discovery endpoint for *peer_id*.

    Returns ``{"reachable": true, "latency_ms": <float>}`` on success or
    ``{"reachable": false, "error": "<message>"}`` if the ping fails.
    """
    import time

    registry = _registry(request)
    peer = registry.get(peer_id)
    if peer is None:
        raise HTTPException(status_code=404, detail=f"Peer {peer_id!r} not found.")

    try:
        from gnat.connectors.gnat_remote.connector import GNATRemoteConnector

        host = peer.taxii_url.rstrip("/")
        for suffix in ("/taxii2", "/taxii2/"):
            if host.endswith(suffix):
                host = host[: -len(suffix)]
                break

        connector = GNATRemoteConnector(host=host, api_key=peer.api_key)
        connector.authenticate()

        t0 = time.perf_counter()
        reachable = connector.health_check()
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        return {"peer_id": peer_id, "reachable": reachable, "latency_ms": latency_ms}
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            status_code=200,
            content={"peer_id": peer_id, "reachable": False, "error": str(exc)},
        )


# ---------------------------------------------------------------------------
# Immediate sync trigger
# ---------------------------------------------------------------------------


@router.post("/peers/{peer_id}/sync")
def trigger_sync(peer_id: str, request: Request) -> Any:
    """
    Trigger an immediate federation sync for *peer_id*.

    Returns the scheduler job run record summary.
    """
    from gnat.federation.peer import PeerRegistry
    from gnat.federation.sync import FederationError, PeerSyncService

    registry: PeerRegistry = _registry(request)
    peer = registry.get(peer_id)
    if peer is None:
        raise HTTPException(status_code=404, detail=f"Peer {peer_id!r} not found.")

    if not peer.enabled:
        raise HTTPException(status_code=409, detail=f"Peer {peer_id!r} is disabled.")

    # Try scheduler trigger first (preserves incremental state)
    sched = getattr(request.app.state, "federation_scheduler", None)
    if sched is not None:
        try:
            run_record = sched.trigger(peer_id)
            return {"peer_id": peer_id, "triggered": True, "run_record": str(run_record)}
        except KeyError:
            pass  # job not registered yet — fall through to direct sync

    # Direct sync fallback
    sync_svc = getattr(request.app.state, "federation_sync_service", None)
    if sync_svc is None:
        sync_svc = PeerSyncService()

    try:
        result = sync_svc.sync_from_peer(peer=peer)
        registry.update_sync_status(peer_id, "success")
        return {
            "peer_id": peer_id,
            "triggered": True,
            "workspaces_synced": result.workspaces_synced,
            "objects_accepted": result.objects_accepted,
            "errors": result.errors,
        }
    except FederationError as exc:
        registry.update_sync_status(peer_id, "failed")
        raise HTTPException(status_code=502, detail=str(exc))


# ---------------------------------------------------------------------------
# Topology graph
# ---------------------------------------------------------------------------


@router.get("/topology")
def get_topology(request: Request) -> Any:
    """
    Return the federation topology graph.

    The response contains:

    - ``nodes`` — all peers with metadata
    - ``edges`` — directed edges (hierarchical) and undirected mesh edges
    - ``hierarchy_edges`` — subset of edges that cross parent-child boundaries
    - ``total_peers`` / ``enabled_peers`` — summary counts
    """
    from gnat.federation.topology import FederationTopology

    registry = _registry(request)
    topo = FederationTopology(registry)
    return topo.hierarchy_graph()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _peer_to_dict(peer: Any) -> dict[str, Any]:
    """Serialize a FederationPeer to a JSON-safe dict."""
    return {
        "peer_id": peer.peer_id,
        "display_name": peer.display_name,
        "taxii_url": peer.taxii_url,
        "direction": peer.direction,
        "max_tlp": peer.max_tlp,
        "parent_peer_id": peer.parent_peer_id,
        "sync_interval_seconds": peer.sync_interval_seconds,
        "workspace_filter": peer.workspace_filter,
        "enabled": peer.enabled,
        "created_at": peer.created_at,
        "last_sync_at": peer.last_sync_at,
        "last_sync_status": peer.last_sync_status,
        "can_pull": peer.can_pull,
        "can_push": peer.can_push,
    }

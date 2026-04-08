# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.federation.sync
=====================

Core synchronisation service for federated GNAT deployments.

Provides pull (fetch from peer) and push (send to peer) operations with
TLP-level enforcement on every object before transmission.

Conflict resolution
-------------------
Last-write-wins based on the STIX 2.1 ``modified`` timestamp:

* Incoming object's ``modified > stored object's modified`` → accept
* Incoming ``modified ≤ stored modified`` → skip (local version is newer)

This matches STIX 2.1 versioning semantics and requires no distributed locking.

TLP gate
--------
Before any object is transmitted to a peer, ``_tlp_allowed(obj, peer)``
checks that the object's ``x_tlp`` field does not exceed the peer's
``max_tlp`` ceiling.  Objects that would violate the ceiling are silently
dropped (logged at DEBUG level).
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gnat.federation.peer import FederationPeer

logger = logging.getLogger(__name__)

# TLP rank map — must match gnat.analysis.tlp._RANKS
_TLP_RANKS: dict[str, int] = {
    "white": 0,
    "clear": 0,
    "green": 1,
    "amber": 2,
    "amber+strict": 3,
    "red": 4,
}


class FederationError(Exception):
    """Raised when a federation sync operation fails unrecoverably."""


# ---------------------------------------------------------------------------
# Sync service
# ---------------------------------------------------------------------------


class PeerSyncService:
    """
    Orchestrates pull and push synchronisation between GNAT peers.

    Parameters
    ----------
    workspace_manager : WorkspaceManager, optional
        Used to open/create local workspaces for received objects.
        When ``None``, objects are returned rather than persisted
        (useful for testing or streaming pipelines).
    """

    def __init__(self, workspace_manager: Any = None) -> None:
        """Initialize PeerSyncService."""
        self._wm = workspace_manager

    # ------------------------------------------------------------------
    # TLP gate
    # ------------------------------------------------------------------

    @staticmethod
    def _tlp_allowed(obj: dict[str, Any], peer: "FederationPeer") -> bool:
        """
        Return True if *obj* may be shared with *peer*.

        Compares the object's ``x_tlp`` field (defaulting to ``"green"``)
        against the peer's ``max_tlp`` ceiling.

        Parameters
        ----------
        obj : dict
            STIX 2.1 object dict.
        peer : FederationPeer
            Target peer with ``max_tlp`` attribute.
        """
        obj_tlp = str(obj.get("x_tlp") or "green").lower()
        obj_rank = _TLP_RANKS.get(obj_tlp, 1)  # unknown → treat as GREEN
        ceiling_rank = _TLP_RANKS.get(peer.max_tlp, 1)
        return obj_rank <= ceiling_rank

    # ------------------------------------------------------------------
    # Pull: fetch from peer
    # ------------------------------------------------------------------

    def sync_from_peer(
        self,
        peer: "FederationPeer",
        added_after: str | None = None,
        dry_run: bool = False,
    ) -> "PullResult":
        """
        Pull new objects from a remote GNAT peer into local workspaces.

        For each workspace listed in ``peer.workspace_filter``:

        1. Create a ``GNATRemoteConnector`` for the peer.
        2. Fetch objects added since *added_after* (or all if None).
        3. Apply the TLP gate — drop objects above ``peer.max_tlp``.
        4. Apply conflict resolution — skip objects whose remote ``modified``
           timestamp is not newer than the locally stored version.
        5. Write accepted objects to the local workspace with
           ``source_platform = "peer:<peer_id>"``.

        Parameters
        ----------
        peer : FederationPeer
            The peer to pull from.  Must have ``can_pull == True`` and a
            non-empty ``workspace_filter``.
        added_after : str, optional
            ISO-8601 timestamp for incremental sync.  Objects added before
            this timestamp are skipped by the remote server.
        dry_run : bool
            If ``True``, fetch and filter objects but do not write to
            local workspaces.  Returns the list of accepted objects.

        Returns
        -------
        PullResult
            Summary of the sync run.

        Raises
        ------
        FederationError
            If the peer is unreachable, disabled, or not configured for pull.
        """
        if not peer.enabled:
            raise FederationError(f"Peer {peer.peer_id!r} is disabled.")
        if not peer.can_pull:
            raise FederationError(
                f"Peer {peer.peer_id!r} direction is {peer.direction!r} — pull not allowed."
            )
        if not peer.workspace_filter:
            raise FederationError(
                f"Peer {peer.peer_id!r} has an empty workspace_filter. "
                "Explicitly list workspace names to sync (empty list = nothing shared)."
            )

        result = PullResult(peer_id=peer.peer_id)

        try:
            connector = self._make_connector(peer)
        except Exception as exc:
            raise FederationError(
                f"Failed to initialise connector for peer {peer.peer_id!r}: {exc}"
            ) from exc

        for workspace_name in peer.workspace_filter:
            try:
                accepted = self._pull_workspace(
                    connector=connector,
                    peer=peer,
                    workspace_name=workspace_name,
                    added_after=added_after,
                    dry_run=dry_run,
                )
                result.workspaces_synced.append(workspace_name)
                result.objects_accepted += accepted
            except FederationError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Sync from peer %r workspace %r failed: %s",
                    peer.peer_id, workspace_name, exc,
                )
                result.errors.append(f"{workspace_name}: {exc}")

        logger.info(
            "Pull from peer %r complete — %d workspaces, %d objects accepted, %d errors",
            peer.peer_id,
            len(result.workspaces_synced),
            result.objects_accepted,
            len(result.errors),
        )
        return result

    def _pull_workspace(
        self,
        connector: Any,
        peer: "FederationPeer",
        workspace_name: str,
        added_after: str | None,
        dry_run: bool,
    ) -> int:
        """Pull objects from one workspace and write to local store. Returns count."""
        objects = connector.fetch_objects(
            workspace=workspace_name,
            added_after=added_after,
            limit=100,
        )

        accepted = 0
        local_ws = None
        if not dry_run and self._wm is not None:
            local_ws = self._wm.get_or_create(workspace_name)

        for obj in objects:
            if not isinstance(obj, dict):
                continue

            # TLP gate
            if not self._tlp_allowed(obj, peer):
                logger.debug(
                    "Dropped object %s from peer %r — TLP %s exceeds ceiling %s",
                    obj.get("id", "?"), peer.peer_id, obj.get("x_tlp", "green"), peer.max_tlp,
                )
                continue

            obj_id = obj.get("id", "")
            obj_modified = obj.get("modified", "")

            # Conflict resolution: last-write-wins on 'modified'
            if local_ws is not None and obj_id:
                existing = local_ws.objects.get(obj_id)
                if existing is not None:
                    existing_modified = getattr(existing, "modified", None) or ""
                    if existing_modified and obj_modified <= existing_modified:
                        logger.debug(
                            "Skipping %s — local modified %s >= incoming %s",
                            obj_id, existing_modified, obj_modified,
                        )
                        continue

            if not dry_run and local_ws is not None:
                try:
                    from gnat.orm.base import STIXBase
                    stix_obj = STIXBase.from_dict(obj)
                    stix_obj._properties["x_federation_peer"] = peer.peer_id
                    local_ws.objects[stix_obj.id] = stix_obj
                    local_ws.dirty.add(stix_obj.id)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Failed to ingest object %s: %s", obj_id, exc)
                    continue

            accepted += 1

        if not dry_run and local_ws is not None and accepted > 0:
            try:
                local_ws.save()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to save workspace %r: %s", workspace_name, exc)

        return accepted

    # ------------------------------------------------------------------
    # Push: send to peer
    # ------------------------------------------------------------------

    def push_to_peer(
        self,
        peer: "FederationPeer",
        objects: list[dict[str, Any]],
        workspace_name: str,
    ) -> "PushResult":
        """
        Push a list of STIX objects to a remote GNAT peer.

        1. Apply the TLP gate — objects above ``peer.max_tlp`` are dropped.
        2. Build a STIX bundle from accepted objects.
        3. POST the bundle to the peer's TAXII collection for *workspace_name*.

        Parameters
        ----------
        peer : FederationPeer
            The peer to push to.  Must have ``can_push == True``.
        objects : list[dict]
            STIX 2.1 object dicts to push.
        workspace_name : str
            Target workspace on the remote peer.

        Returns
        -------
        PushResult
            Summary of the push operation.

        Raises
        ------
        FederationError
            If the peer is disabled or does not allow push.
        """
        if not peer.enabled:
            raise FederationError(f"Peer {peer.peer_id!r} is disabled.")
        if not peer.can_push:
            raise FederationError(
                f"Peer {peer.peer_id!r} direction is {peer.direction!r} — push not allowed."
            )

        result = PushResult(peer_id=peer.peer_id, workspace=workspace_name)

        # TLP gate
        allowed = [o for o in objects if self._tlp_allowed(o, peer)]
        dropped = len(objects) - len(allowed)
        if dropped:
            logger.debug(
                "Dropped %d/%d objects before push to peer %r (TLP ceiling: %s)",
                dropped, len(objects), peer.peer_id, peer.max_tlp,
            )
        result.objects_dropped_tlp = dropped

        if not allowed:
            logger.info("Nothing to push to peer %r (all filtered by TLP gate).", peer.peer_id)
            return result

        try:
            connector = self._make_connector(peer, workspace=workspace_name)
            status = connector.push_bundle(workspace=workspace_name, objects=allowed)
            result.objects_pushed = len(allowed)
            result.remote_status = status.get("status", "unknown") if isinstance(status, dict) else "unknown"
            logger.info(
                "Pushed %d objects to peer %r workspace %r — status: %s",
                len(allowed), peer.peer_id, workspace_name, result.remote_status,
            )
        except Exception as exc:
            result.error = str(exc)
            logger.error(
                "Push to peer %r workspace %r failed: %s",
                peer.peer_id, workspace_name, exc,
            )

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_connector(self, peer: "FederationPeer", workspace: str = "") -> Any:
        """Create and authenticate a GNATRemoteConnector for *peer*."""
        from gnat.connectors.gnat_remote.connector import GNATRemoteConnector

        host = peer.taxii_url.rstrip("/")
        # Strip TAXII path suffix to get the host root
        for suffix in ("/taxii2", "/taxii2/"):
            if host.endswith(suffix):
                host = host[: -len(suffix)]
                break

        connector = GNATRemoteConnector(
            host=host,
            api_key=peer.api_key,
            workspace=workspace,
        )
        connector.authenticate()
        return connector


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


class PullResult:
    """Summary of a pull sync operation."""

    def __init__(self, peer_id: str) -> None:
        """Initialize PullResult."""
        self.peer_id = peer_id
        self.workspaces_synced: list[str] = []
        self.objects_accepted: int = 0
        self.errors: list[str] = []

    @property
    def success(self) -> bool:
        """True if at least one workspace synced without error."""
        return bool(self.workspaces_synced) and not self.errors

    def __repr__(self) -> str:
        """Return repr of PullResult."""
        return (
            f"PullResult(peer={self.peer_id!r}, workspaces={self.workspaces_synced}, "
            f"accepted={self.objects_accepted}, errors={len(self.errors)})"
        )


class PushResult:
    """Summary of a push sync operation."""

    def __init__(self, peer_id: str, workspace: str) -> None:
        """Initialize PushResult."""
        self.peer_id = peer_id
        self.workspace = workspace
        self.objects_pushed: int = 0
        self.objects_dropped_tlp: int = 0
        self.remote_status: str = ""
        self.error: str | None = None

    @property
    def success(self) -> bool:
        """True if push completed without error."""
        return self.error is None

    def __repr__(self) -> str:
        """Return repr of PushResult."""
        return (
            f"PushResult(peer={self.peer_id!r}, workspace={self.workspace!r}, "
            f"pushed={self.objects_pushed}, dropped_tlp={self.objects_dropped_tlp}, "
            f"status={self.remote_status!r})"
        )

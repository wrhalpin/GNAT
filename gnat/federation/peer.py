# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.federation.peer
=====================

Federation peer model and registry.

A *peer* represents another GNAT instance that this node can exchange
threat intelligence with over TAXII 2.1.

Topologies
----------
**Mesh** — declare peers without ``parent_peer_id``.  Every node that
references another node is a symmetric mesh peer.

**Hierarchical** — set ``parent_peer_id`` on subsidiary nodes.  The parent
then appears as a special ancestor in the topology graph.

TLP sharing is controlled per-edge via ``max_tlp``:

* ``"pull"`` direction: this node fetches objects *from* the peer.
* ``"push"`` direction: this node sends objects *to* the peer.
* ``"both"`` direction: bidirectional sync (requires both sides configured).

The default direction is ``"pull"`` — push must be explicitly opted in.

Usage
-----
::

    from gnat.federation.peer import PeerRegistry

    registry = PeerRegistry()
    registry.register(
        "acme-east",
        taxii_url="https://gnat-east.acme.com/taxii2/",
        api_key="Bearer peer-token",
        max_tlp="amber",
        workspace_filter=["threats-2025", "apt-tracking"],
    )
    peer = registry.get("acme-east")
    print(peer.taxii_url)
"""

from __future__ import annotations

import builtins
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Peer ID validation: same rules as tenant_id
_PEER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")

_VALID_DIRECTIONS = frozenset({"pull", "push", "both"})
_VALID_TLP = frozenset({"white", "clear", "green", "amber", "amber+strict", "red"})


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# FederationPeer dataclass
# ---------------------------------------------------------------------------


@dataclass
class FederationPeer:
    """
    Metadata record for a registered federation peer.

    Attributes
    ----------
    peer_id : str
        Unique slug for this peer (e.g. ``"acme-east"``).
    display_name : str
        Human-readable name.
    taxii_url : str
        Root URL of the remote GNAT TAXII 2.1 server
        (e.g. ``"https://gnat.acme.com/taxii2/"``).
    api_key : str
        Bearer token for authenticating to the remote TAXII server.
        Stored as-is; include the ``"Bearer "`` prefix if required.
    direction : str
        Sync direction: ``"pull"`` (fetch from peer), ``"push"`` (send to
        peer), or ``"both"``.  Default ``"pull"``.
    max_tlp : str
        TLP ceiling for this peer edge.  Objects with a TLP rank *above*
        this value are never shared.  Default ``"green"``.
    parent_peer_id : str or None
        If set, declares this node as a *child* of the named peer,
        creating a hierarchical relationship.  Default ``None`` (mesh).
    sync_interval_seconds : int
        How often to pull/push.  Default ``3600`` (hourly).
    workspace_filter : list[str]
        Explicit list of workspace names to sync.  **Empty list means
        nothing is shared** — workspaces must be explicitly named.
    enabled : bool
        Whether this peer is active.  Default ``True``.
    created_at : str
        ISO-8601 creation timestamp (set automatically).
    last_sync_at : str or None
        ISO-8601 timestamp of most recent successful sync run.
    last_sync_status : str or None
        ``"success"``, ``"failed"``, or ``None`` (never synced).
    """

    peer_id: str
    display_name: str = ""
    taxii_url: str = ""
    api_key: str = ""
    direction: str = "pull"
    max_tlp: str = "green"
    parent_peer_id: str | None = None
    sync_interval_seconds: int = 3600
    workspace_filter: list[str] = field(default_factory=list)
    enabled: bool = True
    created_at: str = field(default_factory=_utcnow_iso)
    last_sync_at: str | None = None
    last_sync_status: str | None = None

    def __post_init__(self) -> None:
        """Validate FederationPeer fields."""
        if not _PEER_ID_RE.match(self.peer_id):
            raise ValueError(
                f"Invalid peer_id {self.peer_id!r}. Must be lowercase alphanumeric "
                "with optional hyphens/underscores, 1–63 chars, starting with a letter or digit."
            )
        if self.direction not in _VALID_DIRECTIONS:
            raise ValueError(
                f"Invalid direction {self.direction!r}. Must be one of: "
                + ", ".join(sorted(_VALID_DIRECTIONS))
            )
        if self.max_tlp not in _VALID_TLP:
            raise ValueError(
                f"Invalid max_tlp {self.max_tlp!r}. Must be one of: "
                + ", ".join(sorted(_VALID_TLP))
            )
        if not self.display_name:
            self.display_name = self.peer_id

    @property
    def can_pull(self) -> bool:
        """Return True if this peer relationship allows pulling (fetching from peer)."""
        return self.direction in ("pull", "both")

    @property
    def can_push(self) -> bool:
        """Return True if this peer relationship allows pushing (sending to peer)."""
        return self.direction in ("push", "both")


# ---------------------------------------------------------------------------
# PeerRegistry
# ---------------------------------------------------------------------------


class PeerRegistry:
    """
    JSON-backed registry of federation peers.

    Persists to ``~/.gnat/federation_peers.json`` by default.

    Parameters
    ----------
    registry_path : str, optional
        Path to the JSON registry file.  Created automatically on first write.

    Examples
    --------
    ::

        registry = PeerRegistry()
        registry.register(
            "acme-east",
            taxii_url="https://gnat-east.acme.com/taxii2/",
            api_key="Bearer token",
            max_tlp="amber",
            workspace_filter=["threats-2025"],
        )
        peer = registry.get("acme-east")
        registry.update_sync_status("acme-east", "success", "2026-01-01T12:00:00+00:00")
        registry.delete("acme-east")
    """

    DEFAULT_PATH = "~/.gnat/federation_peers.json"

    def __init__(self, registry_path: str | None = None) -> None:
        """Initialize PeerRegistry."""
        self._path = Path(registry_path or self.DEFAULT_PATH).expanduser()
        self._peers: dict[str, FederationPeer] = {}
        self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            for pid, pd in raw.items():
                try:
                    self._peers[pid] = FederationPeer(**pd)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Skipping malformed peer entry %r: %s", pid, exc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to load peer registry from %s: %s", self._path, exc)

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(
                {pid: asdict(p) for pid, p in self._peers.items()},
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def register(
        self,
        peer_id: str,
        display_name: str = "",
        taxii_url: str = "",
        api_key: str = "",
        direction: str = "pull",
        max_tlp: str = "green",
        parent_peer_id: str | None = None,
        sync_interval_seconds: int = 3600,
        workspace_filter: list[str] | None = None,
        enabled: bool = True,
    ) -> FederationPeer:
        """
        Register a new federation peer.

        Raises
        ------
        ValueError
            If *peer_id* is invalid or already registered.
        """
        if peer_id in self._peers:
            raise ValueError(f"Peer {peer_id!r} is already registered. Use update() to modify it.")
        peer = FederationPeer(
            peer_id=peer_id,
            display_name=display_name,
            taxii_url=taxii_url,
            api_key=api_key,
            direction=direction,
            max_tlp=max_tlp,
            parent_peer_id=parent_peer_id,
            sync_interval_seconds=sync_interval_seconds,
            workspace_filter=list(workspace_filter or []),
            enabled=enabled,
        )
        self._peers[peer_id] = peer
        self._save()
        logger.info("Registered federation peer %r", peer_id)
        return peer

    def get(self, peer_id: str) -> FederationPeer | None:
        """Return the :class:`FederationPeer` for *peer_id*, or ``None``."""
        return self._peers.get(peer_id)

    def list(self, enabled_only: bool = False) -> builtins.list[FederationPeer]:
        """Return all peers sorted by peer_id."""
        peers = sorted(self._peers.values(), key=lambda p: p.peer_id)
        if enabled_only:
            peers = [p for p in peers if p.enabled]
        return peers

    def update(
        self,
        peer_id: str,
        display_name: str | None = None,
        taxii_url: str | None = None,
        api_key: str | None = None,
        direction: str | None = None,
        max_tlp: str | None = None,
        parent_peer_id: str | None = ...,  # type: ignore[assignment]
        sync_interval_seconds: int | None = None,
        workspace_filter: list[str] | None = None,
        enabled: bool | None = None,
    ) -> FederationPeer:
        """
        Update mutable fields of an existing peer.

        Raises
        ------
        KeyError
            If *peer_id* is not registered.
        """
        peer = self._peers.get(peer_id)
        if peer is None:
            raise KeyError(f"Peer {peer_id!r} not found.")
        if display_name is not None:
            peer.display_name = display_name
        if taxii_url is not None:
            peer.taxii_url = taxii_url
        if api_key is not None:
            peer.api_key = api_key
        if direction is not None:
            if direction not in _VALID_DIRECTIONS:
                raise ValueError(f"Invalid direction {direction!r}.")
            peer.direction = direction
        if max_tlp is not None:
            if max_tlp not in _VALID_TLP:
                raise ValueError(f"Invalid max_tlp {max_tlp!r}.")
            peer.max_tlp = max_tlp
        if parent_peer_id is not ...:  # type: ignore[comparison-overlap]
            peer.parent_peer_id = parent_peer_id  # type: ignore[assignment]
        if sync_interval_seconds is not None:
            peer.sync_interval_seconds = sync_interval_seconds
        if workspace_filter is not None:
            peer.workspace_filter = list(workspace_filter)
        if enabled is not None:
            peer.enabled = enabled
        self._save()
        return peer

    def update_sync_status(
        self,
        peer_id: str,
        status: str,
        timestamp: str | None = None,
    ) -> None:
        """
        Record the outcome of a sync run for *peer_id*.

        Parameters
        ----------
        peer_id : str
            Target peer.
        status : str
            ``"success"`` or ``"failed"``.
        timestamp : str, optional
            ISO-8601 timestamp.  Defaults to UTC now.
        """
        peer = self._peers.get(peer_id)
        if peer is None:
            return
        peer.last_sync_status = status
        if status == "success":
            peer.last_sync_at = timestamp or _utcnow_iso()
        self._save()

    def delete(self, peer_id: str) -> bool:
        """
        Remove a peer from the registry.

        Returns ``True`` if found and removed, ``False`` otherwise.
        """
        if peer_id not in self._peers:
            return False
        del self._peers[peer_id]
        self._save()
        logger.info("Deleted federation peer %r", peer_id)
        return True

    # ------------------------------------------------------------------
    # Config factory
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls, config: Any, registry_path: str | None = None) -> PeerRegistry:
        """
        Build a ``PeerRegistry`` from a :class:`~gnat.config.GNATConfig` instance.

        Reads all INI sections matching ``federation.peer.<name>`` and registers
        each as a peer.  The registry file path comes from the ``[federation]``
        section's ``registry`` key, or the *registry_path* parameter.

        Parameters
        ----------
        config : GNATConfig
            Parsed configuration object.
        registry_path : str, optional
            Override the registry file path.
        """
        # Resolve registry file path
        path = registry_path
        try:
            fed_cfg = config.get("federation")
            path = path or fed_cfg.get("registry")
        except (KeyError, AttributeError):
            logger.debug("No [federation] registry path in config; using default")

        registry = cls(registry_path=path)

        # Discover federation.peer.* sections
        peer_prefix = "federation.peer."
        for section in config.sections:
            if not section.startswith(peer_prefix):
                continue
            peer_id = section[len(peer_prefix) :]
            if not peer_id:
                continue
            try:
                raw = config.get(section)
            except KeyError:
                continue

            wf_raw = raw.get("workspace_filter", "")
            workspace_filter = [w.strip() for w in wf_raw.split(",") if w.strip()] if wf_raw else []

            try:
                registry.register(
                    peer_id=peer_id,
                    display_name=raw.get("display_name", ""),
                    taxii_url=raw.get("taxii_url", ""),
                    api_key=raw.get("api_key", ""),
                    direction=raw.get("direction", "pull"),
                    max_tlp=raw.get("max_tlp", "green"),
                    parent_peer_id=raw.get("parent_peer_id") or None,
                    sync_interval_seconds=int(raw.get("sync_interval", 3600)),
                    workspace_filter=workspace_filter,
                    enabled=raw.get("enabled", "true").lower() != "false",
                )
            except ValueError as exc:
                logger.warning("Skipping peer %r from config: %s", peer_id, exc)

        return registry

    @classmethod
    def default(cls) -> PeerRegistry:
        """Return a PeerRegistry using the default path."""
        return cls()

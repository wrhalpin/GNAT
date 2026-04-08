# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.federation.scheduler
==========================

Automated federation sync scheduling.

``FederationScheduler`` creates one :class:`~gnat.schedule.job.FeedJob`
per enabled peer and runs them on their configured ``sync_interval_seconds``
using the platform's existing :class:`~gnat.schedule.scheduler.FeedScheduler`.

Job state persistence
---------------------
:class:`~gnat.schedule.job.FeedJob` keeps ``last_success_at`` in-memory
only.  After each successful run the scheduler calls
:meth:`~gnat.federation.peer.PeerRegistry.update_sync_status` so the
timestamp survives process restarts and is used as ``added_after`` on the
next run.

Usage
-----
::

    from gnat.federation.scheduler import FederationScheduler
    from gnat.federation.peer import PeerRegistry
    from gnat.federation.sync import PeerSyncService

    registry = PeerRegistry()
    sync_svc = PeerSyncService(workspace_manager=wm)
    scheduler = FederationScheduler(registry=registry, sync_service=sync_svc)
    scheduler.start()          # launches background threads
    scheduler.trigger("acme-east")  # one-off immediate sync
    scheduler.stop()
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gnat.federation.peer import FederationPeer, PeerRegistry
    from gnat.federation.sync import PeerSyncService

logger = logging.getLogger(__name__)


class FederationScheduler:
    """
    Manages periodic federation sync jobs for all registered peers.

    Parameters
    ----------
    registry : PeerRegistry
        Source of peer configuration.
    sync_service : PeerSyncService
        Performs the actual pull/push operations.
    """

    def __init__(
        self,
        registry: "PeerRegistry",
        sync_service: "PeerSyncService",
    ) -> None:
        """Initialize FederationScheduler."""
        self._registry = registry
        self._sync = sync_service
        self._jobs: dict[str, Any] = {}   # peer_id → FeedJob
        self._scheduler: Any = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Start the background scheduler and register jobs for all enabled peers.

        Lazily imports :class:`~gnat.schedule.scheduler.FeedScheduler` so
        the ``[schedule]`` extras group is not a hard dependency.
        """
        try:
            from gnat.schedule.scheduler import FeedScheduler
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                'FeedScheduler not available. Install via: pip install "gnat[schedule]"'
            ) from exc

        self._scheduler = FeedScheduler()

        for peer in self._registry.list(enabled_only=True):
            self._add_peer_job(peer)

        self._scheduler.start()
        logger.info("FederationScheduler started with %d peer jobs.", len(self._jobs))

    def stop(self) -> None:
        """Stop all background sync jobs."""
        if self._scheduler is not None:
            try:
                self._scheduler.stop()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Error stopping FederationScheduler: %s", exc)
        logger.info("FederationScheduler stopped.")

    # ------------------------------------------------------------------
    # Job management
    # ------------------------------------------------------------------

    def add_peer(self, peer: "FederationPeer") -> None:
        """
        Register a sync job for *peer* and start it if the scheduler is running.

        If a job already exists for ``peer.peer_id``, it is replaced.
        """
        if peer.peer_id in self._jobs and self._scheduler is not None:
            self._remove_peer_job(peer.peer_id)
        self._add_peer_job(peer)
        if self._scheduler is not None:
            self._scheduler.add_job(self._jobs[peer.peer_id])

    def remove_peer(self, peer_id: str) -> None:
        """Cancel and remove the sync job for *peer_id*."""
        self._remove_peer_job(peer_id)

    def trigger(self, peer_id: str) -> Any:
        """
        Run an immediate one-off sync for *peer_id*.

        Returns the :class:`~gnat.schedule.job.RunRecord` from the execution.

        Raises
        ------
        KeyError
            If no job is registered for *peer_id*.
        """
        job = self._jobs.get(peer_id)
        if job is None:
            raise KeyError(f"No federation job registered for peer {peer_id!r}.")
        logger.info("Triggering immediate federation sync for peer %r.", peer_id)
        return job.execute()

    def status(self) -> list[dict[str, Any]]:
        """
        Return a list of status dicts for all registered peer jobs.

        Each dict contains the job's ``status_dict()`` merged with the
        peer's ``last_sync_status`` from the registry.
        """
        result = []
        for peer_id, job in self._jobs.items():
            peer = self._registry.get(peer_id)
            entry = job.status_dict()
            if peer:
                entry["peer_id"] = peer_id
                entry["taxii_url"] = peer.taxii_url
                entry["direction"] = peer.direction
                entry["max_tlp"] = peer.max_tlp
                entry["last_sync_status"] = peer.last_sync_status
                entry["last_sync_at"] = peer.last_sync_at
            result.append(entry)
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _add_peer_job(self, peer: "FederationPeer") -> None:
        """Create a FeedJob for *peer* and register it internally."""
        try:
            from gnat.schedule.job import FeedJob
            from gnat.ingest.mappers.base import RecordMapper
        except ImportError as exc:
            logger.warning("Cannot create federation job for %r: %s", peer.peer_id, exc)
            return

        registry = self._registry
        sync = self._sync
        peer_id = peer.peer_id

        def _reader_factory(ctx: Any) -> Any:
            from gnat.federation.sync import _FederationReader
            return _FederationReader(
                peer=registry.get(peer_id),  # re-fetch in case updated
                sync_service=sync,
                added_after=ctx.last_sync_iso,
            )

        def _mapper_factory(ctx: Any) -> Any:
            return _PassthroughMapper()

        def _on_success(record: Any) -> None:
            registry.update_sync_status(peer_id, "success")
            logger.info(
                "Federation pull from peer %r succeeded: %s objects.",
                peer_id,
                getattr(getattr(record, "result", None), "written_objects", "?"),
            )

        def _on_failure(record: Any) -> None:
            registry.update_sync_status(peer_id, "failed")
            logger.warning(
                "Federation pull from peer %r failed: %s",
                peer_id, record.error,
            )

        job = FeedJob(
            job_id=f"federation-pull-{peer_id}",
            reader_factory=_reader_factory,
            mapper_factory=_mapper_factory,
            interval_seconds=peer.sync_interval_seconds,
            enabled=peer.enabled,
            on_success=_on_success,
            on_failure=_on_failure,
        )
        self._jobs[peer_id] = job

    def _remove_peer_job(self, peer_id: str) -> None:
        job = self._jobs.pop(peer_id, None)
        if job is not None and self._scheduler is not None:
            try:
                self._scheduler.remove_job(job.job_id)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Could not remove scheduler job for peer %r: %s", peer_id, exc)


# ---------------------------------------------------------------------------
# Internal ingest bridge helpers
# ---------------------------------------------------------------------------


class _FederationReader:
    """Bridges PeerSyncService into the SourceReader protocol used by FeedJob."""

    def __init__(self, peer: Any, sync_service: "PeerSyncService", added_after: str | None) -> None:
        self._peer = peer
        self._sync = sync_service
        self._added_after = added_after

    def read(self) -> Any:
        """Perform the pull and yield accepted objects as records."""
        if self._peer is None or not self._peer.enabled:
            return iter([])
        result = self._sync.sync_from_peer(
            peer=self._peer,
            added_after=self._added_after,
        )
        # Objects were already written to workspaces inside sync_from_peer.
        # Yield empty iterator so FeedJob sees zero records (counts handled separately).
        return iter([])


class _PassthroughMapper:
    """No-op mapper for the federation reader (objects written directly by PeerSyncService)."""

    def map(self, record: Any) -> Any:
        """Map record to STIX (no-op pass-through)."""
        return record

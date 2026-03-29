"""
gnat.context.workspace
==========================

:class:`Workspace` is the analyst's local working context — a named,
persistent collection of STIX objects loaded from one or more global
platform contexts, enriched from secondary sources, and eventually
committed back.

Think of it like a git working tree:

.. code-block:: text

    GlobalContext (remote) ──load()──► Workspace (local staging area)
                                           │
                                       enrich()  ← secondary sources fan out
                                           │
                                        diff()   ← see what changed
                                           │
                                       commit()  ──► GlobalContext (remote)

Persistence
-----------
Every mutation is immediately written to the configured
:class:`~gnat.context.store.WorkspaceStore` (SQLite by default) or
:class:`~gnat.context.store.FlatFileStore`.  If the process crashes
mid-session, the workspace can be resumed with ``WorkspaceManager.open()``.

Enrichment and relationships
-----------------------------
When a secondary source returns data for a known object, the workspace
creates a STIX :class:`~gnat.orm.relationship.Relationship` object linking
the original indicator to the enrichment result and stores *both*.  This
preserves provenance — you can see exactly which platform said what, rather
than silently merging scores.  The ``strategy`` parameter controls the exact
behaviour:

* ``"create_relationships"`` *(default)* — new Relationship + enrichment
  SDO added to the workspace; original object untouched.
* ``"merge_extensions"`` — ``x_`` extension fields from the enrichment are
  merged into the original object; original marked dirty.
* ``"tag_only"`` — a tag label is added to the original object's
  ``x_enrichment_tags`` list; nothing else changes.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Iterator, List, Optional, TYPE_CHECKING

from gnat.orm.base import STIXBase, _utcnow
from gnat.orm.relationship import Relationship

if TYPE_CHECKING:
    from gnat.context.global_context import GlobalContext, GlobalContextRegistry

logger = logging.getLogger(__name__)

# Sentinel so callers can pass strategy=DEFAULT
_DEFAULT_STRATEGY = "create_relationships"


class Workspace:
    """
    A named analyst workspace — the local context for a threat investigation.

    Do not instantiate directly; use :class:`WorkspaceManager` which handles
    persistence setup.

    Parameters
    ----------
    name : str
        Unique workspace name.
    registry : GlobalContextRegistry
        The registry of all available global contexts.
    store : WorkspaceStore or FlatFileStore
        Persistence backend.
    description : str, optional
        Human-readable description shown in listings.

    Attributes
    ----------
    objects : dict
        In-memory object cache ``{stix_id: STIXBase}``.  Always in sync
        with the persistence store.
    dirty : set
        Set of stix_ids that have been modified since the last commit.

    Examples
    --------
    ::

        manager = WorkspaceManager.default()
        ws = manager.create("apt28-investigation",
                            description="APT28 campaign analysis Q1-2025")

        # Load all APT28-tagged indicators from ThreatQ (default global)
        ws.load(stix_type="indicator", filters={"tags": "apt28"})
        print(f"Loaded {len(ws)} objects")

        # Enrich from Recorded Future and CrowdStrike concurrently
        ws.enrich(sources=["recorded_future", "crowdstrike"])

        # Review changes
        for obj_id, changes in ws.diff().items():
            print(obj_id, changes)

        # Write enriched objects back to ThreatQ
        result = ws.commit()
        print(result)

        # Or commit to a specific global
        ws.commit(target="xsoar_prod")

        # Checkpoint — automatically done on every mutation, but explicit is fine
        ws.save()
    """

    def __init__(
        self,
        name: str,
        registry: "GlobalContextRegistry",
        store: Any,  # WorkspaceStore | FlatFileStore
        description: str = "",
    ):
        self.name        = name
        self.description = description
        self._registry   = registry
        self._store      = store

        # In-memory cache: stix_id → STIXBase
        self.objects: Dict[str, STIXBase] = {}
        # Tracks which stix_ids have been changed since load/last-commit
        self.dirty: set = set()
        # Snapshot of objects at load time — used for diff()
        self._snapshot: Dict[str, dict] = {}
        # Workspace DB id (WorkspaceStore only)
        self._ws_id: Optional[int] = None

        self._init_store()

    # ── Initialisation ─────────────────────────────────────────────────────

    def _init_store(self) -> None:
        """Ensure the workspace record exists in the store and load cached objects."""
        from gnat.context.store import WorkspaceStore

        if isinstance(self._store, WorkspaceStore):
            ws_model = self._store.get_or_create_workspace(
                self.name, description=self.description
            )
            self._ws_id = ws_model.id
            # Re-hydrate in-memory cache from persisted objects
            for stix_dict in self._store.get_objects(self._ws_id):
                obj = self._from_dict(stix_dict)
                self.objects[obj.id] = obj
                self._snapshot[obj.id] = stix_dict
        else:  # FlatFileStore
            self._store.get_or_create_workspace(
                self.name, description=self.description
            )
            for stix_dict in self._store.get_objects(self.name):
                obj = self._from_dict(stix_dict)
                self.objects[obj.id] = obj
                self._snapshot[obj.id] = stix_dict

        logger.debug("Workspace %r initialised with %d cached objects",
                     self.name, len(self.objects))

    # ── Load from global context ────────────────────────────────────────────

    def load(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        source: Optional[str] = None,
        page_size: int = 100,
        max_pages: int = 10,
    ) -> "Workspace":
        """
        Pull objects from a global context into this workspace.

        Parameters
        ----------
        stix_type : str
            STIX type to query (``"indicator"``, ``"malware"``, etc.).
        filters : dict, optional
            Platform-specific filter dict forwarded to ``list_objects()``.
        source : str, optional
            Name of the global context to load from.  If omitted the
            default writable context is used.
        page_size : int
            Objects per page.  Default 100.
        max_pages : int
            Maximum pages to fetch.  Default 10 (1 000 objects max).

        Returns
        -------
        Workspace
            ``self`` for chaining.

        Examples
        --------
        >>> ws.load("indicator", filters={"tags": "apt28"}, source="threatq_prod")
        >>> ws.load("indicator", source="crowdstrike_falcon", page_size=50)
        """
        gc = self._resolve_source(source)
        logger.info("Workspace %r: loading %s from %r", self.name, stix_type, gc.name)

        loaded = 0
        for page in range(1, max_pages + 1):
            stix_list = gc.list_objects(stix_type, filters=filters,
                                        page=page, page_size=page_size)
            if not stix_list:
                break
            for stix_dict in stix_list:
                self._add_object(stix_dict, source_platform=gc.name)
                loaded += 1
            if len(stix_list) < page_size:
                break  # last page

        logger.info("Workspace %r: loaded %d %s objects from %r",
                    self.name, loaded, stix_type, gc.name)
        return self

    def add(self, obj: STIXBase, mark_dirty: bool = True) -> "Workspace":
        """
        Add or update a STIX object in the workspace directly.

        Parameters
        ----------
        obj : STIXBase
            Object to add.
        mark_dirty : bool
            If ``True`` (default) the object is marked as modified and will
            be included in the next ``commit()``.

        Returns
        -------
        Workspace
            ``self`` for chaining.
        """
        self._add_object(obj.to_dict(), mark_dirty=mark_dirty)
        return self

    # ── Async enrichment ────────────────────────────────────────────────────

    def enrich(
        self,
        sources: Optional[List[str]] = None,
        stix_ids: Optional[List[str]] = None,
        strategy: str = _DEFAULT_STRATEGY,
        confidence_floor: int = 0,
    ) -> "Workspace":
        """
        Enrich workspace objects from secondary global contexts.

        Runs all source queries concurrently via ``asyncio.gather`` when an
        event loop is available, otherwise falls back to sequential queries.

        Parameters
        ----------
        sources : list of str, optional
            Names of global contexts to query.  If omitted, all read-only
            contexts plus any writable contexts other than the default are used.
        stix_ids : list of str, optional
            Only enrich objects with these STIX ids.  If omitted all objects
            in the workspace are enriched.
        strategy : str
            One of:

            * ``"create_relationships"`` *(default)* — new Relationship + new
              enrichment SDO added; original unchanged.
            * ``"merge_extensions"`` — ``x_`` fields merged into original;
              original marked dirty.
            * ``"tag_only"`` — tag added to ``x_enrichment_tags``; minimal.

        confidence_floor : int
            Enrichment results with ``x_rf_risk_score`` or ``confidence``
            below this value are discarded.  Default ``0`` (keep all).

        Returns
        -------
        Workspace
            ``self`` for chaining.
        """
        source_names = sources or [g.name for g in self._registry.all()
                                   if g.name != self._registry.default.name]
        targets = stix_ids or list(self.objects.keys())

        logger.info("Workspace %r: enriching %d objects from %s",
                    self.name, len(targets), source_names)

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Inside an async context — caller should use await ws.aenrich()
                loop.run_until_complete(
                    self._enrich_async(source_names, targets, strategy, confidence_floor)
                )
            else:
                loop.run_until_complete(
                    self._enrich_async(source_names, targets, strategy, confidence_floor)
                )
        except RuntimeError:
            # No event loop — fall back to sequential
            self._enrich_sequential(source_names, targets, strategy, confidence_floor)

        return self

    async def aenrich(
        self,
        sources: Optional[List[str]] = None,
        stix_ids: Optional[List[str]] = None,
        strategy: str = _DEFAULT_STRATEGY,
        confidence_floor: int = 0,
    ) -> "Workspace":
        """
        Async version of :meth:`enrich`.  Use this inside ``async def`` functions.

        Examples
        --------
        ::

            async with AsyncGNATClient() as cli:
                await cli.connect("threatq")
                ws = manager.open("investigation")
                await ws.aenrich(sources=["recorded_future", "crowdstrike"])
        """
        source_names = sources or [g.name for g in self._registry.all()
                                   if g.name != self._registry.default.name]
        targets = stix_ids or list(self.objects.keys())
        await self._enrich_async(source_names, targets, strategy, confidence_floor)
        return self

    async def _enrich_async(
        self,
        source_names: List[str],
        stix_ids: List[str],
        strategy: str,
        confidence_floor: int,
    ) -> None:
        """Fan out enrichment queries across all sources × all objects concurrently."""
        tasks = []
        for source_name in source_names:
            if source_name not in self._registry:
                logger.warning("Workspace: unknown enrichment source %r", source_name)
                continue
            gc = self._registry.get(source_name)
            for stix_id in stix_ids:
                obj = self.objects.get(stix_id)
                if obj is None:
                    continue
                tasks.append(
                    self._enrich_one_async(gc, obj, strategy, confidence_floor)
                )
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    logger.warning("Enrichment error: %s", r)

    async def _enrich_one_async(
        self,
        gc: "GlobalContext",
        obj: STIXBase,
        strategy: str,
        confidence_floor: int,
    ) -> None:
        """Query one source for one object and apply the result."""
        loop = asyncio.get_event_loop()
        try:
            # Use run_in_executor so sync connector calls don't block the loop
            stix_list = await loop.run_in_executor(
                None,
                lambda: gc.list_objects(
                    obj.stix_type,
                    filters={"value": getattr(obj, "name", "")},
                    page_size=5,
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Enrich %r from %r: no results — %s", obj.id, gc.name, exc)
            return

        for enrichment_dict in stix_list:
            conf = enrichment_dict.get("confidence",
                   enrichment_dict.get("x_rf_risk_score", 100))
            if isinstance(conf, (int, float)) and conf < confidence_floor:
                logger.debug("Skipping low-confidence enrichment %s < %d",
                             conf, confidence_floor)
                continue
            self._apply_enrichment(obj, enrichment_dict, gc.name, strategy)

    def _enrich_sequential(
        self,
        source_names: List[str],
        stix_ids: List[str],
        strategy: str,
        confidence_floor: int,
    ) -> None:
        """Fallback sequential enrichment when no event loop is available."""
        for source_name in source_names:
            if source_name not in self._registry:
                continue
            gc = self._registry.get(source_name)
            for stix_id in stix_ids:
                obj = self.objects.get(stix_id)
                if obj is None:
                    continue
                try:
                    stix_list = gc.list_objects(
                        obj.stix_type,
                        filters={"value": getattr(obj, "name", "")},
                        page_size=5,
                    )
                    for enrichment_dict in stix_list:
                        conf = enrichment_dict.get(
                            "confidence", enrichment_dict.get("x_rf_risk_score", 100)
                        )
                        if isinstance(conf, (int, float)) and conf < confidence_floor:
                            continue
                        self._apply_enrichment(obj, enrichment_dict, gc.name, strategy)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Sequential enrich error for %r: %s", stix_id, exc)

    def _apply_enrichment(
        self,
        original: STIXBase,
        enrichment_dict: dict,
        source_platform: str,
        strategy: str,
    ) -> None:
        """Apply one enrichment result to one object per the chosen strategy."""

        if strategy == "create_relationships":
            # Add the enrichment SDO + a Relationship linking original → enrichment
            enrich_obj = self._from_dict(enrichment_dict)
            enrich_obj._properties["x_enrichment_source"] = source_platform
            self._add_object(enrich_obj.to_dict(), source_platform=source_platform,
                             mark_dirty=True)

            rel = Relationship(
                relationship_type = "related-to",
                source_ref        = original.id,
                target_ref        = enrich_obj.id,
                x_enrichment_source = source_platform,
                x_enrichment_strategy = strategy,
                created           = _utcnow(),
                modified          = _utcnow(),
            )
            self._add_object(rel.to_dict(), source_platform=source_platform,
                             mark_dirty=True)
            # Log to store
            self._log_enrichment(original.id, source_platform, enrichment_dict, strategy)

        elif strategy == "merge_extensions":
            # Always operate on the live object in self.objects, not the passed reference
            live = self.objects.get(original.id, original)
            changed = False
            for key, val in enrichment_dict.items():
                if key.startswith("x_") or key in ("confidence", "labels", "indicator_types"):
                    live._properties[key] = val
                    changed = True
            if changed:
                self.dirty.add(live.id)
                self._persist_object(live.to_dict(), mark_dirty=True)
                self._log_enrichment(live.id, source_platform, enrichment_dict, strategy)

        elif strategy == "tag_only":
            live = self.objects.get(original.id, original)
            tags = list(live._properties.get("x_enrichment_tags", []))
            tag  = f"{source_platform}:enriched"
            if tag not in tags:
                tags.append(tag)
                live._properties["x_enrichment_tags"] = tags
                self.dirty.add(live.id)
                self._persist_object(live.to_dict(), mark_dirty=True)
                self._log_enrichment(live.id, source_platform,
                                     {"tag": tag}, strategy)
        else:
            raise ValueError(
                f"Unknown enrichment strategy {strategy!r}. "
                "Valid: 'create_relationships', 'merge_extensions', 'tag_only'"
            )

    # ── Diff ────────────────────────────────────────────────────────────────

    def diff(self) -> Dict[str, Dict[str, Any]]:
        """
        Return a summary of changes since load or last commit.

        Returns
        -------
        dict
            ``{stix_id: {"action": "added"|"modified"|"deleted",
                         "changed_fields": [...]}}``

        Examples
        --------
        >>> for stix_id, info in ws.diff().items():
        ...     print(stix_id, info["action"], info["changed_fields"])
        """
        result: Dict[str, Dict[str, Any]] = {}

        # Added or modified
        for stix_id, obj in self.objects.items():
            current_dict = obj.to_dict()
            if stix_id not in self._snapshot:
                result[stix_id] = {"action": "added", "changed_fields": []}
            else:
                snap = self._snapshot[stix_id]
                changed = [k for k in current_dict
                           if current_dict.get(k) != snap.get(k)]
                if changed:
                    result[stix_id] = {"action": "modified", "changed_fields": changed}

        # Deleted (in snapshot but not in objects)
        for stix_id in self._snapshot:
            if stix_id not in self.objects:
                result[stix_id] = {"action": "deleted", "changed_fields": []}

        return result

    # ── Commit ──────────────────────────────────────────────────────────────

    def commit(
        self,
        target: Optional[str] = None,
        dry_run: bool = False,
        stix_ids: Optional[List[str]] = None,
    ) -> "CommitResult":
        """
        Write all dirty objects back to a global context.

        Parameters
        ----------
        target : str, optional
            Name of the global context to write to.  If omitted the default
            writable context is used.
        dry_run : bool
            If ``True``, compute what would be written but do not write.
        stix_ids : list of str, optional
            Only commit these specific object ids.  If omitted all dirty objects
            are committed.

        Returns
        -------
        CommitResult
            Summary of the commit operation.

        Examples
        --------
        >>> result = ws.commit()
        >>> result = ws.commit(target="xsoar_prod", dry_run=True)
        >>> result = ws.commit(stix_ids=[ind.id, rel.id])
        """
        gc = self._resolve_target(target)
        ids_to_commit = set(stix_ids or self.dirty)
        to_write = {sid: self.objects[sid]
                    for sid in ids_to_commit if sid in self.objects}

        result = CommitResult(
            workspace_name  = self.name,
            target_platform = gc.name,
            dry_run         = dry_run,
        )

        for stix_id, obj in to_write.items():
            action = "added" if stix_id not in self._snapshot else "modified"
            if dry_run:
                result.would_write.append({"id": stix_id, "action": action})
                continue
            try:
                written = gc.write_object(obj.to_dict())
                # Update local snapshot to reflect committed state
                self._snapshot[stix_id] = written
                result.written.append(stix_id)
            except Exception as exc:  # noqa: BLE001
                result.errors.append({"id": stix_id, "error": str(exc)})
                logger.error("Workspace commit error for %r: %s", stix_id, exc)

        # Handle deletions
        deleted_ids = {sid for sid in self._snapshot if sid not in self.objects}
        for stix_id in (set(stix_ids) if stix_ids else deleted_ids) & deleted_ids:
            stix_type = self._snapshot[stix_id].get("type", "indicator")
            if dry_run:
                result.would_write.append({"id": stix_id, "action": "deleted"})
                continue
            try:
                gc.delete_object(stix_type, stix_id)
                del self._snapshot[stix_id]
                result.deleted.append(stix_id)
            except Exception as exc:  # noqa: BLE001
                result.errors.append({"id": stix_id, "error": str(exc)})

        if not dry_run:
            self.dirty -= set(result.written) | set(result.deleted)
            self._mark_clean()

        logger.info("Workspace %r commit: %s", self.name, result)
        return result

    # ── Persistence helpers ─────────────────────────────────────────────────

    def save(self) -> None:
        """
        Force-flush all in-memory state to the persistent store.

        Normally called automatically on every mutation, but can be called
        explicitly to ensure everything is on disk (e.g. before shutdown).
        """
        for obj in self.objects.values():
            self._persist_object(obj.to_dict(), mark_dirty=obj.id in self.dirty)

    def export_bundle(self) -> dict:
        """
        Export the entire workspace as a STIX 2.1 bundle dict.

        Useful for sharing with external tools or archiving.
        """
        from gnat.context.store import FlatFileStore
        if isinstance(self._store, FlatFileStore):
            return self._store.export_bundle(self.name)
        import uuid as _uuid
        return {
            "type":         "bundle",
            "id":           f"bundle--{_uuid.uuid4()}",
            "spec_version": "2.1",
            "objects":      [o.to_dict() for o in self.objects.values()],
        }

    def remove(self, stix_id: str) -> bool:
        """
        Remove an object from the workspace (marks it for deletion on commit).

        Returns ``True`` if the object was found.
        """
        if stix_id not in self.objects:
            return False
        del self.objects[stix_id]
        self.dirty.add(stix_id)
        from gnat.context.store import WorkspaceStore
        if isinstance(self._store, WorkspaceStore):
            self._store.soft_delete_object(self._ws_id, stix_id)
        else:
            self._store.delete_object(self.name, stix_id)
        return True

    def get_enrichment_history(self, stix_id: Optional[str] = None) -> List[dict]:
        """Return the enrichment log for this workspace."""
        from gnat.context.store import WorkspaceStore
        if isinstance(self._store, WorkspaceStore):
            return self._store.get_enrichment_history(self._ws_id, stix_id)
        return self._store.get_enrichment_history(self.name, stix_id)

    # ── Internal ────────────────────────────────────────────────────────────

    def _add_object(self, stix_dict: dict, source_platform: str = "",
                    mark_dirty: bool = False) -> STIXBase:
        obj = self._from_dict(stix_dict)
        self.objects[obj.id] = obj
        if mark_dirty:
            self.dirty.add(obj.id)
        # Only snapshot objects that come from a platform (not analyst-created dirty objects)
        if not mark_dirty and obj.id not in self._snapshot:
            self._snapshot[obj.id] = stix_dict
        self._persist_object(stix_dict, source_platform=source_platform,
                             mark_dirty=mark_dirty)
        return obj

    def _persist_object(self, stix_dict: dict, source_platform: str = "",
                        mark_dirty: bool = False) -> None:
        from gnat.context.store import WorkspaceStore
        if isinstance(self._store, WorkspaceStore):
            self._store.upsert_object(
                self._ws_id, stix_dict,
                source_platform=source_platform, is_dirty=mark_dirty
            )
        else:
            self._store.save_object(
                self.name, stix_dict,
                source_platform=source_platform, is_dirty=mark_dirty
            )

    def _log_enrichment(self, stix_id: str, source: str,
                        data: dict, strategy: str) -> None:
        from gnat.context.store import WorkspaceStore
        if isinstance(self._store, WorkspaceStore):
            self._store.log_enrichment(self._ws_id, stix_id, source, data, strategy)
        else:
            self._store.log_enrichment(self.name, stix_id, source, data, strategy)

    def _mark_clean(self) -> None:
        from gnat.context.store import WorkspaceStore
        if isinstance(self._store, WorkspaceStore):
            self._store.mark_clean(self._ws_id)

    def _resolve_source(self, name: Optional[str]) -> "GlobalContext":
        if name:
            return self._registry.get(name)
        return self._registry.default

    def _resolve_target(self, name: Optional[str]) -> "GlobalContext":
        gc = self._registry.get(name) if name else self._registry.default
        if gc.read_only:
            raise PermissionError(
                f"Global context {gc.name!r} is read-only. "
                "Specify a writable target with target=..."
            )
        return gc

    @staticmethod
    def _from_dict(stix_dict: dict) -> STIXBase:
        """Reconstruct the most specific ORM class from a STIX dict."""
        from gnat.orm.base import STIXBase
        from gnat.orm.indicator import Indicator
        from gnat.orm.malware import Malware
        from gnat.orm.vulnerability import Vulnerability
        from gnat.orm.threat_actor import ThreatActor
        from gnat.orm.attack_pattern import AttackPattern
        from gnat.orm.relationship import Relationship
        _MAP = {
            "indicator":     Indicator,
            "malware":       Malware,
            "vulnerability": Vulnerability,
            "threat-actor":  ThreatActor,
            "attack-pattern": AttackPattern,
            "relationship":  Relationship,
        }
        cls = _MAP.get(stix_dict.get("type", ""), STIXBase)
        return cls.from_dict(stix_dict)

    # ── Dunder ──────────────────────────────────────────────────────────────

    def __len__(self) -> int:
        return len(self.objects)

    def __iter__(self) -> Iterator[STIXBase]:
        return iter(self.objects.values())

    def __contains__(self, stix_id: str) -> bool:
        return stix_id in self.objects

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"Workspace(name={self.name!r}, objects={len(self)}, "
            f"dirty={len(self.dirty)})"
        )


# ---------------------------------------------------------------------------
# CommitResult
# ---------------------------------------------------------------------------

class CommitResult:
    """Summary of a :meth:`Workspace.commit` operation."""

    def __init__(self, workspace_name: str, target_platform: str, dry_run: bool):
        self.workspace_name  = workspace_name
        self.target_platform = target_platform
        self.dry_run         = dry_run
        self.written:     List[str] = []
        self.deleted:     List[str] = []
        self.errors:      List[dict] = []
        self.would_write: List[dict] = []

    @property
    def success(self) -> bool:
        return len(self.errors) == 0

    def __str__(self) -> str:  # pragma: no cover
        if self.dry_run:
            return (f"CommitResult(dry_run, workspace={self.workspace_name!r}, "
                    f"would_write={len(self.would_write)})")
        return (
            f"CommitResult(workspace={self.workspace_name!r}, "
            f"target={self.target_platform!r}, "
            f"written={len(self.written)}, deleted={len(self.deleted)}, "
            f"errors={len(self.errors)})"
        )


# ---------------------------------------------------------------------------
# WorkspaceManager
# ---------------------------------------------------------------------------

class WorkspaceManager:
    """
    Factory and lifecycle manager for :class:`Workspace` instances.

    Handles store initialisation, workspace creation/opening/listing/deletion,
    and provides the top-level entry point for the context system.

    Parameters
    ----------
    registry : GlobalContextRegistry
        The global context registry.
    store : WorkspaceStore or FlatFileStore, optional
        Persistence backend.  If omitted a SQLite store at
        ``~/.gnat/workspaces.db`` is created automatically.

    Examples
    --------
    Quick start with defaults::

        manager = WorkspaceManager.default()
        ws = manager.create("apt28")
        ws.load("indicator", filters={"tags": "apt28"})
        ws.enrich(sources=["recorded_future"])
        ws.commit()

    Custom store::

        from gnat.context.store import WorkspaceStore, FlatFileStore
        pg_store = WorkspaceStore("postgresql+psycopg2://user:pass@host/ctmsak")
        pg_store.create_all()
        manager = WorkspaceManager(registry, store=pg_store)
    """

    def __init__(
        self,
        registry: "GlobalContextRegistry",
        store: Any = None,
    ):
        self._registry = registry
        self._store    = store or self._default_store()

    @classmethod
    def default(
        cls,
        config_path: Optional[str] = None,
        db_url: Optional[str] = None,
    ) -> "WorkspaceManager":
        """
        Create a WorkspaceManager with auto-configured registry and SQLite store.

        Parameters
        ----------
        config_path : str, optional
            INI config path (defaults to ``~/.gnat/config.ini``).
        db_url : str, optional
            SQLAlchemy URL (defaults to ``~/.gnat/workspaces.db``).
        """
        from gnat.context.global_context import GlobalContextRegistry
        registry = GlobalContextRegistry.from_config(config_path)
        store    = cls._default_store(db_url)
        return cls(registry=registry, store=store)

    @classmethod
    def from_clients(
        cls,
        clients: dict,
        default: Optional[str] = None,
        read_only: Optional[List[str]] = None,
        db_url: Optional[str] = None,
    ) -> "WorkspaceManager":
        """
        Create a WorkspaceManager from a dict of connected GNATClients.

        Parameters
        ----------
        clients : dict
            ``{name: GNATClient}`` mapping.
        default : str, optional
            Name of the default write context.
        read_only : list of str, optional
            Names to mark as read-only enrichment sources.
        db_url : str, optional
            SQLAlchemy URL (defaults to SQLite).

        Examples
        --------
        ::

            tq_cli = GNATClient().connect("threatq")
            rf_cli = GNATClient().connect("recordedfuture")
            cs_cli = GNATClient().connect("crowdstrike")

            manager = WorkspaceManager.from_clients(
                {"threatq": tq_cli, "rf": rf_cli, "cs": cs_cli},
                default="threatq",
                read_only=["rf"],
            )
        """
        from gnat.context.global_context import GlobalContextRegistry
        registry = GlobalContextRegistry.from_clients(
            clients, default=default, read_only=read_only
        )
        return cls(registry=registry, store=cls._default_store(db_url))

    # ── Workspace lifecycle ─────────────────────────────────────────────────

    def create(self, name: str, description: str = "") -> Workspace:
        """
        Create a new named workspace.

        Raises
        ------
        ValueError
            If a workspace with this name already exists.
        """
        from gnat.context.store import WorkspaceStore
        if isinstance(self._store, WorkspaceStore):
            if self._store.get_workspace(name) is not None:
                raise ValueError(
                    f"Workspace {name!r} already exists. Use manager.open({name!r})."
                )
        return Workspace(name, self._registry, self._store, description=description)

    def open(self, name: str) -> Workspace:
        """
        Open an existing workspace, rehydrating its persisted state.

        Raises
        ------
        KeyError
            If no workspace with this name exists.
        """
        from gnat.context.store import WorkspaceStore
        if isinstance(self._store, WorkspaceStore):
            if self._store.get_workspace(name) is None:
                raise KeyError(
                    f"No workspace named {name!r}. "
                    "Use manager.create() to make one."
                )
        else:
            if self._store.get_workspace(name) is None:
                raise KeyError(f"No workspace named {name!r}.")
        return Workspace(name, self._registry, self._store)

    def get_or_create(self, name: str, **kwargs: Any) -> Workspace:
        """Open an existing workspace or create it if it doesn't exist."""
        try:
            return self.open(name)
        except KeyError:
            return self.create(name, **kwargs)

    def list(self) -> List[dict]:
        """Return metadata dicts for all workspaces."""
        from gnat.context.store import WorkspaceStore
        if isinstance(self._store, WorkspaceStore):
            return [
                {
                    "name":        ws.name,
                    "description": ws.description or "",
                    "created_at":  ws.created_at.isoformat() if ws.created_at else "",
                    "updated_at":  ws.updated_at.isoformat() if ws.updated_at else "",
                    "object_count": self._store.object_count(ws.id),
                }
                for ws in self._store.list_workspaces()
            ]
        return self._store.list_workspaces()

    def delete(self, name: str) -> bool:
        """Permanently delete a workspace. Returns ``True`` if found."""
        from gnat.context.store import WorkspaceStore
        if isinstance(self._store, WorkspaceStore):
            return self._store.delete_workspace(name)
        return self._store.delete_workspace(name)

    # ── Internal ────────────────────────────────────────────────────────────

    @staticmethod
    def _default_store(db_url: Optional[str] = None) -> Any:
        from gnat.context.store import WorkspaceStore, FlatFileStore
        if _HAS_SQLALCHEMY := WorkspaceStore.__module__ != "builtins":
            try:
                url   = db_url or "sqlite:///~/.gnat/workspaces.db"
                store = WorkspaceStore(url)
                store.create_all()
                return store
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "WorkspaceStore init failed (%s), falling back to FlatFileStore", exc
                )
        return FlatFileStore()

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"WorkspaceManager(registry={self._registry!r}, store={self._store!r})"
        )

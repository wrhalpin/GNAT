# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.research.library
=========================

:class:`ResearchLibrary` — the three-tier shared research knowledge base.

Tiers
-----

.. code-block:: text

    Personal workspaces   (analyst-owned, arbitrary names)
            │
            │  promote(workspace, topic, note=...)
            ▼
    Staging workspace     (_ctmsak_staging)
            │
            │  CurationJob runs periodically
            ▼
    Library workspace     (_ctmsak_library)   [read-only to analysts]
            │
            │  search / get / is_fresh
            ▼
    Analyst queries before starting new research

Access model
------------
All analyst interaction with the library goes through :class:`ResearchLibrary`
methods — never directly through :class:`~gnat.context.workspace.Workspace`
or :class:`~gnat.context.workspace.WorkspaceManager`.  This keeps the
read-only guard, audit trail, and freshness logic centralised.

INI configuration
-----------------

.. code-block:: ini

    [research_library]
    staging_name     = _ctmsak_staging
    library_name     = _ctmsak_library
    ttl_indicator    = 24      # hours
    ttl_vulnerability = 72
    ttl_campaign     = 336     # 14 days
    ttl_threat_actor = 720     # 30 days
    ttl_other        = 168     # 7 days

Usage
-----
::

    from gnat.research import ResearchLibrary

    lib = ResearchLibrary.default()

    # Before researching — check if fresh result exists
    entry = lib.get("APT29")
    if entry and entry.is_fresh:
        print(entry.note)
        # Load STIX objects into workspace
        ws.add_many(entry.stix_objects)
    else:
        # Run the research agent, then promote
        # ... research ...
        lib.promote(ws, topic="APT29", researcher="analyst1",
                    note="Found new C2 infrastructure and two CVEs")

    # List what's in the library
    for summary in lib.list_entries():
        print(summary["topic"], summary["age_hours"], "h",
              "FRESH" if summary["is_fresh"] else "STALE")

    # Search across topics
    results = lib.search("phishing")
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from gnat.research.entry import (
    DEFAULT_TTLS,
    ResearchEntry,
    categorise_topic,
    topic_key,
)

if TYPE_CHECKING:
    from gnat.context.workspace import Workspace, WorkspaceManager

logger = logging.getLogger(__name__)

_STAGING_NAME = "_ctmsak_staging"
_LIBRARY_NAME = "_ctmsak_library"

# Storage key prefix inside the workspace metadata store
_ENTRY_PREFIX = "research_entry:"


class ResearchLibrary:
    """
    Three-tier shared research knowledge base.

    All library access — reads and writes — goes through this class.
    Analysts never touch the staging or library workspaces directly.

    Parameters
    ----------
    manager : WorkspaceManager
        Workspace manager used to open/create the staging and library
        workspaces.
    ttls : dict, optional
        Override TTL hours per category.  Merged with ``DEFAULT_TTLS``.
    staging_name : str
        Well-known name for the staging workspace.  Default ``"_ctmsak_staging"``.
    library_name : str
        Well-known name for the curated library workspace.
        Default ``"_ctmsak_library"``.

    Examples
    --------
    ::

        lib = ResearchLibrary.default()

        # Check before researching
        if not lib.is_fresh("APT29"):
            # ... run research agent ...
            lib.promote(ws, topic="APT29", researcher="analyst1",
                        note="New C2 IPs found")

        # Load existing research into a workspace
        entry = lib.get("APT29")
        if entry:
            for stix_dict in entry.stix_objects:
                ws.add(STIXBase.from_dict(stix_dict), mark_dirty=False)
    """

    def __init__(
        self,
        manager: WorkspaceManager,
        ttls: dict[str, int] | None = None,
        staging_name: str = _STAGING_NAME,
        library_name: str = _LIBRARY_NAME,
        search_index: Any | None = None,
    ):
        """Initialize ResearchLibrary."""
        self._manager = manager
        self._ttls = {**DEFAULT_TTLS, **(ttls or {})}
        self._staging_name = staging_name
        self._library_name = library_name
        self._ensure_workspaces()
        if search_index is not None:
            self._search_index = search_index
        else:
            from gnat.search.index import NullSearchIndex

            self._search_index = NullSearchIndex()

    # ── Factory ────────────────────────────────────────────────────────────

    @classmethod
    def default(
        cls,
        config_path: str | None = None,
        db_url: str | None = None,
    ) -> ResearchLibrary:
        """
        Construct with auto-configured WorkspaceManager and INI-driven TTLs.

        Parameters
        ----------
        config_path : str, optional
            Explicit path to config.ini.
        db_url : str, optional
            SQLAlchemy URL for the workspace store.  Defaults to SQLite.
        """
        from gnat.context.workspace import WorkspaceManager

        manager = WorkspaceManager.default(config_path=config_path, db_url=db_url)
        ttls = cls._load_ttls(config_path)
        staging, library = cls._load_names(config_path)
        search_index = cls._build_search_index_from_config(config_path)
        return cls(
            manager=manager,
            ttls=ttls,
            staging_name=staging,
            library_name=library,
            search_index=search_index,
        )

    @classmethod
    def from_manager(
        cls,
        manager: WorkspaceManager,
        config_path: str | None = None,
    ) -> ResearchLibrary:
        """
        Construct from an existing WorkspaceManager.

        Useful when the manager is already configured for your context system.
        """
        ttls = cls._load_ttls(config_path)
        staging, library = cls._load_names(config_path)
        search_index = cls._build_search_index_from_config(config_path)
        return cls(
            manager=manager,
            ttls=ttls,
            staging_name=staging,
            library_name=library,
            search_index=search_index,
        )

    @classmethod
    def _build_search_index_from_config(cls, config_path: str | None = None) -> Any:
        """Build a SearchIndex from INI config, returning NullSearchIndex on failure."""
        try:
            from gnat.config import GNATConfig
            from gnat.search import build_search_index

            cfg = GNATConfig(config_path) if config_path else GNATConfig()
            return build_search_index(cfg)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Search index not configured: %s", exc)
            from gnat.search.index import NullSearchIndex

            return NullSearchIndex()

    # ── Promotion (personal → staging) ─────────────────────────────────────

    def promote(
        self,
        workspace: Workspace,
        topic: str,
        researcher: str,
        note: str = "",
        stix_ids: list[str] | None = None,
    ) -> ResearchEntry:
        """
        Promote research from a personal workspace into staging.

        Extracts STIX objects from the workspace (all, or the specified
        subset), wraps them in a :class:`~gnat.research.entry.ResearchEntry`,
        and writes the entry to the staging workspace.

        Parameters
        ----------
        workspace : Workspace
            The analyst's personal workspace containing research results.
        topic : str
            The research topic this entry represents.
        researcher : str
            Analyst identifier — username, workstation name, etc.
        note : str, optional
            Annotation explaining the research and what was found.
            Displayed to other analysts querying the library.
        stix_ids : list of str, optional
            Specific STIX ids to promote.  If omitted, all objects tagged
            ``x_source_type: "ai_extracted"`` or all objects if none are
            tagged are included.

        Returns
        -------
        ResearchEntry
            The newly created staging entry.

        Examples
        --------
        ::

            # Promote all AI-extracted objects
            entry = lib.promote(ws, topic="APT29", researcher="analyst1",
                                note="Found C2 infra and TTPs from Unit42 report")

            # Promote specific objects only
            entry = lib.promote(ws, topic="APT29", researcher="analyst1",
                                stix_ids=[ind.id, actor.id],
                                note="Verified IOCs only — ignore the summary")
        """
        # Collect objects to promote
        if stix_ids:
            objects = [ws_obj for sid, ws_obj in workspace.objects.items() if sid in set(stix_ids)]
        else:
            # Prefer AI-extracted objects; fall back to all objects
            ai_objects = [
                obj
                for obj in workspace.objects.values()
                if obj._properties.get("x_source_type") == "ai_extracted"
            ]
            objects = ai_objects if ai_objects else list(workspace.objects.values())

        stix_dicts = [obj.to_dict() for obj in objects]

        if not stix_dicts:
            raise ValueError(
                f"No objects found in workspace {workspace.name!r} to promote. "
                "Run research first or specify stix_ids explicitly."
            )

        category = categorise_topic(topic)
        ttl_hours = self._ttls.get(category, DEFAULT_TTLS["other"])

        entry = ResearchEntry(
            topic=topic,
            stix_objects=stix_dicts,
            researcher=researcher,
            promoted_at=_utcnow(),
            note=note,
            source_workspace=workspace.name,
            category=category,
        )
        entry.set_ttl(ttl_hours)

        self._write_entry_to_staging(entry)
        self._index_entry_objects(entry)
        logger.info(
            "ResearchLibrary: promoted %d objects for topic %r by %r (note: %s)",
            len(stix_dicts),
            topic,
            researcher,
            repr(note[:60]) if note else "(none)",
        )
        return entry

    # ── Library queries ────────────────────────────────────────────────────

    def is_fresh(self, topic: str) -> bool:
        """
        Return ``True`` if a fresh (non-expired) curated entry exists for
        this topic.

        Use this as the first check before running a research agent:
        ``if not lib.is_fresh(topic): run_agent(topic)``.

        Parameters
        ----------
        topic : str
            Research topic.  Matching is case-insensitive and
            whitespace-normalised.
        """
        entry = self.get(topic)
        return entry is not None and entry.is_fresh

    def get(self, topic: str) -> ResearchEntry | None:
        """
        Return the most recent curated entry for a topic, or ``None``.

        Only returns entries with ``curator_status == "curated"``.
        For pending staging entries, use :meth:`get_staging`.

        Parameters
        ----------
        topic : str
            Research topic.
        """
        return self._find_entry(topic, workspace_name=self._library_name, status="curated")

    def get_staging(self, topic: str) -> ResearchEntry | None:
        """
        Return the most recent pending staging entry for a topic, or ``None``.
        """
        return self._find_entry(topic, workspace_name=self._staging_name, status="pending")

    def search(
        self,
        query: str,
        include_stale: bool = False,
        include_staging: bool = False,
        limit: int = 50,
    ) -> list[ResearchEntry]:
        """
        Search the library for entries matching a query string.

        Routes through Solr when a :class:`~gnat.search.index.SolrSearchIndex`
        is attached; falls back to in-memory scan otherwise.

        Parameters
        ----------
        query : str
            Case-insensitive search string.
        include_stale : bool
            If ``True``, include entries that have passed their TTL.
        include_staging : bool
            If ``True``, also search the staging workspace.
        limit : int
            Maximum entries to return.  Default 50.

        Returns
        -------
        list of ResearchEntry
            Matching entries, newest first.
        """
        from gnat.search.index import NullSearchIndex

        if not isinstance(self._search_index, NullSearchIndex):
            return self._solr_search(
                query,
                include_stale=include_stale,
                include_staging=include_staging,
                limit=limit,
            )
        return self._memory_search(
            query,
            include_stale=include_stale,
            include_staging=include_staging,
            limit=limit,
        )

    def _memory_search(
        self,
        query: str,
        include_stale: bool = False,
        include_staging: bool = False,
        limit: int = 50,
    ) -> list[ResearchEntry]:
        """In-memory search across topic, note, researcher, and category fields."""
        q = query.lower().strip()
        entries = self._load_all_entries(self._library_name, status="curated")
        if include_staging:
            entries += self._load_all_entries(self._staging_name, status="pending")

        matched = []
        for entry in entries:
            if not include_stale and not entry.is_fresh:
                continue
            searchable = " ".join(
                [
                    entry.topic,
                    entry.note,
                    entry.researcher,
                    entry.category,
                    entry.source_workspace,
                ]
            ).lower()
            if q in searchable:
                matched.append(entry)

        matched.sort(key=lambda e: e.promoted_at, reverse=True)
        return matched[:limit]

    def _solr_search(
        self,
        query: str,
        include_stale: bool = False,
        include_staging: bool = False,
        limit: int = 50,
    ) -> list[ResearchEntry]:
        """Solr-backed search: returns STIX IDs → resolves to ResearchEntry objects."""
        stix_ids = self._search_index.search(query, limit=limit * 2)

        entries: list[ResearchEntry] = []
        for stix_id in stix_ids:
            entry = self._entry_by_stix_id(stix_id, include_staging)
            if entry is None:
                continue
            if not include_stale and not entry.is_fresh:
                continue
            entries.append(entry)
            if len(entries) >= limit:
                break
        return entries

    def _entry_by_stix_id(
        self,
        stix_id: str,
        include_staging: bool,
    ) -> ResearchEntry | None:
        """Return the ResearchEntry containing the given STIX object ID, or None."""
        for entry in self._load_all_entries(self._library_name, status="curated"):
            for obj in entry.stix_objects:
                if isinstance(obj, dict) and obj.get("id") == stix_id:
                    return entry
        if include_staging:
            for entry in self._load_all_entries(self._staging_name, status="pending"):
                for obj in entry.stix_objects:
                    if isinstance(obj, dict) and obj.get("id") == stix_id:
                        return entry
        return None

    def _index_entry_objects(self, entry: ResearchEntry) -> None:
        """Index all STIX objects from a ResearchEntry into the search sidecar."""
        for obj in entry.stix_objects:
            try:
                self._search_index.index(
                    obj,
                    source_platform="research_library",
                    extra_fields={"research_topic": entry.topic},
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Solr index failed for object in entry %r: %s", entry.topic, exc)

    def list_entries(
        self,
        include_stale: bool = False,
        category: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        List all curated library entries as lightweight summary dicts.

        Parameters
        ----------
        include_stale : bool
            Include entries past their TTL.
        category : str, optional
            Filter by category: ``"indicator"``, ``"vulnerability"``,
            ``"campaign"``, ``"threat_actor"``, or ``"other"``.

        Returns
        -------
        list of dict
            Summary dicts (no full STIX payloads), newest first.
        """
        entries = self._load_all_entries(self._library_name, status="curated")
        result = []
        for entry in sorted(entries, key=lambda e: e.promoted_at, reverse=True):
            if not include_stale and not entry.is_fresh:
                continue
            if category and entry.category != category:
                continue
            result.append(entry.summary())
        return result

    def list_staging(self) -> list[dict[str, Any]]:
        """List all pending staging entries as summary dicts, newest first."""
        entries = self._load_all_entries(self._staging_name, status="pending")
        return [e.summary() for e in sorted(entries, key=lambda e: e.promoted_at, reverse=True)]

    def load_into_workspace(
        self,
        topic: str,
        workspace: Workspace,
        mark_dirty: bool = False,
    ) -> int:
        """
        Load all STIX objects from a library entry into a workspace.

        Parameters
        ----------
        topic : str
            Research topic to load.
        workspace : Workspace
            Target workspace.
        mark_dirty : bool
            If ``True``, loaded objects are marked dirty in the workspace.
            Default ``False`` (objects come from library, treat as clean).

        Returns
        -------
        int
            Number of objects loaded.

        Raises
        ------
        KeyError
            If no curated entry exists for this topic.
        """
        entry = self.get(topic)
        if entry is None:
            raise KeyError(
                f"No curated library entry for topic {topic!r}. "
                "Run research first or check lib.search() for similar topics."
            )

        count = 0
        for stix_dict in entry.stix_objects:
            workspace._add_object(stix_dict, mark_dirty=mark_dirty)
            count += 1

        logger.info(
            "ResearchLibrary: loaded %d objects for topic %r into workspace %r",
            count,
            topic,
            workspace.name,
        )
        return count

    # ── Staging management ─────────────────────────────────────────────────

    def retire_entry(self, entry_id: str) -> bool:
        """
        Archive (soft-delete) a library entry by its ``entry_id``.

        The entry remains in storage for audit purposes but is excluded
        from all normal queries.  Superseded entries are archived rather
        than deleted by the curation job.

        Parameters
        ----------
        entry_id : str
            The ``entry_id`` of the entry to archive.

        Returns
        -------
        bool
            ``True`` if found and archived, ``False`` if not found.
        """
        for ws_name in (self._library_name, self._staging_name):
            entries = self._load_all_entries(ws_name)
            for entry in entries:
                if entry.entry_id == entry_id:
                    entry.mark_archived()
                    self._save_entry(entry, ws_name)
                    logger.info(
                        "ResearchLibrary: archived entry %r (topic=%r)",
                        entry_id,
                        entry.topic,
                    )
                    return True
        return False

    def stats(self) -> dict[str, Any]:
        """
        Return summary statistics for the library and staging area.

        Returns
        -------
        dict
            Keys: ``library_total``, ``library_fresh``, ``library_stale``,
            ``staging_pending``, ``by_category``, ``oldest_entry_hours``,
            ``newest_entry_hours``.
        """
        lib_entries = self._load_all_entries(self._library_name, status="curated")
        stg_entries = self._load_all_entries(self._staging_name, status="pending")

        by_cat: dict[str, int] = {}
        for e in lib_entries:
            by_cat[e.category] = by_cat.get(e.category, 0) + 1

        fresh = [e for e in lib_entries if e.is_fresh]
        stale = [e for e in lib_entries if not e.is_fresh]

        ages = [e.age_hours for e in lib_entries]

        return {
            "library_total": len(lib_entries),
            "library_fresh": len(fresh),
            "library_stale": len(stale),
            "staging_pending": len(stg_entries),
            "by_category": by_cat,
            "oldest_entry_hours": round(max(ages), 1) if ages else 0,
            "newest_entry_hours": round(min(ages), 1) if ages else 0,
        }

    # ── Internal storage ───────────────────────────────────────────────────

    def _ensure_workspaces(self) -> None:
        """Create staging and library workspaces if they don't exist."""
        self._manager.get_or_create(
            self._staging_name,
            description="GNAT shared research staging area",
        )
        self._manager.get_or_create(
            self._library_name,
            description="GNAT curated research library (managed — do not edit directly)",
        )

    def _entry_store_key(self, entry: ResearchEntry) -> str:
        """Stable storage key for an entry within a workspace's metadata."""
        return f"{_ENTRY_PREFIX}{entry.entry_id}"

    def _write_entry_to_staging(self, entry: ResearchEntry) -> None:
        """Internal helper for write entry to staging."""
        self._save_entry(entry, self._staging_name)

    def _write_entry_to_library(self, entry: ResearchEntry) -> None:
        """Internal helper for write entry to library."""
        self._save_entry(entry, self._library_name)

    def _save_entry(self, entry: ResearchEntry, workspace_name: str) -> None:
        """Persist a ResearchEntry into the named workspace's store."""
        _ws = self._manager.open(workspace_name)
        store = self._manager._store

        from gnat.context.store import WorkspaceStore

        if isinstance(store, WorkspaceStore):
            ws_model = store.get_workspace(workspace_name)
            if ws_model is None:
                return
            # Store entry as a JSON blob using a synthetic STIX-like dict
            # with a well-known id prefix so we can query it back
            synthetic_stix = {
                "type": "x-research-entry",
                "id": f"x-research-entry--{entry.entry_id}",
                "name": entry.topic,
                "created": entry.promoted_at.isoformat(),
                "modified": (entry.curated_at or entry.promoted_at).isoformat(),
                **entry.to_dict(),
            }
            store.upsert_object(
                ws_model.id,
                synthetic_stix,
                source_platform="research_library",
                is_dirty=False,
            )
        else:
            # FlatFileStore — write one JSON file per entry
            entry_dir = Path(store._base) / workspace_name / "research_entries"
            entry_dir.mkdir(parents=True, exist_ok=True)
            fp = entry_dir / f"{entry.entry_id}.json"
            fp.write_text(json.dumps(entry.to_dict(), indent=2))

    def _load_all_entries(
        self,
        workspace_name: str,
        status: str | None = None,
    ) -> list[ResearchEntry]:
        """Load all ResearchEntry objects from a workspace's store."""
        store = self._manager._store

        from gnat.context.store import WorkspaceStore

        raw_entries: list[dict[str, Any]] = []

        if isinstance(store, WorkspaceStore):
            ws_model = store.get_workspace(workspace_name)
            if ws_model is None:
                return []
            objects = store.get_objects(ws_model.id, stix_type="x-research-entry")
            raw_entries = objects
        else:
            entry_dir = Path(store._base) / workspace_name / "research_entries"
            if not entry_dir.exists():
                return []
            for fp in sorted(entry_dir.glob("*.json")):
                try:
                    raw_entries.append(json.loads(fp.read_text()))
                except json.JSONDecodeError:
                    logger.warning("ResearchLibrary: bad JSON in %s", fp)

        entries = []
        for raw in raw_entries:
            try:
                e = ResearchEntry.from_dict(raw)
                if status is None or e.curator_status == status:
                    entries.append(e)
            except (KeyError, ValueError) as exc:
                logger.warning("ResearchLibrary: bad entry data — %s", exc)

        return entries

    def _find_entry(
        self,
        topic: str,
        workspace_name: str,
        status: str | None = None,
    ) -> ResearchEntry | None:
        """Return the most recent entry matching a topic key."""
        tkey = topic_key(topic)
        entries = [
            e
            for e in self._load_all_entries(workspace_name, status=status)
            if topic_key(e.topic) == tkey
        ]
        if not entries:
            return None
        return max(entries, key=lambda e: e.promoted_at)

    def __repr__(self) -> str:  # pragma: no cover
        """Return unambiguous string representation."""
        stats = self.stats()
        return (
            f"ResearchLibrary(library={stats['library_total']} entries, "
            f"fresh={stats['library_fresh']}, staging={stats['staging_pending']})"
        )


def _utcnow() -> datetime:
    """Internal helper for utcnow."""
    return datetime.now(timezone.utc)

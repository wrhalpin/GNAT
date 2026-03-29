"""
gnat.research.library  (search-integrated delta)
====================================================

This module documents the **minimal changes** needed in
:class:`~gnat.research.library.ResearchLibrary` to route
:meth:`search` through the Solr sidecar when configured.

The full library is unchanged except for:

1. ``__init__`` accepts an optional ``search_index: SearchIndex``
   (defaulting to ``NullSearchIndex``).
2. :meth:`search` dispatches to ``_solr_search()`` or the existing
   ``_memory_search()`` depending on the index type.
3. :meth:`promote` calls ``self._search_index.index()`` after writing
   the entry to the staging workspace.

Nothing else changes.  The ``ResearchLibrary.default()`` factory is
updated to call ``build_search_index(cfg)`` from the config.

Delta shown as method replacements / additions only.
Add these into the existing ResearchLibrary class body.
"""

from __future__ import annotations

import logging
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from gnat.research.entry import ResearchEntry
    from gnat.search.index import SearchIndex

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Mixin / patch showing the three changes — integrate into library.py
# ---------------------------------------------------------------------------

class _ResearchLibrarySearchPatch:
    """
    Shows only the changed / added methods.  Integrate these into the
    existing ResearchLibrary class in gnat/research/library.py.
    """

    # --- Change 1: accept search_index in __init__ ---

    def _init_search(self, search_index: Optional["SearchIndex"] = None) -> None:
        """
        Call at the end of ResearchLibrary.__init__::

            self._init_search(search_index)

        Imports lazily to keep research/ free of a hard search/ dependency.
        """
        if search_index is not None:
            self._search_index = search_index
        else:
            from gnat.search.index import NullSearchIndex
            self._search_index: "SearchIndex" = NullSearchIndex()

    # --- Change 2: updated search() dispatcher ---

    def search(
        self,
        query: str,
        include_stale: bool = False,
        include_staging: bool = False,
        limit: int = 50,
    ) -> List["ResearchEntry"]:
        """
        Search the library for entries matching a query string.

        Routes through Solr when a :class:`~gnat.search.index.SolrSearchIndex`
        is attached; falls back to the existing in-memory scan otherwise.
        The external interface is identical in both paths.

        Parameters
        ----------
        query : str
            Case-insensitive search string.
        include_stale : bool
            If ``True``, include entries past their TTL.
        include_staging : bool
            If ``True``, also search the staging workspace.
        limit : int
            Maximum results to return.

        Returns
        -------
        list of ResearchEntry
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

    def _solr_search(
        self,
        query: str,
        include_stale: bool = False,
        include_staging: bool = False,
        limit: int = 50,
    ) -> List["ResearchEntry"]:
        """
        Solr-backed search path.

        Solr returns STIX IDs → we look up the corresponding
        ResearchEntry objects from the workspace metadata store.
        Entries not found in the store (e.g. evicted) are silently skipped.

        Stale filtering is applied post-fetch so TTL semantics are
        consistent with the memory path.
        """
        stix_ids = self._search_index.search(query, limit=limit * 2)
        # limit * 2 over-fetches to account for stale filtering

        entries: List["ResearchEntry"] = []
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
    ) -> Optional["ResearchEntry"]:
        """
        Look up a ResearchEntry by STIX object ID.

        ResearchEntry objects store their STIX objects in
        ``entry.stix_objects`` — we need a reverse map from
        object ID → entry.  Implementations should maintain this
        as a workspace metadata index keyed on ``stix_id:{id}``.

        Returns ``None`` if the entry is not found.
        """
        # This is the join between Solr (returns IDs) and the
        # workspace metadata store (holds ResearchEntry objects).
        # Implementation depends on your workspace backend.
        # Pseudocode shown — fill in with actual store lookup:
        #
        #   key = f"stix_id:{stix_id}"
        #   entry_key = self._library_ws.meta.get(key)
        #   if entry_key is None and include_staging:
        #       entry_key = self._staging_ws.meta.get(key)
        #   if entry_key:
        #       return self._get_entry(entry_key)
        #   return None
        raise NotImplementedError(
            "_entry_by_stix_id must be implemented in ResearchLibrary "
            "using your workspace metadata backend."
        )

    # --- Change 3: index on promote ---

    def _index_entry_objects(self, entry: "ResearchEntry") -> None:
        """
        Index all STIX objects from a ResearchEntry into the search sidecar.

        Called by promote() after the entry is written to staging.
        Fire-and-forget — index failures are logged, never raised.

        Integrate into ResearchLibrary.promote() after writing the entry::

            # ... existing write to staging workspace ...
            self._index_entry_objects(entry)
        """
        if not hasattr(entry, "stix_objects"):
            return
        for obj in entry.stix_objects:
            try:
                ok = self._search_index.index(
                    obj,
                    source_platform="research_library",
                    extra_fields={"research_topic": entry.topic},
                )
                if not ok:
                    logger.debug(
                        "Solr index skipped for %s (non-fatal)", obj.id
                    )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Solr index failed for %s: %s", obj.id, exc)

    # --- Factory update ---

    @classmethod
    def _build_search_index_from_config(cls) -> "SearchIndex":
        """
        Called from ResearchLibrary.default() to get the configured index.

        Add to ResearchLibrary.default()::

            search_index = ResearchLibrary._build_search_index_from_config()
            return cls(..., search_index=search_index)
        """
        try:
            from gnat.config import GNATConfig
            from gnat.search import build_search_index
            cfg = GNATConfig()
            return build_search_index(cfg)
        except Exception as exc:
            logger.debug("Search index not configured: %s", exc)
            from gnat.search.index import NullSearchIndex
            return NullSearchIndex()

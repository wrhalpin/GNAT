"""
ctm_sak.search
==============

Optional full-text search sidecar for CTM-SAK.

This package provides Solr integration as a **read-acceleration layer**
for unstructured text fields (descriptions, aliases, report bodies, notes).
It is entirely opt-in — if no ``[search]`` section exists in ``config.ini``
the :class:`NullSearchIndex` is used and the rest of the system is unaffected.

Public surface
--------------
:class:`SearchIndex`
    Abstract base class.  Type-hint against this, never concrete impls.
:class:`SolrSearchIndex`
    Solr HTTP client.  Constructed via ``SolrSearchIndex.from_config(cfg)``.
:class:`NullSearchIndex`
    Safe no-op default.
:class:`STIXSearchMixin`
    Mixin for :class:`~ctm_sak.orm.base.STIXBase` subclasses that adds
    ``to_search_doc()``.

Factory helper
--------------
:func:`build_search_index` reads ``[search]`` from a :class:`~ctm_sak.config.SAKConfig`
and returns the appropriate concrete implementation::

    from ctm_sak.search import build_search_index
    idx = build_search_index(cfg)   # SolrSearchIndex or NullSearchIndex
"""

from ctm_sak.search.mixin import STIXSearchMixin
from ctm_sak.search.index import SearchIndex, SolrSearchIndex, NullSearchIndex

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctm_sak.config import SAKConfig


def build_search_index(config: "SAKConfig") -> SearchIndex:
    """
    Factory that reads ``[search]`` from *config* and returns the
    appropriate :class:`SearchIndex` implementation.

    Configuration
    -------------
    ::

        [search]
        backend  = solr          ; "solr" or "memory" (default: memory)
        solr_url = http://localhost:8983/solr/ctmsak

    Returns
    -------
    SearchIndex
        :class:`SolrSearchIndex` if ``backend = solr``,
        :class:`NullSearchIndex` otherwise.

    Examples
    --------
    >>> from ctm_sak.config import SAKConfig
    >>> from ctm_sak.search import build_search_index
    >>> idx = build_search_index(SAKConfig())
    """
    try:
        cfg = config.get("search")
    except KeyError:
        return NullSearchIndex()

    backend = cfg.get("backend", "memory").strip().lower()
    if backend == "solr":
        return SolrSearchIndex.from_config(config)
    return NullSearchIndex()


__all__ = [
    "SearchIndex",
    "SolrSearchIndex",
    "NullSearchIndex",
    "STIXSearchMixin",
    "build_search_index",
]

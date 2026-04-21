# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.search.semantic
====================

Semantic search index backed by :class:`~gnat.agents.embeddings.EmbeddingStore`.

Implements the :class:`~gnat.search.index.SearchIndex` interface so it can
be used anywhere a ``SearchIndex`` is accepted (pipelines, research library,
copilot gap detector) without changing callers.

Unlike :class:`~gnat.search.index.SolrSearchIndex` (keyword / BM25), this
index performs *dense retrieval* — it finds semantically similar STIX objects
even when the query shares no keywords with the stored text.

Architecture
------------
* STIX objects are indexed with their text representation
  (``display_name + description + pattern``).
* The underlying ``EmbeddingStore`` holds all vectors in memory; for
  large workspaces (>100K objects) consider a vector DB instead.
* The index is **write-through** — it never serves as the authoritative
  source; callers receive STIX IDs and fetch full objects from Postgres.

Usage::

    from gnat.agents.llm import LLMClient
    from gnat.search.semantic import SemanticSearchIndex
    from gnat.orm.indicator import Indicator

    llm = LLMClient(backend="openai", api_key="sk-...")
    idx = SemanticSearchIndex(llm)

    # Index a STIX object
    indicator = Indicator(name="Cobalt Strike C2", ...)
    idx.index(indicator, source_platform="crowdstrike")

    # Semantic search
    stix_ids = idx.search("beaconing to external IP")
    # → ["indicator--abc...", "indicator--def...", ...]
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from gnat.search.index import SearchIndex

if TYPE_CHECKING:
    from gnat.agents.embeddings import EmbeddingStore
    from gnat.agents.llm import LLMClient
    from gnat.orm.base import STIXBase

logger = logging.getLogger(__name__)


def _stix_to_text(obj: STIXBase) -> str:
    """
    Build a searchable text representation of a STIX object.

    Concatenates name, description, and type-specific fields that carry
    the most semantic signal.
    """
    parts: list[str] = []

    # Common fields present on most SDOs
    for attr in ("name", "description", "pattern", "aliases", "kill_chain_phases"):
        val = getattr(obj, attr, None)
        if val is None:
            val = obj._properties.get(attr)  # type: ignore[attr-defined]
        if isinstance(val, list):
            parts.extend(str(v) for v in val if v)
        elif val:
            parts.append(str(val))

    # STIX type as context hint
    stix_type = getattr(obj, "stix_type", "")
    if stix_type:
        parts.insert(0, stix_type)

    return " ".join(parts)[:4096]  # cap at 4096 chars (≈1024 tokens)


class SemanticSearchIndex(SearchIndex):
    """
    Dense embedding semantic search index.

    Wraps :class:`~gnat.agents.embeddings.EmbeddingStore` to implement the
    :class:`~gnat.search.index.SearchIndex` protocol.

    Parameters
    ----------
    llm : LLMClient
        LLM client used for embedding.  Must support ``embed()`` (openai or gemini).
    embed_model : str, optional
        Embeddings model override.
    batch_size : int
        Texts per embed API call.  Default ``96``.
    """

    def __init__(
        self,
        llm: LLMClient,
        embed_model: str | None = None,
        batch_size: int = 96,
    ) -> None:
        """Initialize SemanticSearchIndex."""
        from gnat.agents.embeddings import EmbeddingStore

        self._store: EmbeddingStore = EmbeddingStore(
            llm, embed_model=embed_model, batch_size=batch_size
        )

    # ── SearchIndex protocol ──────────────────────────────────────────────

    def index(self, obj: STIXBase, source_platform: str = "") -> None:
        """
        Embed and store a STIX object.

        Parameters
        ----------
        obj : STIXBase
            STIX object to index.
        source_platform : str
            Connector / platform name (unused for ranking; stored as metadata
            in future versions).
        """
        stix_id = getattr(obj, "id", None) or getattr(obj, "stix_id", None)
        if not stix_id:
            logger.debug("SemanticSearchIndex.index: object has no id, skipping")
            return
        text = _stix_to_text(obj)
        if not text.strip():
            return
        try:
            self._store.add(stix_id, text)
        except Exception as exc:
            # Fire-and-forget: never block the pipeline on index failure
            logger.warning("SemanticSearchIndex.index failed for %s — %s", stix_id, exc)

    def index_batch(
        self,
        objects: list[STIXBase],
        source_platform: str = "",
    ) -> None:
        """
        Index multiple STIX objects in a single batched API call.

        Parameters
        ----------
        objects : list[STIXBase]
            Objects to embed and store.
        source_platform : str
            Platform label (informational).
        """
        items: list[tuple[str, str]] = []
        for obj in objects:
            stix_id = getattr(obj, "id", None) or getattr(obj, "stix_id", None)
            if not stix_id:
                continue
            text = _stix_to_text(obj)
            if text.strip():
                items.append((stix_id, text))
        if items:
            try:
                self._store.add_batch(items)
            except Exception as exc:
                logger.warning("SemanticSearchIndex.index_batch failed — %s", exc)

    def delete(self, stix_id: str) -> None:
        """Remove a STIX object from the index."""
        self._store.remove(stix_id)

    def search(
        self,
        query: str,
        stix_types: list[str] | None = None,
        source_platforms: list[str] | None = None,
        page: int = 0,
        page_size: int = 20,
        **kwargs: Any,
    ) -> list[str]:
        """
        Return STIX IDs semantically similar to *query*.

        Parameters
        ----------
        query : str
            Natural language search query.
        stix_types : list[str], optional
            Type filter.  Note: this implementation returns all matches
            regardless of type (no type metadata stored).  Type filtering
            must be applied by the caller after fetching full objects.
        source_platforms : list[str], optional
            Platform filter (not applied — semantic index is platform-agnostic).
        page : int
            Zero-based page offset.
        page_size : int
            Results per page.

        Returns
        -------
        list[str]
            STIX IDs ordered by semantic similarity (most similar first).
        """
        top_k = (page + 1) * page_size
        results = self._store.search(query, top_k=top_k, min_score=kwargs.get("min_score", 0.0))
        paginated = results[page * page_size : (page + 1) * page_size]
        return [stix_id for stix_id, _ in paginated]

    def search_with_scores(
        self,
        query: str,
        top_k: int = 10,
        min_score: float = 0.0,
    ) -> list[tuple[str, float]]:
        """
        Return ``(stix_id, score)`` pairs for *query*.

        Use this when you need similarity scores (e.g. for hypothesis
        confidence weighting).

        Parameters
        ----------
        query : str
            Search query.
        top_k : int
            Maximum results.
        min_score : float
            Minimum similarity threshold (0.0–1.0).

        Returns
        -------
        list[tuple[str, float]]
            Sorted by descending similarity score.
        """
        return self._store.search(query, top_k=top_k, min_score=min_score)

    def __len__(self) -> int:
        """Return number of indexed objects."""
        return len(self._store)

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.embeddings
======================

In-memory embedding store with cosine similarity search.

Designed to accelerate semantic search over STIX objects and research
library entries without requiring a dedicated vector database.  For
production use at scale, swap in Pinecone, Weaviate, or pgvector.

Usage::

    from gnat.agents.llm import LLMClient
    from gnat.agents.embeddings import EmbeddingStore

    llm   = LLMClient(backend="openai", api_key="sk-...")
    store = EmbeddingStore(llm)

    # Index documents
    store.add("stix-indicator-001", "Cobalt Strike beacon observed on 1.2.3.4")
    store.add("stix-malware-002",   "LockBit 3.0 ransomware targeting ESXi hosts")

    # Query by similarity
    results = store.search("ESXi ransomware", top_k=5)
    for stix_id, score in results:
        print(stix_id, round(score, 3))
"""

from __future__ import annotations

import logging
import math
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gnat.agents.llm import LLMClient

logger = logging.getLogger(__name__)


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Return cosine similarity between two equal-length vectors."""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


class EmbeddingStore:
    """
    In-memory store of dense embedding vectors with cosine-similarity search.

    Parameters
    ----------
    llm : LLMClient
        Configured ``LLMClient`` used for computing embeddings.
        Must support ``embed()`` — use ``backend="openai"`` or ``backend="gemini"``.
    embed_model : str, optional
        Embeddings model override passed to ``llm.embed()`` (e.g.
        ``"text-embedding-3-large"``).  The provider default is used if omitted.
    batch_size : int
        Number of texts to embed per API call.  Default ``96``.

    Attributes
    ----------
    _store : dict[str, list[float]]
        Maps STIX ID / arbitrary key → embedding vector.
    """

    def __init__(
        self,
        llm: LLMClient,
        embed_model: str | None = None,
        batch_size: int = 96,
    ) -> None:
        """Initialize EmbeddingStore."""
        self._llm = llm
        self._embed_model = embed_model
        self._batch_size = batch_size
        self._store: dict[str, list[float]] = {}

    # ── Indexing ──────────────────────────────────────────────────────────

    def add(self, key: str, text: str) -> None:
        """
        Embed *text* and store the vector under *key*.

        If a vector for *key* already exists it is overwritten.

        Parameters
        ----------
        key : str
            Identifier (e.g. STIX ID or research library entry ID).
        text : str
            Text to embed.
        """
        kwargs: dict[str, Any] = {}
        if self._embed_model:
            kwargs["model"] = self._embed_model
        vectors = self._llm.embed([text], **kwargs)
        self._store[key] = vectors[0]

    def add_batch(self, items: list[tuple[str, str]]) -> None:
        """
        Embed and store multiple *(key, text)* pairs efficiently.

        Sends texts in batches of :attr:`batch_size` to minimise API calls.

        Parameters
        ----------
        items : list[tuple[str, str]]
            Pairs of ``(key, text)`` to index.
        """
        kwargs: dict[str, Any] = {}
        if self._embed_model:
            kwargs["model"] = self._embed_model

        keys = [k for k, _ in items]
        texts = [t for _, t in items]

        for i in range(0, len(texts), self._batch_size):
            batch_keys = keys[i : i + self._batch_size]
            batch_texts = texts[i : i + self._batch_size]
            try:
                vectors = self._llm.embed(batch_texts, **kwargs)
                for key, vec in zip(batch_keys, vectors):
                    self._store[key] = vec
            except Exception as exc:
                logger.warning(
                    "EmbeddingStore.add_batch: batch %d-%d failed — %s",
                    i, i + self._batch_size, exc,
                )

    def remove(self, key: str) -> None:
        """Remove a stored vector.  No-op if *key* is not present."""
        self._store.pop(key, None)

    def clear(self) -> None:
        """Remove all stored vectors."""
        self._store.clear()

    # ── Search ────────────────────────────────────────────────────────────

    def search(
        self,
        query: str,
        top_k: int = 10,
        min_score: float = 0.0,
    ) -> list[tuple[str, float]]:
        """
        Return the *top_k* most similar keys for *query*.

        Parameters
        ----------
        query : str
            Natural language query text.
        top_k : int
            Maximum number of results.  Default ``10``.
        min_score : float
            Minimum cosine similarity threshold (0.0–1.0).  Results below
            this score are excluded.  Default ``0.0`` (no filter).

        Returns
        -------
        list[tuple[str, float]]
            ``(key, score)`` pairs sorted by descending similarity.
        """
        if not self._store:
            return []

        kwargs: dict[str, Any] = {}
        if self._embed_model:
            kwargs["model"] = self._embed_model

        try:
            query_vecs = self._llm.embed([query], **kwargs)
        except Exception as exc:
            logger.error("EmbeddingStore.search: embed failed — %s", exc)
            return []

        query_vec = query_vecs[0]
        scored: list[tuple[str, float]] = []
        for key, vec in self._store.items():
            score = _cosine_similarity(query_vec, vec)
            if score >= min_score:
                scored.append((key, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]

    # ── Inspection ────────────────────────────────────────────────────────

    def __len__(self) -> int:
        """Return number of stored vectors."""
        return len(self._store)

    def __contains__(self, key: str) -> bool:
        """Return True if *key* has a stored vector."""
        return key in self._store

    def keys(self) -> list[str]:
        """Return list of all stored keys."""
        return list(self._store.keys())

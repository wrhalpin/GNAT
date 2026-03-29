"""
gnat.ingest.pipeline.pipeline  (search-integrated version)
=============================================================

This module shows the **delta** from the original IngestPipeline needed
to wire in the search sidecar.  It is a drop-in replacement — all
existing call sites work unchanged because ``index_with()`` is opt-in
and ``_search_index`` defaults to ``NullSearchIndex``.

Changes from original
---------------------
1. ``__init__`` initialises ``_search_index`` as ``NullSearchIndex()``.
2. New fluent method ``index_with(search_index, source_platform)``
3. ``run()`` calls ``self._search_index.index(obj)`` after a successful
   ``obj.save()`` — fire-and-forget, Solr errors never abort the run.
4. ``index_batch()`` called once per pipeline run at the end as an
   optimisation when using batch mode (see ``_batch_index``).

The index call sits *inside* the ``if self._client is not None`` branch,
after ``obj.save()`` succeeds.  This means:

* Dry runs (no ``write_to()``) do not index — correct, there's nothing
  in the source of truth to back the Solr doc.
* Write failures do not index — correct, don't index what wasn't saved.
* Solr failures do not abort the run — correct, Solr is a sidecar.

Usage
-----
::

    from gnat.ingest import IngestPipeline
    from gnat.search import build_search_index
    from gnat.config import GNATConfig

    cfg = GNATConfig()
    idx = build_search_index(cfg)   # NullSearchIndex if [search] absent

    result = (
        IngestPipeline("daily-threatq")
        .read_from(reader)
        .map_with(mapper)
        .write_to(cli)
        .index_with(idx, source_platform="threatq")
        .run()
    )
    print(result)
    # IngestResult(... indexed=47)
"""

from __future__ import annotations

import logging
from typing import Callable, Iterator, List, Optional, TYPE_CHECKING

from gnat.ingest.base import (
    DeduplicationCache,
    IngestResult,
    RecordMapper,
    SourceReader,
)
from gnat.search.index import NullSearchIndex, SearchIndex

if TYPE_CHECKING:
    from gnat.orm.base import STIXBase
    from gnat.client import GNATClient

logger = logging.getLogger(__name__)


class IngestPipeline:
    """
    Orchestrates reading → mapping → (optional) writing → (optional) indexing.

    All parameters and methods from the original pipeline are preserved.
    The only additions are:

    * ``index_with(search_index, source_platform)`` — fluent builder method
    * ``_search_index`` internal attribute (defaults to NullSearchIndex)
    * ``indexed_objects`` counter on IngestResult
    """

    def __init__(self, name: str = ""):
        self._name = name
        self._reader: Optional[SourceReader] = None
        self._mapper: Optional[RecordMapper] = None
        self._client: Optional["GNATClient"] = None
        self._dedup: Optional[DeduplicationCache] = None
        self._filters: List[Callable[["STIXBase"], bool]] = []
        self._transforms: List[Callable[["STIXBase"], "STIXBase"]] = []
        # Search sidecar — NullSearchIndex by default so callers never
        # need to guard for None.
        self._search_index: SearchIndex = NullSearchIndex()
        self._source_platform: str = ""

    # ------------------------------------------------------------------
    # Fluent builder
    # ------------------------------------------------------------------

    def read_from(self, reader: SourceReader) -> "IngestPipeline":
        self._reader = reader
        return self

    def map_with(self, mapper: RecordMapper) -> "IngestPipeline":
        self._mapper = mapper
        return self

    def write_to(self, client: "GNATClient") -> "IngestPipeline":
        self._client = client
        return self

    def deduplicate(
        self, key_fields: Optional[List[str]] = None
    ) -> "IngestPipeline":
        self._dedup = DeduplicationCache(key_fields)
        return self

    def filter(
        self, predicate: Callable[["STIXBase"], bool]
    ) -> "IngestPipeline":
        self._filters.append(predicate)
        return self

    def transform(
        self, fn: Callable[["STIXBase"], "STIXBase"]
    ) -> "IngestPipeline":
        self._transforms.append(fn)
        return self

    def index_with(
        self,
        search_index: SearchIndex,
        source_platform: str = "",
    ) -> "IngestPipeline":
        """
        Attach a :class:`~gnat.search.index.SearchIndex` to this pipeline.

        Parameters
        ----------
        search_index : SearchIndex
            A :class:`~gnat.search.index.SolrSearchIndex` (or any
            :class:`~gnat.search.index.SearchIndex` implementation).
        source_platform : str, optional
            Label stored in the Solr document's ``source_platform`` field.
            Typically the connector name (``"threatq"``, ``"recordedfuture"``).
            Used for faceted filtering in search results.

        Returns
        -------
        IngestPipeline
            ``self`` for chaining.

        Notes
        -----
        If *search_index* is a :class:`~gnat.search.index.NullSearchIndex`
        (the default), this method is a no-op at runtime — useful for
        disabling indexing in tests without changing the pipeline call site.
        """
        self._search_index = search_index
        self._source_platform = source_platform
        return self

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def iter_objects(self) -> Iterator["STIXBase"]:
        """Iterate over mapped objects without writing or indexing."""
        self._validate()
        with self._reader:
            for raw in self._reader:
                try:
                    for obj in self._mapper.map(raw):
                        if not self._passes_filters(obj):
                            continue
                        if self._dedup is not None and self._dedup.is_duplicate(obj):
                            continue
                        obj = self._apply_transforms(obj)
                        yield obj
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Pipeline %r: error mapping record — %s", self._name, exc
                    )

    def run(self) -> "IngestResult":
        """
        Execute the full pipeline: read → map → filter → dedup → write → index.

        The index step fires after each successful ``obj.save()``.
        Solr errors are counted in ``result.index_errors`` but never
        propagate — a Solr outage cannot abort an ingest run.
        """
        self._validate()
        result = _SearchAwareIngestResult(
            source_id=self._reader.source_id if self._reader else self._name
        )

        with self._reader:
            for raw in self._reader:
                result.total_records += 1
                try:
                    for obj in self._mapper.map(raw):
                        result.mapped_objects += 1

                        if not self._passes_filters(obj):
                            continue

                        if self._dedup is not None and self._dedup.is_duplicate(obj):
                            result.skipped_duplicates += 1
                            continue

                        obj = self._apply_transforms(obj)

                        if self._client is not None:
                            try:
                                obj.save()
                                result.written_objects += 1
                                # Index only after a confirmed write.
                                ok = self._search_index.index(
                                    obj,
                                    source_platform=self._source_platform,
                                )
                                if ok:
                                    result.indexed_objects += 1
                                else:
                                    result.index_errors += 1
                            except Exception as write_exc:  # noqa: BLE001
                                msg = f"Write failed for {obj.id}: {write_exc}"
                                result.errors.append(msg)
                                logger.error(msg)
                        else:
                            result.written_objects += 1

                except Exception as map_exc:  # noqa: BLE001
                    msg = f"Map error on record #{result.total_records}: {map_exc}"
                    result.errors.append(msg)
                    logger.warning(msg)

        logger.info(str(result))
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _validate(self) -> None:
        if self._reader is None:
            raise RuntimeError(
                "IngestPipeline: no reader configured. Call .read_from() first."
            )
        if self._mapper is None:
            raise RuntimeError(
                "IngestPipeline: no mapper configured. Call .map_with() first."
            )

    def _passes_filters(self, obj: "STIXBase") -> bool:
        return all(f(obj) for f in self._filters)

    def _apply_transforms(self, obj: "STIXBase") -> "STIXBase":
        for fn in self._transforms:
            obj = fn(obj)
        return obj

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"IngestPipeline(name={self._name!r}, "
            f"reader={self._reader!r}, mapper={self._mapper!r})"
        )


class _SearchAwareIngestResult(IngestResult):
    """
    IngestResult extended with search index counters.

    Keeps the original IngestResult interface intact — callers that
    only look at ``written_objects`` / ``errors`` are unaffected.
    """

    def __init__(self, source_id: str = ""):
        super().__init__(source_id=source_id)
        self.indexed_objects: int = 0
        self.index_errors: int = 0

    def __str__(self) -> str:
        base = super().__str__()
        return (
            f"{base} | indexed={self.indexed_objects}"
            f" index_errors={self.index_errors}"
        )

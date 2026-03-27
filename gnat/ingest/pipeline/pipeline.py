"""
gnat.ingest.pipeline.pipeline
==================================

:class:`IngestPipeline` — the top-level orchestrator that chains a
:class:`~gnat.ingest.base.SourceReader` with a
:class:`~gnat.ingest.base.RecordMapper`, applies optional transforms and
deduplication, and optionally writes results to a connected platform.

Usage::

    from gnat.ingest import IngestPipeline
    from gnat.ingest.sources import CSVSourceReader
    from gnat.ingest.mappers import FlatIOCMapper

    pipeline = (
        IngestPipeline()
        .read_from(CSVSourceReader("iocs.csv", value_col="indicator", type_col="type"))
        .map_with(FlatIOCMapper(tlp_marking="amber", confidence=70))
        .write_to(cli)           # optional — omit to just collect results
        .deduplicate()
    )

    result = pipeline.run()
    print(result)

    # Collect objects without writing
    objects = list(pipeline.iter_objects())
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

if TYPE_CHECKING:
    from gnat.orm.base import STIXBase
    from gnat.client import SAKClient

logger = logging.getLogger(__name__)


class IngestPipeline:
    """
    Orchestrates reading → mapping → (optional) writing for a single source.

    The pipeline is configured via a fluent builder API and executed by
    calling :meth:`run` (writes to platform) or :meth:`iter_objects`
    (yields objects without writing).

    Parameters
    ----------
    name : str, optional
        Human-readable label used in log messages and :class:`IngestResult`.

    Examples
    --------
    Dry-run (no write)::

        objects = list(
            IngestPipeline()
            .read_from(STIXBundleReader("bundle.json"))
            .map_with(STIXPassthroughMapper())
            .iter_objects()
        )

    Full pipeline with write::

        result = (
            IngestPipeline("daily-feed")
            .read_from(TAXIICollectionReader(collection))
            .map_with(STIXPassthroughMapper(client=cli))
            .write_to(cli)
            .deduplicate(key_fields=["name", "pattern"])
            .run()
        )
    """

    def __init__(self, name: str = ""):
        self._name = name
        self._reader: Optional[SourceReader] = None
        self._mapper: Optional[RecordMapper] = None
        self._client: Optional["SAKClient"] = None
        self._dedup: Optional[DeduplicationCache] = None
        self._filters: List[Callable[["STIXBase"], bool]] = []
        self._transforms: List[Callable[["STIXBase"], "STIXBase"]] = []

    # ------------------------------------------------------------------
    # Fluent builder
    # ------------------------------------------------------------------

    def read_from(self, reader: SourceReader) -> "IngestPipeline":
        """
        Set the source reader.

        Parameters
        ----------
        reader : SourceReader
            Any :class:`~gnat.ingest.base.SourceReader` subclass.

        Returns
        -------
        IngestPipeline
            ``self`` for chaining.
        """
        self._reader = reader
        return self

    def map_with(self, mapper: RecordMapper) -> "IngestPipeline":
        """
        Set the record mapper.

        Parameters
        ----------
        mapper : RecordMapper
            Any :class:`~gnat.ingest.base.RecordMapper` subclass.

        Returns
        -------
        IngestPipeline
            ``self`` for chaining.
        """
        self._mapper = mapper
        return self

    def write_to(self, client: "SAKClient") -> "IngestPipeline":
        """
        Set the platform client to write results to.

        Parameters
        ----------
        client : SAKClient
            A connected :class:`~gnat.client.SAKClient`.

        Returns
        -------
        IngestPipeline
            ``self`` for chaining.
        """
        self._client = client
        return self

    def deduplicate(
        self, key_fields: Optional[List[str]] = None
    ) -> "IngestPipeline":
        """
        Enable in-pipeline deduplication.

        Parameters
        ----------
        key_fields : list of str, optional
            Fields used to compute the uniqueness fingerprint.
            Defaults to ``["id"]``.

        Returns
        -------
        IngestPipeline
            ``self`` for chaining.
        """
        self._dedup = DeduplicationCache(key_fields)
        return self

    def filter(
        self, predicate: Callable[["STIXBase"], bool]
    ) -> "IngestPipeline":
        """
        Add a filter predicate; objects for which ``predicate`` returns
        ``False`` are dropped.

        Parameters
        ----------
        predicate : callable
            A function ``(STIXBase) -> bool``.

        Returns
        -------
        IngestPipeline
            ``self`` for chaining.

        Examples
        --------
        >>> pipeline.filter(lambda obj: obj.stix_type == "indicator")
        >>> pipeline.filter(lambda obj: getattr(obj, "score", 0) >= 70)
        """
        self._filters.append(predicate)
        return self

    def transform(
        self, fn: Callable[["STIXBase"], "STIXBase"]
    ) -> "IngestPipeline":
        """
        Add a transform function applied to every passing object.

        Transforms run after filters.

        Parameters
        ----------
        fn : callable
            A function ``(STIXBase) -> STIXBase``.  Must return an object.

        Returns
        -------
        IngestPipeline
            ``self`` for chaining.

        Examples
        --------
        >>> pipeline.transform(lambda obj: setattr(obj, "confidence", 80) or obj)
        """
        self._transforms.append(fn)
        return self

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def iter_objects(self) -> Iterator["STIXBase"]:
        """
        Iterate over mapped (and filtered/deduped) STIX objects without
        writing them anywhere.

        Yields
        ------
        STIXBase
            Mapped, filtered, and transformed objects.

        Raises
        ------
        RuntimeError
            If neither reader nor mapper has been configured.
        """
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

    def run(self) -> IngestResult:
        """
        Execute the full pipeline: read → map → filter → dedup → write.

        Returns
        -------
        IngestResult
            Summary of the run.

        Raises
        ------
        RuntimeError
            If reader or mapper has not been configured.
        """
        self._validate()
        result = IngestResult(
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
                            except Exception as write_exc:  # noqa: BLE001
                                msg = f"Write failed for {obj.id}: {write_exc}"
                                result.errors.append(msg)
                                logger.error(msg)
                        else:
                            result.written_objects += 1  # "written" = processed

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

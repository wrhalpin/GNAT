# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.ingest.base
====================

Abstract base classes and protocols for the GNAT ingestion framework.

Architecture Overview
---------------------
The ingestion layer is built from three composable abstractions:

.. code-block:: text

    SourceReader  ──yields──►  RawRecord
         │
         ▼
    RecordMapper  ──yields──►  STIXBase  (Indicator, ThreatActor, …)
         │
         ▼
    IngestPipeline ──pushes──► GNATClient  (optional, via .write_to())

**SourceReader**
    Knows how to open a data source (file, database, HTTP endpoint, …) and
    yield raw records as plain dicts.  It is deliberately *dumb* — it does
    not understand STIX or security concepts.

**RecordMapper**
    Knows how to convert a raw dict into one or more :class:`~gnat.orm.base.STIXBase`
    instances.  One mapper per source schema (CSV column layout, DB table
    shape, MISP event structure, etc.).

**IngestPipeline**
    Chains a reader and a mapper, applies optional filters and deduplication,
    and optionally writes results to a connected :class:`~gnat.client.GNATClient`.

This design means you can:
* Swap sources without touching mappers (e.g. read same CSV from disk or S3).
* Swap mappers without touching sources (e.g. parse same JSON as MISP or as
  plain IOC list).
* Test readers and mappers independently with zero external dependencies.
"""

from __future__ import annotations

import hashlib
import logging
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gnat.client import GNATClient
    from gnat.orm.base import STIXBase

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Raw record type
# ---------------------------------------------------------------------------

#: A raw record is just a plain dict produced by a SourceReader.
RawRecord = dict[str, Any]


# ---------------------------------------------------------------------------
# SourceReader
# ---------------------------------------------------------------------------


class SourceReader(ABC):
    """
    Abstract base for all data source readers.

    A :class:`SourceReader` opens a source, iterates over its records as
    plain dicts, and closes cleanly.  It supports the context manager
    protocol so callers can use ``with`` blocks.

    Subclasses must implement :meth:`_iter_records`.  They may optionally
    override :meth:`open` and :meth:`close` to manage external resources
    (DB connections, file handles, HTTP sessions, etc.).

    Parameters
    ----------
    source_id : str, optional
        Human-readable label for log messages and pipeline metadata.
    batch_size : int
        Number of records yielded per internal batch (used by sources that
        support server-side pagination).  Default 500.

    Examples
    --------
    >>> with CSVSourceReader("iocs.csv") as reader:
    ...     for record in reader:
    ...         print(record)
    """

    def __init__(
        self,
        source_id: str = "",
        batch_size: int = 500,
    ):
        """Initialize SourceReader."""
        self.source_id = source_id or type(self).__name__
        self.batch_size = batch_size
        self._open = False

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> SourceReader:
        """Enter the context manager."""
        self.open()
        return self

    def __exit__(self, *_: Any) -> None:
        """Exit the context manager, handling any exceptions."""
        self.close()

    # ------------------------------------------------------------------
    # Lifecycle hooks
    # ------------------------------------------------------------------

    def open(self) -> None:
        """Open the source.  Override to allocate connections/handles."""
        self._open = True
        logger.debug("%s: opened", self.source_id)

    def close(self) -> None:
        """Close the source.  Override to release connections/handles."""
        self._open = False
        logger.debug("%s: closed", self.source_id)

    # ------------------------------------------------------------------
    # Iteration
    # ------------------------------------------------------------------

    @abstractmethod
    def _iter_records(self) -> Iterator[RawRecord]:
        """
        Yield raw records from the source.

        Must be implemented by every subclass.  Each record is a plain dict;
        the exact keys depend on the source schema.

        Yields
        ------
        RawRecord
            One raw record (plain dict) per iteration.
        """

    def __iter__(self) -> Iterator[RawRecord]:
        """Iterate over items."""
        if not self._open:
            self.open()
        yield from self._iter_records()

    def read_all(self) -> list[RawRecord]:
        """Materialise all records into a list.  Convenient for small sources."""
        return list(self)

    def __repr__(self) -> str:  # pragma: no cover
        """Return unambiguous string representation."""
        return f"{type(self).__name__}(source_id={self.source_id!r})"


# ---------------------------------------------------------------------------
# RecordMapper
# ---------------------------------------------------------------------------


class RecordMapper(ABC):
    """
    Abstract base for all record-to-STIX mappers.

    A :class:`RecordMapper` receives a raw dict (from a :class:`SourceReader`)
    and yields zero or more :class:`~gnat.orm.base.STIXBase` instances.

    A single raw record may produce multiple STIX objects — for example a
    MISP event that contains many attributes.

    Parameters
    ----------
    client : GNATClient, optional
        If provided, all produced STIX objects are bound to this client so
        CRUD methods work immediately.
    tlp_marking : str, optional
        Default TLP marking to apply to produced objects
        (``"white"``, ``"green"``, ``"amber"``, ``"red"``).
        Default ``"white"``.
    confidence : int, optional
        Default confidence score (0–100) attached to produced objects.
        Default ``50``.

    Examples
    --------
    >>> mapper = IndicatorMapper(client=cli, tlp_marking="amber")
    >>> for stix_obj in mapper.map({"value": "1.2.3.4", "type": "ip"}):
    ...     print(stix_obj.to_dict())
    """

    def __init__(
        self,
        client: GNATClient | None = None,
        tlp_marking: str = "white",
        confidence: int = 50,
    ):
        """Initialize RecordMapper."""
        self._client = client
        self.tlp_marking = tlp_marking
        self.confidence = confidence

    @abstractmethod
    def map(self, record: RawRecord) -> Iterator[STIXBase]:
        """
        Convert one raw record into zero or more STIX objects.

        Parameters
        ----------
        record : RawRecord
            A plain dict produced by a :class:`SourceReader`.

        Yields
        ------
        STIXBase
            One STIX object per yield.  May yield nothing for unrecognised
            or filtered records.
        """

    def map_many(self, records: Iterable[RawRecord]) -> Iterator[STIXBase]:
        """Map an iterable of records, flattening all results."""
        for record in records:
            try:
                yield from self.map(record)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "%s: failed to map record %r — %s",
                    type(self).__name__,
                    record,
                    exc,
                )

    def __repr__(self) -> str:  # pragma: no cover
        """Return unambiguous string representation."""
        return f"{type(self).__name__}(tlp={self.tlp_marking!r}, confidence={self.confidence})"


# ---------------------------------------------------------------------------
# Ingest result metadata
# ---------------------------------------------------------------------------


@dataclass
class IngestResult:
    """
    Summary produced by :class:`IngestPipeline` after a run.

    Attributes
    ----------
    source_id : str
        Identifier of the source that was read.
    total_records : int
        Number of raw records read from the source.
    mapped_objects : int
        Number of STIX objects produced by the mapper.
    written_objects : int
        Number of objects successfully written to the target platform.
    errors : list of str
        Error messages collected during the run.
    skipped_duplicates : int
        Records skipped due to deduplication.
    """

    source_id: str = ""
    total_records: int = 0
    mapped_objects: int = 0
    written_objects: int = 0
    errors: list[str] = field(default_factory=list)
    skipped_duplicates: int = 0

    @property
    def success_rate(self) -> float:
        """Fraction of mapped objects successfully written (0.0–1.0)."""
        if self.mapped_objects == 0:
            return 1.0
        return self.written_objects / self.mapped_objects

    def __str__(self) -> str:  # pragma: no cover
        """Return human-readable string representation."""
        return (
            f"IngestResult({self.source_id!r}): "
            f"{self.total_records} records → "
            f"{self.mapped_objects} STIX objects, "
            f"{self.written_objects} written, "
            f"{self.skipped_duplicates} duplicates skipped, "
            f"{len(self.errors)} errors"
        )


# ---------------------------------------------------------------------------
# Deduplication helper
# ---------------------------------------------------------------------------


class DeduplicationCache:
    """
    In-memory seen-set for deduplication during an ingest run.

    Uses a SHA-256 fingerprint of ``(stix_type, canonical_value)`` so the
    cache stays small even for large ingest runs.

    Parameters
    ----------
    key_fields : list of str
        Which fields to use as the uniqueness key.  Defaults to ``["id"]``.
    """

    def __init__(self, key_fields: list[str] | None = None):
        """Initialize DeduplicationCache."""
        self._fields = key_fields or ["id"]
        self._seen: set = set()

    def is_duplicate(self, stix_obj: STIXBase) -> bool:
        """Return True if this object has been seen before."""
        fingerprint = self._fingerprint(stix_obj)
        if fingerprint in self._seen:
            return True
        self._seen.add(fingerprint)
        return False

    def _fingerprint(self, obj: STIXBase) -> str:
        """Internal helper for fingerprint."""
        parts = []
        for fld in self._fields:
            if fld == "id":
                parts.append(obj.id)
            else:
                parts.append(str(obj._properties.get(fld, "")))
        raw = "|".join(parts).encode()
        return hashlib.sha256(raw).hexdigest()

    def clear(self) -> None:
        """Reset the cache."""
        self._seen.clear()

    def __len__(self) -> int:
        """Return the number of items."""
        return len(self._seen)

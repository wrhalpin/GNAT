# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.ingest.sources.mitre_taxii_reader
==========================================

MITRE ATT&CK TAXII 2.1 reader.

Subclasses :class:`~gnat.ingest.sources.readers.TAXIICollectionReader` and
auto-discovers the enterprise/mobile/ICS matrix collections from MITRE's
public TAXII 2.1 server at ``https://attack-taxii.mitre.org/api/v21/``.

MITRE rate-limits the server to 10 requests per 10 minutes per source IP,
so this reader wraps ``get_objects`` with an internal token-bucket limiter.

Requires the optional ``taxii2-client`` dependency::

    pip install "gnat[taxii]"

Example
-------

>>> reader = MitreAttackTAXIIReader(matrix="enterprise-attack",
...                                  stix_types=["attack-pattern"])
>>> for obj in reader:
...     print(obj["type"], obj.get("name"))
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Iterator
from typing import Any, ClassVar, Literal

from gnat.ingest.base import RawRecord
from gnat.ingest.sources.readers import TAXIICollectionReader

logger = logging.getLogger(__name__)

# MITRE ATT&CK TAXII 2.1 server root and collection IDs.
# See https://attack.mitre.org/resources/attack-data-and-tools/
MITRE_TAXII_ROOT = "https://attack-taxii.mitre.org/api/v21/"

MITRE_COLLECTION_IDS: dict[str, str] = {
    "enterprise-attack": "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019",
    "mobile-attack": "x-mitre-collection--dac0d2d7-8653-445c-9bff-82f934c1e858",
    "ics-attack": "x-mitre-collection--90c00720-636b-4485-b342-8751d232bf09",
}

MatrixName = Literal["enterprise-attack", "mobile-attack", "ics-attack"]


class _TokenBucket:
    """Thread-safe token bucket for rate limiting.

    Allows *capacity* requests per *window_seconds*.  Blocks the caller when
    the bucket is empty until tokens refill.
    """

    def __init__(self, capacity: int, window_seconds: float):
        """Initialize the bucket with a full allotment."""
        self.capacity = capacity
        self.window = window_seconds
        self._tokens = float(capacity)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, cost: int = 1) -> None:
        """Consume *cost* tokens, blocking until they become available."""
        with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(
                    float(self.capacity),
                    self._tokens + (elapsed * self.capacity / self.window),
                )
                if self._tokens >= cost:
                    self._tokens -= cost
                    return
                # Not enough tokens — sleep until at least *cost* are available
                needed = cost - self._tokens
                wait = needed * (self.window / self.capacity)
                time.sleep(max(wait, 0.05))


class MitreAttackTAXIIReader(TAXIICollectionReader):
    """
    Read STIX 2.1 objects from the MITRE ATT&CK TAXII 2.1 server.

    Parameters
    ----------
    matrix : str
        One of ``"enterprise-attack"`` (default), ``"mobile-attack"``, or
        ``"ics-attack"``.
    added_after : str, optional
        ISO 8601 timestamp; only objects added after this time are returned.
    stix_types : list of str, optional
        Filter to these STIX type strings (e.g. ``["attack-pattern"]``).
    limit : int, optional
        Maximum total objects to fetch.
    collection : object, optional
        Pre-constructed ``taxii2client.v21.Collection`` instance.  Primarily
        for testing — production callers should leave this ``None`` and let
        the reader auto-discover the matrix collection.
    taxii_root : str, optional
        Override the TAXII root URL (default: MITRE's public server).
    rate_limit : tuple of (int, float), optional
        ``(capacity, window_seconds)`` for the token bucket.  Defaults to
        ``(10, 600)`` matching MITRE's published limit.

    Examples
    --------
    >>> reader = MitreAttackTAXIIReader(
    ...     matrix="enterprise-attack",
    ...     stix_types=["attack-pattern", "intrusion-set"],
    ... )
    >>> for record in reader:
    ...     print(record["id"])
    """

    _RATE_LIMIT_DEFAULT: ClassVar[tuple[int, float]] = (10, 600.0)

    def __init__(
        self,
        matrix: MatrixName = "enterprise-attack",
        added_after: str | None = None,
        stix_types: list[str] | None = None,
        limit: int | None = None,
        collection: Any = None,
        taxii_root: str = MITRE_TAXII_ROOT,
        rate_limit: tuple[int, float] | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize MitreAttackTAXIIReader."""
        if matrix not in MITRE_COLLECTION_IDS:
            raise ValueError(
                f"Unknown MITRE ATT&CK matrix {matrix!r}. "
                f"Valid values: {sorted(MITRE_COLLECTION_IDS)}"
            )
        self.matrix = matrix
        self.taxii_root = taxii_root
        cap, win = rate_limit or self._RATE_LIMIT_DEFAULT
        self._limiter = _TokenBucket(cap, win)

        if collection is None:
            collection = self._discover_collection(matrix, taxii_root)

        super().__init__(
            collection=collection,
            added_after=added_after,
            stix_types=stix_types,
            limit=limit,
            **kwargs,
        )

    @staticmethod
    def _discover_collection(matrix: MatrixName, taxii_root: str) -> Any:
        """
        Instantiate a ``taxii2client.v21.Collection`` for the given matrix.

        Raises
        ------
        ImportError
            If ``taxii2-client`` is not installed.
        """
        try:
            from taxii2client.v21 import Collection  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "MitreAttackTAXIIReader requires taxii2-client. "
                'Install with: pip install "gnat[taxii]"'
            ) from exc

        collection_id = MITRE_COLLECTION_IDS[matrix]
        # MITRE uses api-root "/api/v21/" and collections under it
        url = f"{taxii_root.rstrip('/')}/collections/{collection_id}/"
        return Collection(url)

    def _iter_records(self) -> Iterator[RawRecord]:
        """Yield STIX objects, honoring the rate limit on each poll."""
        self._limiter.acquire()
        yield from super()._iter_records()

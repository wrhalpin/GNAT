# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.reports.cache
==================

Report render cache — skip re-rendering when aggregates haven't changed.

:class:`ReportCache` computes a content hash of
:class:`~gnat.reports.aggregator.ReportAggregates` and stores rendered
file paths keyed by that hash.  Subsequent calls with identical aggregates
return the cached paths immediately without re-rendering.

Usage::

    from gnat.reports.cache import ReportCache

    cache = ReportCache(cache_dir="/tmp/gnat_report_cache")

    # Check before rendering
    key = cache.compute_key(aggregates, report_type="daily", formats=["pdf"])
    if cache.hit(key):
        paths = cache.get(key)
    else:
        paths = generator.render(aggregates)
        cache.store(key, paths)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default cache TTL in seconds (6 hours)
_DEFAULT_TTL = 6 * 3600


class ReportCache:
    """
    Content-addressed cache for rendered report files.

    Parameters
    ----------
    cache_dir : str
        Directory for the cache index and potentially cached files.
    ttl_seconds : float
        Cache entry TTL.  Entries older than this are treated as misses.
    """

    def __init__(
        self,
        cache_dir: str | None = None,
        ttl_seconds: float = _DEFAULT_TTL,
    ) -> None:
        self._ttl = ttl_seconds
        self._dir = Path(
            cache_dir or os.path.join(os.path.expanduser("~"), ".gnat", "report_cache")
        )
        self._dir.mkdir(parents=True, exist_ok=True)
        self._index_path = self._dir / "cache_index.json"
        self._index: dict[str, dict[str, Any]] = self._load_index()

    # ── Public API ──────────────────────────────────────────────────────────────

    def compute_key(
        self,
        aggregates: Any,
        report_type: str = "",
        formats: list[str] | None = None,
    ) -> str:
        """
        Compute an MD5 content hash key for the given aggregates.

        Parameters
        ----------
        aggregates : ReportAggregates
        report_type : str
            Included in the hash so ``daily`` and ``weekly`` generate distinct keys.
        formats : list[str], optional
            Output format list included in the hash.

        Returns
        -------
        str
            Hex MD5 digest string.
        """
        payload = {
            "report_type": report_type,
            "formats": sorted(formats or []),
            "data": self._serialize_aggregates(aggregates),
        }
        raw = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hashlib.md5(raw).hexdigest()  # nosec B324

    def hit(self, key: str) -> bool:
        """Return ``True`` if *key* is in the cache and not expired."""
        entry = self._index.get(key)
        if not entry:
            return False
        age = time.time() - entry.get("stored_at", 0)
        if age > self._ttl:
            logger.debug("ReportCache: key %s expired (age=%.0fs)", key, age)
            return False
        # Verify at least one file still exists
        paths = entry.get("paths", [])
        if paths and not Path(paths[0]).exists():
            logger.debug("ReportCache: cached file missing for key %s", key)
            return False
        return True

    def get(self, key: str) -> list[str]:
        """Return cached file paths for *key*.  Returns empty list on miss."""
        if not self.hit(key):
            return []
        return list(self._index[key].get("paths", []))

    def store(self, key: str, paths: list[str]) -> None:
        """
        Store rendered file paths under *key*.

        Parameters
        ----------
        key : str
            Cache key from :meth:`compute_key`.
        paths : list[str]
            Rendered file paths to associate with this key.
        """
        self._index[key] = {
            "paths": paths,
            "stored_at": time.time(),
            "stored_iso": datetime.now(timezone.utc).isoformat(),
        }
        self._save_index()
        logger.debug("ReportCache.store: key=%s paths=%s", key, paths)

    def invalidate(self, key: str) -> None:
        """Remove *key* from the cache."""
        self._index.pop(key, None)
        self._save_index()

    def clear(self) -> int:
        """Clear all cache entries.  Returns number of entries removed."""
        count = len(self._index)
        self._index.clear()
        self._save_index()
        return count

    def evict_expired(self) -> int:
        """Remove expired entries.  Returns number of entries evicted."""
        now = time.time()
        before = len(self._index)
        self._index = {
            k: v for k, v in self._index.items() if now - v.get("stored_at", 0) <= self._ttl
        }
        evicted = before - len(self._index)
        if evicted:
            self._save_index()
        return evicted

    def stats(self) -> dict[str, Any]:
        """Return cache statistics."""
        self.evict_expired()
        return {
            "total_entries": len(self._index),
            "cache_dir": str(self._dir),
            "ttl_seconds": self._ttl,
        }

    # ── Internal helpers ────────────────────────────────────────────────────────

    def _serialize_aggregates(self, aggregates: Any) -> Any:
        """Convert aggregates to a JSON-serialisable primitive."""
        if aggregates is None:
            return {}
        if hasattr(aggregates, "__dict__"):
            return {
                k: self._serialize_value(v)
                for k, v in aggregates.__dict__.items()
                if not k.startswith("_")
            }
        return str(aggregates)

    def _serialize_value(self, v: Any) -> Any:
        if isinstance(v, (str, int, float, bool, type(None))):
            return v
        if isinstance(v, (list, tuple)):
            return [self._serialize_value(i) for i in v]
        if isinstance(v, dict):
            return {str(k): self._serialize_value(val) for k, val in v.items()}
        if isinstance(v, datetime):
            return v.isoformat()
        return str(v)

    def _load_index(self) -> dict[str, Any]:
        if self._index_path.exists():
            try:
                return json.loads(self._index_path.read_text("utf-8"))
            except Exception as exc:
                logger.warning("ReportCache: failed to load index (%s) — starting fresh", exc)
        return {}

    def _save_index(self) -> None:
        try:
            self._index_path.write_text(json.dumps(self._index, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.warning("ReportCache: failed to save index: %s", exc)

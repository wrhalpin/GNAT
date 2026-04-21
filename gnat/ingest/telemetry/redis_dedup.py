# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.ingest.telemetry.redis_dedup
====================================

Redis-backed deduplication cache for high-volume telemetry ingestion.
Falls back to in-memory if Redis is unavailable.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

logger = logging.getLogger(__name__)


class RedisDeduplicationCache:
    """
    Deduplication cache backed by Redis SET operations.

    Uses SHA-256 fingerprints as set members so the Redis memory footprint
    stays bounded.  Supports TTL-based expiry so old entries age out.

    Parameters
    ----------
    redis_url : str
        Redis connection URL (e.g. ``"redis://localhost:6379/0"``).
    key_prefix : str
        Redis key prefix for the dedup set.
    ttl_seconds : int
        Time-to-live for the dedup set.  Refreshed on each ``is_duplicate``
        call.  Default 86400 (24 hours).
    fallback_to_memory : bool
        If True (default), falls back to in-memory set when Redis is
        unavailable instead of raising.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        key_prefix: str = "gnat:telemetry:dedup",
        ttl_seconds: int = 86400,
        fallback_to_memory: bool = True,
    ):
        self._redis_url = redis_url
        self._key = f"{key_prefix}:seen"
        self._ttl = ttl_seconds
        self._fallback = fallback_to_memory
        self._redis: Any = None
        self._memory_set: set[str] | None = None
        self._connect()

    def _connect(self) -> None:
        try:
            import redis as redis_lib

            self._redis = redis_lib.Redis.from_url(self._redis_url, decode_responses=True)
            self._redis.ping()
            logger.info("RedisDeduplicationCache: connected to %s", self._redis_url)
        except Exception:
            if self._fallback:
                logger.warning(
                    "RedisDeduplicationCache: Redis unavailable at %s, "
                    "falling back to in-memory dedup",
                    self._redis_url,
                )
                self._redis = None
                self._memory_set = set()
            else:
                raise

    @staticmethod
    def fingerprint(
        ioc_type: str,
        ioc_value: str,
        sensor_id: str = "",
    ) -> str:
        raw = f"{ioc_type}|{ioc_value}|{sensor_id}".encode()
        return hashlib.sha256(raw).hexdigest()

    def is_duplicate(self, fingerprint: str) -> bool:
        if self._redis is not None:
            try:
                added = self._redis.sadd(self._key, fingerprint)
                if self._ttl:
                    self._redis.expire(self._key, self._ttl)
                return added == 0
            except Exception:
                if self._fallback:
                    logger.warning("Redis error; falling back to memory")
                    self._redis = None
                    self._memory_set = set()
                    return self._is_duplicate_memory(fingerprint)
                raise

        return self._is_duplicate_memory(fingerprint)

    def _is_duplicate_memory(self, fingerprint: str) -> bool:
        if self._memory_set is None:
            self._memory_set = set()
        if fingerprint in self._memory_set:
            return True
        self._memory_set.add(fingerprint)
        return False

    def clear(self) -> None:
        if self._redis is not None:
            import contextlib

            with contextlib.suppress(Exception):
                self._redis.delete(self._key)
        if self._memory_set is not None:
            self._memory_set.clear()

    def __len__(self) -> int:
        if self._redis is not None:
            try:
                return self._redis.scard(self._key)
            except Exception:
                pass
        if self._memory_set is not None:
            return len(self._memory_set)
        return 0

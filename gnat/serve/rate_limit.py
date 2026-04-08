# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.serve.rate_limit
=====================
Simple in-memory sliding-window rate limiter for the GNAT web dashboard.

Default: 100 requests per 60-second window per API key.
"""

from __future__ import annotations

import threading
import time

from fastapi import HTTPException, Request, status


class RateLimiter:
    """Sliding-window rate limiter, callable as a FastAPI dependency.

    Parameters
    ----------
    max_requests : int
        Maximum requests allowed per window.  Default ``100``.
    window_seconds : int
        Window length in seconds.  Default ``60``.
    """

    def __init__(self, max_requests: int = 100, window_seconds: int = 60) -> None:
        """Initialize RateLimiter."""
        self._max = max_requests
        self._window = window_seconds
        self._counts: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> bool:
        """Return ``True`` if the request is within limits, ``False`` if exceeded."""
        now = time.monotonic()
        with self._lock:
            times = [t for t in self._counts.get(key, []) if now - t < self._window]
            if len(times) >= self._max:
                self._counts[key] = times
                return False
            times.append(now)
            self._counts[key] = times
            return True

    def __call__(self, request: Request) -> None:
        """FastAPI dependency: raises 429 when the rate limit is exceeded."""
        key = request.headers.get("X-Api-Key") or (
            request.client.host if request.client else "anon"
        )
        if not self.check(key):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded — max 100 requests per minute",
                headers={"Retry-After": str(self._window)},
            )

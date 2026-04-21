# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.health
=======================

Fleet health monitoring for all registered GNAT connectors.

Provides:

* :class:`ConnectorHealth` — structured health result with timing and error info
* :class:`FleetHealthMonitor` — parallel health checks across all or selected connectors

Usage::

    from gnat.connectors.health import FleetHealthMonitor
    from gnat.clients import CLIENT_REGISTRY

    monitor = FleetHealthMonitor(registry=CLIENT_REGISTRY)

    # Check all connectors in parallel
    results = monitor.check_all()
    for r in results:
        status = "OK" if r.ok else f"FAIL ({r.error})"
        print(f"{r.name:30s} {status}  latency={r.latency_ms:.0f}ms")

    # Check a single connector
    result = monitor.check_one("crowdstrike")
    print(result.to_dict())
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Maximum parallelism for fleet health checks
_MAX_WORKERS = 20
# Timeout (seconds) for a single connector health check
_CHECK_TIMEOUT = 10.0


@dataclass
class ConnectorHealth:
    """
    Health result for a single connector.

    Parameters
    ----------
    name : str
        Connector name (registry key).
    ok : bool
        ``True`` if the health check passed.
    latency_ms : float
        Round-trip latency in milliseconds.
    error : str | None
        Error message if ``ok=False``, otherwise ``None``.
    trust_level : str
        Connector ``TRUST_LEVEL`` class attribute
        (``"trusted_internal"`` / ``"semi_trusted"`` / ``"untrusted_external"``).
    checked_at : datetime
        UTC timestamp when the check was performed.
    connector_class : str
        Fully-qualified class name of the connector.
    """

    name: str
    ok: bool = False
    latency_ms: float = 0.0
    error: str | None = None
    trust_level: str = "semi_trusted"
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    connector_class: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-friendly dict."""
        return {
            "name": self.name,
            "ok": self.ok,
            "latency_ms": round(self.latency_ms, 2),
            "error": self.error,
            "trust_level": self.trust_level,
            "checked_at": self.checked_at.isoformat(),
            "connector_class": self.connector_class,
        }


class FleetHealthMonitor:
    """
    Check the health of all (or selected) registered connectors in parallel.

    Parameters
    ----------
    registry : dict[str, type]
        Connector registry mapping name → connector class.
        Defaults to :data:`gnat.clients.CLIENT_REGISTRY` when ``None``.
    config : dict[str, dict], optional
        Per-connector config dicts passed as kwargs to the connector constructor.
        When absent the connector is instantiated with no arguments.
    max_workers : int
        Thread pool size for parallel checks.  Default ``20``.
    timeout : float
        Per-connector check timeout in seconds.  Default ``10``.
    """

    def __init__(
        self,
        registry: dict[str, Any] | None = None,
        config: dict[str, dict] | None = None,
        max_workers: int = _MAX_WORKERS,
        timeout: float = _CHECK_TIMEOUT,
    ) -> None:
        if registry is None:
            from gnat.clients import CLIENT_REGISTRY

            registry = CLIENT_REGISTRY
        self._registry = registry
        self._config = config or {}
        self._max_workers = max_workers
        self._timeout = timeout

    # ── Public API ──────────────────────────────────────────────────────────────

    def check_all(
        self,
        connectors: list[str] | None = None,
    ) -> list[ConnectorHealth]:
        """
        Run health checks for all (or specified) connectors in parallel.

        Parameters
        ----------
        connectors : list[str], optional
            Subset of connector names to check.  Defaults to all registry keys.

        Returns
        -------
        list[ConnectorHealth]
            Results sorted by connector name.
        """
        names = connectors or sorted(self._registry.keys())
        workers = min(len(names), self._max_workers)

        results: list[ConnectorHealth] = []
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="fleet-health") as pool:
            future_to_name = {pool.submit(self.check_one, name): name for name in names}
            for future in as_completed(future_to_name, timeout=self._timeout * 2):
                name = future_to_name[future]
                try:
                    health = future.result(timeout=self._timeout)
                    results.append(health)
                except Exception as exc:
                    results.append(
                        ConnectorHealth(
                            name=name,
                            ok=False,
                            error=f"Check timed out or failed: {exc}",
                            trust_level=self._get_trust_level(name),
                            connector_class=self._get_class_name(name),
                        )
                    )

        results.sort(key=lambda r: r.name)
        return results

    def check_one(self, name: str) -> ConnectorHealth:
        """
        Run a health check for a single named connector.

        Instantiates the connector with any config provided to the monitor,
        calls ``health_check()``, and returns a timed :class:`ConnectorHealth`.

        Parameters
        ----------
        name : str
            Registry key for the connector.

        Returns
        -------
        ConnectorHealth
        """
        cls = self._registry.get(name)
        if cls is None:
            return ConnectorHealth(
                name=name,
                ok=False,
                error=f"Connector {name!r} not found in registry",
            )

        trust_level = self._get_trust_level(name)
        connector_class = self._get_class_name(name)
        connector = None

        start_ns = time.perf_counter_ns()
        try:
            kwargs = self._config.get(name, {})
            connector = cls(**kwargs)
            result = connector.health_check()
            elapsed = (time.perf_counter_ns() - start_ns) / 1_000_000

            # health_check() should return bool (True=healthy)
            ok = bool(result) if result is not None else True

            return ConnectorHealth(
                name=name,
                ok=ok,
                latency_ms=elapsed,
                trust_level=trust_level,
                connector_class=connector_class,
            )

        except NotImplementedError:
            elapsed = (time.perf_counter_ns() - start_ns) / 1_000_000
            return ConnectorHealth(
                name=name,
                ok=False,
                latency_ms=elapsed,
                error="health_check() not implemented",
                trust_level=trust_level,
                connector_class=connector_class,
            )
        except Exception as exc:
            elapsed = (time.perf_counter_ns() - start_ns) / 1_000_000
            logger.debug("FleetHealthMonitor.check_one(%r): %s", name, exc)
            return ConnectorHealth(
                name=name,
                ok=False,
                latency_ms=elapsed,
                error=str(exc),
                trust_level=trust_level,
                connector_class=connector_class,
            )

    def summary(self, results: list[ConnectorHealth] | None = None) -> dict[str, Any]:
        """
        Return a fleet-level summary dict.

        Parameters
        ----------
        results : list[ConnectorHealth], optional
            Pre-computed results.  When ``None``, :meth:`check_all` is called.
        """
        if results is None:
            results = self.check_all()
        healthy = sum(1 for r in results if r.ok)
        return {
            "total": len(results),
            "healthy": healthy,
            "unhealthy": len(results) - healthy,
            "pct_ok": round(healthy / len(results) * 100, 1) if results else 0.0,
            "by_trust": {
                level: {
                    "total": sum(1 for r in results if r.trust_level == level),
                    "healthy": sum(1 for r in results if r.trust_level == level and r.ok),
                }
                for level in ("trusted_internal", "semi_trusted", "untrusted_external")
            },
        }

    # ── Private helpers ─────────────────────────────────────────────────────────

    def _get_trust_level(self, name: str) -> str:
        cls = self._registry.get(name)
        if cls is None:
            return "semi_trusted"
        return getattr(cls, "TRUST_LEVEL", "semi_trusted")

    def _get_class_name(self, name: str) -> str:
        cls = self._registry.get(name)
        if cls is None:
            return ""
        return f"{cls.__module__}.{cls.__qualname__}"

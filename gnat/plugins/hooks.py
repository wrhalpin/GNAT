"""
gnat.plugins.hooks
===================

Thread-safe publish/subscribe hook bus for GNAT lifecycle events.

Handlers can be synchronous functions or async coroutines. Async handlers
are run via :func:`asyncio.run` when called from a sync context.

Built-in events
---------------
==================== ======================================
Event name           When fired
==================== ======================================
``pre_ingest``       Before each ingest pipeline run
``post_ingest``      After each ingest pipeline run
``pre_enrich``       Before enrichment dispatcher fan-out
``post_enrich``      After enrichment dispatcher completes
``pre_export``       Before ExportService writes a file
``post_export``      After ExportService writes a file
``investigation_opened``  When an Investigation is created
``investigation_closed``  When an Investigation reaches CLOSED
``report_published`` When a Report is published
``plugin_loaded``    When a plugin is registered
``plugin_unloaded``  When a plugin is removed
==================== ======================================

Usage::

    from gnat.plugins.hooks import HookBus

    bus = HookBus.instance()

    @bus.on("post_ingest")
    def notify_siem(result, **ctx):
        print(f"Ingested {result.mapped_objects} objects")

    # Emit
    bus.emit("post_ingest", result=ingest_result)
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import threading
from collections import defaultdict
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Known event names (not enforced — custom events are allowed)
KNOWN_EVENTS: frozenset[str] = frozenset({
    "pre_ingest",
    "post_ingest",
    "pre_enrich",
    "post_enrich",
    "pre_export",
    "post_export",
    "investigation_opened",
    "investigation_closed",
    "report_published",
    "plugin_loaded",
    "plugin_unloaded",
})


class HookBus:
    """
    Thread-safe publish/subscribe event bus.

    Use :meth:`instance` to get the process-level singleton or instantiate
    independently for testing isolation.
    """

    _instance: "HookBus | None" = None
    _lock: threading.Lock = threading.Lock()

    def __init__(self) -> None:
        self._handlers: dict[str, list[Callable]] = defaultdict(list)
        self._bus_lock = threading.RLock()

    # ── Singleton ─────────────────────────────────────────────────────────

    @classmethod
    def instance(cls) -> "HookBus":
        """Return the process-level singleton :class:`HookBus`."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton (for testing)."""
        with cls._lock:
            cls._instance = None

    # ── Registration ──────────────────────────────────────────────────────

    def on(self, event: str) -> Callable:
        """
        Decorator that registers *fn* as a handler for *event*.

        ::

            @bus.on("post_ingest")
            def handle(result, **ctx):
                ...
        """
        def decorator(fn: Callable) -> Callable:
            self.register(event, fn)
            return fn
        return decorator

    def register(self, event: str, handler: Callable) -> None:
        """Register *handler* for *event*."""
        with self._bus_lock:
            self._handlers[event].append(handler)
        logger.debug("HookBus: registered handler %r for event %r", handler, event)

    def unregister(self, event: str, handler: Callable) -> bool:
        """Remove *handler* from *event*.  Returns True if found."""
        with self._bus_lock:
            handlers = self._handlers.get(event, [])
            try:
                handlers.remove(handler)
                return True
            except ValueError:
                return False

    def clear(self, event: str | None = None) -> None:
        """Remove all handlers for *event*, or all events if None."""
        with self._bus_lock:
            if event is None:
                self._handlers.clear()
            else:
                self._handlers.pop(event, None)

    # ── Emit ──────────────────────────────────────────────────────────────

    def emit(self, event: str, **ctx: Any) -> list[Any]:
        """
        Fire *event*, calling every registered handler with **ctx**.

        Handlers are called synchronously in registration order.  Async
        handlers are executed via :func:`asyncio.run` (creates a new event
        loop if needed).  Exceptions in handlers are logged but never
        propagated so that a broken hook never breaks the calling workflow.

        Parameters
        ----------
        event : str
            Event name.
        **ctx
            Arbitrary keyword context passed to each handler.

        Returns
        -------
        list
            Return values from each handler (``None`` for handlers that
            raised).
        """
        with self._bus_lock:
            handlers = list(self._handlers.get(event, []))

        results: list[Any] = []
        for handler in handlers:
            try:
                if inspect.iscoroutinefunction(handler):
                    result = _run_async(handler(**ctx))
                else:
                    result = handler(**ctx)
                results.append(result)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "HookBus: handler %r raised for event %r: %s",
                    handler, event, exc,
                )
                results.append(None)
        return results

    def handlers(self, event: str) -> list[Callable]:
        """Return a copy of handlers registered for *event*."""
        with self._bus_lock:
            return list(self._handlers.get(event, []))

    def __repr__(self) -> str:
        with self._bus_lock:
            total = sum(len(v) for v in self._handlers.values())
        return f"HookBus(events={len(self._handlers)}, handlers={total})"


def _run_async(coro: Any) -> Any:
    """Run an async coroutine from a sync context."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Already inside an event loop (e.g. FastAPI) — schedule as task
            import concurrent.futures
            future = asyncio.run_coroutine_threadsafe(coro, loop)
            return future.result(timeout=30)
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)

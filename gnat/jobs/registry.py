# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.jobs.registry
=====================

:class:`JobRegistry` — global registry of job type names to callables.

Job functions are registered either via the :func:`job` decorator or
:meth:`JobRegistry.register`.  The :class:`~gnat.jobs.runner.JobRunner`
dispatches incoming jobs by looking up the ``job_type`` in this registry.

Job Function Signature
----------------------
Every registered job function must accept the following positional arguments::

    def my_job(
        request_payload: dict,
        progress_callback: Callable[[float, str], None],
        cancel_event: threading.Event,
    ) -> dict:
        ...

- ``request_payload`` — the original request dict from the caller.
- ``progress_callback`` — call ``progress_callback(0.5, "halfway")`` to
  report progress back to the :class:`~gnat.jobs.store.JobStore`.
- ``cancel_event`` — a :class:`threading.Event` that is set when the
  caller requests cancellation.  Long-running jobs should check
  ``cancel_event.is_set()`` at reasonable intervals.

The function must return a JSON-serializable ``dict`` as its result.
"""

from __future__ import annotations

import logging
from typing import Callable

logger = logging.getLogger(__name__)

# Module-level registry dict
_REGISTRY: dict[str, Callable] = {}


def job(job_type: str) -> Callable:
    """
    Decorator that registers a function as a job type handler.

    Parameters
    ----------
    job_type : str
        Unique name for this job type (e.g. ``"gap_detection"``).

    Returns
    -------
    Callable
        The original function, unmodified.

    Examples
    --------
    ::

        @job("gap_detection")
        def run_gap_detection(request_payload, progress_callback, cancel_event):
            progress_callback(0.5, "Analysing coverage gaps...")
            return {"gaps": [...]}
    """

    def decorator(fn: Callable) -> Callable:
        if job_type in _REGISTRY:
            logger.warning("JobRegistry: overwriting existing handler for %r", job_type)
        _REGISTRY[job_type] = fn
        logger.debug("JobRegistry: registered %r -> %s", job_type, fn.__name__)
        return fn

    return decorator


class JobRegistry:
    """
    Static facade for the module-level job type registry.

    All methods are class-level — no instantiation required.
    """

    @staticmethod
    def get(job_type: str) -> Callable | None:
        """
        Look up the handler function for a job type.

        Parameters
        ----------
        job_type : str
            Registered job type name.

        Returns
        -------
        Callable or None
            The handler function, or ``None`` if not registered.
        """
        return _REGISTRY.get(job_type)

    @staticmethod
    def list_types() -> list[str]:
        """
        List all registered job type names.

        Returns
        -------
        list of str
            Sorted list of registered job type names.
        """
        return sorted(_REGISTRY.keys())

    @staticmethod
    def register(job_type: str, fn: Callable) -> None:
        """
        Programmatically register a job type handler.

        Equivalent to applying the :func:`job` decorator.

        Parameters
        ----------
        job_type : str
            Unique name for this job type.
        fn : Callable
            Handler function matching the job function signature.
        """
        if job_type in _REGISTRY:
            logger.warning("JobRegistry: overwriting existing handler for %r", job_type)
        _REGISTRY[job_type] = fn
        logger.debug("JobRegistry: registered %r -> %s", job_type, fn.__name__)

    @staticmethod
    def unregister(job_type: str) -> bool:
        """
        Remove a registered job type.

        Parameters
        ----------
        job_type : str
            Job type name to remove.

        Returns
        -------
        bool
            ``True`` if the type was found and removed, ``False`` otherwise.
        """
        if job_type in _REGISTRY:
            del _REGISTRY[job_type]
            return True
        return False

    @staticmethod
    def clear() -> None:
        """Remove all registered job types.  Mainly useful in tests."""
        _REGISTRY.clear()

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.core.domains
=================

Operational domain model and cross-domain boundary enforcement.

Five domains partition GNAT operations:

.. code-block:: text

    ingestion    — connector pulls, normalisation, raw data ingest
    analysis     — enrichment, correlation, STIX assembly
    investigation— hypothesis testing, evidence linking (read-only from ingestion)
    reporting    — export, visualization, alerting
    execution    — SOAR actions, automated response

Domain boundaries are enforced via the :func:`domain_boundary` decorator.
Any call that violates the allowed-caller graph raises
:class:`DomainBoundaryViolation`, giving a clear, logged signal rather than
a silent constraint failure.

Usage
-----
::

    from gnat.core.domains import Domain, domain_boundary

    @domain_boundary(allowed_callers=[Domain.INGESTION, Domain.ANALYSIS])
    def run_enrichment(observable, context):
        ...

Trust-level enforcement
-----------------------
::

    from gnat.core.domains import require_trust_level

    @require_trust_level("trusted_internal")
    def trigger_soar_playbook(playbook_id, context):
        ...
"""

from __future__ import annotations

import functools
import logging
import threading
from enum import Enum
from typing import Any

from gnat.clients.base import GNATClientError

logger = logging.getLogger(__name__)

# Thread-local storage for the active domain stack
_domain_stack = threading.local()


class Domain(str, Enum):
    """Enumeration of GNAT operational domains."""

    INGESTION = "ingestion"
    ANALYSIS = "analysis"
    INVESTIGATION = "investigation"
    REPORTING = "reporting"
    EXECUTION = "execution"


# Permitted caller domains for each target domain.
# A domain may only be entered from the domains listed here.
DOMAIN_CALL_RULES: dict[Domain, frozenset[Domain]] = {
    Domain.INGESTION: frozenset({Domain.INGESTION}),
    Domain.ANALYSIS: frozenset({Domain.INGESTION, Domain.ANALYSIS}),
    Domain.INVESTIGATION: frozenset({Domain.ANALYSIS, Domain.INVESTIGATION}),
    Domain.REPORTING: frozenset({Domain.INVESTIGATION, Domain.REPORTING}),
    Domain.EXECUTION: frozenset({Domain.INVESTIGATION, Domain.EXECUTION}),
}

# Trust levels ordered from least to most privileged
_TRUST_ORDER = ["untrusted_external", "semi_trusted", "trusted_internal"]


class DomainBoundaryViolation(GNATClientError):
    """
    Raised when an operation attempts an illegal cross-domain call.

    Attributes
    ----------
    caller_domain : str
        The domain that attempted the cross-boundary call.
    target_domain : str
        The domain that was called illegally.
    """

    def __init__(
        self,
        caller_domain: str,
        target_domain: str,
        detail: str = "",
    ) -> None:
        """Initialize DomainBoundaryViolation."""
        self.caller_domain = caller_domain
        self.target_domain = target_domain
        msg = (
            f"Domain boundary violation: {caller_domain!r} cannot call into "
            f"{target_domain!r} domain."
        )
        if detail:
            msg = f"{msg} {detail}"
        super().__init__(msg)


class TrustLevelViolation(GNATClientError):
    """
    Raised when an operation requires a higher trust level than present.

    Attributes
    ----------
    required : str
        The required minimum trust level.
    actual : str
        The trust level of the active context.
    """

    def __init__(self, required: str, actual: str) -> None:
        """Initialize TrustLevelViolation."""
        self.required = required
        self.actual = actual
        super().__init__(
            f"Trust level violation: operation requires {required!r} "
            f"but active trust level is {actual!r}."
        )


# ── Active domain stack helpers ────────────────────────────────────────────────

def _get_domain_stack() -> list[Domain]:
    """Return the thread-local domain stack, initialising if absent."""
    if not hasattr(_domain_stack, "stack"):
        _domain_stack.stack = []
    return _domain_stack.stack  # type: ignore[return-value]


def _current_domain() -> Domain | None:
    """Return the domain at the top of the thread-local stack, or None."""
    stack = _get_domain_stack()
    return stack[-1] if stack else None


# ── Decorators ─────────────────────────────────────────────────────────────────

def domain_boundary(target_domain: Domain, allowed_callers: list[Domain] | None = None):
    """
    Decorator that enforces domain boundary rules on the wrapped function.

    The decorated function is tagged with *target_domain*.  When called, the
    decorator checks that the currently active domain (from the thread-local
    stack) is in the set of allowed callers.  If not,
    :class:`DomainBoundaryViolation` is raised before the function executes.

    If no caller domain is active (i.e. this is a top-level call), the call
    is permitted — external code can always enter any domain at the top level.

    Parameters
    ----------
    target_domain : Domain
        The domain this function belongs to.
    allowed_callers : list of Domain, optional
        Domains permitted to call this function.  Defaults to the global
        :data:`DOMAIN_CALL_RULES` for *target_domain*.

    Examples
    --------
    ::

        @domain_boundary(Domain.INGESTION)
        def run_ingest_pipeline(source, context):
            ...

        @domain_boundary(Domain.REPORTING, allowed_callers=[Domain.INVESTIGATION])
        def generate_report(workspace, context):
            ...
    """
    effective_callers = (
        frozenset(allowed_callers)
        if allowed_callers is not None
        else DOMAIN_CALL_RULES.get(target_domain, frozenset())
    )

    def decorator(func):  # type: ignore[no-untyped-def]
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            caller = _current_domain()
            if caller is not None and caller not in effective_callers:
                logger.warning(
                    "DomainBoundaryViolation: %r -> %r in %s",
                    caller.value,
                    target_domain.value,
                    func.__qualname__,
                )
                raise DomainBoundaryViolation(
                    caller_domain=caller.value,
                    target_domain=target_domain.value,
                    detail=f"(function: {func.__qualname__})",
                )

            stack = _get_domain_stack()
            stack.append(target_domain)
            try:
                return func(*args, **kwargs)
            finally:
                stack.pop()

        wrapper._domain = target_domain  # type: ignore[attr-defined]
        return wrapper

    return decorator


def require_trust_level(minimum: str):
    """
    Decorator that enforces a minimum trust level on the wrapped function.

    The *minimum* trust level is compared to the ``trust_level`` attribute of
    the first argument named ``context`` (or the first positional arg if no
    ``context`` kwarg is present).  Falls back to no-op if no context is found.

    Parameters
    ----------
    minimum : str
        Minimum required trust level: ``"trusted_internal"``,
        ``"semi_trusted"``, or ``"untrusted_external"``.

    Raises
    ------
    TrustLevelViolation
        If the active context's trust level is below *minimum*.

    Examples
    --------
    ::

        @require_trust_level("trusted_internal")
        def trigger_soar_playbook(playbook_id, context):
            ...
    """
    min_rank = _TRUST_ORDER.index(minimum) if minimum in _TRUST_ORDER else 0

    def decorator(func):  # type: ignore[no-untyped-def]
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Try to find context in kwargs first, then positional args
            ctx = kwargs.get("context")
            if ctx is None:
                for arg in args:
                    if hasattr(arg, "trust_level"):
                        ctx = arg
                        break

            if ctx is not None:
                actual = getattr(ctx, "trust_level", "untrusted_external")
                actual_rank = (
                    _TRUST_ORDER.index(actual) if actual in _TRUST_ORDER else 0
                )
                if actual_rank < min_rank:
                    logger.warning(
                        "TrustLevelViolation in %s: required=%r actual=%r",
                        func.__qualname__,
                        minimum,
                        actual,
                    )
                    raise TrustLevelViolation(required=minimum, actual=actual)

            return func(*args, **kwargs)

        return wrapper

    return decorator

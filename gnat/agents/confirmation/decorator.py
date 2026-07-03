# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation.decorator
=====================================

@requires_confirmation decorator for gating actions.
"""

from __future__ import annotations

import asyncio
import inspect
from functools import wraps
from typing import Any, Callable

from gnat.agents.confirmation.broker import ConfirmationBroker
from gnat.agents.confirmation.models import ConfirmationRequest

# typing.Literal risk values; kept as a plain tuple to avoid a runtime
# Literal dependency in the signature
_RISK_LEVELS = ("low", "medium", "high", "irreversible")

_SECRET_KEY_FRAGMENTS = ("secret", "key", "token", "password", "credential")


def _redact_secrets(obj: Any) -> Any:
    """
    Redact secret-shaped values from an object for audit logging.

    Recursively handles dicts and lists/tuples. Redacts values whose keys
    contain secret-looking fragments (key, secret, token, password, ...).
    """
    if isinstance(obj, dict):
        redacted = {}
        for k, v in obj.items():
            k_lower = str(k).lower()
            if any(fragment in k_lower for fragment in _SECRET_KEY_FRAGMENTS):
                redacted[k] = "***REDACTED***"
            else:
                redacted[k] = _redact_secrets(v)
        return redacted
    if isinstance(obj, (list, tuple)):
        return [_redact_secrets(item) for item in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    # Arbitrary objects aren't JSON-serializable; record their repr.
    return repr(obj)


def _caller_class_name(skip_self: Any = None) -> str:
    """
    Best-effort name of the class whose method triggered the gated call.

    Walks up the stack looking for a frame with a ``self`` local, skipping
    the decorated method's own receiver.
    """
    frame = inspect.currentframe()
    try:
        while frame:
            candidate = frame.f_locals.get("self")
            if candidate is not None and candidate is not skip_self:
                module = type(candidate).__module__ or ""
                if module.startswith("gnat.agents.confirmation"):
                    frame = frame.f_back
                    continue
                return type(candidate).__name__
            frame = frame.f_back
        return "unknown"
    finally:
        del frame


def requires_confirmation(
    scope: str,
    risk: str = "medium",
    subject_from: Callable[[tuple, dict[str, Any]], dict[str, Any]] | None = None,
    reason: str | Callable | None = None,
    timeout_seconds: int | None = None,
    workspace: str | Callable | None = None,
    principal_type: str = "analyst",
) -> Callable:
    """
    Decorator that gates a function through the ConfirmationBroker.

    When the broker is disabled (no ``[confirmation]`` config section),
    the wrapped function runs unchanged.

    Parameters
    ----------
    scope : str
        Scope identifier (e.g. ``"library.promote"``).
    risk : str
        One of ``low``, ``medium``, ``high``, ``irreversible``.
    subject_from : callable, optional
        ``(args, kwargs) -> dict`` extractor for the audit subject.
        Defaults to redacted args/kwargs.
    reason : str or callable, optional
        Human-readable rationale; callables are resolved lazily with
        ``(args, kwargs)``.
    timeout_seconds : int, optional
        How long the backend may wait for a decision (default 300).
    workspace : str or callable, optional
        Workspace name; callables are resolved lazily with ``(args, kwargs)``.
    principal_type : str
        ``"analyst"`` for interactive flows, ``"system"`` for scheduled jobs.

    Raises
    ------
    ConfirmationDenied
        If the broker denies the action.
    """
    if risk not in _RISK_LEVELS:
        raise ValueError(f"risk must be one of {_RISK_LEVELS}, got {risk!r}")

    def decorator(func: Callable) -> Callable:
        if asyncio.iscoroutinefunction(func):

            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                broker = ConfirmationBroker.default()
                if broker.enabled:
                    req = _build_request(
                        scope,
                        risk,
                        subject_from,
                        reason,
                        timeout_seconds,
                        workspace,
                        principal_type,
                        func,
                        args,
                        kwargs,
                    )
                    broker.request_or_raise(req)
                return await func(*args, **kwargs)

            return async_wrapper

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            broker = ConfirmationBroker.default()
            if broker.enabled:
                req = _build_request(
                    scope,
                    risk,
                    subject_from,
                    reason,
                    timeout_seconds,
                    workspace,
                    principal_type,
                    func,
                    args,
                    kwargs,
                )
                broker.request_or_raise(req)
            return func(*args, **kwargs)

        return sync_wrapper

    return decorator


def _build_request(
    scope: str,
    risk: str,
    subject_from: Callable | None,
    reason: str | Callable | None,
    timeout_seconds: int | None,
    workspace: str | Callable | None,
    principal_type: str,
    func: Callable,
    args: tuple,
    kwargs: dict[str, Any],
) -> ConfirmationRequest:
    """Build a ConfirmationRequest from decorator arguments and call context."""

    if subject_from:
        subject = subject_from(args, kwargs)
    else:
        subject = {
            "args": _redact_secrets(list(args)),
            "kwargs": _redact_secrets(kwargs),
        }

    if reason is None:
        reason_text = f"Calling {func.__name__}"
    elif callable(reason):
        reason_text = reason(args, kwargs)
    else:
        reason_text = reason

    if workspace is None:
        workspace_name = "unknown"
    elif callable(workspace):
        workspace_name = workspace(args, kwargs)
    else:
        workspace_name = workspace

    receiver = args[0] if args else None

    return ConfirmationRequest(
        scope=scope,
        action=func.__name__,
        agent=_caller_class_name(skip_self=receiver),
        workspace=workspace_name,
        subject=subject,
        reason=reason_text,
        risk=risk,
        timeout_seconds=timeout_seconds or 300,
        principal_type=principal_type,
    )

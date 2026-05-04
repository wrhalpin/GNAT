# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation.decorator
=====================================

@requires_confirmation decorator for gating actions.
"""

import asyncio
import inspect
from functools import wraps
from typing import Callable, Optional, Dict, Any, Literal
from uuid import uuid4

from gnat.agents.confirmation.models import (
    ConfirmationRequest,
    ConfirmationDenied,
)
from gnat.agents.confirmation.broker import ConfirmationBroker


def _redact_secrets(obj: Any) -> Any:
    """
    Redact secret-shaped values from an object for audit logging.

    Recursively handles dicts and lists. Redacts values with keys
    matching secret patterns: *_key, *_secret, *_token, password, etc.
    """
    if isinstance(obj, dict):
        redacted = {}
        for k, v in obj.items():
            k_lower = k.lower()
            if any(
                pattern in k_lower
                for pattern in ["secret", "key", "token", "password", "credential", "api_key"]
            ):
                redacted[k] = "***REDACTED***"
            else:
                redacted[k] = _redact_secrets(v)
        return redacted
    elif isinstance(obj, list):
        return [_redact_secrets(item) for item in obj]
    else:
        return obj


def _caller_class_name() -> str:
    """Extract the class name of the caller (for agent field)."""
    frame = inspect.currentframe()
    try:
        # Walk up the stack to find a frame with 'self'
        while frame:
            if "self" in frame.f_locals:
                self_obj = frame.f_locals["self"]
                return self_obj.__class__.__name__
            frame = frame.f_back
        return "unknown"
    finally:
        del frame


def requires_confirmation(
    scope: str,
    risk: Literal["low", "medium", "high", "irreversible"] = "medium",
    subject_from: Optional[Callable[[tuple, Dict[str, Any]], Dict[str, Any]]] = None,
    reason: Optional[str | Callable] = None,
    timeout_seconds: Optional[int] = None,
    workspace: Optional[str | Callable] = None,
) -> Callable:
    """
    Decorator that gates a function with confirmation broker.

    Args:
        scope: The scope string (e.g., "library.promote")
        risk: Risk level of the action
        subject_from: Callable that extracts subject from (args, kwargs)
        reason: String or callable that returns reason text
        timeout_seconds: Timeout for broker decision
        workspace: String or callable that returns workspace name

    Example:
        @requires_confirmation(
            scope="library.promote",
            risk="medium",
            subject_from=lambda args, kw: {"topic": kw["topic"]},
            reason="Promoting to library",
        )
        def promote(self, topic, workspace):
            ...
    """

    def decorator(func: Callable) -> Callable:
        is_async = asyncio.iscoroutinefunction(func)

        if is_async:

            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                # Build confirmation request
                req = _build_request(
                    scope=scope,
                    risk=risk,
                    subject_from=subject_from,
                    reason=reason,
                    timeout_seconds=timeout_seconds,
                    workspace=workspace,
                    func=func,
                    args=args,
                    kwargs=kwargs,
                )

                # Request confirmation
                broker = ConfirmationBroker.default()
                broker.request_or_raise(req)

                # Call the underlying function
                return await func(*args, **kwargs)

            return async_wrapper
        else:

            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                # Build confirmation request
                req = _build_request(
                    scope=scope,
                    risk=risk,
                    subject_from=subject_from,
                    reason=reason,
                    timeout_seconds=timeout_seconds,
                    workspace=workspace,
                    func=func,
                    args=args,
                    kwargs=kwargs,
                )

                # Request confirmation
                broker = ConfirmationBroker.default()
                broker.request_or_raise(req)

                # Call the underlying function
                return func(*args, **kwargs)

            return sync_wrapper

    return decorator


def _build_request(
    scope: str,
    risk: str,
    subject_from: Optional[Callable],
    reason: Optional[str | Callable],
    timeout_seconds: Optional[int],
    workspace: Optional[str | Callable],
    func: Callable,
    args: tuple,
    kwargs: Dict[str, Any],
) -> ConfirmationRequest:
    """Build a ConfirmationRequest from decorator arguments and call context."""

    # Extract subject
    if subject_from:
        subject = subject_from(args, kwargs)
    else:
        # Default: redacted args and kwargs
        subject = {
            "args": _redact_secrets(args),
            "kwargs": _redact_secrets(kwargs),
        }

    # Resolve reason
    if reason is None:
        reason_text = f"Calling {func.__name__}"
    elif callable(reason):
        reason_text = reason(args, kwargs)
    else:
        reason_text = reason

    # Resolve workspace
    if workspace is None:
        workspace_name = "unknown"
    elif callable(workspace):
        workspace_name = workspace(args, kwargs)
    else:
        workspace_name = workspace

    # Build request
    req = ConfirmationRequest(
        scope=scope,
        action=func.__name__,
        agent=_caller_class_name(),
        workspace=workspace_name,
        subject=subject,
        reason=reason_text,
        risk=risk,
        timeout_seconds=timeout_seconds or 300,
    )

    return req

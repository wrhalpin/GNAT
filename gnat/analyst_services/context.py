# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analyst_services.context
================================

:class:`AnalystContext` carries per-request identity and metadata through
the analyst service layer.  It is frozen so that it can be safely shared
across concurrent calls without mutation concerns.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AnalystContext:
    """
    Immutable per-request context for analyst service calls.

    Parameters
    ----------
    actor : str
        Authenticated identity, e.g. ``"alice@acme.com"`` or
        ``"service:sandgnat"``.
    tenant : str or None
        Tenant identifier for multi-tenant deployments.
    request_id : str or None
        Correlation ID for tracing.
    locale : str
        Preferred locale for user-facing text (default ``"en"``).
    """

    actor: str
    tenant: str | None = None
    request_id: str | None = None
    locale: str = "en"

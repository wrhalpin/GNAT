# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Source platform and trust-level helpers."""

from __future__ import annotations

from typing import Any

from gnat.analysis.rules.resolver import trust_at_least
from gnat.clients import CLIENT_REGISTRY

_AI_CONNECTOR_NAMES = {"chatgpt", "copilot", "gemini", "grok"}


def _all_evidence_ids(h: Any) -> list[str]:
    sup = getattr(h, "supporting_evidence", []) or []
    ref = getattr(h, "refuting_evidence", []) or []
    return list(sup) + list(ref)


def evidence_sources(h: Any, ctx: Any) -> set[str]:
    """Connector names for all evidence on this hypothesis."""
    ids = _all_evidence_ids(h)
    if not ids:
        return set()
    resolved = ctx.resolver.resolve_many(ids)
    return {r.source_platform for r in resolved.values() if r.source_platform}


def trust_levels(h: Any, ctx: Any) -> set[str]:
    """Trust levels across all evidence sources."""
    ids = _all_evidence_ids(h)
    if not ids:
        return set()
    resolved = ctx.resolver.resolve_many(ids)
    return {r.trust_level for r in resolved.values()}


def has_trusted_evidence(h: Any, ctx: Any) -> bool:
    """True if any evidence comes from a trusted_internal connector."""
    return "trusted_internal" in trust_levels(h, ctx)


def all_evidence_trusted(h: Any, ctx: Any, minimum: str = "semi_trusted") -> bool:
    """True if all evidence meets the minimum trust level."""
    ids = _all_evidence_ids(h)
    if not ids:
        return False
    resolved = ctx.resolver.resolve_many(ids)
    return all(trust_at_least(r.trust_level, minimum) for r in resolved.values())


def evidence_from(h: Any, ctx: Any, connector_name: str) -> bool:
    """True if any evidence comes from the named connector."""
    return connector_name in evidence_sources(h, ctx)


def unknown_source_count(h: Any, ctx: Any) -> int:
    """Count of evidence items from unknown connectors."""
    ids = _all_evidence_ids(h)
    if not ids:
        return 0
    resolved = ctx.resolver.resolve_many(ids)
    return sum(1 for r in resolved.values() if not r.is_known_connector)


def _is_ai_connector(name: str) -> bool:
    if name in _AI_CONNECTOR_NAMES:
        return True
    cls = CLIENT_REGISTRY.get(name)
    return cls is not None and getattr(cls, "IS_AI_CONNECTOR", False)


def ai_only(h: Any, ctx: Any) -> bool:
    """True if all evidence sources are AI-labeled connectors."""
    sources = evidence_sources(h, ctx)
    if not sources:
        return False
    return all(_is_ai_connector(s) for s in sources)

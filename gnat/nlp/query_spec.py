"""
gnat.nlp.query_spec
=====================
:class:`QuerySpec` — the canonical structured output of any NLP parser backend.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class QuerySpec:
    """
    Structured representation of a natural-language threat-intel query.

    Produced by :class:`~gnat.nlp.builtin.BuiltinParser` or
    :class:`~gnat.nlp.claude_backend.ClaudeParser` from a free-text string.

    Attributes
    ----------
    entities : list of str
        Named entities extracted from the query (threat actors, malware
        families, campaign names, CVE IDs, etc.).
        Examples: ``["APT28", "Cobalt Strike"]``, ``["CVE-2024-1234"]``.
    ioc_types : list of str
        IOC type filters (``"ip"``, ``"domain"``, ``"hash"``, ``"url"``,
        ``"email"``).  Empty list means all types.
    since : datetime or None
        Lower bound for the ``created`` / ``modified`` timestamp filter.
    until : datetime or None
        Upper bound.  ``None`` means up to now.
    platforms : list of str
        Connector keys to query (e.g. ``["threatq", "crowdstrike"]``).
        Empty list means query all configured connectors.
    limit : int
        Maximum number of results per connector.  Default ``100``.
    raw_query : str
        The original query string, preserved for logging / debugging.
    """

    entities: list[str] = field(default_factory=list)
    ioc_types: list[str] = field(default_factory=list)
    since: datetime | None = None
    until: datetime | None = None
    platforms: list[str] = field(default_factory=list)
    limit: int = 100
    raw_query: str = ""

    def to_dict(self) -> dict:
        """Serialise to a plain dict (for logging and CLI output)."""
        return {
            "entities": self.entities,
            "ioc_types": self.ioc_types,
            "since": self.since.isoformat() if self.since else None,
            "until": self.until.isoformat() if self.until else None,
            "platforms": self.platforms,
            "limit": self.limit,
            "raw_query": self.raw_query,
        }

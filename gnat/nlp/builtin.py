"""
gnat.nlp.builtin
==================
:class:`BuiltinParser` — regex + keyword rule-based NLP parser.

No external AI dependencies.  Works offline.  Handles the most common
analyst query patterns well; use :class:`~gnat.nlp.claude_backend.ClaudeParser`
for ambiguous or complex queries.

Extraction rules
----------------
**Time ranges** — anchored to ``datetime.now(UTC)``:

=========================  ============================
Phrase                     Resolution
=========================  ============================
``last N days/weeks/months``  ``since = now - delta``
``since January``          ``since = Jan 1, current year``
``since 2024-03-15``       ``since = 2024-03-15T00:00:00Z``
``from last week``         ``since = 7 days ago``
``yesterday``              ``since = start of yesterday``
``today``                  ``since = start of today``
=========================  ============================

**IOC types** — keyword matching:

- ``ip`` / ``ips`` / ``ip address`` / ``ipv4`` / ``ipv6``
- ``domain`` / ``domains`` / ``hostname``
- ``hash`` / ``hashes`` / ``md5`` / ``sha1`` / ``sha256`` / ``sha-256``
- ``url`` / ``urls``
- ``email`` / ``emails``

**Platforms** — connector key recognition (e.g. ``"from threatq"``,
``"in crowdstrike"``, ``"using splunk"``).

**Entities** — proper-noun heuristic: capitalised words / known threat-actor
patterns (``APT\d+``, ``TA\d+``, ``CVE-\d{4}-\d+``, ``FIN\d+``).

**Limit** — ``"top N"``, ``"first N"``, ``"limit N"``, ``"last N results"``.
"""

from __future__ import annotations

import re
from calendar import monthrange
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from gnat.nlp.query_spec import QuerySpec

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

_RE_LAST_N = re.compile(
    r"\blast\s+(\d+)\s+(day|days|week|weeks|month|months)\b", re.I
)
_RE_SINCE_DATE = re.compile(
    r"\bsince\s+(\d{4}-\d{2}-\d{2})\b", re.I
)
_RE_SINCE_MONTH = re.compile(
    r"\bsince\s+(january|february|march|april|may|june|july|august|"
    r"september|october|november|december)\b", re.I
)
_RE_TOP_N = re.compile(
    r"\b(?:top|first|limit|show me|get)\s+(\d+)\b", re.I
)
_RE_LAST_N_RESULTS = re.compile(
    r"\blast\s+(\d+)\s+results?\b", re.I
)
_RE_PLATFORM_PREP = re.compile(
    r"\b(?:from|in|on|using|via)\s+(\w+)\b", re.I
)
_RE_THREAT_ACTOR = re.compile(
    r"\b(APT[-\s]?\d+|TA\d+|FIN\d+|UNC\d+|G\d{4}|TEMP\.\w+|"
    r"Lazarus(?:\s+Group)?|Sandworm|Cozy\s+Bear|Fancy\s+Bear|"
    r"Volt\s+Typhoon|Scattered\s+Spider|LockBit|REvil|Conti|"
    r"BlackCat|ALPHV)\b",
    re.I,
)
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_RE_MALWARE = re.compile(
    r"\b(Cobalt\s+Strike|Mimikatz|Metasploit|Empire|PowerShell\s+Empire|"
    r"Emotet|TrickBot|QakBot|IcedID|Ryuk|WannaCry|NotPetya|"
    r"Sliver|Havoc|Brute\s+Ratel)\b",
    re.I,
)

_MONTH_MAP = {
    "january": 1, "february": 2, "march": 3, "april": 4,
    "may": 5, "june": 6, "july": 7, "august": 8,
    "september": 9, "october": 10, "november": 11, "december": 12,
}

_IOC_KEYWORDS: dict = {
    "ip":     re.compile(
        r"\b(?:ip(?:v4|v6)?(?:\s+address(?:es)?)?|ips|ipv4s|ipv6s)\b", re.I
    ),
    "domain": re.compile(r"\b(?:domain(?:s)?|hostname(?:s)?|fqdn(?:s)?)\b", re.I),
    "hash":   re.compile(
        r"\b(?:hash(?:es)?|md5(?:s)?|sha[-\s]?(?:1|256|512)(?:s)?|"
        r"file\s+hash(?:es)?|ioc\s+hash(?:es)?)\b", re.I
    ),
    "url":    re.compile(r"\b(?:url(?:s)?|link(?:s)?|uri(?:s)?)\b", re.I),
    "email":  re.compile(r"\b(?:email(?:s)?|e-mail(?:s)?|address(?:es)?)\b", re.I),
}

# Words that look capitalised but are not entity names
_STOP_WORDS = frozenset({
    "get", "give", "show", "find", "fetch", "list", "search",
    "all", "any", "the", "from", "last", "since", "until",
    "related", "linked", "associated", "about", "for",
    "everything", "anything", "results", "objects", "indicators",
    "data", "days", "weeks", "months", "today", "yesterday",
    "first", "top", "limit", "using", "via", "in", "on",
    "stix", "gnat", "intel", "threat", "intelligence",
    # IOC type words that appear capitalised
    "IP", "IPs", "URL", "URLs", "IOC", "IOCs", "CVE",
})


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class BuiltinParser:
    """
    Rule-based natural-language query parser.

    Uses regular expressions and keyword matching — no network calls,
    no AI dependencies.

    Examples
    --------
    >>> p = BuiltinParser()
    >>> spec = p.parse("Get all IPs for APT28 from the last 30 days")
    >>> spec.entities
    ['APT28']
    >>> spec.ioc_types
    ['ip']
    >>> spec.since   # approx 30 days ago
    datetime(...)
    """

    def parse(self, query: str, default_limit: int = 100) -> QuerySpec:
        """
        Parse *query* into a :class:`QuerySpec`.

        Parameters
        ----------
        query : str
            Free-text analyst query.
        default_limit : int
            Fallback result limit when no explicit limit is found.

        Returns
        -------
        QuerySpec
        """
        now = _utcnow()

        since  = self._extract_since(query, now)
        until  = self._extract_until(query, now)
        ioc_types  = self._extract_ioc_types(query)
        entities   = self._extract_entities(query)
        platforms  = self._extract_platforms(query)
        limit      = self._extract_limit(query, default_limit)

        return QuerySpec(
            entities   = entities,
            ioc_types  = ioc_types,
            since      = since,
            until      = until,
            platforms  = platforms,
            limit      = limit,
            raw_query  = query,
        )

    # ------------------------------------------------------------------
    # Extraction helpers
    # ------------------------------------------------------------------

    def _extract_since(self, query: str, now: datetime) -> Optional[datetime]:
        # "last N days/weeks/months"
        m = _RE_LAST_N.search(query)
        if m:
            n, unit = int(m.group(1)), m.group(2).lower().rstrip("s")
            if unit == "day":
                return now - timedelta(days=n)
            if unit == "week":
                return now - timedelta(weeks=n)
            if unit == "month":
                return now - timedelta(days=n * 30)

        # "since YYYY-MM-DD"
        m = _RE_SINCE_DATE.search(query)
        if m:
            try:
                return datetime.fromisoformat(m.group(1)).replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        # "since <month name>"
        m = _RE_SINCE_MONTH.search(query)
        if m:
            month_num = _MONTH_MAP[m.group(1).lower()]
            year = now.year
            # If the named month is in the future this year, use last year
            if month_num > now.month:
                year -= 1
            return datetime(year, month_num, 1, tzinfo=timezone.utc)

        # "yesterday"
        if re.search(r"\byesterday\b", query, re.I):
            d = (now - timedelta(days=1)).date()
            return datetime(d.year, d.month, d.day, tzinfo=timezone.utc)

        # "today"
        if re.search(r"\btoday\b", query, re.I):
            return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)

        return None

    def _extract_until(self, query: str, now: datetime) -> Optional[datetime]:
        m = re.search(
            r"\b(?:until|before|up to)\s+(\d{4}-\d{2}-\d{2})\b", query, re.I
        )
        if m:
            try:
                return datetime.fromisoformat(m.group(1)).replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        return None

    def _extract_ioc_types(self, query: str) -> List[str]:
        found = []
        for ioc_type, pattern in _IOC_KEYWORDS.items():
            if pattern.search(query):
                found.append(ioc_type)
        return found

    def _extract_entities(self, query: str) -> List[str]:
        entities = []

        # Named threat actors
        for m in _RE_THREAT_ACTOR.finditer(query):
            name = " ".join(m.group(0).split())  # normalise whitespace
            if name not in entities:
                entities.append(name)

        # Known malware families
        for m in _RE_MALWARE.finditer(query):
            name = " ".join(m.group(0).split())
            if name not in entities:
                entities.append(name)

        # CVE IDs
        for m in _RE_CVE.finditer(query):
            cve = m.group(0).upper()
            if cve not in entities:
                entities.append(cve)

        # Capitalised-word heuristic for unknown entities
        for word in re.findall(r"\b[A-Z][A-Za-z0-9_\-]+\b", query):
            if (
                word not in _STOP_WORDS
                and word not in entities
                and not any(word.lower() in e.lower() for e in entities)
                and len(word) > 2
            ):
                entities.append(word)

        return entities

    def _extract_platforms(self, query: str) -> List[str]:
        from gnat.clients import CLIENT_REGISTRY
        found = []
        for m in _RE_PLATFORM_PREP.finditer(query):
            candidate = m.group(1).lower()
            if candidate in CLIENT_REGISTRY and candidate not in found:
                found.append(candidate)
        return found

    def _extract_limit(self, query: str, default: int) -> int:
        m = _RE_TOP_N.search(query)
        if m:
            return int(m.group(1))
        m = _RE_LAST_N_RESULTS.search(query)
        if m:
            return int(m.group(1))
        return default

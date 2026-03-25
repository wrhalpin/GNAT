"""
ctm_sak.export.filters
========================

Concrete :class:`~ctm_sak.export.base.ExportFilter` implementations.

Filters are composable via ``&``::

    from ctm_sak.export.filters import TypeFilter, ConfidenceFilter, TLPFilter

    f = TypeFilter("indicator") & ConfidenceFilter(min_confidence=70) & TLPFilter(["white"])

All filters are lazy (generator-based) to avoid materializing large
intermediate lists.

Available filters:
------------------
- :class:`TypeFilter`         — STIX type whitelist
- :class:`ConfidenceFilter`   — minimum confidence/risk score
- :class:`TLPFilter`          — TLP marking allowlist
- :class:`TagFilter`          — required/excluded tags
- :class:`AgeFilter`          — freshness (max age in days)
- :class:`PatternFilter`      — STIX pattern substring match
- :class:`IOCTypeFilter`      — IOC value type (ipv4, domain, url, hash…)
- :class:`LimitFilter`        — hard cap on output count
- :class:`DeduplicateFilter`  — remove objects with duplicate values
- :class:`FunctionFilter`     — arbitrary callable predicate
"""

from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Iterable, Iterator, List, Optional, Set, TYPE_CHECKING

from ctm_sak.export.base import ExportFilter

if TYPE_CHECKING:
    from ctm_sak.orm.base import STIXBase


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _get(obj: "STIXBase", field: str) -> Any:
    """Safely get a field from a STIXBase object."""
    if hasattr(obj, field):
        return getattr(obj, field, None)
    return obj._properties.get(field)


# ---------------------------------------------------------------------------
# TypeFilter
# ---------------------------------------------------------------------------

class TypeFilter(ExportFilter):
    """
    Pass only objects whose ``stix_type`` is in the allowed set.

    Parameters
    ----------
    *stix_types : str
        One or more STIX type strings, e.g. ``"indicator"``, ``"malware"``.

    Examples
    --------
    ::

        TypeFilter("indicator")
        TypeFilter("indicator", "malware", "vulnerability")
    """

    def __init__(self, *stix_types: str):
        if not stix_types:
            raise ValueError("TypeFilter: at least one stix_type is required")
        self._types: Set[str] = set(stix_types)

    def __call__(self, objects: Iterable["STIXBase"]) -> Iterator["STIXBase"]:
        for obj in objects:
            if obj.stix_type in self._types:
                yield obj

    def __repr__(self) -> str:
        return f"TypeFilter(types={sorted(self._types)})"


# ---------------------------------------------------------------------------
# ConfidenceFilter
# ---------------------------------------------------------------------------

class ConfidenceFilter(ExportFilter):
    """
    Pass only objects whose confidence (or risk score) meets a minimum.

    Checks ``confidence`` first, then ``x_rf_risk_score``, then
    ``x_rr_score`` (scaled 0-100).  Objects with no scoreable field
    are treated as having confidence equal to ``default_confidence``.

    Parameters
    ----------
    min_confidence : int
        Minimum value (0–100).  Objects below this are dropped.
    default_confidence : int
        Confidence assumed when no score field is present.  Default 50.
    score_fields : list of str, optional
        Override the default field search order.

    Examples
    --------
    ::

        ConfidenceFilter(min_confidence=70)
        ConfidenceFilter(min_confidence=80, default_confidence=0)
    """

    _DEFAULT_FIELDS = ["confidence", "x_rf_risk_score", "x_rr_score"]

    def __init__(
        self,
        min_confidence: int,
        default_confidence: int = 50,
        score_fields: Optional[List[str]] = None,
    ):
        self.min_confidence    = min_confidence
        self.default_confidence = default_confidence
        self._fields = score_fields or self._DEFAULT_FIELDS

    def _score(self, obj: "STIXBase") -> float:
        for field in self._fields:
            val = _get(obj, field)
            if val is not None:
                try:
                    return float(val)
                except (TypeError, ValueError):
                    pass
        return float(self.default_confidence)

    def __call__(self, objects: Iterable["STIXBase"]) -> Iterator["STIXBase"]:
        for obj in objects:
            if self._score(obj) >= self.min_confidence:
                yield obj

    def __repr__(self) -> str:
        return f"ConfidenceFilter(min={self.min_confidence})"


# ---------------------------------------------------------------------------
# TLPFilter
# ---------------------------------------------------------------------------

class TLPFilter(ExportFilter):
    """
    Pass only objects whose ``x_tlp`` marking is in the allowed set.

    Objects with no ``x_tlp`` field are treated as ``"white"`` (most
    permissive) by default.

    Parameters
    ----------
    allowed : list of str
        TLP levels to allow.  e.g. ``["white", "green"]``.
    default_tlp : str
        TLP assumed when no marking is present.  Default ``"white"``.

    Examples
    --------
    ::

        TLPFilter(["white", "green"])         # exclude amber and red
        TLPFilter(["white"], default_tlp="amber")  # strict: unlabelled = amber
    """

    def __init__(self, allowed: List[str], default_tlp: str = "white"):
        self._allowed    = {t.lower() for t in allowed}
        self._default    = default_tlp.lower()

    def __call__(self, objects: Iterable["STIXBase"]) -> Iterator["STIXBase"]:
        for obj in objects:
            tlp = (_get(obj, "x_tlp") or self._default).lower()
            if tlp in self._allowed:
                yield obj

    def __repr__(self) -> str:
        return f"TLPFilter(allowed={sorted(self._allowed)})"


# ---------------------------------------------------------------------------
# TagFilter
# ---------------------------------------------------------------------------

class TagFilter(ExportFilter):
    """
    Filter by tag membership.

    Checks ``x_gm_tags``, ``labels``, and any list-valued field named
    ``tags`` or ``x_tags`` on the object.

    Parameters
    ----------
    required : list of str, optional
        Object must have ALL of these tags.
    excluded : list of str, optional
        Object must have NONE of these tags.
    match_any : bool
        If ``True``, object must have AT LEAST ONE required tag rather than
        all of them.  Default ``False`` (all required).

    Examples
    --------
    ::

        TagFilter(required=["apt28"])
        TagFilter(required=["apt28", "russia"], match_any=True)
        TagFilter(excluded=["false-positive", "whitelist"])
        TagFilter(required=["apt28"], excluded=["archived"])
    """

    _TAG_FIELDS = ["x_gm_tags", "labels", "tags", "x_tags",
                   "indicator_types", "malware_types", "threat_actor_types"]

    def __init__(
        self,
        required: Optional[List[str]] = None,
        excluded: Optional[List[str]] = None,
        match_any: bool = False,
    ):
        self._required  = [t.lower() for t in (required or [])]
        self._excluded  = {t.lower() for t in (excluded or [])}
        self._match_any = match_any

    def _tags(self, obj: "STIXBase") -> Set[str]:
        tags: Set[str] = set()
        for field in self._TAG_FIELDS:
            val = _get(obj, field)
            if isinstance(val, list):
                tags.update(str(v).lower() for v in val)
            elif isinstance(val, str):
                tags.add(val.lower())
        return tags

    def __call__(self, objects: Iterable["STIXBase"]) -> Iterator["STIXBase"]:
        for obj in objects:
            obj_tags = self._tags(obj)
            # Exclusion check (always AND)
            if obj_tags & self._excluded:
                continue
            # Required check
            if self._required:
                req_set = set(self._required)
                if self._match_any:
                    if not (obj_tags & req_set):
                        continue
                else:
                    if not req_set.issubset(obj_tags):
                        continue
            yield obj

    def __repr__(self) -> str:
        return (
            f"TagFilter(required={self._required}, "
            f"excluded={sorted(self._excluded)}, match_any={self._match_any})"
        )


# ---------------------------------------------------------------------------
# AgeFilter
# ---------------------------------------------------------------------------

class AgeFilter(ExportFilter):
    """
    Pass only objects whose timestamp field is within a maximum age.

    Parameters
    ----------
    max_age_days : float
        Maximum age in days.  Objects older than this are dropped.
    time_field : str
        Field to use as the timestamp.  Default ``"modified"``.
        Falls back to ``"created"`` if ``time_field`` is missing.
    drop_missing : bool
        If ``True``, drop objects with no parseable timestamp.
        Default ``False`` (keep objects with missing timestamps).

    Examples
    --------
    ::

        AgeFilter(max_age_days=30)
        AgeFilter(max_age_days=7, time_field="created", drop_missing=True)
    """

    def __init__(
        self,
        max_age_days: float,
        time_field: str = "modified",
        drop_missing: bool = False,
    ):
        self.max_age_days = max_age_days
        self.time_field   = time_field
        self.drop_missing = drop_missing

    def _timestamp(self, obj: "STIXBase") -> Optional[datetime]:
        for field in (self.time_field, "modified", "created"):
            raw = _get(obj, field)
            if raw:
                try:
                    return datetime.fromisoformat(
                        str(raw).replace("Z", "+00:00")
                    )
                except ValueError:
                    pass
        return None

    def __call__(self, objects: Iterable["STIXBase"]) -> Iterator["STIXBase"]:
        cutoff = _utcnow() - timedelta(days=self.max_age_days)
        for obj in objects:
            ts = self._timestamp(obj)
            if ts is None:
                if not self.drop_missing:
                    yield obj
            elif ts >= cutoff:
                yield obj

    def __repr__(self) -> str:
        return f"AgeFilter(max_age_days={self.max_age_days}, field={self.time_field!r})"


# ---------------------------------------------------------------------------
# PatternFilter
# ---------------------------------------------------------------------------

class PatternFilter(ExportFilter):
    """
    Pass only indicator objects whose STIX pattern matches a substring or regex.

    Non-indicator objects pass through unchanged (use with
    ``TypeFilter("indicator")`` to restrict to indicators).

    Parameters
    ----------
    pattern : str
        Substring or regex to match against the ``pattern`` field.
    regex : bool
        If ``True``, treat *pattern* as a regex.  Default ``False``.
    pattern_types : list of str, optional
        Only match patterns of these types (e.g. ``["ipv4-addr"]``).
        If omitted, all pattern types are checked.

    Examples
    --------
    ::

        PatternFilter("domain-name")           # only domain indicators
        PatternFilter("SHA-256")               # only hash indicators
        PatternFilter(r"10\\.0\\..*", regex=True)  # internal IP range
    """

    def __init__(
        self,
        pattern: str,
        regex: bool = False,
        pattern_types: Optional[List[str]] = None,
    ):
        self._pattern = pattern
        self._regex   = regex
        self._types   = pattern_types
        self._re      = re.compile(pattern) if regex else None

    def _matches(self, stix_pattern: str) -> bool:
        if self._re:
            return bool(self._re.search(stix_pattern))
        return self._pattern in stix_pattern

    def __call__(self, objects: Iterable["STIXBase"]) -> Iterator["STIXBase"]:
        for obj in objects:
            if obj.stix_type != "indicator":
                yield obj
                continue
            stix_pattern = _get(obj, "pattern") or ""
            if self._matches(stix_pattern):
                yield obj

    def __repr__(self) -> str:
        return f"PatternFilter(pattern={self._pattern!r}, regex={self._regex})"


# ---------------------------------------------------------------------------
# IOCTypeFilter
# ---------------------------------------------------------------------------

class IOCTypeFilter(ExportFilter):
    """
    Pass only indicator objects whose pattern encodes one of the specified
    IOC value types.

    Inspects the STIX pattern string for known STIX observable keywords.

    Parameters
    ----------
    ioc_types : list of str
        One or more of: ``"ipv4"``, ``"ipv6"``, ``"domain"``, ``"url"``,
        ``"md5"``, ``"sha1"``, ``"sha256"``, ``"email"``, ``"asn"``.

    Examples
    --------
    ::

        IOCTypeFilter(["ipv4", "domain", "url"])   # typical EDL types
        IOCTypeFilter(["sha256", "md5"])           # endpoint/EDR types
    """

    _KEYWORDS: Dict[str, str] = {
        "ipv4":   "ipv4-addr",
        "ipv6":   "ipv6-addr",
        "domain": "domain-name",
        "url":    "url:",
        "email":  "email-addr",
        "md5":    "hashes.MD5",
        "sha1":   "hashes.SHA-1",
        "sha256": "hashes.SHA-256",
        "asn":    "autonomous-system",
    }

    def __init__(self, ioc_types: List[str]):
        unknown = set(ioc_types) - set(self._KEYWORDS)
        if unknown:
            raise ValueError(
                f"IOCTypeFilter: unknown IOC types {sorted(unknown)}. "
                f"Valid: {sorted(self._KEYWORDS.keys())}"
            )
        self._keywords = {self._KEYWORDS[t] for t in ioc_types}
        self._types    = ioc_types

    def __call__(self, objects: Iterable["STIXBase"]) -> Iterator["STIXBase"]:
        for obj in objects:
            if obj.stix_type != "indicator":
                continue
            pattern = _get(obj, "pattern") or ""
            if any(kw in pattern for kw in self._keywords):
                yield obj

    def __repr__(self) -> str:
        return f"IOCTypeFilter(types={sorted(self._types)})"


# ---------------------------------------------------------------------------
# LimitFilter
# ---------------------------------------------------------------------------

class LimitFilter(ExportFilter):
    """
    Hard cap on the number of objects passed downstream.

    Parameters
    ----------
    n : int
        Maximum number of objects to yield.

    Examples
    --------
    ::

        LimitFilter(1000)   # cap EDL at 1000 entries
    """

    def __init__(self, n: int):
        self.n = n

    def __call__(self, objects: Iterable["STIXBase"]) -> Iterator["STIXBase"]:
        count = 0
        for obj in objects:
            if count >= self.n:
                return
            yield obj
            count += 1

    def __repr__(self) -> str:
        return f"LimitFilter(n={self.n})"


# ---------------------------------------------------------------------------
# DeduplicateFilter
# ---------------------------------------------------------------------------

class DeduplicateFilter(ExportFilter):
    """
    Remove objects with duplicate values of a key field.

    Only the first occurrence is kept (in iteration order).

    Parameters
    ----------
    key_field : str
        Field to deduplicate on.  Default ``"name"``.

    Examples
    --------
    ::

        DeduplicateFilter()               # dedup by name
        DeduplicateFilter("x_value")      # dedup by a custom field
    """

    def __init__(self, key_field: str = "name"):
        self.key_field = key_field

    def __call__(self, objects: Iterable["STIXBase"]) -> Iterator["STIXBase"]:
        seen: Set[Any] = set()
        for obj in objects:
            key = _get(obj, self.key_field)
            if key is None or key not in seen:
                if key is not None:
                    seen.add(key)
                yield obj

    def __repr__(self) -> str:
        return f"DeduplicateFilter(key={self.key_field!r})"


# ---------------------------------------------------------------------------
# FunctionFilter
# ---------------------------------------------------------------------------

class FunctionFilter(ExportFilter):
    """
    Filter with an arbitrary callable predicate.

    Parameters
    ----------
    predicate : callable
        ``(STIXBase) -> bool`` — return ``True`` to include the object.

    Examples
    --------
    ::

        # Only indicators with a specific tag
        FunctionFilter(lambda obj: "apt28" in (obj._properties.get("x_gm_tags") or []))

        # Only objects modified in the last week
        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        FunctionFilter(lambda obj: obj.modified_dt >= cutoff)
    """

    def __init__(self, predicate: Callable[["STIXBase"], bool]):
        self._predicate = predicate

    def __call__(self, objects: Iterable["STIXBase"]) -> Iterator["STIXBase"]:
        return filter(self._predicate, objects)

    def __repr__(self) -> str:
        return f"FunctionFilter(fn={self._predicate.__name__!r})"


# Re-export for convenience
from typing import Dict   # noqa: E402 (needed for _KEYWORDS type hint above)

"""
gnat.analysis.correlation.entity_resolver
==========================================

:class:`EntityResolver` deduplicates indicators across platforms, assigns
canonical IDs, and surfaces cross-platform aliases.

Without entity resolution, the same IP appearing in ThreatQ, GreyMatter, and
XSOAR is treated as three distinct artifacts.  The resolver normalises values
to a canonical key and groups all platform-specific records that refer to the
same real-world entity.

Supported IOC types and normalisation rules
-------------------------------------------
- ``ipv4-addr``     — lowercased; CIDR /32 suffix stripped
- ``ipv6-addr``     — lowercased, compressed form (``::`` notation)
- ``domain-name``   — lowercased, trailing dot stripped
- ``url``           — scheme+host lowercased; path preserved
- ``file:hashes.*`` — MD5/SHA1/SHA256 lowercased
- ``email-addr``    — lowercased
- ``hostname``      — lowercased, trailing dot stripped
- ``user-account``  — lowercased username
- ``autonomous-system`` — "AS<number>" uppercased

Usage::

    from gnat.analysis.correlation.entity_resolver import EntityResolver, IndicatorRecord

    records = [
        IndicatorRecord(platform="threatq",    value="185.220.101.5", ioc_type="ipv4-addr", source_id="501"),
        IndicatorRecord(platform="greymatter", value="185.220.101.5", ioc_type="ipv4-addr", source_id="obs-301"),
        IndicatorRecord(platform="xsoar",      value="185.220.101.5", ioc_type="ipv4-addr", source_id="ind-001"),
    ]
    resolver = EntityResolver()
    groups = resolver.resolve(records)
    # groups["ipv4-addr:185.220.101.5"] → all three records
"""

from __future__ import annotations

import ipaddress
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class IndicatorRecord:
    """
    A single indicator record from one platform.

    Parameters
    ----------
    platform : str
        Source platform name (e.g. ``"threatq"``).
    value : str
        Raw indicator value.
    ioc_type : str
        STIX SCO type or free-form type string (e.g. ``"ipv4-addr"``,
        ``"domain-name"``, ``"file:hashes.MD5"``).
    source_id : str
        Platform-specific identifier.
    raw : dict, optional
        Full raw record from the platform.
    first_seen : str, optional
        ISO 8601 timestamp of first observation.
    last_seen : str, optional
        ISO 8601 timestamp of most recent observation.
    confidence : int
        Platform-reported confidence 0–100 (default 50).
    tags : list of str
        Platform tags.
    """

    platform: str
    value: str
    ioc_type: str
    source_id: str
    raw: dict[str, Any] = field(default_factory=dict)
    first_seen: str | None = None
    last_seen: str | None = None
    confidence: int = 50
    tags: list[str] = field(default_factory=list)


@dataclass
class EntityGroup:
    """
    A group of :class:`IndicatorRecord` objects that all refer to the same
    real-world entity.

    Parameters
    ----------
    canonical_id : str
        UUID derived deterministically from the canonical key.
    canonical_key : str
        Normalised key, e.g. ``"ipv4-addr:185.220.101.5"``.
    ioc_type : str
        STIX SCO type.
    canonical_value : str
        Normalised canonical form of the value.
    records : list of IndicatorRecord
        All platform records in this group.
    """

    canonical_id: str
    canonical_key: str
    ioc_type: str
    canonical_value: str
    records: list[IndicatorRecord] = field(default_factory=list)

    @property
    def platforms(self) -> list[str]:
        """List of platforms contributing records to this group (deduped)."""
        seen: set[str] = set()
        result: list[str] = []
        for r in self.records:
            if r.platform not in seen:
                seen.add(r.platform)
                result.append(r.platform)
        return result

    @property
    def is_cross_platform(self) -> bool:
        """True if records come from more than one platform."""
        return len(self.platforms) > 1

    @property
    def max_confidence(self) -> Any | None:
        """ConfidenceScore with the highest numeric value across records, or None."""
        scored = [r.confidence for r in self.records if r.confidence is not None]
        if not scored:
            return None
        return max(
            scored,
            key=lambda c: (
                c.stix_confidence
                if hasattr(c, "stix_confidence")
                else c.numeric
                if hasattr(c, "numeric")
                else 0
            ),
        )

    @property
    def all_tags(self) -> list[str]:
        """Union of all tags across records (deduped)."""
        tags: set[str] = set()
        for r in self.records:
            tags.update(r.tags)
        return sorted(tags)


class EntityResolver:
    """
    Deduplicate indicators across platforms by canonical value.

    Parameters
    ----------
    case_sensitive_paths : bool
        If True, URL paths are treated as case-sensitive (default False).

    Examples
    --------
    >>> resolver = EntityResolver()
    >>> records = [
    ...     IndicatorRecord("tq",  "185.220.101.5", "ipv4-addr", "501"),
    ...     IndicatorRecord("gm",  "185.220.101.5", "ipv4-addr", "obs-301"),
    ... ]
    >>> groups = resolver.resolve(records)
    >>> len(groups)
    1
    >>> list(groups.values())[0].is_cross_platform
    True
    """

    def __init__(self, case_sensitive_paths: bool = False) -> None:
        self._case_sensitive_paths = case_sensitive_paths

    def resolve(
        self,
        records: list[IndicatorRecord],
    ) -> dict[str, EntityGroup]:
        """
        Group indicator records by canonical entity.

        Parameters
        ----------
        records : list of IndicatorRecord

        Returns
        -------
        dict
            Mapping ``canonical_key → EntityGroup``.
        """
        groups: dict[str, EntityGroup] = {}

        for record in records:
            key, norm_value = self._canonical_key(record.ioc_type, record.value)
            if not key:
                continue

            if key not in groups:
                canonical_id = str(uuid.uuid5(uuid.NAMESPACE_URL, key))
                groups[key] = EntityGroup(
                    canonical_id=canonical_id,
                    canonical_key=key,
                    ioc_type=record.ioc_type,
                    canonical_value=norm_value,
                )
            groups[key].records.append(record)

        logger.debug(
            "EntityResolver: resolved %d records into %d entity groups (%d cross-platform)",
            len(records),
            len(groups),
            sum(1 for g in groups.values() if g.is_cross_platform),
        )
        return groups

    def canonical_key(self, ioc_type: str, value: str) -> str | None:
        """
        Return the canonical key for a single IOC value, or ``None`` if the
        type is not supported.
        """
        key, _ = self._canonical_key(ioc_type, value)
        return key

    # ── Normalisation ─────────────────────────────────────────────────────────

    def _canonical_key(self, ioc_type: str, value: str) -> tuple[str | None, str]:
        """Return ``(canonical_key, normalised_value)`` or ``(None, value)``."""
        t = ioc_type.lower()
        v = value.strip()

        if t in ("ipv4-addr", "ip", "ipv4"):
            norm = self._norm_ipv4(v)
            return (f"ipv4-addr:{norm}", norm) if norm else (None, v)

        if t in ("ipv6-addr", "ipv6"):
            norm = self._norm_ipv6(v)
            return (f"ipv6-addr:{norm}", norm) if norm else (None, v)

        if t in ("domain-name", "domain", "fqdn"):
            norm = v.lower().rstrip(".")
            return (f"domain-name:{norm}", norm)

        if t in ("hostname",):
            norm = v.lower().rstrip(".")
            return (f"hostname:{norm}", norm)

        if t in ("url",):
            norm = self._norm_url(v)
            return (f"url:{norm}", norm)

        if t in ("email-addr", "email"):
            norm = v.lower()
            return (f"email-addr:{norm}", norm)

        if t in ("user-account", "username"):
            norm = v.lower()
            return (f"user-account:{norm}", norm)

        if re.match(r"file:hashes\.", t) or t in ("md5", "sha1", "sha256", "sha512"):
            norm = v.lower()
            # Derive hash type from length if not in type name
            hash_type = self._infer_hash_type(t, norm)
            return (f"file:hashes.{hash_type}:{norm}", norm)

        if t in ("autonomous-system", "asn"):
            norm = re.sub(r"[^0-9]", "", v)
            return (f"as:AS{norm}", f"AS{norm}")

        # Unknown type — use as-is but lowercased
        norm = v.lower()
        return (f"{t}:{norm}", norm)

    @staticmethod
    def _norm_ipv4(value: str) -> str | None:
        try:
            # Strip CIDR /32
            addr = value.split("/")[0]
            return str(ipaddress.IPv4Address(addr))
        except ValueError:
            return None

    @staticmethod
    def _norm_ipv6(value: str) -> str | None:
        try:
            addr = value.split("/")[0]
            return str(ipaddress.IPv6Address(addr))
        except ValueError:
            return None

    def _norm_url(self, value: str) -> str:
        try:
            parsed = urlparse(value)
            scheme = parsed.scheme.lower()
            host = parsed.netloc.lower()
            path = parsed.path if self._case_sensitive_paths else parsed.path.lower()
            query = parsed.query
            return f"{scheme}://{host}{path}" + (f"?{query}" if query else "")
        except Exception:
            return value.lower()

    @staticmethod
    def _infer_hash_type(type_hint: str, value: str) -> str:
        if "sha256" in type_hint or len(value) == 64:
            return "SHA-256"
        if "sha512" in type_hint or len(value) == 128:
            return "SHA-512"
        if "sha1" in type_hint or len(value) == 40:
            return "SHA-1"
        return "MD5"

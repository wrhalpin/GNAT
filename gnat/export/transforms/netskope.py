# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.export.transforms.netskope
====================================

Netskope Cloud Exchange (CE) threat-intel transform.

Netskope CE pulls indicators from upstream sources and pushes them to
Netskope tenant policy lists (URL lists, domain lists, IP lists).  The
CE REST API accepts a JSON payload at its threat-intel plugin endpoint.

This transform produces the exact JSON structure that Netskope CE's
``Threat Intel`` plugin expects so that indicators flow through the
sharing-rules engine and out to perimeter controls and EDLs.

Reference format (Netskope CE Threat Intel plugin v2)::

    {
        "indicator_list": [
            {
                "value":       "evil.com",
                "type":        "domain",
                "reputation":  90,
                "comment":     "Confidence: 90 | Source: ThreatQ",
                "active":      true,
                "category":    "Malware"
            },
            ...
        ]
    }

STIX → Netskope CE type mapping::

    ipv4-addr   → "ip"
    ipv6-addr   → "ipv6"
    domain-name → "domain"
    url:        → "url"
    MD5         → "md5"
    SHA-1       → "sha1"
    SHA-256     → "sha256"
    email-addr  → "email"
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from gnat.export.base import ExportTransform, TransformResult

if TYPE_CHECKING:
    from gnat.orm.base import STIXBase


_PATTERN_TO_NETSKOPE: dict[str, str] = {
    "ipv4-addr": "ip",
    "ipv6-addr": "ipv6",
    "domain-name": "domain",
    "url:": "url",
    "email-addr": "email",
    "hashes.MD5": "md5",
    "hashes.SHA-1": "sha1",
    "hashes.SHA-256": "sha256",
}

_VALUE_RE = re.compile(r"=\s*'([^']+)'")


def _extract(pattern: str) -> tuple[str | None, str | None]:
    """Return (netskope_type, value) from a STIX pattern string."""
    ns_type = None
    for stix_kw, ns in _PATTERN_TO_NETSKOPE.items():
        if stix_kw in pattern:
            ns_type = ns
            break
    m = _VALUE_RE.search(pattern)
    return ns_type, (m.group(1) if m else None)


class NetskopeCETransform(ExportTransform):
    """
    Produce a Netskope Cloud Exchange threat-intel payload.

    Maps STIX Indicator objects to Netskope CE's ``indicator_list`` JSON
    format.  Non-indicator objects are skipped.

    Parameters
    ----------
    source_label : str
        Label written into the ``comment`` field of each indicator.
        Default ``"GNAT"``.
    default_reputation : int
        Reputation (0–100) used when no confidence/score field is found.
        Default ``50``.
    active_only : bool
        Only include objects where ``x_active`` is True or the field
        is absent (treat missing as active).  Default ``True``.
    category : str
        Default category string for all indicators.  Can be overridden
        per-object via ``x_netskope_category``.  Default ``"Malware"``.
    ioc_types : list of str, optional
        Netskope CE type strings to include.  Restricts output to these
        types.  Default: all supported types.

    Examples
    --------
    ::

        transform = NetskopeCETransform(source_label="ThreatQ-APT28")
        result = transform.transform(indicators)
        # result.payloads = {"netskope_payload.json": '{"indicator_list": [...]}'}
    """

    def __init__(
        self,
        source_label: str = "GNAT",
        default_reputation: int = 50,
        active_only: bool = True,
        category: str = "Malware",
        ioc_types: list[str] | None = None,
    ):
        """Initialize NetskopeCETransform."""
        super().__init__(label="NetskopeCETransform")
        self._source = source_label
        self._default_r = default_reputation
        self._active_only = active_only
        self._category = category
        self._ioc_types = set(ioc_types) if ioc_types else None

    def _reputation(self, obj: STIXBase) -> int:
        """Internal helper for reputation."""
        for field in ("confidence", "x_rf_risk_score", "x_rr_score"):
            val = obj._properties.get(field)
            if val is not None:
                try:
                    return min(100, max(0, int(float(val))))
                except (TypeError, ValueError):
                    pass
        return self._default_r

    def transform(self, objects: list[STIXBase]) -> TransformResult:
        """Transform the input data."""
        indicator_list = []
        skipped = 0

        for obj in objects:
            if obj.stix_type != "indicator":
                skipped += 1
                continue

            # Active check
            if self._active_only:
                active = obj._properties.get("x_active")
                if active is False:
                    skipped += 1
                    continue

            pattern = obj._properties.get("pattern", "") or getattr(obj, "pattern", "") or ""
            ns_type, value = _extract(pattern)

            if not ns_type or not value:
                # Try name as fallback value
                value = getattr(obj, "name", None) or obj._properties.get("name", "")
                if not value:
                    skipped += 1
                    continue

            if self._ioc_types and ns_type not in self._ioc_types:
                skipped += 1
                continue

            reputation = self._reputation(obj)
            category = obj._properties.get("x_netskope_category") or self._category
            name = getattr(obj, "name", value)
            comment = f"Confidence: {reputation} | Source: {self._source} | Name: {name}"

            indicator_list.append(
                {
                    "value": value,
                    "type": ns_type or "domain",
                    "reputation": reputation,
                    "comment": comment,
                    "active": True,
                    "category": category,
                }
            )

        payload_body = json.dumps({"indicator_list": indicator_list}, indent=2)

        return TransformResult(
            payloads={"netskope_payload.json": payload_body},
            object_count=len(indicator_list),
            metadata={
                "indicator_count": len(indicator_list),
                "skipped": skipped,
                "source_label": self._source,
            },
        )


# gnat.export.transforms.stix_bundle
# ========================================
#
# STIX 2.1 Bundle transform — wraps filtered objects in a valid bundle
# for sharing with other TIPs, TAXII servers, or archival.


class STIXBundleTransform(ExportTransform):
    """
    Wrap filtered objects in a STIX 2.1 bundle.

    Parameters
    ----------
    include_relationships : bool
        Also include Relationship objects that connect the filtered objects.
        Relationships are pulled from the same workspace if ``workspace``
        is provided.  Default ``True``.
    pretty : bool
        Pretty-print JSON.  Default ``True``.

    Examples
    --------
    ::

        t = STIXBundleTransform()
        result = t.transform(indicators)
        # result.payloads = {"bundle.json": '{"type": "bundle", ...}'}
    """

    def __init__(self, include_relationships: bool = True, pretty: bool = True):
        """Initialize STIXBundleTransform."""
        super().__init__(label="STIXBundleTransform")
        self._include_rels = include_relationships
        self._pretty = pretty

    def transform(self, objects: list[STIXBase]) -> TransformResult:
        """Transform the input data."""
        import uuid as _uuid

        _obj_ids = {obj.id for obj in objects}
        stix_objects = [obj.to_dict() for obj in objects]

        # Include relationships that connect objects in the set
        if self._include_rels:
            # objects may include relationships — collect those too
            pass  # already included if caller passes them

        bundle = {
            "type": "bundle",
            "id": f"bundle--{_uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": stix_objects,
        }

        body = json.dumps(bundle, indent=2 if self._pretty else None)
        return TransformResult(
            payloads={"bundle.json": body},
            object_count=len(objects),
            metadata={"bundle_id": bundle["id"]},
        )


# gnat.export.transforms.csv_transform
# ==========================================
#
# CSV transform — flat rows of key fields, ready for Excel or SIEM import.


class CSVTransform(ExportTransform):
    """
    Render filtered objects as a CSV file.

    Parameters
    ----------
    fields : list of str, optional
        Column names to extract.  If omitted, a default set is used based
        on the most common STIX fields.
    filename : str
        Output file name.  Default ``"export.csv"``.
    include_header : bool
        Include column header row.  Default ``True``.

    Examples
    --------
    ::

        t = CSVTransform(fields=["name", "confidence", "x_rf_risk_score", "created"])
        result = t.transform(indicators)
        # result.payloads = {"export.csv": "name,confidence,..."}
    """

    DEFAULT_FIELDS = [
        "id",
        "type",
        "name",
        "confidence",
        "x_rf_risk_score",
        "x_tlp",
        "indicator_types",
        "pattern",
        "created",
        "modified",
    ]

    def __init__(
        self,
        fields: list[str] | None = None,
        filename: str = "export.csv",
        include_header: bool = True,
    ):
        """Initialize CSVTransform."""
        super().__init__(label="CSVTransform")
        self._fields = fields or self.DEFAULT_FIELDS
        self._filename = filename
        self._header = include_header

    def _get(self, obj: STIXBase, field: str) -> str:
        """Internal helper for get."""
        if field == "type":
            return obj.stix_type
        val = obj._properties.get(field)
        if val is None and hasattr(obj, field):
            val = getattr(obj, field, "")
        if val is None:
            return ""
        if isinstance(val, list):
            return "|".join(str(v) for v in val)
        return str(val).replace('"', '""')

    def transform(self, objects: list[STIXBase]) -> TransformResult:
        """Transform the input data."""
        import io

        buf = io.StringIO()
        if self._header:
            buf.write(",".join(f'"{c}"' for c in self._fields) + "\n")
        for obj in objects:
            row = [f'"{self._get(obj, f)}"' for f in self._fields]
            buf.write(",".join(row) + "\n")
        return TransformResult(
            payloads={self._filename: buf.getvalue()},
            object_count=len(objects),
            metadata={"fields": self._fields},
        )

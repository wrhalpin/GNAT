# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.misp.stix_mapper
======================================
STIX 2.1 mapping layer for the MISP connector.

MISP has native STIX 2.1 export/import via restSearch
(returnFormat=stix2). This mapper provides Python-level conversion
for programmatic use without the round-trip HTTP call.

Direction A — MISP Event → STIX 2.1 report bundle
---------------------------------------------------
  Event metadata  → STIX report SDO
  Each attribute  → appropriate SCO (ipv4-addr, domain-name, url, file, etc.)
  Tags            → report labels
  Galaxy clusters → STIX threat-actor / attack-pattern / malware SDOs (stub)

Direction B — STIX 2.1 bundle → MISP Event
-------------------------------------------
  Bundle          → One MISP event per bundle
  indicator SDOs  → Attributes with to_ids=True
  SCOs            → Attributes with to_ids based on type
  report SDO      → Event info / metadata

Direction C — MISP Attribute → STIX SCO/indicator
---------------------------------------------------
  ip-src/ip-dst   → ipv4-addr SCO
  domain/hostname → domain-name SCO
  url             → url SCO
  md5/sha1/sha256 → file SCO (with hashes dict)
  email-src       → email-addr SCO
  vulnerability   → vulnerability SDO
  Any to_ids attr → also produce a STIX indicator SDO wrapping the SCO

References
----------
- https://www.misp-project.org/openapi/#tag/Events (returnFormat=stix2)
- https://github.com/MISP/misp-stix
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from .exceptions import MISPSTIXError

_STIX_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

# MISP attribute type → STIX SCO type
_ATTR_TO_STIX: dict[str, str] = {
    "ip-src": "ipv4-addr",
    "ip-dst": "ipv4-addr",
    "ip-src|port": "ipv4-addr",
    "ip-dst|port": "ipv4-addr",
    "domain": "domain-name",
    "hostname": "domain-name",
    "url": "url",
    "md5": "file",
    "sha1": "file",
    "sha256": "file",
    "sha512": "file",
    "filename": "file",
    "filename|md5": "file",
    "filename|sha256": "file",
    "email-src": "email-addr",
    "email-dst": "email-addr",
    "vulnerability": "vulnerability",
    "AS": "autonomous-system",
    "regkey": "windows-registry-key",
}

# MISP threat level → STIX confidence
_THREAT_TO_CONFIDENCE = {1: 85, 2: 60, 3: 35, 4: 0}


class MISPSTIXMapper:
    """
    Bidirectional mapper between MISP data structures and STIX 2.1.

    Usage
    -----
    mapper = MISPSTIXMapper()

    # MISP event → STIX bundle
    bundle = mapper.event_to_stix_bundle(normalised_event, attributes)

    # Single attribute → STIX object(s)
    objects = mapper.attribute_to_stix_objects(normalised_attr)

    # STIX bundle → MISP event creation dict
    event_dict = mapper.stix_bundle_to_misp_event(bundle)
    """

    # ── A: MISP Event → STIX bundle ───────────────────────────────────────

    def event_to_stix_bundle(
        self,
        event: dict,
        attributes: list[dict] | None = None,
    ) -> dict:
        """
        Convert a normalised MISP event to a STIX 2.1 bundle.

        Produces a report SDO and SCOs/indicator SDOs for each attribute.

        Parameters
        ----------
        event : dict
            Normalised event from MISPEventCommands.normalise_event().
        attributes : list[dict] | None
            Normalised attribute list. If None, uses event._raw.Attribute.

        Returns
        -------
        dict
            STIX 2.1 bundle.
        """
        now = _now_ts()
        objects: list[dict] = []
        seen: set[str] = set()
        object_refs: list[str] = []

        # Resolve attributes
        raw_attrs = attributes or [
            self._normalise_attr_stub(a) for a in event.get("_raw", {}).get("Attribute", [])
        ]

        for attr in raw_attrs:
            for stix_obj in self.attribute_to_stix_objects(attr):
                if stix_obj["id"] not in seen:
                    seen.add(stix_obj["id"])
                    objects.append(stix_obj)
                object_refs.append(stix_obj["id"])

        # Report SDO
        threat_level = event.get("threat_level_id", 4)
        confidence = _THREAT_TO_CONFIDENCE.get(threat_level, 0)
        report_id = f"report--{_det_uuid('report', event.get('uuid', event.get('id', now)))}"
        report: dict = {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": _epoch_to_stix(event.get("timestamp")) or now,
            "modified": now,
            "name": event.get("info", "MISP Event"),
            "report_types": ["threat-report"],
            "published": now,
            "object_refs": list(dict.fromkeys(object_refs)),
            "confidence": confidence,
            "labels": event.get("tags", []),
            "x_misp_event": {
                "event_id": event.get("id"),
                "uuid": event.get("uuid"),
                "threat_level_id": threat_level,
                "analysis": event.get("analysis"),
                "distribution": event.get("distribution"),
                "published": event.get("published"),
                "attribute_count": event.get("attribute_count"),
            },
        }
        objects.append(report)
        return _make_bundle(objects)

    # ── C: MISP Attribute → STIX objects ──────────────────────────────────

    def attribute_to_stix_objects(self, attr: dict) -> list[dict]:
        """
        Convert a normalised MISP attribute to STIX object(s).

        For to_ids=True attributes, produces both an SCO and a wrapping
        indicator SDO. For to_ids=False (context-only), produces only the SCO.

        Parameters
        ----------
        attr : dict
            Normalised attribute from MISPAttributeCommands.normalise_attribute().

        Returns
        -------
        list[dict]
            One or two STIX objects.
        """
        attr_type = attr.get("type", "")
        value = attr.get("value", "")
        if not value:
            return []

        stix_type = _ATTR_TO_STIX.get(attr_type)
        if not stix_type:
            return []

        objects: list[dict] = []
        sco = self._build_sco(stix_type, attr_type, value, attr)
        if not sco:
            return []
        objects.append(sco)

        # Wrap in indicator SDO if to_ids is set
        if attr.get("to_ids"):
            indicator = self._build_indicator_from_attr(attr, sco)
            if indicator:
                objects.append(indicator)

        return objects

    # ── B: STIX bundle → MISP event dict ──────────────────────────────────

    def stix_bundle_to_misp_event(
        self,
        bundle: dict,
        default_distribution: int = 0,
        default_threat_level: int = 2,
        default_analysis: int = 0,
    ) -> dict:
        """
        Convert a STIX 2.1 bundle to a MISP event creation dict.

        Extracts a report SDO for event metadata (if present), then
        converts indicators and SCOs to MISP attributes.

        Parameters
        ----------
        bundle : dict
            STIX 2.1 bundle.
        default_distribution : int
        default_threat_level : int
        default_analysis : int

        Returns
        -------
        dict
            Dict with 'event' (event fields) and 'attributes' (list).

        Raises
        ------
        MISPSTIXError
        """
        if bundle.get("type") != "bundle":
            raise MISPSTIXError(f"Expected STIX bundle, got type='{bundle.get('type')}'.")

        objects = bundle.get("objects", [])
        report = next((o for o in objects if o.get("type") == "report"), None)

        event_info = report.get("name", "STIX Import") if report else "STIX Import"
        event: dict = {
            "info": event_info,
            "distribution": default_distribution,
            "threat_level_id": default_threat_level,
            "analysis": default_analysis,
            "published": False,
        }

        attributes: list[dict] = []
        seen_values: set[str] = set()

        for obj in objects:
            _obj_type = obj.get("type", "")
            attrs = self._stix_object_to_misp_attributes(obj)
            for attr in attrs:
                key = f"{attr['type']}:{attr['value']}"
                if key not in seen_values:
                    seen_values.add(key)
                    attributes.append(attr)

        return {"event": event, "attributes": attributes}

    # ── Internal helpers ───────────────────────────────────────────────────

    def _build_sco(
        self,
        stix_type: str,
        attr_type: str,
        value: str,
        attr: dict,
    ) -> dict | None:
        """Build a STIX SCO from a MISP attribute."""
        # Strip port suffix for ip|port types
        ip_value = value.split("|")[0] if "|" in value else value

        if stix_type == "ipv4-addr":
            return {
                "type": "ipv4-addr",
                "id": f"ipv4-addr--{_det_uuid('ipv4-addr', ip_value)}",
                "spec_version": "2.1",
                "value": ip_value,
            }
        if stix_type == "domain-name":
            return {
                "type": "domain-name",
                "id": f"domain-name--{_det_uuid('domain-name', value)}",
                "spec_version": "2.1",
                "value": value,
            }
        if stix_type == "url":
            return {
                "type": "url",
                "id": f"url--{_det_uuid('url', value)}",
                "spec_version": "2.1",
                "value": value,
            }
        if stix_type == "email-addr":
            return {
                "type": "email-addr",
                "id": f"email-addr--{_det_uuid('email-addr', value)}",
                "spec_version": "2.1",
                "value": value,
            }
        if stix_type == "file":
            hash_map = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512"}
            base_type = attr_type.split("|")[0]
            obj: dict = {
                "type": "file",
                "id": f"file--{_det_uuid('file', value)}",
                "spec_version": "2.1",
            }
            if base_type in hash_map:
                obj["hashes"] = {hash_map[base_type]: value}
            else:
                obj["name"] = value
            return obj
        if stix_type == "vulnerability":
            return {
                "type": "vulnerability",
                "id": f"vulnerability--{_det_uuid('vulnerability', value)}",
                "spec_version": "2.1",
                "created": _now_ts(),
                "modified": _now_ts(),
                "name": value,
                "external_references": [
                    {
                        "source_name": "cve",
                        "external_id": value,
                        "url": f"https://nvd.nist.gov/vuln/detail/{value}",
                    }
                ],
            }
        if stix_type == "autonomous-system":
            try:
                return {
                    "type": "autonomous-system",
                    "id": f"autonomous-system--{_det_uuid('AS', value)}",
                    "spec_version": "2.1",
                    "number": int(value.lstrip("AS")),
                }
            except ValueError:
                return None
        return None

    def _build_indicator_from_attr(self, attr: dict, sco: dict) -> dict | None:
        """Build a STIX indicator SDO wrapping an SCO."""
        attr_type = attr.get("type", "")
        value = attr.get("value", "")
        sco_type = sco.get("type", "")

        # Build pattern from SCO type
        pattern_map: dict = {
            "ipv4-addr": f"[ipv4-addr:value = '{value.split('|')[0]}']",
            "domain-name": f"[domain-name:value = '{value}']",
            "url": f"[url:value = '{value}']",
            "email-addr": f"[email-addr:value = '{value}']",
        }
        if sco_type == "file":
            hash_map = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512"}
            base_type = attr_type.split("|")[0]
            algo = hash_map.get(base_type, "SHA-256")
            pattern_map["file"] = f"[file:hashes.'{algo}' = '{value}']"

        pattern = pattern_map.get(sco_type)
        if not pattern:
            return None

        now = _now_ts()
        return {
            "type": "indicator",
            "id": f"indicator--{_det_uuid('indicator', pattern)}",
            "spec_version": "2.1",
            "created": _epoch_to_stix(attr.get("timestamp")) or now,
            "modified": now,
            "name": attr.get("value", ""),
            "description": attr.get("comment", ""),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "indicator_types": ["malicious-activity"],
            "labels": attr.get("tags", []),
        }

    @staticmethod
    def _stix_object_to_misp_attributes(obj: dict) -> list[dict]:
        """Convert a STIX object to a list of MISP attribute dicts."""
        obj_type = obj.get("type", "")
        attrs: list[dict] = []

        if obj_type in ("ipv4-addr", "ipv6-addr"):
            attrs.append(
                {
                    "type": "ip-src",
                    "value": obj.get("value", ""),
                    "category": "Network activity",
                    "to_ids": True,
                }
            )
        elif obj_type == "domain-name":
            attrs.append(
                {
                    "type": "domain",
                    "value": obj.get("value", ""),
                    "category": "Network activity",
                    "to_ids": True,
                }
            )
        elif obj_type == "url":
            attrs.append(
                {
                    "type": "url",
                    "value": obj.get("value", ""),
                    "category": "Network activity",
                    "to_ids": True,
                }
            )
        elif obj_type == "email-addr":
            attrs.append(
                {
                    "type": "email-src",
                    "value": obj.get("value", ""),
                    "category": "Payload delivery",
                    "to_ids": True,
                }
            )
        elif obj_type == "file":
            hashes = obj.get("hashes", {})
            hash_map = {"MD5": "md5", "SHA-1": "sha1", "SHA-256": "sha256"}
            for stix_algo, misp_type in hash_map.items():
                if v := hashes.get(stix_algo):
                    attrs.append(
                        {
                            "type": misp_type,
                            "value": v,
                            "category": "Payload delivery",
                            "to_ids": True,
                        }
                    )
            if name := obj.get("name"):
                attrs.append(
                    {
                        "type": "filename",
                        "value": name,
                        "category": "Payload delivery",
                        "to_ids": False,
                    }
                )
        elif obj_type == "indicator":
            # Extract value from simple pattern
            pattern = obj.get("pattern", "")
            m = re.search(r"=\s*'([^']+)'", pattern)
            if m:
                value = m.group(1)
                type_hint = (
                    "ip-src"
                    if "ipv4-addr" in pattern
                    else "domain"
                    if "domain-name" in pattern
                    else "url"
                    if "url:" in pattern
                    else "comment"
                )
                attrs.append(
                    {
                        "type": type_hint,
                        "value": value,
                        "category": "Network activity",
                        "to_ids": True,
                        "comment": obj.get("description", ""),
                    }
                )
        return attrs

    @staticmethod
    def _normalise_attr_stub(raw_attr: dict) -> dict:
        """Minimal normalisation for raw attributes from event._raw."""
        return {
            "id": raw_attr.get("id"),
            "uuid": raw_attr.get("uuid"),
            "event_id": raw_attr.get("event_id"),
            "type": raw_attr.get("type"),
            "category": raw_attr.get("category"),
            "value": raw_attr.get("value"),
            "to_ids": raw_attr.get("to_ids", False),
            "comment": raw_attr.get("comment", ""),
            "timestamp": raw_attr.get("timestamp"),
            "tags": [t.get("name", "") for t in raw_attr.get("Tag", [])],
            "_raw": raw_attr,
        }


def _det_uuid(stix_type: str, value: str) -> str:
    return str(uuid.uuid5(_STIX_NS, f"{stix_type}:{value}"))


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _epoch_to_stix(epoch: str | int | None) -> str | None:
    if not epoch:
        return None
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        )
    except (ValueError, TypeError):
        return None


def _make_bundle(objects: list[dict]) -> dict:
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }

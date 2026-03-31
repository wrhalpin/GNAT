"""
gnat.connectors.sentinel.stix_mapper
==========================================
STIX 2.1 mapping for the Microsoft Sentinel connector.

Direction A — Sentinel TI Indicator → STIX indicator SDO
Direction B — STIX indicator SDO → Sentinel TI indicator properties
Direction C — Sentinel Incident → STIX observed-data bundle
Direction D — STIX bundle → Sentinel TI indicator batch
"""

from __future__ import annotations

import contextlib
import uuid
from datetime import datetime, timezone

from .exceptions import SentinelSTIXError

_STIX_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


class SentinelSTIXMapper:
    """Bidirectional STIX 2.1 ↔ Sentinel TI indicator mapper."""

    # ── A: Sentinel TI → STIX ─────────────────────────────────────────────

    def ti_indicator_to_stix(self, indicator: dict) -> dict:
        """
        Convert a Sentinel TI indicator resource to a STIX 2.1 indicator SDO.

        Parameters
        ----------
        indicator : dict
            Raw Sentinel TI indicator resource.

        Returns
        -------
        dict
            STIX 2.1 indicator SDO.
        """
        props = indicator.get("properties", {})
        now = _now_ts()
        kcp = [
            {"kill_chain_name": k.get("killChainName", ""),
             "phase_name": k.get("phaseName", "")}
            for k in props.get("killChainPhases", [])
        ]
        ext_refs = [
            {"source_name": r.get("sourceName", ""),
             "url": r.get("url", ""),
             "description": r.get("description", "")}
            for r in props.get("externalReferences", [])
        ]
        obj: dict = {
            "type": "indicator",
            "id": f"indicator--{_det_uuid('indicator', indicator.get('name', now))}",
            "spec_version": "2.1",
            "created": props.get("created") or now,
            "modified": props.get("lastUpdatedTimeUtc") or now,
            "name": props.get("displayName", ""),
            "description": props.get("description", ""),
            "pattern": props.get("pattern", ""),
            "pattern_type": props.get("patternType", "stix"),
            "valid_from": props.get("validFrom") or now,
            "indicator_types": props.get("threatTypes") or ["malicious-activity"],
            "confidence": props.get("confidence", 0),
        }
        if props.get("validUntil"):
            obj["valid_until"] = props["validUntil"]
        if props.get("revoked"):
            obj["revoked"] = True
        if kcp:
            obj["kill_chain_phases"] = kcp
        if ext_refs:
            obj["external_references"] = ext_refs
        if props.get("threatIntelligenceTags"):
            obj["labels"] = props["threatIntelligenceTags"]
        return obj

    def ti_indicators_to_stix_bundle(self, indicators: list[dict]) -> dict:
        """Convert a list of Sentinel TI indicators to a STIX 2.1 bundle."""
        objects = []
        seen: set[str] = set()
        for ind in indicators:
            obj = self.ti_indicator_to_stix(ind)
            if obj["id"] not in seen:
                seen.add(obj["id"])
                objects.append(obj)
        return _make_bundle(objects)

    # ── B: STIX → Sentinel TI properties ──────────────────────────────────

    def stix_indicator_to_ti_properties(self, indicator: dict) -> dict:
        """
        Convert a STIX 2.1 indicator SDO to Sentinel TI indicator properties.

        Parameters
        ----------
        indicator : dict
            STIX 2.1 indicator dict.

        Returns
        -------
        dict
            Properties dict for POST /createIndicator.
        """
        if indicator.get("type") != "indicator":
            raise SentinelSTIXError(
                f"Expected STIX indicator, got type='{indicator.get('type')}'."
            )
        kcp = [
            {"killChainName": k.get("kill_chain_name", ""),
             "phaseName": k.get("phase_name", "")}
            for k in indicator.get("kill_chain_phases", [])
        ]
        ext_refs = [
            {"sourceName": r.get("source_name", ""),
             "url": r.get("url", ""),
             "description": r.get("description", "")}
            for r in indicator.get("external_references", [])
        ]
        props: dict = {
            "displayName": indicator.get("name", ""),
            "description": indicator.get("description", ""),
            "pattern": indicator.get("pattern", ""),
            "patternType": indicator.get("pattern_type", "stix"),
            "validFrom": indicator.get("valid_from", _now_ts()),
            "confidence": indicator.get("confidence", 0),
            "threatTypes": indicator.get("indicator_types", ["malicious-activity"]),
            "source": indicator.get("x_opencti_score", "gnat"),
            "revoked": indicator.get("revoked", False),
        }
        if indicator.get("valid_until"):
            props["validUntil"] = indicator["valid_until"]
        if kcp:
            props["killChainPhases"] = kcp
        if ext_refs:
            props["externalReferences"] = ext_refs
        if indicator.get("labels"):
            props["threatIntelligenceTags"] = indicator["labels"]
        return props

    # ── C: Sentinel Incident → STIX bundle ────────────────────────────────

    def incident_to_stix_bundle(self, incident: dict) -> dict:
        """
        Convert a normalised Sentinel incident to a STIX 2.1 observed-data bundle.

        Parameters
        ----------
        incident : dict
            Normalised incident from SentinelIncidentCommands.normalise_incident().

        Returns
        -------
        dict
            STIX 2.1 bundle.
        """
        now = _now_ts()
        ts = incident.get("created") or now
        objects: list[dict] = []
        obs_id = f"observed-data--{uuid.uuid4()}"
        objects.append({
            "type": "observed-data",
            "id": obs_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "first_observed": incident.get("first_activity") or ts,
            "last_observed": incident.get("last_activity") or ts,
            "number_observed": max(1, incident.get("alert_count", 1)),
            "object_refs": [],
            "x_sentinel_incident": {
                "incident_id": incident.get("id"),
                "incident_number": incident.get("number"),
                "title": incident.get("title"),
                "severity": incident.get("severity"),
                "severity_label": incident.get("severity_label"),
                "status": incident.get("status"),
                "classification": incident.get("classification"),
                "owner": incident.get("owner"),
                "labels": incident.get("labels", []),
            },
        })
        return _make_bundle(objects)

    # ── D: STIX bundle → Sentinel TI batch ────────────────────────────────

    def stix_bundle_to_ti_properties_list(self, bundle: dict) -> list[dict]:
        """
        Extract STIX indicator SDOs from a bundle and convert to Sentinel
        TI indicator properties dicts ready for bulk creation.

        Parameters
        ----------
        bundle : dict
            STIX 2.1 bundle.

        Returns
        -------
        list[dict]
            List of properties dicts for SentinelThreatIntelCommands.bulk_create_indicators().
        """
        if bundle.get("type") != "bundle":
            raise SentinelSTIXError(
                f"Expected STIX bundle, got type='{bundle.get('type')}'."
            )
        results = []
        for obj in bundle.get("objects", []):
            if obj.get("type") == "indicator":
                with contextlib.suppress(SentinelSTIXError):
                    results.append(self.stix_indicator_to_ti_properties(obj))
        return results


def _det_uuid(stix_type: str, value: str) -> str:
    return str(uuid.uuid5(_STIX_NS, f"{stix_type}:{value}"))


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _make_bundle(objects: list[dict]) -> dict:
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }

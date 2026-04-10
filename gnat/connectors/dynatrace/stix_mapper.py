# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.dynatrace.stix_mapper
==========================================
STIX 2.1 mapping for the Dynatrace connector.

Direction A — Dynatrace entity → STIX infrastructure SDO
Direction B — Dynatrace security problem → STIX vulnerability SDO
Direction C — Dynatrace attack → STIX indicator SDO
Direction D — Dynatrace problem → STIX observed-data SDO
Direction E — Dynatrace event → STIX observed-data SDO
Direction F — STIX dict → Dynatrace event ingest payload (from_stix)

Timestamp note
--------------
Many Dynatrace fields use epoch-millisecond integers:
  firstSeenTms, lastSeenTms, startTime, endTime
Use _epoch_ms_to_iso() to convert these to ISO 8601 strings.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .exceptions import DynatraceSTIXError

# Entity type → STIX infrastructure type mapping
_ENTITY_INFRA_TYPE: dict[str, str] = {
    "HOST": "workstation",
    "SERVICE": "network",
    "APPLICATION": "network",
    "NETWORK_INTERFACE": "network",
    "PROCESS_GROUP": "server",
    "CONTAINER_GROUP": "server",
    "KUBERNETES_CLUSTER": "server",
    "KUBERNETES_NODE": "server",
    "KUBERNETES_POD": "server",
    "CLOUD_APPLICATION": "network",
    "CLOUD_APPLICATION_NAMESPACE": "network",
    "AUTO_SCALING_GROUP": "server",
    "VIRTUAL_MACHINE": "server",
    "DOCKER_CONTAINER_GROUP": "server",
}

# Severity → STIX confidence score mapping
_SEVERITY_CONFIDENCE: dict[str, int] = {
    "critical": 90,
    "high": 75,
    "medium": 55,
    "low": 35,
}


def _epoch_ms_to_iso(ms: int | float | None) -> str:
    """
    Convert an epoch-millisecond integer to an ISO 8601 UTC string.

    Parameters
    ----------
    ms : int, float, or None
        Epoch time in milliseconds.

    Returns
    -------
    str
        ISO 8601 UTC string, e.g. '2024-01-15T10:30:00.000000+00:00'.
        Returns current UTC time if ms is None or 0.
    """
    if not ms:
        return datetime.now(timezone.utc).isoformat()
    try:
        dt = datetime.fromtimestamp(int(ms) / 1000.0, tz=timezone.utc)
        return dt.isoformat()
    except (ValueError, OSError, OverflowError):
        return datetime.now(timezone.utc).isoformat()


class DynatraceSTIXMapper:
    """Bidirectional STIX 2.1 ↔ Dynatrace object mapper."""

    # ── A: Entity → STIX infrastructure ──────────────────────────────────

    def entity_to_stix(self, entity: dict) -> dict:
        """
        Convert a Dynatrace entity to a STIX 2.1 infrastructure SDO.

        Parameters
        ----------
        entity : dict
            Raw Dynatrace entity from /api/v2/entities.

        Returns
        -------
        dict
            STIX 2.1 infrastructure SDO with Dynatrace extension fields.
        """
        try:
            entity_id = entity["entityId"]
            display_name = entity["displayName"]
        except KeyError as exc:
            raise DynatraceSTIXError(
                f"Entity missing required field: {exc}"
            ) from exc

        entity_type = entity.get("type", "")
        infra_type = _ENTITY_INFRA_TYPE.get(entity_type, "unknown")
        first_seen = _epoch_ms_to_iso(entity.get("firstSeenTms"))
        last_seen = _epoch_ms_to_iso(entity.get("lastSeenTms"))

        tags = [t.get("key", "") for t in entity.get("tags", []) if t.get("key")]
        mgmt_zones = [
            mz.get("name", "") for mz in entity.get("managementZones", []) if mz.get("name")
        ]

        return {
            "type": "infrastructure",
            "id": f"infrastructure--dt-{entity_id}",
            "spec_version": "2.1",
            "name": display_name,
            "infrastructure_types": [infra_type],
            "created": first_seen,
            "modified": last_seen,
            "x_dt_entity_id": entity_id,
            "x_dt_entity_type": entity_type,
            "x_dt_tags": tags,
            "x_dt_management_zones": mgmt_zones,
            "x_dt_properties": entity.get("properties", {}),
        }

    # ── B: Security problem → STIX vulnerability ──────────────────────────

    def security_problem_to_stix(self, sp: dict) -> dict:
        """
        Convert a Dynatrace security problem to a STIX 2.1 vulnerability SDO.

        Parameters
        ----------
        sp : dict
            Raw Dynatrace security problem from /api/v2/securityProblems.

        Returns
        -------
        dict
            STIX 2.1 vulnerability SDO.
        """
        try:
            sp_id = sp["securityProblemId"]
        except KeyError as exc:
            raise DynatraceSTIXError(
                f"Security problem missing required field: {exc}"
            ) from exc

        risk = sp.get("riskAssessment", {})
        cvss_score = risk.get("baseScore") or risk.get("exploitabilityScore")
        risk_level = risk.get("riskLevel", "").lower()

        cve_ids = sp.get("cveIds", [])
        affected_entities = [
            e.get("entityId", "") for e in sp.get("affectedEntities", []) if e.get("entityId")
        ]

        return {
            "type": "vulnerability",
            "id": f"vulnerability--dt-{sp_id}",
            "spec_version": "2.1",
            "name": sp.get("displayId", sp_id),
            "description": sp.get("title", ""),
            "created": _epoch_ms_to_iso(sp.get("firstSeenTimestamp")),
            "modified": _epoch_ms_to_iso(sp.get("lastUpdatedTimestamp")),
            "x_dt_security_problem_id": sp_id,
            "x_dt_cve_ids": cve_ids,
            "x_dt_risk_level": risk_level,
            "x_dt_cvss_score": cvss_score,
            "x_dt_status": sp.get("status", ""),
            "x_dt_technology": sp.get("technology", ""),
            "x_dt_affected_entities": affected_entities,
        }

    # ── C: Attack → STIX indicator ────────────────────────────────────────

    def attack_to_stix(self, attack: dict) -> dict:
        """
        Convert a Dynatrace attack to a STIX 2.1 indicator SDO.

        Parameters
        ----------
        attack : dict
            Raw Dynatrace attack from /api/v2/attacks.

        Returns
        -------
        dict
            STIX 2.1 indicator SDO.
        """
        try:
            attack_id = attack["attackId"]
        except KeyError as exc:
            raise DynatraceSTIXError(
                f"Attack missing required field: {exc}"
            ) from exc

        attack_type = attack.get("type", "UNKNOWN")
        severity = attack.get("severity", "").lower()
        confidence = _SEVERITY_CONFIDENCE.get(severity, 50)

        attacked_entity = attack.get("attackedEntity", {})
        entity_id = attacked_entity.get("id", "") if isinstance(attacked_entity, dict) else ""

        attack_target = attack.get("attackTarget", {})
        target_url = attack_target.get("url", "") if isinstance(attack_target, dict) else ""

        return {
            "type": "indicator",
            "id": f"indicator--dt-{attack_id}",
            "spec_version": "2.1",
            "name": f"Dynatrace Attack: {attack_type}",
            "pattern": f"[domain-name:value = 'dynatrace.attack.{attack_type.lower()}']",
            "pattern_type": "stix",
            "valid_from": _epoch_ms_to_iso(attack.get("timestamp")),
            "created": _epoch_ms_to_iso(attack.get("timestamp")),
            "modified": _epoch_ms_to_iso(attack.get("timestamp")),
            "confidence": confidence,
            "indicator_types": ["malicious-activity"],
            "x_dt_attack_id": attack_id,
            "x_dt_attack_type": attack_type,
            "x_dt_state": attack.get("state", ""),
            "x_dt_severity": severity,
            "x_dt_attacked_entity": entity_id,
            "x_dt_attack_target_url": target_url,
        }

    # ── D: Problem → STIX observed-data ──────────────────────────────────

    def problem_to_stix(self, problem: dict) -> dict:
        """
        Convert a Dynatrace problem to a STIX 2.1 observed-data SDO.

        Parameters
        ----------
        problem : dict
            Raw Dynatrace problem from /api/v2/problems.

        Returns
        -------
        dict
            STIX 2.1 observed-data SDO.
        """
        try:
            problem_id = problem["problemId"]
        except KeyError as exc:
            raise DynatraceSTIXError(
                f"Problem missing required field: {exc}"
            ) from exc

        first_obs = _epoch_ms_to_iso(problem.get("startTime"))
        last_obs = _epoch_ms_to_iso(problem.get("endTime") or problem.get("startTime"))

        affected_entities = [
            e.get("entityId", "")
            for e in problem.get("affectedEntities", [])
            if e.get("entityId")
        ]

        return {
            "type": "observed-data",
            "id": f"observed-data--dt-{problem_id}",
            "spec_version": "2.1",
            "created": first_obs,
            "modified": last_obs,
            "first_observed": first_obs,
            "last_observed": last_obs,
            "number_observed": 1,
            "objects": {},
            "x_dt_problem_id": problem_id,
            "x_dt_title": problem.get("title", ""),
            "x_dt_impact_level": problem.get("impactLevel", ""),
            "x_dt_severity": problem.get("severityLevel", ""),
            "x_dt_status": problem.get("status", ""),
            "x_dt_affected_entities": affected_entities,
        }

    # ── E: Event → STIX observed-data ─────────────────────────────────────

    def event_to_stix(self, event: dict) -> dict:
        """
        Convert a Dynatrace event to a STIX 2.1 observed-data SDO.

        Parameters
        ----------
        event : dict
            Raw Dynatrace event from /api/v2/events.

        Returns
        -------
        dict
            STIX 2.1 observed-data SDO.
        """
        try:
            event_id = event["eventId"]
        except KeyError as exc:
            raise DynatraceSTIXError(
                f"Event missing required field: {exc}"
            ) from exc

        start_time = _epoch_ms_to_iso(event.get("startTime"))
        end_time = _epoch_ms_to_iso(event.get("endTime") or event.get("startTime"))

        entity_id = ""
        entity_ref = event.get("entityId", {})
        if isinstance(entity_ref, dict):
            entity_id = entity_ref.get("entityId", "")
        elif isinstance(entity_ref, str):
            entity_id = entity_ref

        return {
            "type": "observed-data",
            "id": f"observed-data--dt-event-{event_id}",
            "spec_version": "2.1",
            "created": start_time,
            "modified": end_time,
            "first_observed": start_time,
            "last_observed": end_time,
            "number_observed": 1,
            "objects": {},
            "x_dt_event_id": event_id,
            "x_dt_event_type": event.get("eventType", ""),
            "x_dt_title": event.get("title", ""),
            "x_dt_entity_id": entity_id,
            "x_dt_properties": event.get("properties", {}),
        }

    # ── F: STIX → Dynatrace event ingest payload ──────────────────────────

    def from_stix_to_event(self, stix_dict: dict) -> dict:
        """
        Convert a STIX dict to a Dynatrace event ingest payload.

        Parameters
        ----------
        stix_dict : dict
            STIX 2.1 object (any type; typically observed-data or indicator).

        Returns
        -------
        dict
            Dynatrace event ingest payload for POST /api/v2/events/ingest.
        """
        entity_id = stix_dict.get("x_dt_entity_id")
        entity_selector = f"entityId({entity_id})" if entity_id else None

        payload: dict = {
            "eventType": stix_dict.get("x_dt_event_type", "CUSTOM_INFO"),
            "title": (
                stix_dict.get("x_dt_title")
                or stix_dict.get("name")
                or "GNAT event"
            ),
            "properties": stix_dict.get("x_dt_properties", {}),
        }
        if entity_selector:
            payload["entitySelector"] = entity_selector

        return payload

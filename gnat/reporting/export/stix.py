# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.reporting.export.stix
============================

Serialise a :class:`~gnat.reporting.models.Report` to a STIX 2.1 bundle.

STIX mapping
------------
- :class:`~gnat.reporting.models.Report` → STIX ``report`` SDO
- :class:`~gnat.reporting.models.Attribution` → STIX ``threat-actor`` SDO
  + ``attributed-to`` relationship
- Linked indicators/observables/threat-actors are referenced via
  ``object_refs`` in the report SDO
- TLP classification → ``object_marking_refs``
- Key findings → ``x_gnat_findings`` extension
- Evidence links → ``x_gnat_evidence_links`` extension

Usage::

    from gnat.reporting.export.stix import report_to_stix_bundle

    bundle = report_to_stix_bundle(published_report)
    import json
    print(json.dumps(bundle, indent=2))
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.reporting.models import Report


def _utcnow() -> str:
    """Internal helper for utcnow."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _stix_id(obj_type: str, seed: str | None = None) -> str:
    """Internal helper for stix id."""
    if seed:
        return f"{obj_type}--{_uuid.uuid5(_uuid.NAMESPACE_URL, seed)}"
    return f"{obj_type}--{_uuid.uuid4()}"


def report_to_stix_bundle(report: Report) -> dict[str, Any]:
    """
    Serialise a :class:`~gnat.reporting.models.Report` to a STIX 2.1 bundle.

    The bundle contains:

    1. A STIX ``report`` SDO
    2. A STIX ``threat-actor`` SDO + ``attributed-to`` relationship (if
       attribution is set)
    3. Identity SDO for the GNAT platform (producer)
    4. TLP marking definition reference in ``object_marking_refs``

    The ``object_refs`` field of the STIX Report SDO contains:
    - All ``evidence_links[*].artifact_id`` values (deduped)
    - Attribution threat actor STIX ID (if present)
    - The GNAT identity ID

    Parameters
    ----------
    report : Report
        The report to serialise.  Should be in PUBLISHED or APPROVED status
        for a meaningful ``published`` field, but this is not enforced here.

    Returns
    -------
    dict
        STIX 2.1 bundle (JSON-serialisable).
    """
    now_str = _utcnow()
    created_at = (
        report.published_at.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        if report.published_at
        else now_str
    )

    objects: list[dict[str, Any]] = []
    object_refs: list[str] = []

    # ── Identity: GNAT platform ───────────────────────────────────────────────
    identity_id = _stix_id("identity", "gnat-platform-identity")
    identity: dict[str, Any] = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": created_at,
        "modified": created_at,
        "name": "GNAT CTM Toolkit",
        "identity_class": "system",
    }
    objects.append(identity)
    object_refs.append(identity_id)

    # ── Attribution: threat-actor SDO + relationship ──────────────────────────
    threat_actor_id: str | None = None
    if report.attribution:
        attr = report.attribution
        # Use provided STIX id if available, otherwise derive deterministically
        threat_actor_id = attr.threat_actor_id or _stix_id(
            "threat-actor", f"ta-{attr.threat_actor_name}"
        )
        ta_properties: dict[str, Any] = {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": threat_actor_id,
            "created": created_at,
            "modified": created_at,
            "name": attr.threat_actor_name,
            "threat_actor_types": ["criminal"],
            "confidence": attr.confidence.stix_confidence,
            "x_gnat_attribution_rationale": attr.rationale,
        }
        if attr.mitre_group_id:
            ta_properties["x_mitre_group_id"] = attr.mitre_group_id
        objects.append(ta_properties)
        object_refs.append(threat_actor_id)

        # attributed-to relationship: report ← threat-actor
        attr_rel_id = _stix_id("relationship", f"attr-{report.id}-{threat_actor_id}")
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": attr_rel_id,
                "created": created_at,
                "modified": created_at,
                "relationship_type": "attributed-to",
                "source_ref": _stix_id("report", report.id),
                "target_ref": threat_actor_id,
                "confidence": attr.confidence.stix_confidence,
            }
        )

    # ── Evidence artifact refs ────────────────────────────────────────────────
    seen_artifact_ids: set[str] = set()
    for link in report.evidence_links:
        aid = link.artifact_id
        if aid and aid not in seen_artifact_ids:
            seen_artifact_ids.add(aid)
            object_refs.append(aid)

    # Dedup object_refs while preserving order
    _seen: set[str] = set()
    object_refs_deduped: list[str] = []
    for ref in object_refs:
        if ref not in _seen:
            _seen.add(ref)
            object_refs_deduped.append(ref)

    # ── TLP marking refs ──────────────────────────────────────────────────────
    marking_refs = [report.classification.stix_marking_id]

    # ── STIX report SDO ───────────────────────────────────────────────────────
    report_stix_id = _stix_id("report", report.id)
    stix_labels = [report.report_type.value.replace("_", "-")]
    stix_labels.append(report.classification.label.lower())

    report_sdo: dict[str, Any] = {
        "type": "report",
        "spec_version": "2.1",
        "id": report_stix_id,
        "created": created_at,
        "modified": created_at,
        "name": report.title,
        "published": created_at,
        "object_refs": object_refs_deduped or [identity_id],
        "labels": stix_labels,
        "object_marking_refs": marking_refs,
        "created_by_ref": identity_id,
        # GNAT extensions
        "x_gnat_report_id": report.id,
        "x_gnat_report_type": report.report_type.value,
        "x_gnat_version": report.version,
        "x_gnat_status": report.status.value,
        "x_gnat_authors": report.authors,
    }

    if report.executive_summary:
        report_sdo["description"] = report.executive_summary

    if report.overall_confidence:
        report_sdo["confidence"] = report.overall_confidence.stix_confidence

    # Key findings as extension
    if report.key_findings:
        report_sdo["x_gnat_findings"] = [
            {
                "id": f["id"],
                "statement": f["statement"],
                "confidence": f.get("confidence", {}).get("stix_confidence")
                if f.get("confidence")
                else None,
                "mitre_techniques": f.get("mitre_techniques", []),
            }
            for f in [finding.to_dict() for finding in report.key_findings]
        ]

    # Recommendations as extension
    if report.recommendations:
        report_sdo["x_gnat_recommendations"] = report.recommendations

    if report.linked_investigation:
        report_sdo["x_gnat_investigation_id"] = report.linked_investigation

    objects.insert(0, report_sdo)

    # ── Bundle ────────────────────────────────────────────────────────────────
    return {
        "type": "bundle",
        "id": f"bundle--{_uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }

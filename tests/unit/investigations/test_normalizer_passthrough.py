# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
Unit tests for cross-tool investigation property pass-through in the normalizer.

Verifies that the three custom STIX properties
(``x_gnat_investigation_id``, ``x_gnat_investigation_origin``,
``x_gnat_investigation_link_type``) survive the normalize step and are
correctly mapped to ``EvidenceNode`` metadata fields.
"""

from __future__ import annotations

import uuid

import pytest

from gnat.investigations.model import EvidenceNode, NodeType
from gnat.investigations.normalizer import normalize

# ---------------------------------------------------------------------------
# Fixture data
# ---------------------------------------------------------------------------

VALID_ORIGINS = ("gnat", "sandgnat", "sensegnat", "redgnat", "external")
VALID_LINK_TYPES = ("confirmed", "inferred", "suggested")


def _raw_xsoar_incident(
    *,
    investigation_id: str | None = None,
    investigation_origin: str | None = None,
    investigation_link_type: str | None = None,
) -> dict:
    """Build a minimal XSOAR incident record, optionally stamped with investigation props."""
    record: dict = {
        "id": str(uuid.uuid4()),
        "name": "Suspicious activity on 10.0.0.5",
        "occurred": "2026-04-20T12:00:00Z",
        "modified": "2026-04-20T14:00:00Z",
        "status": 2,
        "severity": 3,
        "owner": "analyst@example.com",
        "type": "Malware",
        "details": "Detected C2 beacon to 198.51.100.42",
        "CustomFields": {
            "src_hostname": "workstation-42",
            "src_user": "jdoe",
        },
        "labels": [
            {"type": "campaign", "value": "BLACKCAT"},
        ],
    }
    if investigation_id is not None:
        record["x_gnat_investigation_id"] = investigation_id
    if investigation_origin is not None:
        record["x_gnat_investigation_origin"] = investigation_origin
    if investigation_link_type is not None:
        record["x_gnat_investigation_link_type"] = investigation_link_type
    return record


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestNormalizerPassthrough:
    """Verify that custom investigation properties pass through normalize()."""

    def test_all_three_properties_set(self):
        """When all three x_gnat_investigation_* properties are present, the
        resulting EvidenceNode carries matching metadata fields."""
        inv_id = f"investigation--{uuid.uuid4()}"
        raw = _raw_xsoar_incident(
            investigation_id=inv_id,
            investigation_origin="sandgnat",
            investigation_link_type="confirmed",
        )

        node = normalize("xsoar", "incident", raw)

        assert node is not None
        assert isinstance(node, EvidenceNode)
        assert node.investigation_id == inv_id
        assert node.investigation_origin == "sandgnat"
        assert node.investigation_link_type == "confirmed"

    def test_defaults_when_properties_absent(self):
        """When the custom properties are NOT in the raw record, EvidenceNode
        has sensible defaults: investigation_id=None, investigation_origin=None,
        investigation_link_type=None, origin="gnat"."""
        raw = _raw_xsoar_incident()

        node = normalize("xsoar", "incident", raw)

        assert node is not None
        assert node.investigation_id is None
        assert node.investigation_origin is None
        assert node.investigation_link_type is None
        assert node.origin == "gnat"

    def test_origin_field_set_from_investigation_origin(self):
        """The top-level ``origin`` field on EvidenceNode is set from
        ``x_gnat_investigation_origin`` when that property is present."""
        raw = _raw_xsoar_incident(
            investigation_origin="sensegnat",
        )

        node = normalize("xsoar", "incident", raw)

        assert node is not None
        assert node.origin == "sensegnat"

    def test_origin_field_default_without_property(self):
        """Without x_gnat_investigation_origin, the ``origin`` field defaults
        to ``"gnat"``."""
        raw = _raw_xsoar_incident()

        node = normalize("xsoar", "incident", raw)

        assert node is not None
        assert node.origin == "gnat"

    @pytest.mark.parametrize("origin", VALID_ORIGINS)
    def test_all_valid_origins_accepted(self, origin: str):
        """Each of the five allowed origin values passes through correctly."""
        raw = _raw_xsoar_incident(investigation_origin=origin)

        node = normalize("xsoar", "incident", raw)

        assert node is not None
        assert node.investigation_origin == origin
        assert node.origin == origin

    @pytest.mark.parametrize("link_type", VALID_LINK_TYPES)
    def test_all_valid_link_types_accepted(self, link_type: str):
        """Each of the three allowed link_type values passes through correctly."""
        raw = _raw_xsoar_incident(investigation_link_type=link_type)

        node = normalize("xsoar", "incident", raw)

        assert node is not None
        assert node.investigation_link_type == link_type

    def test_partial_properties_only_id(self):
        """Setting only x_gnat_investigation_id — origin and link_type stay None."""
        inv_id = f"investigation--{uuid.uuid4()}"
        raw = _raw_xsoar_incident(investigation_id=inv_id)

        node = normalize("xsoar", "incident", raw)

        assert node is not None
        assert node.investigation_id == inv_id
        assert node.investigation_origin is None
        assert node.investigation_link_type is None
        assert node.origin == "gnat"

    def test_other_node_fields_unaffected(self):
        """Verify that adding investigation properties does not break the
        standard normalizer outputs (IOCs, hostnames, etc.)."""
        raw = _raw_xsoar_incident(
            investigation_id=f"investigation--{uuid.uuid4()}",
            investigation_origin="redgnat",
            investigation_link_type="inferred",
        )

        node = normalize("xsoar", "incident", raw)

        assert node is not None
        assert node.node_type == NodeType.INCIDENT
        assert node.platform == "xsoar"
        # Standard extraction should still work
        assert "198.51.100.42" in node.ioc_values
        assert "workstation-42" in node.hostnames
        assert "jdoe" in node.usernames
        assert "BLACKCAT" in node.campaign_labels

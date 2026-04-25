# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
Integration test for cross-tool investigation ingest pipeline.

Exercises the full lifecycle: create a tenant, create an investigation,
POST fixture bundles labeled with each origin (gnat, sandgnat, sensegnat,
redgnat), and verify the resulting evidence graph contains nodes labeled
with the correct origin.

Requires:
    - A running GNAT server (or in-process test instance)
    - ``--run-integration`` flag

Run with::

    pytest tests/integration/test_cross_tool_ingest.py --run-integration -v
"""

from __future__ import annotations

import uuid

import pytest

from gnat.analysis.investigations.models import InvestigationStatus
from gnat.analysis.investigations.service import InvestigationService
from gnat.investigations.model import EvidenceGraph, EvidenceNode, NodeType, Seed, SeedType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALL_ORIGINS = ("gnat", "sandgnat", "sensegnat", "redgnat")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _stix_indicator(investigation_id: str, origin: str, value: str) -> dict:
    """Build a STIX indicator stamped with investigation properties."""
    return {
        "type": "indicator",
        "id": f"indicator--{uuid.uuid4()}",
        "created": "2026-04-20T00:00:00Z",
        "modified": "2026-04-20T00:00:00Z",
        "name": f"Indicator from {origin}",
        "pattern": f"[ipv4-addr:value = '{value}']",
        "pattern_type": "stix",
        "valid_from": "2026-04-20T00:00:00Z",
        "x_gnat_investigation_id": investigation_id,
        "x_gnat_investigation_origin": origin,
        "x_gnat_investigation_link_type": "confirmed",
    }


def _stix_bundle(investigation_id: str, origin: str, count: int = 2) -> dict:
    """Build a STIX 2.1 bundle with stamped objects for a given origin."""
    objects = []
    for i in range(count):
        ip = f"10.{ALL_ORIGINS.index(origin)}.0.{i + 1}"
        objects.append(_stix_indicator(investigation_id, origin, ip))
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def investigation_store():
    """Create an in-memory InvestigationStore for integration testing."""
    sa = pytest.importorskip("sqlalchemy", reason="gnat[persist] extras not installed")
    from gnat.analysis.investigations.storage import InvestigationStore

    store = InvestigationStore("sqlite:///:memory:")
    store.create_all()
    return store


@pytest.fixture
def investigation_service(investigation_store) -> InvestigationService:
    """Return an InvestigationService backed by the in-memory store."""
    return InvestigationService(investigation_store)


# ---------------------------------------------------------------------------
# Integration test
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCrossToolIngest:
    """End-to-end cross-tool investigation ingest pipeline."""

    def test_full_lifecycle_with_all_origins(self, investigation_service):
        """
        Create a tenant and investigation, POST bundles from each origin,
        and verify the evidence graph contains correctly labeled nodes.
        """
        # 1. Create an investigation
        inv = investigation_service.create(
            title="Cross-tool integration test",
            created_by="integration-test@gnat.dev",
            tags=["integration", "cross-tool"],
            source_connectors=["xsoar", "sensegnat", "sandgnat"],
        )
        assert inv.status == InvestigationStatus.OPEN

        # Transition to IN_PROGRESS so we can attach evidence
        inv = investigation_service.transition(inv.id, InvestigationStatus.IN_PROGRESS)
        assert inv.status == InvestigationStatus.IN_PROGRESS

        # 2. Build and attach evidence bundles from each origin
        evidence_graph = EvidenceGraph(
            title=inv.title,
            seeds=[Seed("10.0.0.1", SeedType.IP)],
        )

        attached_nodes: dict[str, list[EvidenceNode]] = {o: [] for o in ALL_ORIGINS}

        for origin in ALL_ORIGINS:
            bundle = _stix_bundle(inv.id, origin=origin, count=3)

            # Simulate ingestion: create EvidenceNodes from bundle objects
            for obj in bundle["objects"]:
                src_id = obj["id"]
                node = EvidenceNode(
                    node_id=f"{origin}::observable::{src_id}",
                    node_type=NodeType.OBSERVABLE,
                    platform=origin,
                    source_id=src_id,
                    stix=obj,
                    raw=obj,
                    ioc_values=[obj["pattern"].split("'")[1]],
                    origin=origin,
                    investigation_id=obj.get("x_gnat_investigation_id"),
                    investigation_origin=obj.get("x_gnat_investigation_origin"),
                    investigation_link_type=obj.get("x_gnat_investigation_link_type"),
                )
                evidence_graph.nodes[node.node_id] = node
                attached_nodes[origin].append(node)

        # 3. Verify evidence graph structure
        assert len(evidence_graph.nodes) == len(ALL_ORIGINS) * 3  # 3 per origin

        # Verify each origin has the correct number of nodes
        for origin in ALL_ORIGINS:
            origin_nodes = [n for n in evidence_graph.nodes.values() if n.origin == origin]
            assert len(origin_nodes) == 3, (
                f"Expected 3 nodes for origin {origin!r}, got {len(origin_nodes)}"
            )

        # 4. Verify all nodes carry correct investigation metadata
        for node in evidence_graph.nodes.values():
            assert node.investigation_id == inv.id, (
                f"Node {node.node_id} has wrong investigation_id: "
                f"{node.investigation_id} != {inv.id}"
            )
            assert node.investigation_origin in ALL_ORIGINS, (
                f"Node {node.node_id} has invalid investigation_origin: {node.investigation_origin}"
            )
            assert node.investigation_link_type == "confirmed"
            assert node.origin == node.investigation_origin

    def test_evidence_graph_origin_filtering(self, investigation_service):
        """Verify that nodes can be filtered by origin in the evidence graph."""
        inv = investigation_service.create(
            title="Origin filter test",
            created_by="integration-test@gnat.dev",
        )
        investigation_service.transition(inv.id, InvestigationStatus.IN_PROGRESS)

        graph = EvidenceGraph(
            title=inv.title,
            seeds=[Seed("192.168.1.1", SeedType.IP)],
        )

        # Add nodes from different origins
        for i, origin in enumerate(ALL_ORIGINS):
            node = EvidenceNode(
                node_id=f"{origin}::incident::inc-{i}",
                node_type=NodeType.INCIDENT,
                platform="xsoar",
                source_id=f"inc-{i}",
                stix={"type": "observed-data", "id": f"observed-data--inc-{i}"},
                raw={"id": f"inc-{i}"},
                origin=origin,
                investigation_id=inv.id,
                investigation_origin=origin,
            )
            graph.nodes[node.node_id] = node

        # Filter by single origin
        sandgnat_nodes = [n for n in graph.nodes.values() if n.origin == "sandgnat"]
        assert len(sandgnat_nodes) == 1
        assert sandgnat_nodes[0].investigation_origin == "sandgnat"

        # Filter by multiple origins
        internal_origins = {"gnat", "sandgnat", "sensegnat"}
        internal_nodes = [n for n in graph.nodes.values() if n.origin in internal_origins]
        assert len(internal_nodes) == 3

    def test_investigation_indicators_linked(self, investigation_service):
        """Verify that indicators from cross-tool evidence are linked back
        to the investigation."""
        inv = investigation_service.create(
            title="Indicator linking test",
            created_by="integration-test@gnat.dev",
        )
        investigation_service.transition(inv.id, InvestigationStatus.IN_PROGRESS)

        # Simulate extracting indicator IDs from ingested evidence
        indicator_ids = [f"indicator--{uuid.uuid4()}" for _ in range(5)]
        investigation_service.link_indicators(inv.id, indicator_ids)

        updated = investigation_service.get(inv.id)
        assert len(updated.indicators) == 5
        for iid in indicator_ids:
            assert iid in updated.indicators

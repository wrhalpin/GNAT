# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for investigations evidence graph schemas — round-trip from domain dataclasses."""

from __future__ import annotations

from gnat.investigations.model import (
    EvidenceEdge,
    EvidenceGraph,
    EvidenceNode,
    NodeType,
    Seed,
    SeedType,
)
from gnat.schemas.investigations.graph import (
    EvidenceEdgeSchema,
    EvidenceGraphSchema,
    EvidenceNodeSchema,
)
from gnat.schemas.investigations.seed import SeedSchema


class TestSeedSchema:
    def test_round_trip(self) -> None:
        domain = Seed(
            value="185.220.101.0",
            seed_type=SeedType.IP,
            hint_platform="xsoar",
        )
        schema = SeedSchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["value"] == "185.220.101.0"
        assert dumped["seed_type"] == "ip"
        assert dumped["hint_platform"] == "xsoar"

    def test_no_hint(self) -> None:
        domain = Seed(value="INC-4892", seed_type=SeedType.CASE_ID)
        schema = SeedSchema.from_domain(domain)
        assert schema.hint_platform is None

    def test_all_seed_types(self) -> None:
        for st in SeedType:
            domain = Seed(value="test", seed_type=st)
            schema = SeedSchema.from_domain(domain)
            assert schema.seed_type == st.value


class TestEvidenceNodeSchema:
    def test_round_trip(self) -> None:
        domain = EvidenceNode(
            node_id="xsoar::incident::INC-001",
            node_type=NodeType.INCIDENT,
            platform="xsoar",
            source_id="INC-001",
            stix={"type": "incident", "name": "Test"},
            raw={"id": "INC-001", "status": "active"},
            ioc_values=["185.220.101.5"],
            hostnames=["srv-dc01"],
            usernames=["admin"],
            campaign_labels=["BLACKCAT"],
            ticket_refs=["JIRA-123"],
            infrastructure_roles=["c2"],
            time_window=("2026-04-01T00:00:00Z", "2026-04-02T00:00:00Z"),
            origin="gnat",
            investigation_id="inv-001",
            investigation_origin="sandgnat",
            investigation_link_type="confirmed",
        )
        schema = EvidenceNodeSchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["node_id"] == "xsoar::incident::INC-001"
        assert dumped["node_type"] == "incident"
        assert dumped["platform"] == "xsoar"
        assert dumped["source_id"] == "INC-001"
        assert dumped["stix"] == {"type": "incident", "name": "Test"}
        assert dumped["raw"] == {"id": "INC-001", "status": "active"}
        assert dumped["ioc_values"] == ["185.220.101.5"]
        assert dumped["hostnames"] == ["srv-dc01"]
        assert dumped["usernames"] == ["admin"]
        assert dumped["campaign_labels"] == ["BLACKCAT"]
        assert dumped["ticket_refs"] == ["JIRA-123"]
        assert dumped["infrastructure_roles"] == ["c2"]
        assert dumped["time_window"] == ("2026-04-01T00:00:00Z", "2026-04-02T00:00:00Z")
        assert dumped["origin"] == "gnat"
        assert dumped["investigation_id"] == "inv-001"
        assert dumped["investigation_origin"] == "sandgnat"
        assert dumped["investigation_link_type"] == "confirmed"

    def test_minimal(self) -> None:
        domain = EvidenceNode(
            node_id="tq::obs::1",
            node_type=NodeType.OBSERVABLE,
            platform="threatq",
            source_id="1",
            stix={},
            raw={},
        )
        schema = EvidenceNodeSchema.from_domain(domain)
        assert schema.ioc_values == []
        assert schema.time_window is None
        assert schema.origin == "gnat"
        assert schema.investigation_id is None


class TestEvidenceEdgeSchema:
    def test_round_trip(self) -> None:
        domain = EvidenceEdge(
            source_id="xsoar::incident::1",
            target_id="tq::obs::2",
            relationship_type="same-ioc",
            confidence=0.9,
            source_platform="gnat",
            reasoning="Shared IOC: 185.220.101.5",
            link_type="inferred",
        )
        schema = EvidenceEdgeSchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["source_id"] == "xsoar::incident::1"
        assert dumped["target_id"] == "tq::obs::2"
        assert dumped["relationship_type"] == "same-ioc"
        assert dumped["confidence"] == 0.9
        assert dumped["reasoning"] == "Shared IOC: 185.220.101.5"
        assert dumped["link_type"] == "inferred"

    def test_defaults(self) -> None:
        domain = EvidenceEdge(
            source_id="a",
            target_id="b",
            relationship_type="related-to",
        )
        schema = EvidenceEdgeSchema.from_domain(domain)
        assert schema.confidence == 1.0
        assert schema.source_platform == ""
        assert schema.reasoning == ""
        assert schema.link_type == "inferred"


class TestEvidenceGraphSchema:
    def test_round_trip(self) -> None:
        seed = Seed(value="185.220.101.0", seed_type=SeedType.IP)
        node = EvidenceNode(
            node_id="xsoar::obs::1",
            node_type=NodeType.OBSERVABLE,
            platform="xsoar",
            source_id="1",
            stix={"type": "indicator"},
            raw={},
            ioc_values=["185.220.101.0"],
        )
        edge = EvidenceEdge(
            source_id="xsoar::obs::1",
            target_id="xsoar::obs::2",
            relationship_type="same-ioc",
        )
        domain = EvidenceGraph(
            title="Test Investigation",
            seeds=[seed],
            nodes={"xsoar::obs::1": node},
            edges=[edge],
            by_ioc={"185.220.101.0": ["xsoar::obs::1"]},
        )

        schema = EvidenceGraphSchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["title"] == "Test Investigation"
        assert len(dumped["seeds"]) == 1
        assert dumped["seeds"][0]["value"] == "185.220.101.0"
        assert "xsoar::obs::1" in dumped["nodes"]
        assert len(dumped["edges"]) == 1
        assert dumped["by_ioc"] == {"185.220.101.0": ["xsoar::obs::1"]}

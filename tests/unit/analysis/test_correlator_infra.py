# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/analysis/test_correlator_infra.py
===============================================

Unit tests for infrastructure classification integration in the
evidence graph correlator.
"""

from __future__ import annotations

from typing import Any

from gnat.investigations.correlator import classify_infrastructure, correlate
from gnat.investigations.model import (
    EvidenceGraph,
    EvidenceNode,
    NodeType,
    Seed,
    SeedType,
)


def _observable(
    node_id: str,
    ioc_values: list[str] | None = None,
    stix: dict[str, Any] | None = None,
    platform: str = "splunk",
) -> EvidenceNode:
    return EvidenceNode(
        node_id=node_id,
        node_type=NodeType.OBSERVABLE,
        platform=platform,
        source_id=node_id,
        stix=stix or {"type": "indicator"},
        raw={},
        ioc_values=ioc_values or [],
    )


def _incident(node_id: str, platform: str = "xsoar") -> EvidenceNode:
    return EvidenceNode(
        node_id=node_id,
        node_type=NodeType.INCIDENT,
        platform=platform,
        source_id=node_id,
        stix={"type": "incident"},
        raw={},
    )


def _graph(*nodes: EvidenceNode) -> EvidenceGraph:
    return EvidenceGraph(
        title="test",
        seeds=[Seed(value="test", seed_type=SeedType.IOC_VALUE)],
        nodes={n.node_id: n for n in nodes},
    )


class TestClassifyInfrastructure:
    def test_classify_observable_c2_by_ports(self):
        node = _observable(
            "n1",
            ioc_values=["192.168.1.1"],
            stix={"type": "indicator", "x_gnat_ports": [443, 8443]},
        )
        graph = _graph(node)
        classify_infrastructure(graph)
        assert "c2" in node.infrastructure_roles

    def test_classify_observable_delivery_by_killchain(self):
        node = _observable(
            "n1",
            ioc_values=["evil.com"],
            stix={
                "type": "indicator",
                "kill_chain_phases": [{"phase_name": "TA0001"}],
            },
        )
        graph = _graph(node)
        classify_infrastructure(graph)
        assert "delivery" in node.infrastructure_roles

    def test_classify_observable_c2_by_infra_type(self):
        node = _observable(
            "n1",
            ioc_values=["10.0.0.1"],
            stix={
                "type": "indicator",
                "x_gnat_infrastructure_types": ["command-and-control"],
            },
        )
        graph = _graph(node)
        classify_infrastructure(graph)
        assert "c2" in node.infrastructure_roles

    def test_classify_observable_exfil_by_killchain(self):
        node = _observable(
            "n1",
            ioc_values=["exfil.example.com"],
            stix={
                "type": "indicator",
                "kill_chain_phases": [{"phase_name": "TA0010"}],
            },
        )
        graph = _graph(node)
        classify_infrastructure(graph)
        assert "exfiltration" in node.infrastructure_roles

    def test_classify_skips_non_observable(self):
        node = _incident("inc-1")
        graph = _graph(node)
        classify_infrastructure(graph)
        assert node.infrastructure_roles == []

    def test_classify_skips_no_ioc(self):
        node = _observable("n1", ioc_values=[])
        graph = _graph(node)
        classify_infrastructure(graph)
        assert node.infrastructure_roles == []

    def test_classify_unknown_not_added(self):
        node = _observable(
            "n1",
            ioc_values=["1.2.3.4"],
            stix={"type": "indicator"},
        )
        graph = _graph(node)
        classify_infrastructure(graph)
        assert "unknown" not in node.infrastructure_roles

    def test_by_infra_role_index_populated(self):
        n1 = _observable(
            "n1",
            ioc_values=["1.2.3.4"],
            stix={"type": "indicator", "x_gnat_ports": [443]},
        )
        n2 = _observable(
            "n2",
            ioc_values=["evil.com"],
            stix={
                "type": "indicator",
                "kill_chain_phases": [{"phase_name": "TA0001"}],
            },
        )
        graph = _graph(n1, n2)
        classify_infrastructure(graph)
        assert "c2" in graph.by_infra_role
        assert "n1" in graph.by_infra_role["c2"]
        assert "delivery" in graph.by_infra_role
        assert "n2" in graph.by_infra_role["delivery"]

    def test_classify_deduplicates_roles(self):
        node = _observable(
            "n1",
            ioc_values=["10.0.0.1"],
            stix={"type": "indicator", "x_gnat_ports": [443]},
        )
        graph = _graph(node)
        classify_infrastructure(graph)
        classify_infrastructure(graph)
        assert node.infrastructure_roles.count("c2") == 1

    def test_correlate_populates_infra_index(self):
        n1 = _observable(
            "n1",
            ioc_values=["shared-ioc"],
            stix={"type": "indicator", "x_gnat_ports": [8080]},
            platform="splunk",
        )
        n2 = _observable(
            "n2",
            ioc_values=["shared-ioc"],
            stix={"type": "indicator"},
            platform="sentinel",
        )
        graph = _graph(n1, n2)
        correlate(graph)
        assert "c2" in graph.by_infra_role
        assert "n1" in graph.by_infra_role["c2"]


class TestEvidenceGraphSummaryInfra:
    def test_summary_includes_infrastructure_roles(self):
        node = _observable(
            "n1",
            ioc_values=["1.2.3.4"],
            stix={"type": "indicator", "x_gnat_ports": [443]},
        )
        graph = _graph(node)
        classify_infrastructure(graph)
        s = graph.summary()
        assert "infrastructure_roles" in s
        assert s["infrastructure_roles"]["c2"] == 1

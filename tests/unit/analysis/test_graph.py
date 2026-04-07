"""
Unit tests for gnat.analysis.graph (GraphQuery / GraphContext)
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

from gnat.analysis.graph import GraphContext, GraphQuery


def _dt(days_ago: int = 0) -> datetime:
    return datetime.now(tz=timezone.utc) - timedelta(days=days_ago)


def _node(node_id: str, node_type: str = "indicator", platform: str = "p1",
          confidence: float = 80.0, observed_at: datetime | None = None) -> MagicMock:
    n = MagicMock()
    n.id           = node_id
    n.node_type    = node_type
    n.label        = node_id
    n.platforms    = {platform}
    n.confidence   = confidence
    n.observed_at  = observed_at or _dt(5)
    n.stix_object  = {"id": node_id, "type": "indicator"}
    # Set time_window and stix to None to avoid MagicMock auto-attribute interference
    ts_iso = (observed_at or _dt(5)).isoformat()
    n.time_window  = (ts_iso, ts_iso)
    n.stix         = {"first_observed": ts_iso}
    return n


def _edge(source: str, target: str, rel_type: str = "related-to",
          confidence: float = 70.0) -> MagicMock:
    e = MagicMock()
    e.source_id    = source
    e.target_id    = target
    e.relationship = rel_type
    e.confidence   = confidence
    e.platforms    = {"p1"}
    return e


def _make_graph(*node_ids, edges: list | None = None):
    g = MagicMock()
    g.nodes = {nid: _node(nid) for nid in node_ids}
    g.edges = edges or []
    return g


class TestGraphQuery:
    def test_pivot_returns_seed_node(self):
        g = _make_graph("n1", "n2", "n3")
        q = GraphQuery(g)
        ctx = q.pivot("n1", hops=0)
        assert "n1" in ctx.nodes

    def test_pivot_one_hop_includes_neighbors(self):
        e = _edge("n1", "n2")
        g = _make_graph("n1", "n2", "n3", edges=[e])
        q = GraphQuery(g)
        ctx = q.pivot("n1", hops=1)
        assert "n1" in ctx.nodes
        assert "n2" in ctx.nodes
        assert "n3" not in ctx.nodes

    def test_pivot_two_hops_reaches_further(self):
        e1 = _edge("n1", "n2")
        e2 = _edge("n2", "n3")
        g  = _make_graph("n1", "n2", "n3", edges=[e1, e2])
        q  = GraphQuery(g)
        ctx = q.pivot("n1", hops=2)
        assert "n3" in ctx.nodes

    def test_pivot_unknown_seed_raises(self):
        g = _make_graph("n1")
        q = GraphQuery(g)
        with pytest.raises(KeyError):
            q.pivot("does-not-exist", hops=1)

    def test_expand_adds_neighbors(self):
        e = _edge("n1", "n2")
        g = _make_graph("n1", "n2", "n3", edges=[e])
        q  = GraphQuery(g)
        ctx = q.pivot("n1", hops=0)
        ctx = q.expand(ctx, ["n1"])
        assert "n2" in ctx.nodes

    def test_filter_by_min_confidence(self):
        g      = _make_graph("n1", "n2", "n3")
        g.nodes["n1"].confidence = 90.0
        g.nodes["n2"].confidence = 30.0
        g.nodes["n3"].confidence = 70.0
        ctx = GraphContext(
            nodes    = g.nodes,
            edges    = [],
            seed_ids = ["n1"],
        )
        q   = GraphQuery(g)
        filtered = q.filter(ctx, min_confidence=70.0)
        assert "n1" in filtered.nodes
        assert "n3" in filtered.nodes
        assert "n2" not in filtered.nodes

    def test_filter_by_platform(self):
        g = _make_graph("n1", "n2")
        g.nodes["n1"].platforms = {"xsoar"}
        g.nodes["n2"].platforms = {"threatq"}
        ctx = GraphContext(nodes=g.nodes, edges=[], seed_ids=["n1"])
        q   = GraphQuery(g)
        filtered = q.filter(ctx, platforms={"xsoar"})
        assert "n1" in filtered.nodes
        assert "n2" not in filtered.nodes

    def test_filter_by_node_types(self):
        g = _make_graph("n1", "n2")
        g.nodes["n1"].node_type = "indicator"
        g.nodes["n2"].node_type = "threat-actor"
        ctx = GraphContext(nodes=g.nodes, edges=[], seed_ids=[])
        q   = GraphQuery(g)
        filtered = q.filter(ctx, node_types={"indicator"})
        assert "n1" in filtered.nodes
        assert "n2" not in filtered.nodes

    def test_shortest_path_direct_edge(self):
        e = _edge("n1", "n2")
        g = _make_graph("n1", "n2", edges=[e])
        q = GraphQuery(g)
        path = q.shortest_path("n1", "n2")
        assert path == ["n1", "n2"]

    def test_shortest_path_two_hops(self):
        e1 = _edge("n1", "n2")
        e2 = _edge("n2", "n3")
        g  = _make_graph("n1", "n2", "n3", edges=[e1, e2])
        q  = GraphQuery(g)
        path = q.shortest_path("n1", "n3")
        assert path is not None
        assert path[0] == "n1"
        assert path[-1] == "n3"

    def test_shortest_path_no_connection(self):
        g = _make_graph("n1", "n2")  # no edges
        q = GraphQuery(g)
        path = q.shortest_path("n1", "n2")
        assert path is None

    def test_shortest_path_same_node(self):
        g = _make_graph("n1")
        q = GraphQuery(g)
        path = q.shortest_path("n1", "n1")
        assert path == ["n1"]

    def test_graph_context_to_dict(self):
        ctx = GraphContext(
            nodes    = {"n1": _node("n1")},
            edges    = [_edge("n1", "n2")],
            seed_ids = ["n1"],
        )
        d = ctx.to_dict()
        assert "nodes" in d
        assert "edges" in d
        assert d["node_count"] == 1

    def test_graph_context_platforms(self):
        g = _make_graph("n1", "n2")
        g.nodes["n1"].platforms = {"xsoar", "tq"}
        g.nodes["n2"].platforms = {"tq"}
        ctx = GraphContext(nodes=g.nodes, edges=[], seed_ids=[])
        assert ctx.platforms() == {"xsoar", "tq"}

    def test_filter_by_date_from(self):
        g = _make_graph("n1", "n2")
        # Override time_window to control timestamps for filtering
        g.nodes["n1"].time_window = (_dt(1).isoformat(), _dt(1).isoformat())
        g.nodes["n2"].time_window = (_dt(30).isoformat(), _dt(30).isoformat())
        g.nodes["n1"].stix = None
        g.nodes["n2"].stix = None
        ctx = GraphContext(nodes=g.nodes, edges=[], seed_ids=[])
        q   = GraphQuery(g)
        filtered = q.filter(ctx, date_from=_dt(7))
        assert "n1" in filtered.nodes
        assert "n2" not in filtered.nodes

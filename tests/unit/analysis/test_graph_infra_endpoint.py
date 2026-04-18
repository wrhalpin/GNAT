# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/analysis/test_graph_infra_endpoint.py
====================================================

Unit tests for the /api/graph/infrastructure endpoint.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

fastapi = pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from gnat.serve.routers.analysis import router  # noqa: E402


def _build_app(graph_query=None):
    app = fastapi.FastAPI()
    app.include_router(router)
    if graph_query is not None:
        app.state.graph_query = graph_query
    return app


class TestGraphInfrastructureEndpoint:
    def test_returns_role_summary(self):
        gq = MagicMock()
        gq._graph.by_infra_role = {
            "c2": ["n1", "n3"],
            "delivery": ["n2"],
        }
        app = _build_app(graph_query=gq)
        client = TestClient(app)
        resp = client.post("/api/graph/infrastructure", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert data["counts"]["c2"] == 2
        assert data["counts"]["delivery"] == 1
        assert "n1" in data["roles"]["c2"]
        assert "n3" in data["roles"]["c2"]

    def test_empty_infra_index(self):
        gq = MagicMock()
        gq._graph.by_infra_role = {}
        app = _build_app(graph_query=gq)
        client = TestClient(app)
        resp = client.post("/api/graph/infrastructure", json={})
        assert resp.status_code == 200
        assert resp.json()["roles"] == {}
        assert resp.json()["counts"] == {}

    def test_503_without_graph_query(self):
        app = _build_app(graph_query=None)
        client = TestClient(app)
        resp = client.post("/api/graph/infrastructure", json={})
        assert resp.status_code == 503

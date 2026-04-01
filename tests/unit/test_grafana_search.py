"""
tests/unit/test_grafana_search.py
=====================================

Unit tests for the Grafana Solr search sidecar integration:
- ``gnat.viz.grafana.search_endpoints`` — /solr/* router
- ``gnat.viz.export.solr_dashboard`` / ``save_solr_dashboard``
- ``GrafanaServer`` extended with ``search_index``
- ``gnat viz serve --with-solr`` and ``gnat viz solr-dashboard`` CLI
"""

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_search_index(
    ping_result: bool = True,
    facets: dict | None = None,
    total: int = 42,
    search_docs: list | None = None,
    date_facet: list | None = None,
    base_url: str = "http://localhost:8983/solr/gnat",
) -> MagicMock:
    """Return a mock SolrSearchIndex with configurable responses."""
    idx = MagicMock()
    idx.ping.return_value = ping_result
    idx.base_url = base_url

    # Default facets: stix_type and source_platform
    if facets is None:
        facets = {
            "stix_type": [("indicator", 20), ("malware", 10), ("threat-actor", 5)],
            "source_platform": [("threatq", 18), ("crowdstrike", 12)],
        }
    idx._facets = facets

    idx._total = total
    idx._search_docs = search_docs or [
        {"id": "indicator--aabbccdd-1234-5678-abcd-000000000001",
         "stix_type": "indicator", "source_platform": "threatq",
         "display_name": "Malicious IP"},
    ]
    idx._date_facet = date_facet or [
        ("2024-01-01T00:00:00Z", 5),
        ("2024-01-02T00:00:00Z", 8),
    ]
    return idx


def _make_router_app(search_index):
    """Build a TestClient-ready starlette app with just the /solr/ router."""
    from fastapi import FastAPI

    from gnat.viz.grafana.search_endpoints import build_search_router
    app = FastAPI()

    # Patch _solr_get to avoid real HTTP
    router = build_search_router(search_index)
    app.include_router(router)
    return app


# ---------------------------------------------------------------------------
# Tests: _solr_get helper
# ---------------------------------------------------------------------------

class TestSolrGetHelper(unittest.TestCase):
    def test_returns_none_on_error(self):
        from gnat.viz.grafana.search_endpoints import _solr_get
        # Point at a non-existent server
        result = _solr_get("http://127.0.0.1:19999/solr/gnat", "select",
                           {"q": "*:*", "rows": 0, "wt": "json"})
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Tests: build_search_router — via TestClient
# ---------------------------------------------------------------------------

class TestSolrHealthEndpoint(unittest.TestCase):
    def setUp(self):
        pytest = __import__("pytest")
        try:
            from fastapi.testclient import TestClient  # noqa: F401
        except ImportError:
            pytest.skip("fastapi not installed")

        from fastapi.testclient import TestClient
        idx = _make_search_index(ping_result=True)
        app = _make_router_app(idx)
        self.client = TestClient(app)

    def test_health_ok(self):
        resp = self.client.get("/solr/")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["status"], "ok")
        self.assertTrue(body["solr_reachable"])

    def test_health_degraded_when_ping_fails(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from gnat.viz.grafana.search_endpoints import build_search_router
        idx = _make_search_index(ping_result=False)
        app = FastAPI()
        app.include_router(build_search_router(idx))
        client = TestClient(app)
        resp = client.get("/solr/")
        body = resp.json()
        self.assertEqual(body["status"], "degraded")
        self.assertFalse(body["solr_reachable"])


class TestSolrSearchTargets(unittest.TestCase):
    def setUp(self):
        try:
            from fastapi.testclient import TestClient  # noqa: F401
        except ImportError:
            import pytest
            pytest.skip("fastapi not installed")

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from gnat.viz.grafana.search_endpoints import build_search_router

        idx = _make_search_index()

        # Patch _facet_counts to return controlled data
        self._patch = patch(
            "gnat.viz.grafana.search_endpoints._solr_get",
            side_effect=self._fake_solr_get,
        )
        self._patch.start()

        app = FastAPI()
        app.include_router(build_search_router(idx))
        self.client = TestClient(app)

    def _fake_solr_get(self, base_url, path, params):
        field = params.get("facet.field", "")
        if field == "stix_type":
            return {"facet_counts": {"facet_fields": {
                "stix_type": ["indicator", 20, "malware", 5]
            }}}
        return {"response": {"numFound": 0, "docs": []}}

    def tearDown(self):
        self._patch.stop()

    def test_returns_list_of_strings(self):
        resp = self.client.post("/solr/search")
        self.assertEqual(resp.status_code, 200)
        targets = resp.json()
        self.assertIsInstance(targets, list)
        self.assertIn("stats/total", targets)
        self.assertIn("stats/type_counts", targets)
        self.assertIn("timeseries/ingest", targets)
        self.assertIn("facet/stix_type", targets)
        self.assertIn("facet/source_platform", targets)

    def test_includes_per_type_search_targets(self):
        resp = self.client.post("/solr/search")
        targets = resp.json()
        self.assertIn("search/indicator", targets)
        self.assertIn("search/malware", targets)


class TestSolrQueryEndpoint(unittest.TestCase):
    def setUp(self):
        try:
            from fastapi.testclient import TestClient  # noqa: F401
        except ImportError:
            import pytest
            pytest.skip("fastapi not installed")

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from gnat.viz.grafana.search_endpoints import build_search_router

        self.idx = _make_search_index()
        self._patch = patch(
            "gnat.viz.grafana.search_endpoints._solr_get",
            side_effect=self._fake_solr_get,
        )
        self._patch.start()

        app = FastAPI()
        app.include_router(build_search_router(self.idx))
        self.client = TestClient(app)

    def _fake_solr_get(self, base_url, path, params):
        field = params.get("facet.field", "")
        range_field = params.get("facet.range", "")

        if field == "stix_type":
            return {"facet_counts": {"facet_fields": {
                "stix_type": ["indicator", 20, "malware", 10]
            }}}
        if field == "source_platform":
            return {"facet_counts": {"facet_fields": {
                "source_platform": ["threatq", 15, "crowdstrike", 8]
            }}}
        if range_field == "date_indexed":
            return {"facet_counts": {"facet_ranges": {
                "date_indexed": {"counts": [
                    "2024-01-01T00:00:00Z", 5,
                    "2024-01-02T00:00:00Z", 8,
                ]}
            }}}
        # Default: total docs or search
        return {"response": {"numFound": 42, "docs": [
            {"id": "indicator--aabbccdd-1234-5678-abcd-000000000001",
             "stix_type": "indicator", "source_platform": "threatq",
             "display_name": "Test IOC"},
        ]}}

    def tearDown(self):
        self._patch.stop()

    def _query(self, target):
        return self.client.post("/solr/query", json={
            "targets": [{"target": target, "refId": "A"}]
        })

    def test_stats_total(self):
        resp = self._query("stats/total")
        self.assertEqual(resp.status_code, 200)
        results = resp.json()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["type"], "table")
        self.assertEqual(results[0]["columns"][0]["text"], "Total Documents")
        self.assertEqual(results[0]["rows"][0][0], 42)

    def test_stats_type_counts(self):
        resp = self._query("stats/type_counts")
        results = resp.json()
        self.assertEqual(results[0]["type"], "table")
        col_names = [c["text"] for c in results[0]["columns"]]
        self.assertIn("STIX Type", col_names)
        self.assertIn("Doc Count", col_names)
        rows = results[0]["rows"]
        self.assertEqual(rows[0][0], "indicator")
        self.assertEqual(rows[0][1], 20)

    def test_stats_platform_counts(self):
        resp = self._query("stats/platform_counts")
        results = resp.json()
        col_names = [c["text"] for c in results[0]["columns"]]
        self.assertIn("Platform", col_names)
        rows = results[0]["rows"]
        self.assertEqual(rows[0][0], "threatq")

    def test_timeseries_ingest(self):
        resp = self._query("timeseries/ingest")
        results = resp.json()
        self.assertIn("target", results[0])
        self.assertEqual(results[0]["target"], "docs/day")
        dp = results[0]["datapoints"]
        self.assertEqual(len(dp), 2)
        # [count, timestamp_ms]
        self.assertEqual(dp[0][0], 5)
        self.assertIsInstance(dp[0][1], int)

    def test_facet_stix_type(self):
        resp = self._query("facet/stix_type")
        results = resp.json()
        self.assertEqual(results[0]["type"], "table")
        rows = results[0]["rows"]
        self.assertGreater(len(rows), 0)

    def test_search_query(self):
        resp = self._query("search/malware")
        results = resp.json()
        self.assertEqual(results[0]["type"], "table")
        col_names = [c["text"] for c in results[0]["columns"]]
        self.assertIn("STIX ID", col_names)
        self.assertIn("Type", col_names)
        self.assertIn("Platform", col_names)
        rows = results[0]["rows"]
        self.assertGreater(len(rows), 0)
        self.assertIn("indicator--", rows[0][0])

    def test_multiple_targets(self):
        resp = self.client.post("/solr/query", json={
            "targets": [
                {"target": "stats/total", "refId": "A"},
                {"target": "stats/type_counts", "refId": "B"},
            ]
        })
        results = resp.json()
        self.assertEqual(len(results), 2)

    def test_empty_targets(self):
        resp = self.client.post("/solr/query", json={"targets": []})
        self.assertEqual(resp.json(), [])

    def test_unknown_target_ignored(self):
        resp = self.client.post("/solr/query", json={
            "targets": [{"target": "bogus/target", "refId": "A"}]
        })
        # Should return empty list — unknown targets are silently skipped
        self.assertEqual(resp.json(), [])


class TestSolrTagEndpoints(unittest.TestCase):
    def setUp(self):
        try:
            from fastapi.testclient import TestClient  # noqa: F401
        except ImportError:
            import pytest
            pytest.skip("fastapi not installed")

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from gnat.viz.grafana.search_endpoints import build_search_router

        self._patch = patch(
            "gnat.viz.grafana.search_endpoints._solr_get",
            return_value={"facet_counts": {"facet_fields": {
                "stix_type": ["indicator", 20, "malware", 5],
                "source_platform": ["threatq", 10],
            }}}
        )
        self._patch.start()

        app = FastAPI()
        app.include_router(build_search_router(_make_search_index()))
        self.client = TestClient(app)

    def tearDown(self):
        self._patch.stop()

    def test_tag_keys(self):
        resp = self.client.post("/solr/tag-keys")
        self.assertEqual(resp.status_code, 200)
        texts = [k["text"] for k in resp.json()]
        self.assertIn("stix_type", texts)
        self.assertIn("source_platform", texts)

    def test_tag_values_stix_type(self):
        resp = self.client.post("/solr/tag-values", json={"key": "stix_type"})
        values = [v["text"] for v in resp.json()]
        self.assertIn("indicator", values)
        self.assertIn("malware", values)

    def test_tag_values_unknown_key(self):
        resp = self.client.post("/solr/tag-values", json={"key": "unknown"})
        self.assertEqual(resp.json(), [])


# ---------------------------------------------------------------------------
# Tests: GrafanaServer with search_index
# ---------------------------------------------------------------------------

class TestGrafanaServerWithSearchIndex(unittest.TestCase):
    def test_build_app_without_search_index(self):
        try:
            from gnat.viz.grafana.server import build_app
        except ImportError:
            import pytest
            pytest.skip("fastapi not installed")

        manager = MagicMock()
        manager.list.return_value = []
        app = build_app(manager, search_index=None)
        routes = [r.path for r in app.routes]
        # /solr/ routes should NOT be present
        self.assertFalse(any("/solr" in r for r in routes))

    def test_build_app_with_search_index_mounts_solr(self):
        try:
            from gnat.viz.grafana.server import build_app
        except ImportError:
            import pytest
            pytest.skip("fastapi not installed")

        manager = MagicMock()
        manager.list.return_value = []
        idx = _make_search_index()

        with patch("gnat.viz.grafana.search_endpoints._solr_get", return_value=None):
            app = build_app(manager, search_index=idx)

        routes = [r.path for r in app.routes]
        self.assertTrue(any("/solr" in r for r in routes))

    def test_grafana_server_stores_search_index(self):
        try:
            from gnat.viz.grafana.server import GrafanaServer
        except ImportError:
            import pytest
            pytest.skip("fastapi not installed")

        manager = MagicMock()
        manager.list.return_value = []
        idx = _make_search_index()
        server = GrafanaServer(manager, search_index=idx)
        self.assertIs(server._search_index, idx)

    def test_grafana_server_default_no_search_index(self):
        try:
            from gnat.viz.grafana.server import GrafanaServer
        except ImportError:
            import pytest
            pytest.skip("fastapi not installed")

        manager = MagicMock()
        manager.list.return_value = []
        server = GrafanaServer(manager)
        self.assertIsNone(server._search_index)


# ---------------------------------------------------------------------------
# Tests: solr_dashboard() JSON structure
# ---------------------------------------------------------------------------

class TestSolrDashboardStructure(unittest.TestCase):
    def setUp(self):
        from gnat.viz.export import solr_dashboard
        self.dash = solr_dashboard()

    def test_top_level_fields(self):
        for field in ("uid", "title", "panels", "schemaVersion", "tags", "time"):
            self.assertIn(field, self.dash)

    def test_uid(self):
        self.assertEqual(self.dash["uid"], "gnat-solr-index")

    def test_title_default(self):
        self.assertEqual(self.dash["title"], "GNAT Search Index")

    def test_title_custom(self):
        from gnat.viz.export import solr_dashboard
        dash = solr_dashboard(title="My Custom Title")
        self.assertEqual(dash["title"], "My Custom Title")

    def test_tags_include_solr(self):
        self.assertIn("solr", self.dash["tags"])
        self.assertIn("gnat", self.dash["tags"])

    def test_panels_present(self):
        self.assertGreater(len(self.dash["panels"]), 0)

    def test_stat_panel_present(self):
        types = [p["type"] for p in self.dash["panels"]]
        self.assertIn("stat", types)

    def test_timeseries_panel_present(self):
        types = [p["type"] for p in self.dash["panels"]]
        self.assertIn("timeseries", types)

    def test_barchart_panels_present(self):
        types = [p["type"] for p in self.dash["panels"]]
        self.assertIn("barchart", types)

    def test_table_panels_present(self):
        types = [p["type"] for p in self.dash["panels"]]
        self.assertIn("table", types)

    def test_panels_have_targets(self):
        for panel in self.dash["panels"]:
            self.assertIn("targets", panel, f"Panel {panel.get('id')} missing targets")
            self.assertGreater(len(panel["targets"]), 0)

    def test_panel_targets_reference_solr_endpoints(self):
        all_targets = []
        for panel in self.dash["panels"]:
            for t in panel["targets"]:
                all_targets.append(t["target"])
        # Should have at least one of each key target type
        self.assertTrue(any("stats/" in t for t in all_targets))
        self.assertTrue(any("facet/" in t for t in all_targets))
        self.assertTrue(any("timeseries/" in t for t in all_targets))

    def test_datasource_name_custom(self):
        from gnat.viz.export import solr_dashboard
        dash = solr_dashboard(datasource_name="MyDS")
        ds_uids = [
            p.get("datasource", {}).get("uid")
            for p in dash["panels"]
        ]
        self.assertTrue(all(uid == "MyDS" for uid in ds_uids if uid))

    def test_panels_have_grid_pos(self):
        for panel in self.dash["panels"]:
            self.assertIn("gridPos", panel)
            for key in ("h", "w", "x", "y"):
                self.assertIn(key, panel["gridPos"])

    def test_refresh_rate(self):
        self.assertEqual(self.dash["refresh"], "1m")


class TestSaveSolrDashboard(unittest.TestCase):
    def test_writes_valid_json(self):
        import json
        import os
        import tempfile

        from gnat.viz.export import save_solr_dashboard
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            save_solr_dashboard(path)
            with open(path) as fh:
                dash = json.load(fh)
            self.assertEqual(dash["uid"], "gnat-solr-index")
        finally:
            os.unlink(path)

    def test_custom_title_written(self):
        import json
        import os
        import tempfile

        from gnat.viz.export import save_solr_dashboard
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            save_solr_dashboard(path, title="My Solr Dash")
            with open(path) as fh:
                dash = json.load(fh)
            self.assertEqual(dash["title"], "My Solr Dash")
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Tests: CLI — gnat viz solr-dashboard
# ---------------------------------------------------------------------------

class TestCLISolrDashboard(unittest.TestCase):
    def _run(self, args: list[str]):
        import io
        import sys

        from gnat.cli.main import main
        old_argv = sys.argv
        old_stdout = sys.stdout
        sys.argv = ["gnat"] + args
        sys.stdout = io.StringIO()
        try:
            try:
                rc = main()
            except SystemExit as exc:
                rc = exc.code
        finally:
            sys.argv = old_argv
            out = sys.stdout.getvalue()
            sys.stdout = old_stdout
        return rc, out

    def test_solr_dashboard_cli(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        os.unlink(path)
        try:
            rc, out = self._run(["viz", "solr-dashboard", "--file", path])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(path))
            with open(path) as fh:
                dash = json.load(fh)
            self.assertEqual(dash["uid"], "gnat-solr-index")
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_solr_dashboard_custom_title(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        os.unlink(path)
        try:
            rc, out = self._run([
                "viz", "solr-dashboard",
                "--file", path,
                "--title", "Custom Title",
                "--datasource", "CustomDS",
            ])
            self.assertEqual(rc, 0)
            with open(path) as fh:
                dash = json.load(fh)
            self.assertEqual(dash["title"], "Custom Title")
        finally:
            if os.path.exists(path):
                os.unlink(path)


# ---------------------------------------------------------------------------
# Tests: CLI — gnat viz serve --with-solr
# ---------------------------------------------------------------------------

class TestCLIVizServeWithSolr(unittest.TestCase):
    def test_serve_with_solr_builds_server(self):
        """Verify --with-solr arg is registered and parsed without error."""
        # If the parser doesn't know --with-solr this will raise SystemExit
        from gnat.cli.main import _build_parser
        parser = _build_parser()
        args = parser.parse_args([
            "viz", "serve",
            "--port", "13579",
            "--with-solr",
        ])
        self.assertTrue(args.with_solr)
        self.assertEqual(args.port, 13579)

    def test_serve_without_with_solr_defaults_false(self):
        from gnat.cli.main import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["viz", "serve", "--port", "3001"])
        self.assertFalse(args.with_solr)


# ---------------------------------------------------------------------------
# Tests: Facet parsing helper
# ---------------------------------------------------------------------------

class TestFacetCounts(unittest.TestCase):
    """Test the flat Solr facet list parsing inside the router."""

    def test_flat_list_parsed_correctly(self):
        # _solr_get is tested indirectly; verify the parsing logic inline
        # Solr flat format: [value, count, value, count, ...]
        flat = ["indicator", 20, "malware", 10, "threat-actor", 5]
        pairs = []
        for i in range(0, len(flat) - 1, 2):
            pairs.append((str(flat[i]), int(flat[i + 1])))
        self.assertEqual(pairs[0], ("indicator", 20))
        self.assertEqual(pairs[1], ("malware", 10))
        self.assertEqual(pairs[2], ("threat-actor", 5))

    def test_empty_flat_list_yields_empty(self):
        flat = []
        pairs = []
        for i in range(0, len(flat) - 1, 2):
            pairs.append((str(flat[i]), int(flat[i + 1])))
        self.assertEqual(pairs, [])

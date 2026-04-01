"""
tests/integration/test_docker_solr.py
=======================================

Docker-harness integration tests for the GNAT Solr search sidecar
(``GNATIndexer``) against a real Solr 9.x container.

All tests are marked ``@pytest.mark.docker`` and skipped unless
``--run-docker`` is passed.

Run::

    pytest tests/integration/test_docker_solr.py --run-docker -v
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

import pytest

pytestmark = pytest.mark.docker

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _solr_request(url: str, *, body: dict | None = None, method: str = "GET") -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read())
        except Exception:
            return exc.code, {}


# ---------------------------------------------------------------------------
# Tests: Solr core health
# ---------------------------------------------------------------------------


class TestSolrCore:
    def test_ping(self, solr_url):
        status, body = _solr_request(f"{solr_url}/solr/gnat/admin/ping")
        assert status == 200
        assert body.get("status") == "OK"

    def test_core_status(self, solr_url):
        status, body = _solr_request(f"{solr_url}/solr/admin/cores?action=STATUS&core=gnat")
        assert status == 200
        assert "gnat" in body.get("status", {})

    def test_solr_version(self, solr_url):
        status, body = _solr_request(f"{solr_url}/solr/admin/info/system")
        assert status == 200
        assert "lucene" in body


# ---------------------------------------------------------------------------
# Tests: Document indexing and query (raw Solr API)
# ---------------------------------------------------------------------------


class TestSolrDocuments:
    _CORE = "gnat"

    def _add_doc(self, solr_url: str, doc: dict) -> None:
        status, body = _solr_request(
            f"{solr_url}/solr/{self._CORE}/update/json/docs?commit=true",
            body=doc,
            method="POST",
        )
        assert status == 200, f"Add doc failed: {body}"

    def _query(self, solr_url: str, q: str, **params) -> dict:
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        status, body = _solr_request(
            f"{solr_url}/solr/{self._CORE}/select?q={q}&wt=json&{qs}",
        )
        assert status == 200
        return body

    def test_add_single_document(self, solr_url):
        self._add_doc(
            solr_url,
            {
                "id": "indicator--dddddddd-0001-0001-0001-000000000001",
                "stix_type": "indicator",
                "name": "Solr docker test IOC",
            },
        )

    def test_query_by_id(self, solr_url):
        doc_id = "indicator--dddddddd-0001-0001-0001-000000000002"
        self._add_doc(
            solr_url,
            {
                "id": doc_id,
                "stix_type": "indicator",
                "name": "Unique solr query test",
            },
        )
        result = self._query(solr_url, f"id:{doc_id}")
        assert result["response"]["numFound"] >= 1

    def test_full_text_search(self, solr_url):
        self._add_doc(
            solr_url,
            {
                "id": "indicator--dddddddd-0001-0001-0001-000000000003",
                "stix_type": "indicator",
                "name": "SOLRUNIQUE_FULLTEXT_TERM",
            },
        )
        result = self._query(solr_url, "SOLRUNIQUE_FULLTEXT_TERM")
        assert result["response"]["numFound"] >= 1

    def test_delete_by_id(self, solr_url):
        doc_id = "indicator--dddddddd-0001-0001-0001-000000000099"
        self._add_doc(solr_url, {"id": doc_id, "stix_type": "indicator", "name": "delete-me"})

        # Delete via update handler
        status, body = _solr_request(
            f"{solr_url}/solr/{self._CORE}/update?commit=true",
            body={"delete": {"id": doc_id}},
            method="POST",
        )
        assert status == 200

        result = self._query(solr_url, f"id:{doc_id}")
        assert result["response"]["numFound"] == 0


# ---------------------------------------------------------------------------
# Tests: GNATIndexer (search sidecar)
# ---------------------------------------------------------------------------


class TestGNATIndexer:
    """Exercise GNATIndexer against the live Solr container."""

    @pytest.fixture(autouse=True)
    def setup_indexer(self, solr_url, tmp_path):
        ini = tmp_path / "gnat.ini"
        ini.write_text(f"""[search]
solr_url = {solr_url}/solr/gnat
enabled = true
batch_size = 10
""")
        import os

        os.environ["GNAT_CONFIG"] = str(ini)

        try:
            from gnat.search import GNATIndexer, SolrSearchConfig

            cfg = SolrSearchConfig(solr_url=f"{solr_url}/solr/gnat", enabled=True, batch_size=10)
            self.indexer = GNATIndexer(cfg)
        except ImportError:
            pytest.skip("GNATIndexer not importable — install gnat[search]")

    def test_index_single_object(self):
        from gnat.orm.indicator import Indicator

        ioc = Indicator(
            id="indicator--eeeeeeee-0001-0001-0001-000000000001",
            name="GNATIndexer docker test",
            pattern="[ipv4-addr:value = '192.0.2.1']",
            pattern_type="stix",
            valid_from="2024-01-01T00:00:00Z",
            indicator_types=["malicious-activity"],
        )
        self.indexer.index(ioc)
        time.sleep(0.5)  # allow commit

    def test_search_indexed_object(self, solr_url):
        from gnat.orm.indicator import Indicator

        ioc = Indicator(
            id="indicator--eeeeeeee-0001-0001-0001-000000000002",
            name="GNATSEARCHUNIQUE_DOCKER_TERM",
            pattern="[ipv4-addr:value = '192.0.2.2']",
            pattern_type="stix",
            valid_from="2024-01-01T00:00:00Z",
            indicator_types=["malicious-activity"],
        )
        self.indexer.index(ioc)
        time.sleep(1)

        results = self.indexer.search("GNATSEARCHUNIQUE_DOCKER_TERM")
        assert isinstance(results, list)
        assert len(results) >= 1

    def test_index_batch(self):
        from gnat.orm.indicator import Indicator

        batch = [
            Indicator(
                id=f"indicator--eeeeeeee-0002-0002-0002-{i:012x}",
                name=f"Batch IOC {i}",
                pattern=f"[ipv4-addr:value = '198.51.100.{i}']",
                pattern_type="stix",
                valid_from="2024-01-01T00:00:00Z",
                indicator_types=["malicious-activity"],
            )
            for i in range(15)
        ]
        self.indexer.index_batch(batch)
        time.sleep(1)

    def test_delete_from_index(self, solr_url):
        from gnat.orm.indicator import Indicator

        ioc = Indicator(
            id="indicator--eeeeeeee-0001-0001-0001-000000000099",
            name="delete-from-index-test",
            pattern="[ipv4-addr:value = '198.51.100.99']",
            pattern_type="stix",
            valid_from="2024-01-01T00:00:00Z",
            indicator_types=["malicious-activity"],
        )
        self.indexer.index(ioc)
        time.sleep(0.5)

        self.indexer.delete(ioc.id)
        time.sleep(0.5)

        results = self.indexer.search(f'id:"{ioc.id}"')
        assert not any(r.id == ioc.id for r in results)

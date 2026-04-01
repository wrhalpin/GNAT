"""
tests/integration/test_docker_elastic.py
==========================================

Docker-harness integration tests for the Elastic SIEM connector
against a real Elasticsearch 8.x container.

All tests are marked ``@pytest.mark.docker`` and skipped unless
``--run-docker`` is passed.

Run::

    pytest tests/integration/test_docker_elastic.py --run-docker -v
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


def _es_request(
    url: str,
    *,
    method: str = "GET",
    body: dict | None = None,
) -> tuple[int, dict]:
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
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def es(elasticsearch_url):
    """Return a thin ES client dict for use in tests."""
    return {"url": elasticsearch_url}


# ---------------------------------------------------------------------------
# Tests: Elasticsearch cluster health
# ---------------------------------------------------------------------------


class TestElasticsearchCluster:
    def test_cluster_health(self, es):
        status, body = _es_request(f"{es['url']}/_cluster/health")
        assert status == 200
        assert body["status"] in ("green", "yellow")

    def test_cluster_info(self, es):
        status, body = _es_request(es["url"])
        assert status == 200
        assert "version" in body
        assert "number" in body["version"]


# ---------------------------------------------------------------------------
# Tests: Index and document CRUD
# ---------------------------------------------------------------------------


class TestIndexOperations:
    _INDEX = "gnat-test-indicators"

    def test_create_index(self, es):
        status, body = _es_request(
            f"{es['url']}/{self._INDEX}",
            method="PUT",
            body={
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "stix_id": {"type": "keyword"},
                        "type": {"type": "keyword"},
                        "name": {"type": "text"},
                        "pattern": {"type": "text"},
                        "valid_from": {"type": "date"},
                        "created": {"type": "date"},
                    }
                },
            },
        )
        # 200 if already exists, 400 if exists with different settings
        assert status in (200, 400)

    def test_index_document(self, es):
        doc = {
            "stix_id": "indicator--aaaaaaaa-0001-0001-0001-000000000001",
            "type": "indicator",
            "name": "Test IOC docker",
            "pattern": "[ipv4-addr:value = '203.0.113.42']",
            "valid_from": "2024-01-01T00:00:00Z",
            "created": "2024-01-01T00:00:00Z",
        }
        status, body = _es_request(
            f"{es['url']}/{self._INDEX}/_doc/ioc-docker-1",
            method="PUT",
            body=doc,
        )
        assert status in (200, 201)
        assert body.get("result") in ("created", "updated")

    def test_get_document(self, es):
        status, body = _es_request(
            f"{es['url']}/{self._INDEX}/_doc/ioc-docker-1",
        )
        assert status == 200
        assert body["_source"]["type"] == "indicator"

    def test_search_document(self, es):
        # Wait a moment for index refresh
        time.sleep(1)
        status, body = _es_request(
            f"{es['url']}/{self._INDEX}/_search",
            method="POST",
            body={"query": {"term": {"type": "indicator"}}},
        )
        assert status == 200
        hits = body["hits"]["total"]["value"]
        assert hits >= 1

    def test_delete_document(self, es):
        status, body = _es_request(
            f"{es['url']}/{self._INDEX}/_doc/ioc-docker-1",
            method="DELETE",
        )
        assert status == 200
        assert body.get("result") == "deleted"

    def test_get_deleted_document_404(self, es):
        status, _ = _es_request(
            f"{es['url']}/{self._INDEX}/_doc/ioc-docker-1",
        )
        assert status == 404


# ---------------------------------------------------------------------------
# Tests: Bulk indexing (simulating ingest pipeline output)
# ---------------------------------------------------------------------------


class TestBulkIndexing:
    _INDEX = "gnat-test-bulk"

    def _build_bulk_body(self, count: int) -> bytes:
        lines = []
        for i in range(count):
            lines.append(json.dumps({"index": {"_index": self._INDEX, "_id": f"bulk-{i}"}}))
            lines.append(
                json.dumps(
                    {
                        "stix_id": f"indicator--bbbbbbbb-{i:04x}-0000-0000-000000000000",
                        "type": "indicator",
                        "name": f"Bulk IOC {i}",
                        "pattern": f"[ipv4-addr:value = '10.10.{i // 256}.{i % 256}']",
                        "created": "2024-06-01T00:00:00Z",
                    }
                )
            )
        return ("\n".join(lines) + "\n").encode()

    def test_bulk_index_100_docs(self, es):
        body = self._build_bulk_body(100)
        req = urllib.request.Request(
            f"{es['url']}/_bulk",
            data=body,
            method="POST",
        )
        req.add_header("Content-Type", "application/x-ndjson")
        req.add_header("Accept", "application/json")

        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())

        assert not result.get("errors"), f"Bulk errors: {result}"
        assert len(result["items"]) == 100

    def test_bulk_count(self, es):
        time.sleep(1)  # allow index refresh
        status, body = _es_request(
            f"{es['url']}/{self._INDEX}/_count",
        )
        assert status == 200
        assert body["count"] >= 100


# ---------------------------------------------------------------------------
# Tests: GNAT Elastic connector (unit-style, against live ES)
# ---------------------------------------------------------------------------


class TestGNATElasticConnector:
    """Wire the actual ElasticConnector to the Docker ES instance."""

    @pytest.fixture(autouse=True)
    def setup_connector(self, elasticsearch_url, tmp_path):
        ini = tmp_path / "gnat.ini"
        ini.write_text(f"""[elastic]
host = {elasticsearch_url}
auth_type = none
index = gnat-connector-test
""")
        import os

        os.environ["GNAT_CONFIG"] = str(ini)

        try:
            from gnat.connectors.elastic import ElasticConnector

            self.connector = ElasticConnector(
                host=elasticsearch_url,
                auth_type="none",
            )
        except ImportError:
            pytest.skip("ElasticConnector not importable")

    def test_health_check(self):
        result = self.connector.health_check()
        assert result is True

    def test_authenticate_noop(self):
        # auth_type=none should not raise
        self.connector.authenticate()

    def test_upsert_and_get(self):
        from gnat.orm.indicator import Indicator

        ioc = Indicator(
            id="indicator--cccccccc-1234-5678-abcd-000000000001",
            name="Docker Connector Test IOC",
            pattern="[domain-name:value = 'evil.example.com']",
            pattern_type="stix",
            valid_from="2024-01-01T00:00:00Z",
            indicator_types=["malicious-activity"],
        )
        self.connector.upsert_object(ioc)
        time.sleep(0.5)

        retrieved = self.connector.get_object(ioc.id)
        assert retrieved is not None
        assert retrieved.id == ioc.id

    def test_list_objects(self):
        from gnat.orm.indicator import Indicator

        ioc = Indicator(
            id="indicator--cccccccc-1234-5678-abcd-000000000002",
            name="Docker List Test IOC",
            pattern="[url:value = 'http://malware.example.com']",
            pattern_type="stix",
            valid_from="2024-01-01T00:00:00Z",
            indicator_types=["malicious-activity"],
        )
        self.connector.upsert_object(ioc)
        time.sleep(0.5)

        objects = self.connector.list_objects()
        assert isinstance(objects, list)
        ids = [o.id for o in objects]
        assert ioc.id in ids

    def test_delete_object(self):
        from gnat.orm.indicator import Indicator

        ioc = Indicator(
            id="indicator--cccccccc-1234-5678-abcd-000000000003",
            name="Docker Delete Test IOC",
            pattern="[file:hashes.MD5 = 'aabbccddeeff00112233445566778899']",
            pattern_type="stix",
            valid_from="2024-01-01T00:00:00Z",
            indicator_types=["malicious-activity"],
        )
        self.connector.upsert_object(ioc)
        time.sleep(0.5)

        self.connector.delete_object(ioc.id)
        time.sleep(0.5)

        retrieved = self.connector.get_object(ioc.id)
        assert retrieved is None

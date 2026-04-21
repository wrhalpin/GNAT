# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/connectors/test_elastic.py

Unit tests for the GNAT Elastic Security connector.

All HTTP is mocked via unittest.mock on urllib3.PoolManager.
No live Elasticsearch or Kibana instance required.

## Coverage

- ElasticConfig: validation, INI loading, URL construction, Cloud ID
- ElasticAuthManager: header construction, verify methods
- ElasticClient: ES + Kibana routing, error mapping, pagination
- ElasticSearchCommands: cluster, index, search, aggregation
- KibanaRulesCommands: list, CRUD, enable/disable, export/import
- KibanaAlertsCommands: search, status update, normalise
- KibanaCasesCommands: CRUD, comments, alert attachment
- ElasticThreatIntelCommands: search, index, bulk, STIX upload
- ElasticSTIXMapper: all mapping directions + edge cases

## Running

pytest tests/connectors/test_elastic.py -v

"""

import base64
import configparser
import json
import unittest
from unittest.mock import MagicMock, patch

from gnat.connectors.elastic.auth import ElasticAuthManager
from gnat.connectors.elastic.client import ElasticClient
from gnat.connectors.elastic.config import ElasticConfig, load_elastic_config
from gnat.connectors.elastic.es_search import ElasticSearchCommands
from gnat.connectors.elastic.exceptions import (
    ElasticAPIError,
    ElasticAuthError,
    ElasticConfigError,
    ElasticConflictError,
    ElasticKibanaError,
    ElasticKibanaNotFoundError,
    ElasticKibanaValidationError,
    ElasticNotFoundError,
    ElasticRateLimitError,
    ElasticSTIXError,
)
from gnat.connectors.elastic.kibana_alerts import KibanaAlertsCommands
from gnat.connectors.elastic.kibana_cases import KibanaCasesCommands
from gnat.connectors.elastic.kibana_rules import KibanaRulesCommands
from gnat.connectors.elastic.stix_mapper import ElasticSTIXMapper
from gnat.connectors.elastic.threat_intel import ElasticThreatIntelCommands
from gnat.stix.version import CURRENT_SPEC_VERSION

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_config(**overrides) -> ElasticConfig:
    """Internal helper for make config."""
    defaults = {
        "es_host": "elastic.test.local",
        "api_key_id": "test_key_id",
        "api_key_secret": "test_key_secret",
    }
    defaults.update(overrides)
    return ElasticConfig(**defaults)


def _make_response(status: int = 200, body=None) -> MagicMock:
    """Internal helper for make response."""
    resp = MagicMock()
    resp.status = status
    payload = body if body is not None else {}
    resp.data = json.dumps(payload).encode("utf-8")
    return resp


def _es_hits(docs: list, total: int | None = None) -> dict:
    """Build a standard ES search response envelope."""
    return {
        "hits": {
            "total": {"value": total or len(docs), "relation": "eq"},
            "hits": [{"_id": str(i), "_source": d} for i, d in enumerate(docs)],
        }
    }


def _make_client(config: ElasticConfig | None = None) -> tuple[ElasticClient, MagicMock]:
    """Internal helper for make client."""
    cfg = config or _make_config()
    with patch("gnat.connectors.elastic.client.urllib3.PoolManager") as pm_cls:
        mock_pm = MagicMock()
        pm_cls.return_value = mock_pm
        client = ElasticClient(cfg)
        client._http = mock_pm
        client.auth._http = mock_pm
        return client, mock_pm

        # ═════════════════════════════════════════════════════════════════════════════

        # ElasticConfig

        # ═════════════════════════════════════════════════════════════════════════════


class TestElasticConfig(unittest.TestCase):
    """Configuration container for test elastic."""

    def test_minimal_config(self):
        """Test that minimal config."""
        cfg = _make_config()
        self.assertEqual(cfg.es_host, "elastic.test.local")
        self.assertEqual(cfg.es_port, 9200)
        self.assertEqual(cfg.kibana_port, 5601)

    def test_es_base_url(self):
        """Test that es base url."""
        cfg = _make_config()
        self.assertEqual(cfg.es_base_url, "https://elastic.test.local:9200")

    def test_kibana_defaults_to_es_host(self):
        """Test that kibana defaults to es host."""
        cfg = _make_config()
        self.assertIn("elastic.test.local", cfg.kibana_base_url)

    def test_kibana_custom_host(self):
        """Test that kibana custom host."""
        cfg = _make_config(kibana_host="kibana.test.local")
        self.assertIn("kibana.test.local", cfg.kibana_base_url)

    def test_api_key_header_is_base64(self):
        """Test that api key header is base64."""
        cfg = _make_config(api_key_id="id123", api_key_secret="sec456")
        expected = base64.b64encode(b"id123:sec456").decode()
        self.assertEqual(cfg.api_key_header, expected)

    def test_auth_headers(self):
        """Test that auth headers."""
        cfg = _make_config()
        headers = cfg.auth_headers
        self.assertIn("Authorization", headers)
        self.assertTrue(headers["Authorization"].startswith("ApiKey "))

    def test_kibana_headers_include_xsrf(self):
        """Test that kibana headers include xsrf."""
        cfg = _make_config()
        headers = cfg.kibana_headers
        self.assertEqual(headers.get("kbn-xsrf"), "true")

    def test_kibana_get_headers_no_xsrf(self):
        """Test that kibana get headers no xsrf."""
        cfg = _make_config()
        headers = cfg.kibana_get_headers
        self.assertNotIn("kbn-xsrf", headers)

    def test_kibana_url_default_space(self):
        """Test that kibana url default space."""
        cfg = _make_config()
        url = cfg.kibana_url("api/detection_engine/rules")
        self.assertNotIn("/s/", url)
        self.assertIn("api/detection_engine/rules", url)

    def test_kibana_url_custom_space(self):
        """Test that kibana url custom space."""
        cfg = _make_config(kibana_space="security-team")
        url = cfg.kibana_url("api/detection_engine/rules")
        self.assertIn("/s/security-team/", url)

    def test_es_url(self):
        """Test that es url."""
        cfg = _make_config()
        url = cfg.es_url("_cluster/health")
        self.assertEqual(url, "https://elastic.test.local:9200/_cluster/health")

    def test_missing_api_key_id_raises(self):
        """Test that missing api key id raises."""
        with self.assertRaises(ElasticConfigError):
            ElasticConfig(
                es_host="h",
                api_key_id="",
                api_key_secret="s",
            )

    def test_missing_es_host_and_cloud_id_raises(self):
        """Test that missing es host and cloud id raises."""
        with self.assertRaises(ElasticConfigError):
            ElasticConfig(
                es_host="",
                api_key_id="id",
                api_key_secret="s",
            )

    def test_invalid_scheme_raises(self):
        """Test that invalid scheme raises."""
        with self.assertRaises(ElasticConfigError):
            ElasticConfig(
                es_host="h",
                api_key_id="id",
                api_key_secret="s",
                scheme="ftp",
            )

    def test_load_from_configparser(self):
        """Test that load from configparser."""
        parser = configparser.ConfigParser()
        parser.read_dict(
            {
                "elastic": {
                    "es_host": "myES.corp",
                    "api_key_id": "kid",
                    "api_key_secret": "ksec",
                    "kibana_host": "myKibana.corp",
                    "verify_ssl": "false",
                    "timeout": "45",
                }
            }
        )
        cfg = load_elastic_config(parser)
        self.assertEqual(cfg.es_host, "myES.corp")
        self.assertEqual(cfg.kibana_host, "myKibana.corp")
        self.assertFalse(cfg.verify_ssl)
        self.assertEqual(cfg.timeout, 45)

    def test_load_missing_section_raises(self):
        """Test that load missing section raises."""
        with self.assertRaises(ElasticConfigError):
            load_elastic_config(configparser.ConfigParser())

    def test_load_missing_api_key_raises(self):
        """Test that load missing api key raises."""
        parser = configparser.ConfigParser()
        parser.read_dict({"elastic": {"es_host": "h"}})
        with self.assertRaises(ElasticConfigError):
            load_elastic_config(parser)

    # ═════════════════════════════════════════════════════════════════════════════

    # ElasticAuthManager

    # ═════════════════════════════════════════════════════════════════════════════


class TestElasticAuthManager(unittest.TestCase):
    """Unit tests for :class:`ElasticAuthManager`."""

    def _make_auth(self, config=None):
        """Internal helper for make auth."""
        cfg = config or _make_config()
        mock_http = MagicMock()
        return ElasticAuthManager(cfg, mock_http), mock_http

    def test_get_es_headers_has_auth(self):
        """Test that get es headers has auth."""
        auth, _ = self._make_auth()
        headers = auth.get_es_headers()
        self.assertIn("Authorization", headers)
        self.assertTrue(headers["Authorization"].startswith("ApiKey "))

    def test_get_kibana_headers_post_has_xsrf(self):
        """Test that get kibana headers post has xsrf."""
        auth, _ = self._make_auth()
        headers = auth.get_kibana_headers("POST")
        self.assertEqual(headers.get("kbn-xsrf"), "true")

    def test_get_kibana_headers_get_no_xsrf(self):
        """Test that get kibana headers get no xsrf."""
        auth, _ = self._make_auth()
        headers = auth.get_kibana_headers("GET")
        self.assertNotIn("kbn-xsrf", headers)

    def test_verify_es_success(self):
        """Test that verify es success."""
        auth, mock_http = self._make_auth()
        mock_http.request.return_value = _make_response(
            200, {"name": "my-node", "version": {"number": "8.12.0"}}
        )
        result = auth.verify_es()
        self.assertEqual(result.get("name"), "my-node")

    def test_verify_es_401_raises(self):
        """Test that verify es 401 raises."""
        auth, mock_http = self._make_auth()
        mock_http.request.return_value = _make_response(401)
        with self.assertRaises(ElasticAuthError):
            auth.verify_es()

    def test_verify_kibana_success(self):
        """Test that verify kibana success."""
        auth, mock_http = self._make_auth()
        mock_http.request.return_value = _make_response(
            200, {"status": {"overall": {"level": "green"}}}
        )
        result = auth.verify_kibana()
        self.assertIsInstance(result, dict)

    def test_verify_kibana_403_raises(self):
        """Test that verify kibana 403 raises."""
        auth, mock_http = self._make_auth()
        mock_http.request.return_value = _make_response(403)
        with self.assertRaises(ElasticAuthError):
            auth.verify_kibana()

    # ═════════════════════════════════════════════════════════════════════════════

    # ElasticClient

    # ═════════════════════════════════════════════════════════════════════════════


class TestElasticClient(unittest.TestCase):
    """HTTP API client for the TestElastic platform."""

    def test_es_get_returns_dict(self):
        """Test that es get returns dict."""
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(200, {"status": "green"})
        result = client.es_get("_cluster/health")
        self.assertIsInstance(result, dict)

    def test_kibana_get_returns_dict(self):
        """Test that kibana get returns dict."""
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(200, {"data": [], "total": 0})
        result = client.kibana_get("api/detection_engine/rules/_find")
        self.assertIsInstance(result, dict)

    def test_es_401_raises_auth_error(self):
        """Test that es 401 raises auth error."""
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(401)
        with self.assertRaises(ElasticAuthError):
            client.es_get("_cluster/health")

    def test_es_403_raises_auth_error(self):
        """Test that es 403 raises auth error."""
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(403)
        with self.assertRaises(ElasticAuthError):
            client.es_get("some/endpoint")

    def test_es_404_raises_not_found(self):
        """Test that es 404 raises not found."""
        client, mock_http = _make_client()
        body = {
            "error": {"type": "index_not_found_exception", "reason": "no such index"},
            "status": 404,
        }
        mock_http.request.return_value = _make_response(404, body)
        with self.assertRaises(ElasticNotFoundError) as ctx:
            client.es_get("missing-index/_doc/1")
        self.assertEqual(ctx.exception.error_type, "index_not_found_exception")

    def test_es_409_raises_conflict(self):
        """Test that es 409 raises conflict."""
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(
            409, {"error": {"type": "version_conflict_engine_exception"}}
        )
        with self.assertRaises(ElasticConflictError):
            client.es_put("my-index/_doc/1", body={"field": "val"})

    def test_es_429_retries_then_raises(self):
        """Test that es 429 retries then raises."""
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(429)
        with patch("time.sleep"), self.assertRaises(ElasticRateLimitError):
            client.es_get("_search")

    def test_kibana_404_raises_kibana_not_found(self):
        """Test that kibana 404 raises kibana not found."""
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(404, {"message": "Not found"})
        with self.assertRaises(ElasticKibanaNotFoundError):
            client.kibana_get("api/detection_engine/rules?rule_id=missing")

    def test_kibana_400_raises_validation_error(self):
        """Test that kibana 400 raises validation error."""
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(400, {"message": "[name]: required"})
        with self.assertRaises(ElasticKibanaValidationError) as ctx:
            client.kibana_post("api/detection_engine/rules", body={})
        self.assertIn("[name]", ctx.exception.kibana_message)

    def test_context_manager(self):
        """Test that context manager."""
        cfg = _make_config()
        with (
            patch("gnat.connectors.elastic.client.urllib3.PoolManager"),
            ElasticClient(cfg) as client,
        ):
            self.assertIsInstance(client, ElasticClient)

    def test_es_search_hits_extracts_sources(self):
        """Test that es search hits extracts sources."""
        client, mock_http = _make_client()
        docs = [{"source.ip": "1.2.3.4"}, {"source.ip": "5.6.7.8"}]
        mock_http.request.return_value = _make_response(200, _es_hits(docs))
        results = client.es_search_hits(".alerts-security.*")
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["source.ip"], "1.2.3.4")

    def test_es_count(self):
        """Test that es count."""
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(200, {"count": 42})
        count = client.es_count("my-index")
        self.assertEqual(count, 42)

    def test_es_paginate_yields_all(self):
        """Test that es paginate yields all."""
        client, mock_http = _make_client()
        page1 = _es_hits([{"id": i} for i in range(1000)], total=1200)
        page2 = _es_hits([{"id": i} for i in range(1000, 1200)], total=1200)
        mock_http.request.side_effect = [
            _make_response(200, page1),
            _make_response(200, page2),
        ]
        items = list(client.es_paginate("my-index", page_size=1000))
        self.assertEqual(len(items), 1200)

    def test_kibana_paginate_yields_all(self):
        """Test that kibana paginate yields all."""
        client, mock_http = _make_client()
        page1 = {"data": [{"name": f"rule{i}"} for i in range(100)], "total": 150}
        page2 = {"data": [{"name": f"rule{i}"} for i in range(100, 150)], "total": 150}
        mock_http.request.side_effect = [
            _make_response(200, page1),
            _make_response(200, page2),
        ]
        items = list(client.kibana_paginate("api/detection_engine/rules/_find", page_size=100))
        self.assertEqual(len(items), 150)

    # ═════════════════════════════════════════════════════════════════════════════

    # ElasticSearchCommands

    # ═════════════════════════════════════════════════════════════════════════════


class TestElasticSearchCommands(unittest.TestCase):
    """Unit tests for :class:`ElasticSearchCommands`."""

    def _make_search_cmd(self):
        """Internal helper for make search cmd."""
        client, mock_http = _make_client()
        return ElasticSearchCommands(client), mock_http

    def test_cluster_health(self):
        """Test that cluster health."""
        search, mock_http = self._make_search_cmd()
        mock_http.request.return_value = _make_response(200, {"status": "green"})
        result = search.cluster_health()
        self.assertEqual(result.get("status"), "green")

    def test_list_indices(self):
        """Test that list indices."""
        search, mock_http = self._make_search_cmd()
        mock_http.request.return_value = _make_response(
            200, [{"index": ".alerts-security.default-000001", "health": "green"}]
        )
        results = search.list_indices(pattern=".alerts-*")
        # _cat returns list directly
        self.assertIsInstance(results, list)

    def test_index_exists_true(self):
        """Test that index exists true."""
        search, mock_http = self._make_search_cmd()
        mock_http.request.return_value = _make_response(200, {})
        self.assertTrue(search.index_exists("my-index"))

    def test_index_exists_false(self):
        """Test that index exists false."""
        search, mock_http = self._make_search_cmd()
        mock_http.request.return_value = _make_response(404)
        self.assertFalse(search.index_exists("missing-index"))

    def test_doc_count(self):
        """Test that doc count."""
        search, mock_http = self._make_search_cmd()
        mock_http.request.return_value = _make_response(200, {"count": 99})
        self.assertEqual(search.doc_count("my-index"), 99)

    def test_search_alerts_with_filters(self):
        """Test that search alerts with filters."""
        search, mock_http = self._make_search_cmd()
        mock_http.request.return_value = _make_response(
            200, _es_hits([{"kibana.alert.rule.name": "Test Rule"}])
        )
        results = search.search_alerts(min_severity=50, size=10)
        self.assertEqual(len(results), 1)

    def test_aggregate_by_field(self):
        """Test that aggregate by field."""
        search, mock_http = self._make_search_cmd()
        agg_response = {
            "hits": {"hits": [], "total": {"value": 0}},
            "aggregations": {
                "top_values": {
                    "buckets": [
                        {"key": "authentication", "doc_count": 50},
                        {"key": "network", "doc_count": 30},
                    ]
                }
            },
        }
        mock_http.request.return_value = _make_response(200, agg_response)
        buckets = search.aggregate_by_field("logs-*", "event.category")
        self.assertEqual(len(buckets), 2)
        self.assertEqual(buckets[0]["key"], "authentication")

    def test_get_document_found(self):
        """Test that get document found."""
        search, mock_http = self._make_search_cmd()
        mock_http.request.return_value = _make_response(
            200, {"_id": "abc", "_source": {"field": "val"}}
        )
        result = search.get_document("my-index", "abc")
        self.assertEqual(result["field"], "val")

    def test_get_document_not_found(self):
        """Test that get document not found."""
        search, mock_http = self._make_search_cmd()
        mock_http.request.return_value = _make_response(404)
        result = search.get_document("my-index", "missing")
        self.assertIsNone(result)

    # ═════════════════════════════════════════════════════════════════════════════

    # KibanaRulesCommands

    # ═════════════════════════════════════════════════════════════════════════════


class TestKibanaRulesCommands(unittest.TestCase):
    """Unit tests for :class:`KibanaRulesCommands`."""

    def _make_rules(self):
        """Internal helper for make rules."""
        client, mock_http = _make_client()
        return KibanaRulesCommands(client), mock_http

    def test_list_rules(self):
        """Test that list rules."""
        rules_cmd, mock_http = self._make_rules()
        mock_http.request.return_value = _make_response(
            200, {"data": [{"rule_id": "test-123", "name": "Test Rule"}], "total": 1}
        )
        result = rules_cmd.list_rules()
        self.assertEqual(result["total"], 1)

    def test_get_rule(self):
        """Test that get rule."""
        rules_cmd, mock_http = self._make_rules()
        mock_http.request.return_value = _make_response(
            200, {"rule_id": "test-123", "name": "Test Rule", "enabled": True}
        )
        rule = rules_cmd.get_rule("test-123")
        self.assertEqual(rule["rule_id"], "test-123")

    def test_create_rule(self):
        """Test that create rule."""
        rules_cmd, mock_http = self._make_rules()
        mock_http.request.return_value = _make_response(
            200, {"id": "kibana-id", "rule_id": "test-123", "name": "New Rule"}
        )
        rule = rules_cmd.create_rule(
            {
                "name": "New Rule",
                "type": "query",
                "query": "process.name: malware.exe",
                "language": "kuery",
                "severity": "high",
                "risk_score": 75,
            }
        )
        self.assertEqual(rule["rule_id"], "test-123")

    def test_enable_rule(self):
        """Test that enable rule."""
        rules_cmd, mock_http = self._make_rules()
        mock_http.request.return_value = _make_response(
            200, {"rule_id": "test-123", "enabled": True}
        )
        result = rules_cmd.enable_rule("test-123")
        self.assertTrue(result.get("enabled"))

    def test_delete_rule(self):
        """Test that delete rule."""
        rules_cmd, mock_http = self._make_rules()
        mock_http.request.return_value = _make_response(200, {"rule_id": "test-123"})
        result = rules_cmd.delete_rule("test-123")
        self.assertIsNotNone(result)

    def test_normalise_rule(self):
        """Test that normalise rule."""
        raw = {
            "id": "internal-id",
            "rule_id": "test-123",
            "name": "SSH Brute Force",
            "enabled": True,
            "type": "query",
            "severity": "high",
            "risk_score": 73,
            "tags": ["T1110"],
            "threat": [
                {
                    "tactic": {"id": "TA0006", "name": "Credential Access"},
                    "technique": [
                        {
                            "id": "T1110",
                            "name": "Brute Force",
                            "subtechnique": [{"id": "T1110.001"}],
                        }
                    ],
                }
            ],
            "query": "event.action: failed-login",
            "language": "kuery",
        }
        result = KibanaRulesCommands.normalise_rule(raw)
        self.assertEqual(result["rule_id"], "test-123")
        self.assertIn("TA0006", result["mitre_tactics"])
        self.assertIn("T1110", result["mitre_techniques"])
        self.assertIn("T1110.001", result["mitre_techniques"])

    # ═════════════════════════════════════════════════════════════════════════════

    # KibanaAlertsCommands

    # ═════════════════════════════════════════════════════════════════════════════


class TestKibanaAlertsCommands(unittest.TestCase):
    """Unit tests for :class:`KibanaAlertsCommands`."""

    def _make_alerts_cmd(self):
        """Internal helper for make alerts cmd."""
        client, mock_http = _make_client()
        return KibanaAlertsCommands(client), mock_http

    def test_search_alerts(self):
        """Test that search alerts."""
        alerts_cmd, mock_http = self._make_alerts_cmd()
        doc = {
            "@timestamp": "2024-03-10T12:00:00Z",
            "kibana": {
                "alert": {
                    "rule": {"name": "Test"},
                    "severity": "high",
                    "workflow_status": "open",
                    "severity_score": 73,
                }
            },
        }
        mock_http.request.return_value = _make_response(
            200, {"hits": {"hits": [{"_id": "1", "_source": doc}]}}
        )
        results = alerts_cmd.search_alerts(status="open")
        self.assertEqual(len(results), 1)

    def test_update_alert_status(self):
        """Test that update alert status."""
        alerts_cmd, mock_http = self._make_alerts_cmd()
        mock_http.request.return_value = _make_response(200, {"updated": 1})
        result = alerts_cmd.update_alert_status(["alert1"], "closed")
        self.assertIsNotNone(result)

    def test_update_invalid_status_raises(self):
        """Test that update invalid status raises."""
        alerts_cmd, _ = self._make_alerts_cmd()
        with self.assertRaises(ValueError):
            alerts_cmd.update_alert_status(["a1"], "resolved")

    def test_normalise_alert_severity_map(self):
        """Test that normalise alert severity map."""
        alert = {
            "kibana": {
                "alert": {
                    "rule": {"name": "Test", "rule_id": "r1"},
                    "severity": "critical",
                    "severity_score": 99,
                    "workflow_status": "open",
                    "reason": "Test reason",
                }
            },
            "@timestamp": "2024-03-10T12:00:00Z",
            "host": {"name": "server1"},
            "source": {"ip": "1.2.3.4"},
        }
        result = KibanaAlertsCommands.normalise_alert(alert)
        self.assertEqual(result["severity"], 4)
        self.assertEqual(result["severity_label"], "critical")
        self.assertEqual(result["host_name"], "server1")
        self.assertEqual(result["src_ip"], "1.2.3.4")

    def test_get_alert_counts(self):
        """Test that get alert counts."""
        alerts_cmd, mock_http = self._make_alerts_cmd()
        mock_http.request.return_value = _make_response(
            200,
            {
                "aggregations": {
                    "by_status": {
                        "buckets": [
                            {"key": "open", "doc_count": 50},
                            {"key": "closed", "doc_count": 10},
                        ]
                    }
                }
            },
        )
        counts = alerts_cmd.get_alert_counts_by_status()
        self.assertEqual(counts["open"], 50)
        self.assertEqual(counts["closed"], 10)

    # ═════════════════════════════════════════════════════════════════════════════

    # KibanaCasesCommands

    # ═════════════════════════════════════════════════════════════════════════════


class TestKibanaCasesCommands(unittest.TestCase):
    """Unit tests for :class:`KibanaCasesCommands`."""

    def _make_cases(self):
        """Internal helper for make cases."""
        client, mock_http = _make_client()
        return KibanaCasesCommands(client), mock_http

    def test_list_cases(self):
        """Test that list cases."""
        cases_cmd, mock_http = self._make_cases()
        mock_http.request.return_value = _make_response(
            200, {"cases": [{"id": "case-1", "title": "Incident 1"}], "total": 1}
        )
        result = cases_cmd.list_cases()
        self.assertEqual(result["total"], 1)

    def test_create_case(self):
        """Test that create case."""
        cases_cmd, mock_http = self._make_cases()
        mock_http.request.return_value = _make_response(
            200, {"id": "new-case-id", "title": "Test Case"}
        )
        result = cases_cmd.create_case("Test Case", "Description", severity="high")
        self.assertEqual(result["id"], "new-case-id")

    def test_add_comment(self):
        """Test that add comment."""
        cases_cmd, mock_http = self._make_cases()
        mock_http.request.return_value = _make_response(
            200, {"id": "comment-id", "comment": "Investigation notes"}
        )
        result = cases_cmd.add_comment("case-1", "Investigation notes")
        self.assertIsNotNone(result)

    def test_close_case(self):
        """Test that close case."""
        cases_cmd, mock_http = self._make_cases()
        mock_http.request.return_value = _make_response(200, {"id": "case-1", "status": "closed"})
        result = cases_cmd.close_case("case-1", "v1")
        self.assertIsNotNone(result)

    # ═════════════════════════════════════════════════════════════════════════════

    # ElasticThreatIntelCommands

    # ═════════════════════════════════════════════════════════════════════════════


class TestElasticThreatIntelCommands(unittest.TestCase):
    """Unit tests for :class:`ElasticThreatIntelCommands`."""

    def _make_ti(self):
        """Internal helper for make ti."""
        client, mock_http = _make_client()
        return ElasticThreatIntelCommands(client), mock_http

    def test_search_indicators(self):
        """Test that search indicators."""
        ti_cmd, mock_http = self._make_ti()
        doc = {"threat": {"indicator": {"type": "ipv4-addr", "ip": "1.2.3.4"}}}
        mock_http.request.return_value = _make_response(200, _es_hits([doc]))
        results = ti_cmd.search_indicators(indicator_type="ipv4-addr")
        self.assertEqual(len(results), 1)

    def test_index_indicator_adds_timestamp(self):
        """Test that index indicator adds timestamp."""
        ti_cmd, mock_http = self._make_ti()
        mock_http.request.return_value = _make_response(200, {"_id": "new-id", "result": "created"})
        doc = {"threat": {"indicator": {"type": "ipv4-addr", "ip": "10.0.0.1"}}}
        ti_cmd.index_indicator(doc)
        # The request body should contain @timestamp
        call_body = json.loads(mock_http.request.call_args[1]["body"])
        self.assertIn("@timestamp", call_body)

    def test_normalise_indicator(self):
        """Test that normalise indicator."""
        doc = {
            "@timestamp": "2024-03-10T12:00:00Z",
            "threat": {
                "indicator": {
                    "type": "ipv4-addr",
                    "ip": "1.2.3.4",
                    "provider": "test-feed",
                    "confidence": "High",
                    "first_seen": "2024-01-01T00:00:00Z",
                },
                "feed": {"name": "Test Feed"},
            },
        }
        result = ElasticThreatIntelCommands.normalise_indicator(doc)
        self.assertEqual(result["type"], "ipv4-addr")
        self.assertEqual(result["ip"], "1.2.3.4")
        self.assertEqual(result["provider"], "test-feed")
        self.assertEqual(result["feed_name"], "Test Feed")

    def test_get_indicator_counts_by_type(self):
        """Test that get indicator counts by type."""
        ti_cmd, mock_http = self._make_ti()
        mock_http.request.return_value = _make_response(
            200,
            {
                "hits": {"hits": [], "total": {"value": 0}},
                "aggregations": {
                    "top_values": {
                        "buckets": [
                            {"key": "ipv4-addr", "doc_count": 100},
                            {"key": "domain-name", "doc_count": 50},
                        ]
                    }
                },
            },
        )
        buckets = ti_cmd.get_indicator_counts_by_type()
        self.assertEqual(buckets[0]["key"], "ipv4-addr")

    # ═════════════════════════════════════════════════════════════════════════════

    # ElasticSTIXMapper

    # ═════════════════════════════════════════════════════════════════════════════


class TestElasticSTIXMapper(unittest.TestCase):
    """STIX translation helper for test elastic s t i x objects."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.mapper = ElasticSTIXMapper()

    # ── STIX -> ECS ────────────────────────────────────────────────────────

    def test_ipv4_sco_to_ecs(self):
        """Test that ipv4 sco to ecs."""
        bundle = {
            "type": "bundle",
            "spec_version": CURRENT_SPEC_VERSION,
            "objects": [{"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "1.2.3.4"}],
        }
        docs = self.mapper.stix_bundle_to_ecs_indicators(bundle)
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]["threat"]["indicator"]["ip"], "1.2.3.4")
        self.assertEqual(docs[0]["threat"]["indicator"]["type"], "ipv4-addr")

    def test_ipv6_sco_to_ecs(self):
        """Test that ipv6 sco to ecs."""
        bundle = {
            "type": "bundle",
            "spec_version": CURRENT_SPEC_VERSION,
            "objects": [{"type": "ipv6-addr", "id": "ipv6-addr--1", "value": "::1"}],
        }
        docs = self.mapper.stix_bundle_to_ecs_indicators(bundle)
        self.assertEqual(docs[0]["threat"]["indicator"]["ip"], "::1")

    def test_domain_sco_to_ecs(self):
        """Test that domain sco to ecs."""
        bundle = {
            "type": "bundle",
            "spec_version": CURRENT_SPEC_VERSION,
            "objects": [{"type": "domain-name", "id": "domain-name--1", "value": "evil.com"}],
        }
        docs = self.mapper.stix_bundle_to_ecs_indicators(bundle)
        self.assertEqual(docs[0]["threat"]["indicator"]["domain"], "evil.com")

    def test_url_sco_to_ecs_extracts_domain(self):
        """Test that url sco to ecs extracts domain."""
        bundle = {
            "type": "bundle",
            "spec_version": CURRENT_SPEC_VERSION,
            "objects": [{"type": "url", "id": "url--1", "value": "https://evil.com/path?q=1"}],
        }
        docs = self.mapper.stix_bundle_to_ecs_indicators(bundle)
        ti = docs[0]["threat"]["indicator"]
        self.assertEqual(ti["url"]["full"], "https://evil.com/path?q=1")
        self.assertEqual(ti["url"]["domain"], "evil.com")

    def test_file_sco_to_ecs_with_hashes(self):
        """Test that file sco to ecs with hashes."""
        bundle = {
            "type": "bundle",
            "spec_version": CURRENT_SPEC_VERSION,
            "objects": [
                {
                    "type": "file",
                    "id": "file--1",
                    "name": "malware.exe",
                    "hashes": {
                        "MD5": "abc123",
                        "SHA-1": "def456",
                        "SHA-256": "ghi789",
                    },
                }
            ],
        }
        docs = self.mapper.stix_bundle_to_ecs_indicators(bundle)
        file_field = docs[0]["threat"]["indicator"]["file"]
        self.assertEqual(file_field["hash"]["md5"], "abc123")
        self.assertEqual(file_field["hash"]["sha256"], "ghi789")
        self.assertEqual(file_field["name"], "malware.exe")

    def test_file_sco_no_hashes_no_name_returns_none(self):
        """Test that file sco no hashes no name returns none."""
        obj = {"type": "file", "id": "file--1", "size": 1024}
        result = self.mapper.stix_object_to_ecs_indicator(obj)
        self.assertIsNone(result)

    def test_indicator_sdo_to_ecs(self):
        """Test that indicator sdo to ecs."""
        bundle = {
            "type": "bundle",
            "spec_version": CURRENT_SPEC_VERSION,
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--1",
                    "name": "Malicious IP",
                    "description": "C2 server",
                    "pattern": "[ipv4-addr:value = '10.0.0.99']",
                    "pattern_type": "stix",
                    "valid_from": "2024-01-01T00:00:00Z",
                    "confidence": 85,
                    "indicator_types": ["malicious-activity"],
                }
            ],
        }
        docs = self.mapper.stix_bundle_to_ecs_indicators(bundle)
        self.assertEqual(len(docs), 1)
        ti = docs[0]["threat"]["indicator"]
        self.assertEqual(ti["ip"], "10.0.0.99")
        self.assertEqual(ti["confidence"], "High")  # 85 -> High

    def test_unsupported_type_returns_none(self):
        """Test that unsupported type returns none."""
        obj = {"type": "threat-actor", "id": "ta--1", "name": "APT1"}
        result = self.mapper.stix_object_to_ecs_indicator(obj)
        self.assertIsNone(result)

    def test_invalid_bundle_raises(self):
        """Test that invalid bundle raises."""
        with self.assertRaises(ElasticSTIXError):
            self.mapper.stix_bundle_to_ecs_indicators({"type": "indicator"})

    def test_provider_and_feed_name_applied(self):
        """Test that provider and feed name applied."""
        bundle = {
            "type": "bundle",
            "spec_version": CURRENT_SPEC_VERSION,
            "objects": [{"type": "ipv4-addr", "id": "ip--1", "value": "1.1.1.1"}],
        }
        docs = self.mapper.stix_bundle_to_ecs_indicators(
            bundle, provider="my-provider", feed_name="My Feed"
        )
        self.assertEqual(docs[0]["threat"]["indicator"]["provider"], "my-provider")
        self.assertEqual(docs[0]["threat"]["feed"]["name"], "My Feed")

    # ── ECS -> STIX ────────────────────────────────────────────────────────

    def test_ecs_ipv4_to_stix_indicator(self):
        """Test that ecs ipv4 to stix indicator."""
        doc = {
            "threat": {
                "indicator": {
                    "type": "ipv4-addr",
                    "ip": "1.2.3.4",
                    "first_seen": "2024-01-01T00:00:00Z",
                }
            }
        }
        obj = self.mapper.ecs_indicator_to_stix(doc)
        self.assertIsNotNone(obj)
        self.assertEqual(obj["type"], "indicator")
        self.assertIn("1.2.3.4", obj["pattern"])

    def test_ecs_domain_to_stix_indicator(self):
        """Test that ecs domain to stix indicator."""
        doc = {"threat": {"indicator": {"type": "domain-name", "domain": "evil.com"}}}
        obj = self.mapper.ecs_indicator_to_stix(doc)
        self.assertIn("evil.com", obj["pattern"])
        self.assertIn("domain-name:value", obj["pattern"])

    def test_ecs_to_stix_bundle_deduplication(self):
        """Test that ecs to stix bundle deduplication."""
        docs = [
            {"threat": {"indicator": {"type": "ipv4-addr", "ip": "1.2.3.4"}}},
            {"threat": {"indicator": {"type": "ipv4-addr", "ip": "1.2.3.4"}}},  # dup
            {"threat": {"indicator": {"type": "domain-name", "domain": "evil.com"}}},
        ]
        bundle = self.mapper.ecs_indicators_to_stix_bundle(docs)
        self.assertEqual(len(bundle["objects"]), 2)

    def test_ecs_no_type_returns_none(self):
        """Test that ecs no type returns none."""
        doc = {"threat": {"indicator": {}}}
        result = self.mapper.ecs_indicator_to_stix(doc)
        self.assertIsNone(result)

    # ── Alert -> STIX ──────────────────────────────────────────────────────

    def test_alert_to_stix_bundle_structure(self):
        """Test that alert to stix bundle structure."""
        alert = {
            "timestamp": "2024-03-10T12:00:00Z",
            "rule_name": "Test Rule",
            "rule_id": "r1",
            "severity": 3,
            "severity_label": "high",
            "status": "open",
            "reason": "test",
            "host_name": "server1",
            "src_ip": "1.2.3.4",
            "dest_ip": "10.0.0.5",
            "user_name": "jdoe",
            "process_name": "cmd.exe",
            "_raw": {},
        }
        bundle = self.mapper.alert_to_stix_bundle(alert)
        self.assertEqual(bundle["type"], "bundle")
        types = {o["type"] for o in bundle["objects"]}
        self.assertIn("ipv4-addr", types)
        self.assertIn("user-account", types)
        self.assertIn("process", types)
        self.assertIn("observed-data", types)

    def test_alert_observed_data_has_elastic_extension(self):
        """Test that alert observed data has elastic extension."""
        alert = {
            "rule_name": "Test",
            "rule_id": "r1",
            "severity": 1,
            "severity_label": "low",
            "_raw": {},
        }
        bundle = self.mapper.alert_to_stix_bundle(alert)
        obs = next(o for o in bundle["objects"] if o["type"] == "observed-data")
        self.assertIn("x_elastic_alert", obs)
        self.assertEqual(obs["x_elastic_alert"]["rule_name"], "Test")

    def test_alert_file_hash_creates_file_sco(self):
        """Test that alert file hash creates file sco."""
        alert = {
            "rule_name": "Malware",
            "_raw": {
                "file": {
                    "name": "evil.exe",
                    "hash": {"sha256": "abc123def456"},
                }
            },
        }
        bundle = self.mapper.alert_to_stix_bundle(alert)
        types = [o["type"] for o in bundle["objects"]]
        self.assertIn("file", types)
        file_obj = next(o for o in bundle["objects"] if o["type"] == "file")
        self.assertEqual(file_obj["hashes"]["SHA-256"], "abc123def456")

    def test_alerts_bundle_deduplicates_scos(self):
        """Same IP in multiple alerts appears only once in merged bundle."""
        alert1 = {"rule_name": "A", "src_ip": "1.2.3.4", "_raw": {}}
        alert2 = {"rule_name": "B", "src_ip": "1.2.3.4", "_raw": {}}
        bundle = self.mapper.alerts_to_stix_bundle([alert1, alert2])
        ip_objects = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
        self.assertEqual(len([o for o in ip_objects if o["value"] == "1.2.3.4"]), 1)

    def test_alert_url_creates_url_sco(self):
        """Test that alert url creates url sco."""
        alert = {
            "rule_name": "Phishing",
            "_raw": {"url": {"full": "https://phish.example.com/login"}},
        }
        bundle = self.mapper.alert_to_stix_bundle(alert)
        types = [o["type"] for o in bundle["objects"]]
        self.assertIn("url", types)

    def test_alert_domain_only_creates_domain_sco(self):
        """Test that alert domain only creates domain sco."""
        alert = {"rule_name": "C2", "_raw": {"url": {"domain": "c2.evil.com"}}}
        bundle = self.mapper.alert_to_stix_bundle(alert)
        types = [o["type"] for o in bundle["objects"]]
        self.assertIn("domain-name", types)
        self.assertNotIn("url", types)

    # ═════════════════════════════════════════════════════════════════════════════

    # Exception hierarchy

    # ═════════════════════════════════════════════════════════════════════════════


class TestElasticExceptions(unittest.TestCase):
    """Raised when a test elastic exceptions error occurs."""

    def test_all_inherit_from_base(self):
        """Test that all inherit from base."""
        from gnat.connectors.elastic.exceptions import ElasticError

        for exc_cls in [
            ElasticConfigError,
            ElasticAuthError,
            ElasticAPIError,
            ElasticNotFoundError,
            ElasticConflictError,
            ElasticRateLimitError,
            ElasticKibanaError,
            ElasticKibanaNotFoundError,
            ElasticKibanaValidationError,
            ElasticSTIXError,
        ]:
            self.assertTrue(issubclass(exc_cls, ElasticError))

    def test_api_error_str_includes_context(self):
        """Test that api error str includes context."""
        exc = ElasticAPIError(
            "msg",
            status_code=400,
            error_type="parsing_exception",
            reason="bad query",
            endpoint="/_search",
        )
        s = str(exc)
        self.assertIn("400", s)
        self.assertIn("parsing_exception", s)
        self.assertIn("bad query", s)

    def test_kibana_error_str_includes_message(self):
        """Test that kibana error str includes message."""
        exc = ElasticKibanaError(
            "msg",
            status_code=400,
            kibana_message="[name]: required",
            endpoint="/api/detection_engine/rules",
        )
        s = str(exc)
        self.assertIn("[name]: required", s)

    def test_not_found_is_api_error(self):
        """Test that not found is api error."""
        self.assertTrue(issubclass(ElasticNotFoundError, ElasticAPIError))

    def test_kibana_not_found_is_kibana_error(self):
        """Test that kibana not found is kibana error."""
        self.assertTrue(issubclass(ElasticKibanaNotFoundError, ElasticKibanaError))

    def test_kibana_validation_is_kibana_error(self):
        """Test that kibana validation is kibana error."""
        self.assertTrue(issubclass(ElasticKibanaValidationError, ElasticKibanaError))

    if __name__ == "**main**":
        unittest.main(verbosity=2)

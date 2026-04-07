# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
Comprehensive unit tests for the Splunk connector modules.

Covers:
- gnat/connectors/splunk/client.py
- gnat/connectors/splunk/stix_mapper.py
- gnat/connectors/splunk/threat_intel.py
- gnat/connectors/splunk/search.py
- gnat/connectors/splunk/kvstore.py
- gnat/connectors/splunk/alerts.py
"""

import json
from unittest.mock import MagicMock, patch

import pytest
import urllib3

from gnat.connectors.splunk.alerts import SplunkAlertCommands
from gnat.connectors.splunk.client import SplunkClient
from gnat.connectors.splunk.config import SplunkConfig
from gnat.connectors.splunk.exceptions import (
    SplunkAPIError,
    SplunkAuthError,
    SplunkNotFoundError,
    SplunkRateLimitError,
    SplunkSearchError,
    SplunkSTIXError,
    SplunkThreatIntelError,
)
from gnat.connectors.splunk.kvstore import SplunkKVStoreCommands
from gnat.connectors.splunk.search import SplunkSearchCommands
from gnat.connectors.splunk.stix_mapper import SplunkSTIXMapper
from gnat.connectors.splunk.threat_intel import SplunkThreatIntelCommands

# ── Shared helpers ────────────────────────────────────────────────────────────


def _make_config(
    host="splunk.example.com",
    token="test-token",
    username="",
    password="",
    es_enabled=False,
    app_context="search",
    owner_name="admin",
) -> SplunkConfig:
    """Build a minimal SplunkConfig for tests (bypasses validation)."""
    cfg = SplunkConfig.__new__(SplunkConfig)
    cfg.host = host
    cfg.port = 8089
    cfg.scheme = "https"
    cfg.username = username or owner_name if not token else username
    cfg.password = password
    cfg.token = token
    cfg.verify_ssl = True
    cfg.app_context = app_context
    cfg.es_enabled = es_enabled
    cfg.default_index = "main"
    cfg.timeout = 30
    cfg.max_results = 10000
    cfg.base_url = f"https://{host}:8089"
    return cfg


def _make_http_response(status: int, body: dict | list | bytes) -> MagicMock:
    """Create a mock urllib3 HTTPResponse."""
    resp = MagicMock()
    resp.status = status
    if isinstance(body, (dict, list)):
        resp.data = json.dumps(body).encode("utf-8")
    else:
        resp.data = body
    return resp


def _make_client(token="test-token", es_enabled=False) -> SplunkClient:
    """Create a SplunkClient with a mocked pool manager."""
    cfg = _make_config(token=token, es_enabled=es_enabled)
    with patch("urllib3.PoolManager"):
        client = SplunkClient(config=cfg)
    client._authenticated = True
    return client


# ═══════════════════════════════════════════════════════════════════════════════
# SplunkClient tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSplunkClientInit:
    def test_init_with_config_object(self):
        cfg = _make_config()
        with patch("urllib3.PoolManager"):
            client = SplunkClient(config=cfg)
        assert client.config is cfg

    def test_init_with_keyword_args_token(self):
        with patch("urllib3.PoolManager"):
            client = SplunkClient(host="https://splunk.corp.com:8089", api_token="mytoken")
        assert client.config.token == "mytoken"

    def test_init_with_keyword_args_username_password(self):
        with patch("urllib3.PoolManager"):
            client = SplunkClient(
                host="https://splunk.corp.com:8089",
                username="admin",
                password="secret",
            )
        assert client.config.username == "admin"
        assert client.config.password == "secret"

    def test_init_no_credentials_allowed(self):
        """Client construction without credentials is allowed; raises only on authenticate()."""
        with patch("urllib3.PoolManager"):
            client = SplunkClient(host="https://splunk.corp.com:8089")
        assert client.config.token == ""

    def test_context_manager(self):
        cfg = _make_config()
        with patch("urllib3.PoolManager"):
            client = SplunkClient(config=cfg)
        client._splunk_auth = MagicMock()
        client._splunk_http = MagicMock()
        with client as c:
            assert c is client
        client._splunk_auth.logout.assert_called_once()

    def test_base_url_parsed_from_host(self):
        with patch("urllib3.PoolManager"):
            client = SplunkClient(host="https://splunk.corp.com:9000", api_token="tok")
        assert client.config.port == 9000
        assert client.config.host == "splunk.corp.com"
        assert client.config.scheme == "https"


class TestSplunkClientAuthenticate:
    def test_authenticate_token_sets_bearer_header(self):
        client = _make_client(token="mytoken")
        client._authenticated = False
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Bearer mytoken"
        assert client._authenticated is True

    def test_authenticate_session_key_via_post(self):
        client = _make_client(token="")
        client.config.username = "admin"
        client.config.password = "pass"
        client._authenticated = False
        client.post = MagicMock(return_value={"sessionKey": "SK123"})
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Splunk SK123"
        assert client._authenticated is True

    def test_authenticate_no_credentials_raises(self):
        client = _make_client(token="")
        client._authenticated = False
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError, match="no credentials"):
            client.authenticate()


class TestSplunkClientHTTPMethods:
    @pytest.fixture
    def client(self):
        return _make_client()

    def test_get_calls_request(self, client):
        mock_resp = _make_http_response(200, {"entry": []})
        client._splunk_auth = MagicMock()
        client._splunk_auth.get_auth_headers.return_value = {"Authorization": "Splunk tok"}
        client._splunk_http = MagicMock()
        client._splunk_http.request.return_value = mock_resp
        result = client.get("server/info", namespaced=False)
        assert result == {"entry": []}

    def test_get_namespaced_uses_servicesns(self, client):
        mock_resp = _make_http_response(200, {"entry": []})
        client._splunk_auth = MagicMock()
        client._splunk_auth.get_auth_headers.return_value = {"Authorization": "Splunk tok"}
        client._splunk_http = MagicMock()
        client._splunk_http.request.return_value = mock_resp
        client.get("search/jobs", namespaced=True)
        call_args = client._splunk_http.request.call_args
        url = call_args[0][1]
        assert "/servicesNS/" in url

    def test_get_raw_returns_bytes(self, client):
        raw_bytes = b"raw content"
        mock_resp = _make_http_response(200, raw_bytes)
        client._splunk_auth = MagicMock()
        client._splunk_auth.get_auth_headers.return_value = {"Authorization": "Splunk tok"}
        client._splunk_http = MagicMock()
        client._splunk_http.request.return_value = mock_resp
        result = client.get("data/file", namespaced=False, raw=True)
        assert result == raw_bytes

    def test_post_form_encodes_data(self, client):
        mock_resp = _make_http_response(200, {"sid": "12345"})
        client._splunk_auth = MagicMock()
        client._splunk_auth.get_auth_headers.return_value = {"Authorization": "Splunk tok"}
        client._splunk_http = MagicMock()
        client._splunk_http.request.return_value = mock_resp
        result = client.post("search/jobs", data={"search": "index=main"})
        assert result == {"sid": "12345"}

    def test_post_raw_body(self, client):
        mock_resp = _make_http_response(200, {"_key": "abc"})
        client._splunk_auth = MagicMock()
        client._splunk_auth.get_auth_headers.return_value = {"Authorization": "Splunk tok"}
        client._splunk_http = MagicMock()
        client._splunk_http.request.return_value = mock_resp
        body = json.dumps({"ip": "1.2.3.4"}).encode()
        result = client.post(
            "storage/collections/data/ip_intel",
            raw_body=body,
            content_type="application/json",
            namespaced=False,
        )
        assert result["_key"] == "abc"

    def test_delete_appends_output_mode(self, client):
        mock_resp = _make_http_response(200, {})
        client._splunk_auth = MagicMock()
        client._splunk_auth.get_auth_headers.return_value = {"Authorization": "Splunk tok"}
        client._splunk_http = MagicMock()
        client._splunk_http.request.return_value = mock_resp
        client.delete("search/jobs/123", namespaced=False)
        url = client._splunk_http.request.call_args[0][1]
        assert "output_mode=json" in url

    def test_put_sends_json_body(self, client):
        mock_resp = _make_http_response(200, {"_key": "k1"})
        client._splunk_auth = MagicMock()
        client._splunk_auth.get_auth_headers.return_value = {"Authorization": "Splunk tok"}
        client._splunk_http = MagicMock()
        client._splunk_http.request.return_value = mock_resp
        result = client.put(
            "storage/collections/data/ip_intel/k1", data={"ip": "5.5.5.5"}, namespaced=False
        )
        assert result["_key"] == "k1"


class TestSplunkClientErrorHandling:
    @pytest.fixture
    def client(self):
        return _make_client()

    def _setup_response(self, client, status, body=None):
        mock_resp = _make_http_response(status, body or {})
        client._splunk_auth = MagicMock()
        client._splunk_auth.get_auth_headers.return_value = {"Authorization": "Splunk tok"}
        client._splunk_http = MagicMock()
        client._splunk_http.request.return_value = mock_resp
        return mock_resp

    def test_404_raises_splunk_not_found(self, client):
        self._setup_response(client, 404)
        with pytest.raises(SplunkNotFoundError):
            client.get("missing/resource", namespaced=False)

    def test_403_raises_splunk_auth_error(self, client):
        self._setup_response(client, 403)
        with pytest.raises(SplunkAuthError):
            client.get("forbidden/endpoint", namespaced=False)

    def test_500_raises_after_retries(self, client):
        mock_resp = _make_http_response(500, {"messages": [{"text": "Internal Error"}]})
        client._splunk_auth = MagicMock()
        client._splunk_auth.get_auth_headers.return_value = {"Authorization": "Splunk tok"}
        client._splunk_http = MagicMock()
        client._splunk_http.request.return_value = mock_resp
        with patch("time.sleep"), pytest.raises(SplunkAPIError):
            client.get("server/info", namespaced=False)

    def test_401_on_first_attempt_invalidates_and_retries(self, client):
        ok_resp = _make_http_response(200, {"entry": []})
        unauthorized_resp = _make_http_response(401, {})
        client._splunk_auth = MagicMock()
        client._splunk_auth.get_auth_headers.return_value = {"Authorization": "Splunk tok"}
        client._splunk_http = MagicMock()
        client._splunk_http.request.side_effect = [unauthorized_resp, ok_resp]
        result = client.get("server/info", namespaced=False)
        assert result == {"entry": []}
        client._splunk_auth.invalidate_session.assert_called_once()

    def test_401_on_second_attempt_raises_auth_error(self, client):
        unauthorized_resp = _make_http_response(401, {})
        client._splunk_auth = MagicMock()
        client._splunk_auth.get_auth_headers.return_value = {"Authorization": "Splunk tok"}
        client._splunk_http = MagicMock()
        client._splunk_http.request.return_value = unauthorized_resp
        with pytest.raises(SplunkAuthError):
            client.get("server/info", namespaced=False)

    def test_429_raises_rate_limit_after_retries(self, client):
        rate_resp = _make_http_response(429, {})
        client._splunk_auth = MagicMock()
        client._splunk_auth.get_auth_headers.return_value = {"Authorization": "Splunk tok"}
        client._splunk_http = MagicMock()
        client._splunk_http.request.return_value = rate_resp
        with patch("time.sleep"), pytest.raises(SplunkRateLimitError):
            client.get("server/info", namespaced=False)

    def test_invalid_json_response_raises_api_error(self, client):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.data = b"not valid json {{{"
        client._splunk_auth = MagicMock()
        client._splunk_auth.get_auth_headers.return_value = {"Authorization": "Splunk tok"}
        client._splunk_http = MagicMock()
        client._splunk_http.request.return_value = mock_resp
        with pytest.raises(SplunkAPIError, match="Failed to parse JSON"):
            client.get("server/info", namespaced=False)

    def test_http_error_raises_api_error_after_retries(self, client):
        client._splunk_auth = MagicMock()
        client._splunk_auth.get_auth_headers.return_value = {"Authorization": "Splunk tok"}
        client._splunk_http = MagicMock()
        client._splunk_http.request.side_effect = urllib3.exceptions.HTTPError("conn refused")
        with patch("time.sleep"), pytest.raises(SplunkAPIError, match="Connection error"):
            client.get("server/info", namespaced=False)


class TestSplunkClientPaginate:
    def test_paginate_yields_all_entries(self):
        client = _make_client()
        page1 = {"entry": [{"name": f"e{i}"} for i in range(5)]}
        page2 = {"entry": [{"name": f"e{i}"} for i in range(5, 8)]}
        client.get = MagicMock(side_effect=[page1, page2])
        entries = list(client.paginate("saved/searches", page_size=5))
        assert len(entries) == 8

    def test_paginate_stops_on_short_page(self):
        client = _make_client()
        page1 = {"entry": [{"name": "e1"}, {"name": "e2"}]}
        client.get = MagicMock(return_value=page1)
        entries = list(client.paginate("saved/searches", page_size=100))
        assert len(entries) == 2
        assert client.get.call_count == 1


class TestSplunkClientHealthCheck:
    def test_health_check_true_on_success(self):
        client = _make_client()
        client.get = MagicMock(return_value={"entry": [{"content": {}}]})
        assert client.health_check() is True

    def test_health_check_false_on_error(self):
        client = _make_client()
        client.get = MagicMock(side_effect=SplunkAPIError("connection refused"))
        assert client.health_check() is False


class TestSplunkClientStixIntegration:
    @pytest.fixture
    def client(self):
        return _make_client()

    def test_get_object_indicator_found(self, client):
        entry = {"content": {"ip": "9.9.9.9", "_time": "2024-01-01T00:00:00Z"}}
        client.get = MagicMock(return_value={"entry": [entry]})
        result = client.get_object("indicator", "key-123")
        assert "ipv4-addr" in result["pattern"]

    def test_get_object_indicator_not_found_raises(self, client):
        client.get = MagicMock(return_value={"entry": []})
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError, match="not found"):
            client.get_object("indicator", "missing-key")

    def test_get_object_observed_data_found(self, client):
        client.post = MagicMock(
            return_value={"results": [{"rule_name": "Rule1", "_time": "2024-01-01T00:00:00Z"}]}
        )
        result = client.get_object("observed-data", "EVT-001")
        assert result["type"] == "indicator"

    def test_get_object_observed_data_not_found_raises(self, client):
        client.post = MagicMock(return_value={"results": []})
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError, match="not found"):
            client.get_object("observed-data", "EVT-MISSING")

    def test_list_objects_indicator(self, client):
        entries = [{"content": {"ip": f"10.0.0.{i}", "_time": ""}} for i in range(3)]
        client.get = MagicMock(return_value={"entry": entries})
        results = client.list_objects("indicator")
        assert len(results) == 3
        for r in results:
            assert r["type"] == "indicator"

    def test_list_objects_default_runs_search(self, client):
        client.post = MagicMock(
            return_value={"results": [{"rule_name": "Rule1", "_time": "2024-01-01"}]}
        )
        results = client.list_objects("observed-data")
        assert len(results) == 1

    def test_upsert_object_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.upsert_object("indicator", {})

    def test_delete_object_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.delete_object("indicator", "id-123")

    def test_to_stix_domain(self, client):
        result = client.to_stix({"domain": "evil.com", "_time": "2024-01-01"})
        assert "domain-name" in result["pattern"]
        assert "evil.com" in result["pattern"]

    def test_to_stix_unknown_defaults_to_network(self, client):
        result = client.to_stix({"_time": "2024-01-01"})
        assert result["type"] == "indicator"
        assert "network-traffic" in result["pattern"]

    def test_from_stix_url_pattern(self, client):
        result = client.from_stix(
            {
                "name": "http://bad.com/path",
                "pattern": "[url:value = 'http://bad.com/path']",
            }
        )
        assert result["ioc_type"] == "url"

    def test_from_stix_hash_pattern(self, client):
        result = client.from_stix(
            {
                "name": "aabbccdd",
                "pattern": "[file:hashes.MD5 = 'aabbccdd']",
            }
        )
        assert result["ioc_type"] == "hash"

    def test_from_stix_unknown_pattern(self, client):
        result = client.from_stix(
            {
                "name": "unknown",
                "pattern": "[something:weird = 'val']",
            }
        )
        assert result["ioc_type"] == "unknown"

    def test_post_raw_method(self, client):
        fake_response = MagicMock()
        fake_response.data = json.dumps({"sessionKey": "sk"}).encode()
        with patch("urllib3.PoolManager") as mock_pm:
            mock_pm.return_value.request.return_value = fake_response
            result = client.post_raw(
                "https://splunk.example.com:8089/services/auth/login",
                data={"username": "admin", "password": "pass"},
            )
        assert result.get("sessionKey") == "sk"


class TestSplunkClientBuildUrl:
    def test_build_url_namespaced(self):
        client = _make_client()
        url = client._build_url("search/jobs", namespaced=True)
        assert "/servicesNS/" in url
        assert "search/jobs" in url

    def test_build_url_not_namespaced(self):
        client = _make_client()
        url = client._build_url("server/info", namespaced=False)
        assert "/services/server/info" in url

    def test_inject_output_mode_adds_json(self):
        result = SplunkClient._inject_output_mode(None)
        assert result["output_mode"] == "json"

    def test_inject_output_mode_preserves_existing(self):
        result = SplunkClient._inject_output_mode({"count": 10})
        assert result["output_mode"] == "json"
        assert result["count"] == 10


# ═══════════════════════════════════════════════════════════════════════════════
# SplunkSTIXMapper tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSplunkSTIXMapperSCOToRecord:
    @pytest.fixture
    def mapper(self):
        return SplunkSTIXMapper()

    def test_ipv4_maps_to_ip_collection(self, mapper):
        obj = {"type": "ipv4-addr", "id": "ipv4-addr--abc", "value": "1.2.3.4"}
        result = mapper._sco_to_record(obj, 50)
        assert result["collection"] == "ip"
        assert result["record"]["ip"] == "1.2.3.4"

    def test_ipv6_maps_to_ip_collection(self, mapper):
        obj = {"type": "ipv6-addr", "id": "ipv6-addr--abc", "value": "::1"}
        result = mapper._sco_to_record(obj, 50)
        assert result["collection"] == "ip"

    def test_domain_maps_correctly(self, mapper):
        obj = {"type": "domain-name", "id": "domain-name--abc", "value": "evil.com"}
        result = mapper._sco_to_record(obj, 50)
        assert result["collection"] == "domain"
        assert result["record"]["domain"] == "evil.com"

    def test_url_maps_correctly(self, mapper):
        obj = {"type": "url", "id": "url--abc", "value": "https://evil.com/path"}
        result = mapper._sco_to_record(obj, 50)
        assert result["collection"] == "url"
        assert result["record"]["url"] == "https://evil.com/path"

    def test_file_maps_hashes(self, mapper):
        obj = {
            "type": "file",
            "id": "file--abc",
            "name": "evil.exe",
            "hashes": {"MD5": "deadbeef", "SHA-256": "abcdef01"},
        }
        result = mapper._sco_to_record(obj, 50)
        assert result["collection"] == "file"
        assert result["record"]["md5"] == "deadbeef"
        assert result["record"]["sha256"] == "abcdef01"
        assert result["record"]["file_name"] == "evil.exe"

    def test_email_addr_maps_correctly(self, mapper):
        obj = {
            "type": "email-addr",
            "id": "email-addr--abc",
            "value": "threat@evil.com",
            "display_name": "Threat Actor",
        }
        result = mapper._sco_to_record(obj, 50)
        assert result["collection"] == "email"
        assert result["record"]["src_user"] == "threat@evil.com"

    def test_process_maps_correctly(self, mapper):
        obj = {
            "type": "process",
            "id": "process--abc",
            "name": "malware.exe",
            "command_line": "malware.exe --install",
        }
        result = mapper._sco_to_record(obj, 50)
        assert result["collection"] == "process"
        assert result["record"]["process"] == "malware.exe"

    def test_windows_registry_key_maps_correctly(self, mapper):
        obj = {
            "type": "windows-registry-key",
            "id": "windows-registry-key--abc",
            "key": r"HKLM\Software\evil",
        }
        result = mapper._sco_to_record(obj, 50)
        assert result["collection"] == "registry"
        assert result["record"]["registry_key_name"] == r"HKLM\Software\evil"

    def test_x509_certificate_maps_correctly(self, mapper):
        obj = {
            "type": "x509-certificate",
            "id": "x509-certificate--abc",
            "hashes": {"SHA-256": "certsha256"},
            "serial_number": "SN123",
            "subject": "CN=evil.com",
        }
        result = mapper._sco_to_record(obj, 50)
        assert result["collection"] == "certificate"
        assert result["record"]["ssl_hash"] == "certsha256"
        assert result["record"]["ssl_serial"] == "SN123"

    def test_user_account_maps_correctly(self, mapper):
        obj = {
            "type": "user-account",
            "id": "user-account--abc",
            "user_id": "jdoe",
            "account_login": "DOMAIN\\jdoe",
        }
        result = mapper._sco_to_record(obj, 50)
        assert result["collection"] == "user"
        assert result["record"]["user"] == "jdoe"

    def test_unsupported_type_raises_stix_error(self, mapper):
        obj = {"type": "threat-actor", "id": "threat-actor--abc"}
        with pytest.raises(SplunkSTIXError):
            mapper._sco_to_record(obj, 50)

    def test_default_weight_applied_when_missing(self, mapper):
        obj = {"type": "ipv4-addr", "id": "ipv4-addr--abc", "value": "9.9.9.9"}
        result = mapper._sco_to_record(obj, 75)
        assert result["record"]["weight"] == "75"

    def test_key_defaults_to_object_id(self, mapper):
        obj = {"type": "ipv4-addr", "id": "ipv4-addr--myid", "value": "9.9.9.9"}
        result = mapper._sco_to_record(obj, 50)
        assert result["record"]["_key"] == "ipv4-addr--myid"

    def test_extra_gnat_fields_mapped(self, mapper):
        obj = {
            "type": "ipv4-addr",
            "id": "ipv4-addr--abc",
            "value": "1.2.3.4",
            "x_gnat_description": "C2 server",
            "x_gnat_threat_type": "c2",
            "x_gnat_weight": "80",
        }
        result = mapper._sco_to_record(obj, 50)
        assert result["record"]["description"] == "C2 server"
        assert result["record"]["threat_key"] == "c2"


class TestSplunkSTIXMapperIndicatorToRecord:
    @pytest.fixture
    def mapper(self):
        return SplunkSTIXMapper()

    def test_indicator_with_ip_pattern_maps_to_ip_collection(self, mapper):
        obj = {
            "type": "indicator",
            "id": "indicator--abc",
            "name": "Malicious IP",
            "pattern": "[ipv4-addr:value = '192.168.1.1']",
            "indicator_types": ["malicious-url"],
        }
        result = mapper._indicator_to_record(obj, 50)
        assert result["collection"] == "url"  # indicator_types hint
        assert result["record"]["stix_pattern"] == "[ipv4-addr:value = '192.168.1.1']"

    def test_indicator_default_collection_is_ip(self, mapper):
        obj = {
            "type": "indicator",
            "id": "indicator--abc",
            "name": "Unknown",
            "pattern": "[ipv4-addr:value = '10.0.0.1']",
            "indicator_types": [],
        }
        result = mapper._indicator_to_record(obj, 50)
        assert result["collection"] == "ip"

    def test_indicator_extracts_ip_from_pattern(self, mapper):
        obj = {
            "type": "indicator",
            "id": "indicator--abc",
            "name": "Bad IP",
            "pattern": "[ipv4-addr:value = '10.10.10.10']",
        }
        result = mapper._indicator_to_record(obj, 50)
        assert result["record"].get("ip") == "10.10.10.10"

    def test_indicator_extracts_domain_from_pattern(self, mapper):
        obj = {
            "type": "indicator",
            "id": "indicator--abc",
            "name": "Bad Domain",
            "pattern": "[domain-name:value = 'bad.example.com']",
            "indicator_types": ["attribution"],
        }
        result = mapper._indicator_to_record(obj, 50)
        assert result["collection"] == "domain"
        assert result["record"].get("domain") == "bad.example.com"

    def test_indicator_stores_valid_from(self, mapper):
        obj = {
            "type": "indicator",
            "id": "indicator--abc",
            "pattern": "[ipv4-addr:value = '1.1.1.1']",
            "valid_from": "2024-01-01T00:00:00Z",
            "valid_until": "2025-01-01T00:00:00Z",
        }
        result = mapper._indicator_to_record(obj, 50)
        assert result["record"]["valid_from"] == "2024-01-01T00:00:00Z"
        assert result["record"]["valid_until"] == "2025-01-01T00:00:00Z"


class TestSplunkSTIXMapperBulkConversion:
    @pytest.fixture
    def mapper(self):
        return SplunkSTIXMapper()

    def test_stix_objects_to_splunk_records_mixed_types(self, mapper):
        objects = [
            {"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "1.1.1.1"},
            {"type": "domain-name", "id": "domain-name--1", "value": "evil.com"},
            {"type": "url", "id": "url--1", "value": "https://evil.com"},
        ]
        results = mapper.stix_objects_to_splunk_records(objects)
        assert len(results) == 3
        collections = [r["collection"] for r in results]
        assert "ip" in collections
        assert "domain" in collections
        assert "url" in collections

    def test_stix_objects_unsupported_type_raises(self, mapper):
        objects = [{"type": "threat-actor", "id": "threat-actor--1", "name": "APT99"}]
        with pytest.raises(SplunkSTIXError, match="no Splunk KV store mapping"):
            mapper.stix_objects_to_splunk_records(objects)

    def test_stix_bundle_to_splunk_records(self, mapper):
        bundle = {
            "type": "bundle",
            "id": "bundle--abc",
            "spec_version": "2.1",
            "objects": [
                {"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "2.2.2.2"},
            ],
        }
        results = mapper.stix_bundle_to_splunk_records(bundle)
        assert len(results) == 1
        assert results[0]["collection"] == "ip"

    def test_stix_bundle_wrong_type_raises(self, mapper):
        with pytest.raises(SplunkSTIXError, match="Expected a STIX 2.1 bundle"):
            mapper.stix_bundle_to_splunk_records({"type": "indicator"})

    def test_observed_data_expands_inline_scos(self, mapper):
        observed = {
            "type": "observed-data",
            "id": "observed-data--1",
            "spec_version": "2.1",
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "first_observed": "2024-01-01T00:00:00Z",
            "last_observed": "2024-01-01T00:00:00Z",
            "number_observed": 1,
            "object_refs": [
                {"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "3.3.3.3"},
                {"type": "domain-name", "id": "domain-name--1", "value": "example.com"},
            ],
        }
        results = mapper.stix_objects_to_splunk_records([observed])
        assert len(results) == 2


class TestSplunkSTIXMapperSplunkToSTIX:
    @pytest.fixture
    def mapper(self):
        return SplunkSTIXMapper()

    def test_notable_to_stix_bundle_with_src_and_dest(self, mapper):
        notable = {
            "src": "10.0.0.1",
            "dest": "192.168.1.100",
            "user": "jdoe",
            "rule_name": "Brute Force Detected",
            "urgency": "high",
            "severity": "high",
            "event_id": "EVT-001",
            "timestamp": "2024-01-15T10:00:00Z",
        }
        bundle = mapper.splunk_notable_to_stix_bundle(notable)
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        # Should have: src ipv4, dest ipv4, user-account, observed-data
        types = [obj["type"] for obj in bundle["objects"]]
        assert "ipv4-addr" in types
        assert "user-account" in types
        assert "observed-data" in types

    def test_notable_to_stix_bundle_same_src_dest_deduped(self, mapper):
        notable = {"src": "10.0.0.1", "dest": "10.0.0.1"}
        bundle = mapper.splunk_notable_to_stix_bundle(notable)
        ip_objs = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
        assert len(ip_objs) == 1

    def test_notable_to_stix_bundle_empty_notable(self, mapper):
        bundle = mapper.splunk_notable_to_stix_bundle({})
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"

    def test_notable_has_gnat_metadata_fields(self, mapper):
        notable = {
            "rule_name": "Test Rule",
            "urgency": "medium",
            "event_id": "E123",
        }
        bundle = mapper.splunk_notable_to_stix_bundle(notable)
        obs_list = [o for o in bundle["objects"] if o["type"] == "observed-data"]
        assert len(obs_list) == 1
        obs = obs_list[0]
        assert obs["x_gnat_source"] == "splunk_es"
        assert obs["x_gnat_rule_name"] == "Test Rule"
        assert obs["x_gnat_urgency"] == "medium"

    def test_search_rows_to_stix_bundle_ip_fields(self, mapper):
        rows = [{"src_ip": "10.1.1.1", "dest_ip": "10.2.2.2"}]
        bundle = mapper.splunk_search_rows_to_stix_bundle(rows)
        ip_objs = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
        assert len(ip_objs) == 2

    def test_search_rows_to_stix_bundle_domain_fields(self, mapper):
        rows = [{"domain": "malware.com"}]
        bundle = mapper.splunk_search_rows_to_stix_bundle(rows)
        domain_objs = [o for o in bundle["objects"] if o["type"] == "domain-name"]
        assert len(domain_objs) == 1
        assert domain_objs[0]["value"] == "malware.com"

    def test_search_rows_to_stix_bundle_url_fields(self, mapper):
        rows = [{"url": "http://evil.com/payload"}]
        bundle = mapper.splunk_search_rows_to_stix_bundle(rows)
        url_objs = [o for o in bundle["objects"] if o["type"] == "url"]
        assert len(url_objs) == 1

    def test_search_rows_to_stix_bundle_file_hashes(self, mapper):
        rows = [{"md5": "deadbeef", "sha256": "abc123", "file_name": "bad.exe"}]
        bundle = mapper.splunk_search_rows_to_stix_bundle(rows)
        file_objs = [o for o in bundle["objects"] if o["type"] == "file"]
        assert len(file_objs) == 1
        assert file_objs[0]["hashes"]["MD5"] == "deadbeef"
        assert file_objs[0]["name"] == "bad.exe"

    def test_search_rows_to_stix_bundle_user_fields(self, mapper):
        rows = [{"src_user": "DOMAIN\\jdoe"}]
        bundle = mapper.splunk_search_rows_to_stix_bundle(rows)
        user_objs = [o for o in bundle["objects"] if o["type"] == "user-account"]
        assert len(user_objs) == 1

    def test_search_rows_deduplicates_identical_ips(self, mapper):
        rows = [
            {"src_ip": "10.0.0.1"},
            {"src_ip": "10.0.0.1"},
        ]
        bundle = mapper.splunk_search_rows_to_stix_bundle(rows)
        ip_objs = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
        assert len(ip_objs) == 1

    def test_search_rows_empty_list_returns_empty_bundle(self, mapper):
        bundle = mapper.splunk_search_rows_to_stix_bundle([])
        assert bundle["type"] == "bundle"
        obj_types = [o["type"] for o in bundle["objects"]]
        assert "observed-data" not in obj_types

    def test_search_rows_gnat_source_tag(self, mapper):
        rows = [{"src_ip": "1.1.1.1"}]
        bundle = mapper.splunk_search_rows_to_stix_bundle(rows)
        obs = [o for o in bundle["objects"] if o["type"] == "observed-data"]
        assert obs[0]["x_gnat_source"] == "splunk_search"

    def test_search_rows_with_alt_src_field(self, mapper):
        rows = [{"src": "172.16.0.1"}]
        bundle = mapper.splunk_search_rows_to_stix_bundle(rows)
        ip_objs = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
        assert len(ip_objs) == 1


class TestSplunkSTIXMapperExtractPatternValue:
    def test_extract_ip_value(self):
        record = {}
        SplunkSTIXMapper._extract_pattern_value("[ipv4-addr:value = '5.5.5.5']", "ip", record)
        assert record["ip"] == "5.5.5.5"

    def test_extract_domain_value(self):
        record = {}
        SplunkSTIXMapper._extract_pattern_value(
            "[domain-name:value = 'bad.example.com']", "domain", record
        )
        assert record["domain"] == "bad.example.com"

    def test_no_match_does_nothing(self):
        record = {}
        SplunkSTIXMapper._extract_pattern_value("no pattern here", "ip", record)
        assert record == {}

    def test_does_not_overwrite_existing_value(self):
        record = {"ip": "1.1.1.1"}
        SplunkSTIXMapper._extract_pattern_value("[ipv4-addr:value = '2.2.2.2']", "ip", record)
        assert record["ip"] == "1.1.1.1"


# ═══════════════════════════════════════════════════════════════════════════════
# SplunkThreatIntelCommands tests
# ═══════════════════════════════════════════════════════════════════════════════


def _make_threat_intel_client(es_enabled=True):
    client = _make_client(es_enabled=es_enabled)
    client.config.username = "admin"
    threat_intel = SplunkThreatIntelCommands(client)
    return threat_intel, client


class TestSplunkThreatIntelCommands:
    def test_require_es_raises_when_disabled(self):
        ti, _ = _make_threat_intel_client(es_enabled=False)
        with pytest.raises(SplunkThreatIntelError, match="es_enabled"):
            ti._require_es()

    def test_require_es_passes_when_enabled(self):
        ti, _ = _make_threat_intel_client(es_enabled=True)
        ti._require_es()  # should not raise

    def test_validate_collection_valid(self):
        ti, _ = _make_threat_intel_client()
        assert ti._validate_collection("ip") == "ip_intel"
        assert ti._validate_collection("domain") == "domain_intel"
        assert ti._validate_collection("url") == "url_intel"
        assert ti._validate_collection("file") == "file_intel"
        assert ti._validate_collection("email") == "email_intel"

    def test_validate_collection_strips_intel_suffix(self):
        ti, _ = _make_threat_intel_client()
        assert ti._validate_collection("ip_intel") == "ip_intel"

    def test_validate_collection_invalid_raises(self):
        ti, _ = _make_threat_intel_client()
        with pytest.raises(SplunkThreatIntelError, match="Unknown intel collection"):
            ti._validate_collection("foobar")

    def test_list_iocs_returns_list_response(self):
        ti, client = _make_threat_intel_client()
        records = [{"ip": "1.2.3.4", "_key": "k1"}]
        client.get = MagicMock(return_value=records)
        result = ti.list_iocs("ip", count=50)
        assert result == records

    def test_list_iocs_returns_entry_wrapped_response(self):
        ti, client = _make_threat_intel_client()
        entries = [{"content": {"ip": "5.5.5.5"}}]
        client.get = MagicMock(return_value={"entry": entries})
        result = ti.list_iocs("ip")
        assert result == entries

    def test_list_iocs_with_query_filter(self):
        ti, client = _make_threat_intel_client()
        client.get = MagicMock(return_value=[])
        ti.list_iocs("ip", query={"ip": "1.2.3.4"})
        call_kwargs = client.get.call_args[1]
        assert "query" in call_kwargs.get("params", {})

    def test_list_iocs_requires_es(self):
        ti, _ = _make_threat_intel_client(es_enabled=False)
        with pytest.raises(SplunkThreatIntelError):
            ti.list_iocs("ip")

    def test_get_ioc_returns_record(self):
        ti, client = _make_threat_intel_client()
        expected = {"ip": "1.2.3.4", "_key": "k1"}
        client.get = MagicMock(return_value=expected)
        result = ti.get_ioc("ip", "k1")
        assert result == expected

    def test_get_ioc_returns_none_on_exception(self):
        ti, client = _make_threat_intel_client()
        client.get = MagicMock(side_effect=Exception("not found"))
        result = ti.get_ioc("ip", "missing")
        assert result is None

    def test_upsert_ioc_with_key_calls_put(self):
        ti, client = _make_threat_intel_client()
        client.put = MagicMock(return_value={"_key": "k1"})
        result = ti.upsert_ioc("ip", {"_key": "k1", "ip": "1.2.3.4"})
        assert result["_key"] == "k1"
        client.put.assert_called_once()

    def test_upsert_ioc_without_key_calls_post(self):
        ti, client = _make_threat_intel_client()
        client.post = MagicMock(return_value={"_key": "generated-key"})
        result = ti.upsert_ioc("ip", {"ip": "2.2.2.2"})
        assert result["_key"] == "generated-key"
        client.post.assert_called_once()

    def test_upsert_iocs_bulk_batches_correctly(self):
        ti, client = _make_threat_intel_client()
        client.post = MagicMock(return_value={"_key": "k"})
        records = [{"ip": f"10.0.0.{i}"} for i in range(600)]
        ti.upsert_iocs_bulk("ip", records, batch_size=200)
        assert client.post.call_count == 3

    def test_delete_ioc_calls_client_delete(self):
        ti, client = _make_threat_intel_client()
        client.delete = MagicMock(return_value={})
        ti.delete_ioc("ip", "k1")
        client.delete.assert_called_once()

    def test_clear_collection_calls_client_delete(self):
        ti, client = _make_threat_intel_client()
        client.delete = MagicMock(return_value={})
        ti.clear_collection("domain")
        client.delete.assert_called_once()

    def test_upload_stix_file_posts_content(self):
        ti, client = _make_threat_intel_client()
        client.post = MagicMock(return_value={"status": "ok"})
        stix_bytes = json.dumps({"type": "bundle", "objects": []}).encode()
        result = ti.upload_stix_file(stix_bytes, "my_source", collection="ip")
        assert result["status"] == "ok"

    def test_upload_stix_file_wraps_exception_as_threat_intel_error(self):
        ti, client = _make_threat_intel_client()
        client.post = MagicMock(side_effect=Exception("network error"))
        stix_bytes = b'{"type":"bundle","objects":[]}'
        with pytest.raises(SplunkThreatIntelError, match="failed"):
            ti.upload_stix_file(stix_bytes, "source", collection="ip")

    def test_upload_stix_bundle_dict(self):
        ti, client = _make_threat_intel_client()
        client.post = MagicMock(return_value={"status": "ok"})
        bundle = {"type": "bundle", "spec_version": "2.1", "objects": []}
        result = ti.upload_stix_bundle_dict(bundle, "test_source")
        assert result["status"] == "ok"

    def test_list_intel_sources_returns_normalised(self):
        ti, client = _make_threat_intel_client()
        client.get = MagicMock(
            return_value={
                "entry": [
                    {
                        "name": "my_feed",
                        "content": {
                            "type": "stix2",
                            "collection": "ip_intel",
                            "weight": "50",
                            "disabled": "false",
                            "status": "active",
                            "last_successful_execution": "2024-01-01T00:00:00Z",
                        },
                    }
                ]
            }
        )
        result = ti.list_intel_sources()
        assert len(result) == 1
        assert result[0]["name"] == "my_feed"
        assert result[0]["type"] == "stix2"

    def test_enable_intel_source_calls_post_with_disabled_false(self):
        ti, client = _make_threat_intel_client()
        client.post = MagicMock(return_value={})
        ti.enable_intel_source("my_feed")
        call_kwargs = client.post.call_args[1]
        assert call_kwargs.get("data", {}).get("disabled") == "false"

    def test_disable_intel_source_calls_post_with_disabled_true(self):
        ti, client = _make_threat_intel_client()
        client.post = MagicMock(return_value={})
        ti.disable_intel_source("my_feed")
        call_kwargs = client.post.call_args[1]
        assert call_kwargs.get("data", {}).get("disabled") == "true"

    def test_es_path_builds_correct_url(self):
        ti, client = _make_threat_intel_client()
        path = ti._es_path("storage/collections/data/ip_intel")
        assert "SplunkEnterpriseSecuritySuite" in path
        assert "storage/collections/data/ip_intel" in path


# ═══════════════════════════════════════════════════════════════════════════════
# SplunkSearchCommands tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSplunkSearchCommands:
    @pytest.fixture
    def client(self):
        return _make_client()

    @pytest.fixture
    def searcher(self, client):
        return SplunkSearchCommands(client)

    def test_create_search_job_returns_sid(self, searcher, client):
        client.post = MagicMock(return_value={"sid": "1234567890.1"})
        sid = searcher.create_search_job("search index=main | head 10")
        assert sid == "1234567890.1"

    def test_create_search_job_raises_when_no_sid(self, searcher, client):
        client.post = MagicMock(return_value={})
        with pytest.raises(SplunkSearchError, match="SID"):
            searcher.create_search_job("search index=main")

    def test_create_search_job_passes_extra_kwargs(self, searcher, client):
        client.post = MagicMock(return_value={"sid": "abc"})
        searcher.create_search_job("search *", status_buckets=300, rf="*")
        call_kwargs = client.post.call_args[1]
        assert "status_buckets" in call_kwargs["data"]

    def test_poll_job_returns_done(self, searcher, client):
        done_response = {"entry": [{"content": {"dispatchState": "DONE"}}]}
        client.get = MagicMock(return_value=done_response)
        state = searcher.poll_job("test-sid")
        assert state == "DONE"

    def test_poll_job_raises_on_failed_state(self, searcher, client):
        failed_response = {"entry": [{"content": {"dispatchState": "FAILED", "messages": {}}}]}
        client.get = MagicMock(return_value=failed_response)
        with pytest.raises(SplunkSearchError, match="failed"):
            searcher.poll_job("test-sid")

    def test_poll_job_raises_on_timeout(self, searcher, client):
        running_response = {"entry": [{"content": {"dispatchState": "RUNNING"}}]}
        client.get = MagicMock(return_value=running_response)
        with (
            patch("time.sleep"),
            patch("time.time", side_effect=[0, 0, 999]),
            pytest.raises(SplunkSearchError, match="timed out"),
        ):
            searcher.poll_job("test-sid", timeout=5)

    def test_fetch_results_returns_rows(self, searcher, client):
        rows = [{"src": "10.0.0.1"}, {"src": "10.0.0.2"}]
        client.get = MagicMock(return_value={"results": rows})
        result = searcher.fetch_results("test-sid")
        assert result == rows

    def test_fetch_results_with_field_list(self, searcher, client):
        client.get = MagicMock(return_value={"results": []})
        searcher.fetch_results("sid", field_list=["src", "dest"])
        params = client.get.call_args[1]["params"]
        assert "f" in params

    def test_iter_results_pages_through_all(self, searcher, client):
        page1 = [{"i": i} for i in range(5)]
        page2 = [{"i": i} for i in range(5, 8)]
        client.get = MagicMock(
            side_effect=[
                {"results": page1},
                {"results": page2},
            ]
        )
        results = list(searcher.iter_results("sid", page_size=5))
        assert len(results) == 8

    def test_cancel_job_calls_delete(self, searcher, client):
        client.delete = MagicMock(return_value={})
        searcher.cancel_job("test-sid")
        client.delete.assert_called_once()

    def test_cancel_job_ignores_errors(self, searcher, client):
        client.delete = MagicMock(side_effect=Exception("gone"))
        searcher.cancel_job("test-sid")  # should not raise

    def test_run_oneshot_returns_results(self, searcher, client):
        rows = [{"_raw": "event1"}]
        client.post = MagicMock(return_value={"results": rows})
        result = searcher.run_oneshot("search index=main | head 1")
        assert result == rows

    def test_run_oneshot_caps_at_50000(self, searcher, client):
        client.post = MagicMock(return_value={"results": []})
        searcher.run_oneshot("search *", max_results=100_000)
        data = client.post.call_args[1]["data"]
        assert data["count"] == 50_000

    def test_run_search_orchestrates_full_lifecycle(self, searcher, client):
        client.post = MagicMock(return_value={"sid": "job-1"})
        done_resp = {"entry": [{"content": {"dispatchState": "DONE"}}]}
        results_resp = {"results": [{"src": "1.1.1.1"}]}
        client.get = MagicMock(side_effect=[done_resp, results_resp])
        client.delete = MagicMock(return_value={})
        rows = searcher.run_search("search index=main | head 1")
        assert rows == [{"src": "1.1.1.1"}]
        client.delete.assert_called_once()

    def test_run_search_propagates_search_error(self, searcher, client):
        client.post = MagicMock(return_value={"sid": "job-2"})
        failed_resp = {"entry": [{"content": {"dispatchState": "FAILED", "messages": {}}}]}
        client.get = MagicMock(return_value=failed_resp)
        client.delete = MagicMock(return_value={})
        with pytest.raises(SplunkSearchError):
            searcher.run_search("search bad query")

    def test_list_saved_searches_returns_normalised(self, searcher, client):
        entries = [
            {
                "name": "My Alert",
                "content": {
                    "search": "index=main | stats count",
                    "cron_schedule": "0 * * * *",
                    "is_scheduled": "1",
                    "disabled": "0",
                },
            }
        ]
        client.paginate = MagicMock(return_value=iter(entries))
        result = searcher.list_saved_searches()
        assert len(result) == 1
        assert result[0]["name"] == "My Alert"
        assert result[0]["search"] == "index=main | stats count"

    def test_get_saved_search_returns_content(self, searcher, client):
        client.get = MagicMock(
            return_value={"entry": [{"content": {"search": "index=main | head 10"}}]}
        )
        content = searcher.get_saved_search("My Alert")
        assert content["search"] == "index=main | head 10"

    def test_get_saved_search_not_found_raises(self, searcher, client):
        client.get = MagicMock(return_value={"entry": []})
        with pytest.raises(SplunkNotFoundError):
            searcher.get_saved_search("NonExistent")

    def test_run_saved_search_returns_sid(self, searcher, client):
        client.post = MagicMock(return_value={"sid": "dispatch-sid"})
        sid = searcher.run_saved_search("My Alert")
        assert sid == "dispatch-sid"

    def test_run_saved_search_raises_on_no_sid(self, searcher, client):
        client.post = MagicMock(return_value={})
        with pytest.raises(SplunkSearchError, match="dispatch"):
            searcher.run_saved_search("My Alert")

    def test_list_indexes_returns_normalised(self, searcher, client):
        entries = [
            {
                "name": "main",
                "content": {
                    "totalEventCount": "12345",
                    "currentDBSizeMB": "500",
                    "disabled": "0",
                    "datatype": "event",
                },
            }
        ]
        client.paginate = MagicMock(return_value=iter(entries))
        result = searcher.list_indexes()
        assert len(result) == 1
        assert result[0]["name"] == "main"
        assert result[0]["total_event_count"] == "12345"

    def test_get_index_stats_returns_content(self, searcher, client):
        client.get = MagicMock(return_value={"entry": [{"content": {"totalEventCount": "100"}}]})
        stats = searcher.get_index_stats("main")
        assert stats["totalEventCount"] == "100"

    def test_get_index_stats_not_found_raises(self, searcher, client):
        client.get = MagicMock(return_value={"entry": []})
        with pytest.raises(SplunkNotFoundError):
            searcher.get_index_stats("nonexistent")


# ═══════════════════════════════════════════════════════════════════════════════
# SplunkKVStoreCommands tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSplunkKVStoreCommands:
    @pytest.fixture
    def client(self):
        return _make_client()

    @pytest.fixture
    def kv(self, client):
        client.config.username = "admin"
        return SplunkKVStoreCommands(client)

    def test_list_collections_returns_names(self, kv, client):
        client.get = MagicMock(
            return_value={"entry": [{"name": "my_collection"}, {"name": "another_coll"}]}
        )
        result = kv.list_collections()
        assert result == ["my_collection", "another_coll"]

    def test_collection_exists_true(self, kv, client):
        client.get = MagicMock(return_value={"entry": [{"name": "my_collection"}]})
        assert kv.collection_exists("my_collection") is True

    def test_collection_exists_false(self, kv, client):
        client.get = MagicMock(return_value={"entry": []})
        assert kv.collection_exists("nonexistent") is False

    def test_create_collection_posts_with_name(self, kv, client):
        client.post = MagicMock(return_value={"entry": []})
        kv.create_collection("new_coll")
        call_kwargs = client.post.call_args[1]
        assert call_kwargs["data"]["name"] == "new_coll"

    def test_create_collection_with_fields(self, kv, client):
        client.post = MagicMock(return_value={})
        kv.create_collection("coll", fields={"ip": "string", "score": "number"})
        data = client.post.call_args[1]["data"]
        assert "field.ip" in data
        assert "field.score" in data

    def test_create_collection_with_accelerated_fields(self, kv, client):
        client.post = MagicMock(return_value={})
        kv.create_collection("coll", accelerated_fields={"ix_ip": "ip"})
        data = client.post.call_args[1]["data"]
        assert "accelerated_fields.ix_ip" in data

    def test_delete_collection_calls_delete(self, kv, client):
        client.delete = MagicMock(return_value={})
        kv.delete_collection("my_coll")
        client.delete.assert_called_once()

    def test_list_records_returns_list_response(self, kv, client):
        records = [{"_key": "k1", "ip": "1.2.3.4"}]
        client.get = MagicMock(return_value=records)
        result = kv.list_records("ip_cache")
        assert result == records

    def test_list_records_with_query(self, kv, client):
        client.get = MagicMock(return_value=[])
        kv.list_records("coll", query={"ip": "1.2.3.4"})
        params = client.get.call_args[1]["params"]
        assert "query" in params

    def test_list_records_with_field_projection(self, kv, client):
        client.get = MagicMock(return_value=[])
        kv.list_records("coll", fields=["ip", "score"])
        params = client.get.call_args[1]["params"]
        assert "fields" in params

    def test_list_records_with_sort(self, kv, client):
        client.get = MagicMock(return_value=[])
        kv.list_records("coll", sort_key="ip", sort_dir="desc")
        params = client.get.call_args[1]["params"]
        assert "sort" in params
        assert "desc" in params["sort"]

    def test_list_records_entry_wrapped_response(self, kv, client):
        entries = [{"name": "k1", "content": {"ip": "1.2.3.4"}}]
        client.get = MagicMock(return_value={"entry": entries})
        result = kv.list_records("coll")
        assert result == entries

    def test_get_record_returns_doc(self, kv, client):
        doc = {"_key": "k1", "ip": "1.2.3.4"}
        client.get = MagicMock(return_value=doc)
        result = kv.get_record("ip_cache", "k1")
        assert result == doc

    def test_get_record_returns_none_on_not_found(self, kv, client):
        client.get = MagicMock(side_effect=SplunkNotFoundError("not found", status_code=404))
        result = kv.get_record("ip_cache", "missing")
        assert result is None

    def test_insert_record_calls_post_with_json(self, kv, client):
        client.post = MagicMock(return_value={"_key": "new-uuid"})
        result = kv.insert_record("ip_cache", {"ip": "2.2.2.2", "score": 95})
        assert result["_key"] == "new-uuid"
        call_kwargs = client.post.call_args[1]
        assert call_kwargs["content_type"] == "application/json"

    def test_update_record_calls_put(self, kv, client):
        client.put = MagicMock(return_value={"_key": "k1"})
        result = kv.update_record("ip_cache", "k1", {"ip": "3.3.3.3"})
        assert result["_key"] == "k1"
        client.put.assert_called_once()

    def test_delete_record_calls_delete(self, kv, client):
        client.delete = MagicMock(return_value={})
        kv.delete_record("ip_cache", "k1")
        client.delete.assert_called_once()

    def test_delete_records_without_query(self, kv, client):
        client.delete = MagicMock(return_value={})
        kv.delete_records("ip_cache")
        url = client.delete.call_args[0][0]
        assert "?" not in url

    def test_delete_records_with_query_appends_param(self, kv, client):
        client.delete = MagicMock(return_value={})
        kv.delete_records("ip_cache", query={"ip": "1.2.3.4"})
        url = client.delete.call_args[0][0]
        assert "query=" in url

    def test_batch_insert_chunks_records(self, kv, client):
        client.post = MagicMock(return_value={"_key": "k"})
        records = [{"ip": f"10.0.0.{i}"} for i in range(1200)]
        kv.batch_insert("ip_cache", records, batch_size=500)
        assert client.post.call_count == 3

    def test_count_records_delegates_to_list_records(self, kv, client):
        client.get = MagicMock(return_value=[{"_key": "k1"}, {"_key": "k2"}])
        count = kv.count_records("ip_cache")
        assert count == 2

    def test_count_records_with_query(self, kv, client):
        client.get = MagicMock(return_value=[{"_key": "k1"}])
        count = kv.count_records("ip_cache", query={"score": {"$gt": 80}})
        assert count == 1


# ═══════════════════════════════════════════════════════════════════════════════
# SplunkAlertCommands tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSplunkAlertCommands:
    @pytest.fixture
    def client(self):
        c = _make_client()
        c.config.username = "admin"
        return c

    @pytest.fixture
    def alerts(self, client):
        return SplunkAlertCommands(client)

    def test_list_fired_alerts_returns_normalised(self, alerts, client):
        entries = [
            {
                "name": "alert-1",
                "content": {
                    "savedsearch_name": "My Alert",
                    "trigger_time": "1704067200",
                    "trigger_time_rendered": "2024-01-01 00:00:00",
                    "severity": "high",
                    "result_count": "5",
                    "sid": "abc123",
                },
            }
        ]
        client.paginate = MagicMock(return_value=iter(entries))
        result = alerts.list_fired_alerts(count=10)
        assert len(result) == 1
        assert result[0]["name"] == "alert-1"
        assert result[0]["saved_search_name"] == "My Alert"
        assert result[0]["severity"] == "high"

    def test_list_fired_alerts_caps_at_count(self, alerts, client):
        entries = [{"name": f"a{i}", "content": {}} for i in range(10)]
        client.paginate = MagicMock(return_value=iter(entries))
        result = alerts.list_fired_alerts(count=3)
        assert len(result) == 3

    def test_get_alert_history_returns_records(self, alerts, client):
        entries = [
            {
                "name": "sid-001",
                "content": {
                    "dispatchState": "DONE",
                    "eventCount": "10",
                    "resultCount": "5",
                    "runDuration": "2.5",
                    "ttl": "600",
                    "isDone": "1",
                    "isFailed": "0",
                },
            }
        ]
        client.get = MagicMock(return_value={"entry": entries})
        result = alerts.get_alert_history("My Alert")
        assert len(result) == 1
        assert result[0]["sid"] == "sid-001"
        assert result[0]["dispatch_state"] == "DONE"

    def test_get_alert_metadata_returns_content(self, alerts, client):
        entries = [
            {
                "name": "My Alert",
                "content": {
                    "search": "index=main | head 10",
                    "cron_schedule": "0 * * * *",
                    "alert_type": "number of events",
                    "alert_comparator": "greater than",
                    "alert_threshold": "0",
                    "alert.severity": "3",
                    "alert.suppress": "0",
                    "is_scheduled": "1",
                    "disabled": "0",
                },
            }
        ]
        client.get = MagicMock(return_value={"entry": entries})
        result = alerts.get_alert_metadata("My Alert")
        assert result["name"] == "My Alert"
        assert result["search"] == "index=main | head 10"
        assert result["alert_comparator"] == "greater than"

    def test_get_alert_metadata_not_found_raises(self, alerts, client):
        client.get = MagicMock(return_value={"entry": []})
        with pytest.raises(SplunkNotFoundError):
            alerts.get_alert_metadata("Nonexistent Alert")

    def test_require_es_raises_when_disabled(self, alerts):
        alerts._client.config.es_enabled = False
        with pytest.raises(SplunkThreatIntelError, match="es_enabled"):
            alerts._require_es()

    def test_search_notables_requires_es(self, alerts):
        alerts._client.config.es_enabled = False
        with pytest.raises(SplunkThreatIntelError):
            alerts.search_notables()

    def test_search_notables_builds_spl_with_filters(self, alerts, client):
        alerts._client.config.es_enabled = True
        searcher_mock = MagicMock()
        searcher_mock.run_search.return_value = []
        with patch(
            "gnat.connectors.splunk.search.SplunkSearchCommands",
            return_value=searcher_mock,
        ):
            alerts.search_notables(status="new", urgency="high", owner="analyst1")
        spl = searcher_mock.run_search.call_args[0][0]
        assert "status=0" in spl  # "new" maps to "0"
        assert "urgency=high" in spl
        assert 'owner="analyst1"' in spl

    def test_search_notables_normalises_results(self, alerts, client):
        alerts._client.config.es_enabled = True
        raw_rows = [
            {
                "event_id": "EVT-001",
                "rule_name": "Brute Force",
                "urgency": "high",
                "status": "0",
                "owner": "admin",
                "_time": "2024-01-15T10:00:00Z",
                "src": "10.0.0.1",
                "dest": "192.168.1.100",
                "user": "jdoe",
                "rule_description": "Multiple failed logins",
            }
        ]
        searcher_mock = MagicMock()
        searcher_mock.run_search.return_value = raw_rows
        with patch(
            "gnat.connectors.splunk.search.SplunkSearchCommands",
            return_value=searcher_mock,
        ):
            result = alerts.search_notables()
        assert len(result) == 1
        n = result[0]
        assert n["event_id"] == "EVT-001"
        assert n["rule_name"] == "Brute Force"
        assert n["severity"] == 3  # high -> 3
        assert n["src"] == "10.0.0.1"

    def test_normalise_notable_severity_mapping(self, alerts):
        for urgency, expected_severity in [
            ("critical", 4),
            ("high", 3),
            ("medium", 2),
            ("low", 1),
            ("informational", 0),
            ("unknown", 0),
            ("CRITICAL", 4),  # uppercase is lowercased
        ]:
            row = {"urgency": urgency}
            result = alerts._normalise_notable(row)
            assert result["severity"] == expected_severity, f"Failed for {urgency}"

    def test_normalise_notable_maps_all_fields(self, alerts):
        row = {
            "event_id": "E1",
            "rule_name": "Test Rule",
            "urgency": "medium",
            "status": "1",
            "owner": "analyst",
            "_time": "2024-01-01T00:00:00Z",
            "src": "192.168.1.1",
            "dest": "10.0.0.1",
            "user": "bob",
            "rule_description": "A test rule",
        }
        result = alerts._normalise_notable(row)
        assert result["event_id"] == "E1"
        assert result["timestamp"] == "2024-01-01T00:00:00Z"
        assert result["description"] == "A test rule"
        assert result["_raw"] is row

    def test_update_notable_status_valid(self, alerts, client):
        alerts._client.config.es_enabled = True
        client.post = MagicMock(return_value={"success": True})
        result = alerts.update_notable_status(
            ["EVT-001", "EVT-002"], status="in_progress", comment="investigating"
        )
        assert result["success"] is True
        data = client.post.call_args[1]["data"]
        assert data["status"] == "1"  # in_progress -> "1"
        assert data["comment"] == "investigating"
        assert "EVT-001" in data["ruleUIDs[]"]

    def test_update_notable_status_with_owner_and_urgency(self, alerts, client):
        alerts._client.config.es_enabled = True
        client.post = MagicMock(return_value={})
        alerts.update_notable_status(
            ["EVT-001"], status="resolved", owner="analyst2", urgency="critical"
        )
        data = client.post.call_args[1]["data"]
        assert data["newOwner"] == "analyst2"
        assert data["urgency"] == "critical"

    def test_update_notable_status_invalid_status_raises(self, alerts, client):
        alerts._client.config.es_enabled = True
        with pytest.raises(ValueError, match="Invalid status"):
            alerts.update_notable_status(["EVT-001"], status="invalid_status")

    def test_update_notable_restores_app_context(self, alerts, client):
        alerts._client.config.es_enabled = True
        original_app = client.config.app_context
        client.post = MagicMock(return_value={})
        alerts.update_notable_status(["EVT-001"], status="closed")
        assert client.config.app_context == original_app

    def test_get_notable_by_id_found(self, alerts, client):
        alerts._client.config.es_enabled = True
        searcher_mock = MagicMock()
        searcher_mock.run_search.return_value = [{"event_id": "EVT-001", "urgency": "high"}]
        with patch(
            "gnat.connectors.splunk.search.SplunkSearchCommands",
            return_value=searcher_mock,
        ):
            result = alerts.get_notable_by_id("EVT-001")
        assert result is not None
        assert result["event_id"] == "EVT-001"

    def test_get_notable_by_id_not_found_returns_none(self, alerts, client):
        alerts._client.config.es_enabled = True
        searcher_mock = MagicMock()
        searcher_mock.run_search.return_value = [{"event_id": "OTHER-001", "urgency": "low"}]
        with patch(
            "gnat.connectors.splunk.search.SplunkSearchCommands",
            return_value=searcher_mock,
        ):
            result = alerts.get_notable_by_id("MISSING-ID")
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# SplunkConfig tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSplunkConfig:
    def test_valid_config_with_token(self):
        cfg = SplunkConfig(
            host="splunk.example.com",
            token="my-token",
        )
        assert cfg.uses_token_auth is True
        assert cfg.base_url == "https://splunk.example.com:8089"

    def test_valid_config_with_username_password(self):
        cfg = SplunkConfig(
            host="splunk.example.com",
            username="admin",
            password="secret",
        )
        assert cfg.uses_token_auth is False

    def test_owner_returns_username_when_set(self):
        cfg = SplunkConfig(
            host="splunk.example.com",
            username="myuser",
            password="pass",
        )
        assert cfg.owner == "myuser"

    def test_owner_returns_nobody_when_token_auth(self):
        cfg = SplunkConfig(
            host="splunk.example.com",
            token="tok",
        )
        assert cfg.owner == "nobody"

    def test_namespace_path(self):
        cfg = SplunkConfig(
            host="splunk.example.com",
            token="tok",
            app_context="search",
        )
        path = cfg.namespace_path("search/jobs")
        assert "/servicesNS/nobody/search/search/jobs" in path

    def test_services_path(self):
        cfg = SplunkConfig(host="splunk.example.com", token="tok")
        path = cfg.services_path("server/info")
        assert "/services/server/info" in path

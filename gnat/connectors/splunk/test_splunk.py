# “””
tests/connectors/test_splunk.py

Unit tests for the GNAT Splunk connector.

## Test strategy

All HTTP calls are mocked via unittest.mock.patch on urllib3.PoolManager.
No live Splunk instance is required to run the test suite.

## Coverage targets

- SplunkConfig: validation, loading from ConfigParser, computed properties
- SplunkAuthManager: token auth, session key auth, renewal, logout
- SplunkClient: request routing, retry logic, error mapping
- SplunkSearchCommands: job lifecycle, one-shot, pagination, saved searches
- SplunkAlertCommands: fired alerts, notable events, status updates
- SplunkThreatIntelCommands: IOC CRUD, bulk ops, STIX file upload
- SplunkKVStoreCommands: collection management, document CRUD, batch ops
- SplunkSTIXMapper: STIX→Splunk mapping, Splunk→STIX bundle construction

## Running

```
pytest tests/connectors/test_splunk.py -v
pytest tests/connectors/test_splunk.py -v --tb=short -x
```

“””

import configparser
import json
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

# ── Connector imports ─────────────────────────────────────────────────────────

from gnat.connectors.splunk.config import SplunkConfig, load_splunk_config
from gnat.connectors.splunk.exceptions import (
SplunkAuthError,
SplunkAPIError,
SplunkConfigError,
SplunkNotFoundError,
SplunkRateLimitError,
SplunkSearchError,
SplunkThreatIntelError,
SplunkSTIXError,
)
from gnat.connectors.splunk.auth import SplunkAuthManager
from gnat.connectors.splunk.client import SplunkClient
from gnat.connectors.splunk.search import SplunkSearchCommands
from gnat.connectors.splunk.alerts import SplunkAlertCommands
from gnat.connectors.splunk.threat_intel import SplunkThreatIntelCommands
from gnat.connectors.splunk.kvstore import SplunkKVStoreCommands
from gnat.connectors.splunk.stix_mapper import SplunkSTIXMapper

# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_config(
host: str = “splunk.test.local”,
token: str = “test-token-abc123”,
es_enabled: bool = False,
**overrides,
) -> SplunkConfig:
“”“Return a minimal valid SplunkConfig for tests.”””
return SplunkConfig(
host=host,
token=token,
es_enabled=es_enabled,
**overrides,
)

def _make_response(status: int = 200, body: dict | list | None = None) -> MagicMock:
“”“Return a mock urllib3 response object.”””
resp = MagicMock()
resp.status = status
payload = body if body is not None else {}
resp.data = json.dumps(payload).encode(“utf-8”)
return resp

def _make_client(config: SplunkConfig | None = None) -> tuple[SplunkClient, MagicMock]:
“”“Return a SplunkClient with a mocked urllib3 PoolManager.”””
cfg = config or _make_config()
with patch(“gnat.connectors.splunk.client.urllib3.PoolManager”) as mock_pm_cls:
mock_pm = MagicMock()
mock_pm_cls.return_value = mock_pm
client = SplunkClient(cfg)
client._http = mock_pm
client.auth._http = mock_pm
return client, mock_pm

# ═════════════════════════════════════════════════════════════════════════════

# SplunkConfig tests

# ═════════════════════════════════════════════════════════════════════════════

class TestSplunkConfig(unittest.TestCase):

```
def test_minimal_token_config(self):
    """Token-only config constructs without error."""
    cfg = _make_config()
    self.assertEqual(cfg.host, "splunk.test.local")
    self.assertEqual(cfg.port, 8089)
    self.assertEqual(cfg.scheme, "https")
    self.assertTrue(cfg.uses_token_auth)

def test_username_password_config(self):
    """Username+password config is valid when no token present."""
    cfg = SplunkConfig(
        host="splunk.test.local",
        username="admin",
        password="s3cr3t",
    )
    self.assertFalse(cfg.uses_token_auth)

def test_missing_host_raises(self):
    """Empty host raises SplunkConfigError."""
    with self.assertRaises(SplunkConfigError):
        SplunkConfig(host="", token="tok")

def test_missing_credentials_raises(self):
    """No token and no username/password raises SplunkConfigError."""
    with self.assertRaises(SplunkConfigError):
        SplunkConfig(host="splunk.test.local")

def test_invalid_scheme_raises(self):
    with self.assertRaises(SplunkConfigError):
        SplunkConfig(host="h", token="t", scheme="ftp")

def test_invalid_port_raises(self):
    with self.assertRaises(SplunkConfigError):
        SplunkConfig(host="h", token="t", port=99999)

def test_base_url_computed(self):
    cfg = _make_config()
    self.assertEqual(cfg.base_url, "https://splunk.test.local:8089")

def test_namespace_path(self):
    cfg = _make_config()
    expected = "https://splunk.test.local:8089/servicesNS/nobody/search/search/jobs"
    self.assertEqual(cfg.namespace_path("search/jobs"), expected)

def test_services_path(self):
    cfg = _make_config()
    expected = "https://splunk.test.local:8089/services/auth/login"
    self.assertEqual(cfg.services_path("auth/login"), expected)

def test_load_from_configparser_token(self):
    """load_splunk_config parses [splunk] section correctly."""
    parser = configparser.ConfigParser()
    parser.read_dict({
        "splunk": {
            "host": "mysplunk.corp",
            "token": "abc123",
            "es_enabled": "true",
            "timeout": "45",
        }
    })
    cfg = load_splunk_config(parser)
    self.assertEqual(cfg.host, "mysplunk.corp")
    self.assertEqual(cfg.token, "abc123")
    self.assertTrue(cfg.es_enabled)
    self.assertEqual(cfg.timeout, 45)

def test_load_missing_section_raises(self):
    parser = configparser.ConfigParser()
    with self.assertRaises(SplunkConfigError):
        load_splunk_config(parser, section="splunk")

def test_load_missing_host_raises(self):
    parser = configparser.ConfigParser()
    parser.read_dict({"splunk": {"token": "tok"}})
    with self.assertRaises(SplunkConfigError):
        load_splunk_config(parser)
```

# ═════════════════════════════════════════════════════════════════════════════

# SplunkAuthManager tests

# ═════════════════════════════════════════════════════════════════════════════

class TestSplunkAuthManager(unittest.TestCase):

```
def _make_auth(self, config=None) -> tuple[SplunkAuthManager, MagicMock]:
    cfg = config or _make_config()
    mock_http = MagicMock()
    return SplunkAuthManager(cfg, mock_http), mock_http

def test_token_auth_returns_header(self):
    """Pre-generated token is returned directly without login."""
    auth, mock_http = self._make_auth()
    headers = auth.get_auth_headers()
    self.assertEqual(headers, {"Authorization": "Splunk test-token-abc123"})
    mock_http.request.assert_not_called()

def test_session_key_login(self):
    """Username/password auth POSTs to /auth/login and caches the key."""
    cfg = SplunkConfig(host="h", username="admin", password="pw")
    auth, mock_http = self._make_auth(cfg)
    mock_http.request.return_value = _make_response(
        200, {"sessionKey": "sess-key-xyz"}
    )
    headers = auth.get_auth_headers()
    self.assertEqual(headers, {"Authorization": "Splunk sess-key-xyz"})
    mock_http.request.assert_called_once()
    # Second call should NOT re-login (cached)
    headers2 = auth.get_auth_headers()
    self.assertEqual(headers2, {"Authorization": "Splunk sess-key-xyz"})
    self.assertEqual(mock_http.request.call_count, 1)

def test_login_401_raises_auth_error(self):
    cfg = SplunkConfig(host="h", username="admin", password="wrong")
    auth, mock_http = self._make_auth(cfg)
    mock_http.request.return_value = _make_response(401)
    with self.assertRaises(SplunkAuthError):
        auth.get_auth_headers()

def test_login_403_raises_auth_error(self):
    cfg = SplunkConfig(host="h", username="locked", password="pw")
    auth, mock_http = self._make_auth(cfg)
    mock_http.request.return_value = _make_response(403)
    with self.assertRaises(SplunkAuthError):
        auth.get_auth_headers()

def test_invalidate_session_clears_key(self):
    cfg = SplunkConfig(host="h", username="admin", password="pw")
    auth, mock_http = self._make_auth(cfg)
    mock_http.request.return_value = _make_response(200, {"sessionKey": "sk"})
    auth.get_auth_headers()
    auth.invalidate_session()
    self.assertIsNone(auth._session_key)

def test_token_auth_logout_is_noop(self):
    """logout() on token auth should not make any requests."""
    auth, mock_http = self._make_auth()
    auth.logout()
    mock_http.request.assert_not_called()
```

# ═════════════════════════════════════════════════════════════════════════════

# SplunkClient tests

# ═════════════════════════════════════════════════════════════════════════════

class TestSplunkClient(unittest.TestCase):

```
def test_get_returns_parsed_json(self):
    client, mock_http = _make_client()
    mock_http.request.return_value = _make_response(200, {"entry": []})
    result = client.get("search/jobs")
    self.assertIsInstance(result, dict)

def test_404_raises_not_found(self):
    client, mock_http = _make_client()
    mock_http.request.return_value = _make_response(404)
    with self.assertRaises(SplunkNotFoundError):
        client.get("search/jobs/bad-sid", namespaced=False)

def test_403_raises_auth_error(self):
    client, mock_http = _make_client()
    mock_http.request.return_value = _make_response(403)
    with self.assertRaises(SplunkAuthError):
        client.get("some/endpoint")

def test_401_retries_once_then_raises(self):
    client, mock_http = _make_client()
    mock_http.request.return_value = _make_response(401)
    with self.assertRaises(SplunkAuthError):
        client.get("some/endpoint")
    # Should have been called twice (initial + one refresh attempt)
    self.assertGreaterEqual(mock_http.request.call_count, 2)

def test_429_raises_rate_limit_after_retries(self):
    client, mock_http = _make_client()
    mock_http.request.return_value = _make_response(429)
    with patch("time.sleep"):  # Don't actually sleep in tests
        with self.assertRaises(SplunkRateLimitError):
            client.get("some/endpoint")

def test_context_manager(self):
    """Client can be used as a context manager."""
    cfg = _make_config()
    with patch("gnat.connectors.splunk.client.urllib3.PoolManager"):
        with SplunkClient(cfg) as client:
            self.assertIsInstance(client, SplunkClient)

def test_output_mode_json_injected(self):
    """Every GET request has output_mode=json in fields."""
    client, mock_http = _make_client()
    mock_http.request.return_value = _make_response(200, {})
    client.get("search/jobs", params={"count": 10})
    call_kwargs = mock_http.request.call_args
    fields = call_kwargs[1].get("fields") or call_kwargs[0][2]
    self.assertEqual(fields.get("output_mode"), "json")

def test_paginate_yields_all_entries(self):
    """paginate() iterates until a partial page is returned."""
    client, mock_http = _make_client()
    page1 = {"entry": [{"name": f"item{i}"} for i in range(5)]}
    page2 = {"entry": [{"name": "item5"}, {"name": "item6"}]}
    mock_http.request.side_effect = [
        _make_response(200, page1),
        _make_response(200, page2),
    ]
    results = list(client.paginate("saved/searches", page_size=5))
    self.assertEqual(len(results), 7)
```

# ═════════════════════════════════════════════════════════════════════════════

# SplunkSearchCommands tests

# ═════════════════════════════════════════════════════════════════════════════

class TestSplunkSearchCommands(unittest.TestCase):

```
def _make_search(self) -> tuple[SplunkSearchCommands, MagicMock]:
    client, mock_http = _make_client()
    return SplunkSearchCommands(client), mock_http

def test_create_search_job_returns_sid(self):
    search, mock_http = self._make_search()
    mock_http.request.return_value = _make_response(200, {"sid": "abc123"})
    sid = search.create_search_job("search index=main")
    self.assertEqual(sid, "abc123")

def test_create_search_job_no_sid_raises(self):
    search, mock_http = self._make_search()
    mock_http.request.return_value = _make_response(200, {})
    with self.assertRaises(SplunkSearchError):
        search.create_search_job("search index=main")

def test_poll_job_done(self):
    """poll_job returns 'DONE' when job reaches terminal state."""
    search, mock_http = self._make_search()
    job_response = {
        "entry": [{"content": {"dispatchState": "DONE"}}]
    }
    mock_http.request.return_value = _make_response(200, job_response)
    state = search.poll_job("abc123")
    self.assertEqual(state, "DONE")

def test_poll_job_failed_raises(self):
    search, mock_http = self._make_search()
    job_response = {
        "entry": [{"content": {"dispatchState": "FAILED", "messages": {}}}]
    }
    mock_http.request.return_value = _make_response(200, job_response)
    with self.assertRaises(SplunkSearchError):
        search.poll_job("abc123")

def test_poll_job_timeout_raises(self):
    search, mock_http = self._make_search()
    job_response = {
        "entry": [{"content": {"dispatchState": "RUNNING"}}]
    }
    mock_http.request.return_value = _make_response(200, job_response)
    with patch("time.sleep"), patch("time.time", side_effect=[0, 0, 999]):
        with self.assertRaises(SplunkSearchError) as ctx:
            search.poll_job("abc123", timeout=1)
    self.assertIn("timed out", str(ctx.exception).lower())

def test_fetch_results_returns_list(self):
    search, mock_http = self._make_search()
    mock_http.request.return_value = _make_response(
        200, {"results": [{"src": "1.2.3.4"}, {"src": "5.6.7.8"}]}
    )
    results = search.fetch_results("abc123")
    self.assertEqual(len(results), 2)

def test_run_oneshot_returns_results(self):
    search, mock_http = self._make_search()
    mock_http.request.return_value = _make_response(
        200, {"results": [{"host": "server1"}]}
    )
    results = search.run_oneshot("search index=main")
    self.assertEqual(results[0]["host"], "server1")

def test_list_saved_searches(self):
    search, mock_http = self._make_search()
    entry = {
        "name": "My Alert",
        "content": {
            "search": "index=main error",
            "cron_schedule": "*/5 * * * *",
            "is_scheduled": "1",
            "disabled": "0",
        }
    }
    mock_http.request.return_value = _make_response(200, {"entry": [entry]})
    results = search.list_saved_searches()
    self.assertEqual(results[0]["name"], "My Alert")
```

# ═════════════════════════════════════════════════════════════════════════════

# SplunkAlertCommands tests

# ═════════════════════════════════════════════════════════════════════════════

class TestSplunkAlertCommands(unittest.TestCase):

```
def _make_alerts(self, es_enabled=False):
    cfg = _make_config(es_enabled=es_enabled)
    client, mock_http = _make_client(cfg)
    return SplunkAlertCommands(client), mock_http

def test_list_fired_alerts(self):
    alerts, mock_http = self._make_alerts()
    entry = {
        "name": "Brute Force Detected",
        "content": {
            "savedsearch_name": "Brute Force Access Behavior",
            "trigger_time": "1710000000",
            "trigger_time_rendered": "2024-03-10T00:00:00",
            "severity": "high",
            "result_count": "42",
            "sid": "rt_12345",
        }
    }
    mock_http.request.return_value = _make_response(200, {"entry": [entry]})
    results = alerts.list_fired_alerts()
    self.assertEqual(len(results), 1)
    self.assertEqual(results[0]["severity"], "high")

def test_update_notable_requires_es(self):
    alerts, _ = self._make_alerts(es_enabled=False)
    with self.assertRaises(SplunkThreatIntelError):
        alerts.update_notable_status(["evt1"], "resolved")

def test_update_notable_invalid_status(self):
    alerts, _ = self._make_alerts(es_enabled=True)
    with self.assertRaises(ValueError):
        alerts.update_notable_status(["evt1"], "invalid_status")

def test_normalise_notable_severity_mapping(self):
    """ES urgency strings are mapped to integer severity correctly."""
    row = {"urgency": "critical", "event_id": "e1", "rule_name": "Test"}
    result = SplunkAlertCommands._normalise_notable(row)
    self.assertEqual(result["severity"], 4)

def test_normalise_notable_unknown_urgency(self):
    row = {"urgency": "undefined"}
    result = SplunkAlertCommands._normalise_notable(row)
    self.assertEqual(result["severity"], 0)
```

# ═════════════════════════════════════════════════════════════════════════════

# SplunkThreatIntelCommands tests

# ═════════════════════════════════════════════════════════════════════════════

class TestSplunkThreatIntelCommands(unittest.TestCase):

```
def _make_ti(self, es_enabled=True):
    cfg = _make_config(es_enabled=es_enabled)
    client, mock_http = _make_client(cfg)
    return SplunkThreatIntelCommands(client), mock_http

def test_requires_es_enabled(self):
    ti, _ = self._make_ti(es_enabled=False)
    with self.assertRaises(SplunkThreatIntelError):
        ti.list_iocs("ip")

def test_invalid_collection_raises(self):
    ti, _ = self._make_ti()
    with self.assertRaises(SplunkThreatIntelError):
        ti.list_iocs("nonsense_collection")

def test_validate_collection_strips_intel_suffix(self):
    """'ip_intel' and 'ip' both resolve to 'ip_intel'."""
    from gnat.connectors.splunk.threat_intel import (
        SplunkThreatIntelCommands as TI,
    )
    self.assertEqual(TI._validate_collection("ip"), "ip_intel")
    self.assertEqual(TI._validate_collection("ip_intel"), "ip_intel")
    self.assertEqual(TI._validate_collection("domain"), "domain_intel")

def test_list_iocs_returns_list(self):
    ti, mock_http = self._make_ti()
    mock_http.request.return_value = _make_response(
        200, [{"ip": "1.2.3.4", "threat_key": "malware"}]
    )
    results = ti.list_iocs("ip")
    self.assertEqual(results[0]["ip"], "1.2.3.4")

def test_upload_stix_file(self):
    ti, mock_http = self._make_ti()
    mock_http.request.return_value = _make_response(200, {"status": "ok"})
    bundle_bytes = json.dumps({
        "type": "bundle",
        "id": "bundle--abc",
        "spec_version": "2.1",
        "objects": [],
    }).encode()
    result = ti.upload_stix_file(bundle_bytes, "test_feed", "ip")
    self.assertIsNotNone(result)

def test_upsert_ioc_without_key(self):
    """Upsert without _key should POST to create."""
    ti, mock_http = self._make_ti()
    mock_http.request.return_value = _make_response(200, {"_key": "new-key"})
    result = ti.upsert_ioc("ip", {"ip": "10.0.0.1"})
    self.assertIsNotNone(result)
```

# ═════════════════════════════════════════════════════════════════════════════

# SplunkKVStoreCommands tests

# ═════════════════════════════════════════════════════════════════════════════

class TestSplunkKVStoreCommands(unittest.TestCase):

```
def _make_kvstore(self):
    client, mock_http = _make_client()
    return SplunkKVStoreCommands(client), mock_http

def test_list_collections(self):
    kv, mock_http = self._make_kvstore()
    mock_http.request.return_value = _make_response(
        200, {"entry": [{"name": "gnat_cache"}, {"name": "gnat_state"}]}
    )
    names = kv.list_collections()
    self.assertIn("gnat_cache", names)

def test_collection_exists_true(self):
    kv, mock_http = self._make_kvstore()
    mock_http.request.return_value = _make_response(
        200, {"entry": [{"name": "my_coll"}]}
    )
    self.assertTrue(kv.collection_exists("my_coll"))

def test_collection_exists_false(self):
    kv, mock_http = self._make_kvstore()
    mock_http.request.return_value = _make_response(200, {"entry": []})
    self.assertFalse(kv.collection_exists("missing_coll"))

def test_insert_record(self):
    kv, mock_http = self._make_kvstore()
    mock_http.request.return_value = _make_response(
        200, {"_key": "generated-key-123"}
    )
    result = kv.insert_record("my_coll", {"field": "value"})
    self.assertEqual(result["_key"], "generated-key-123")

def test_get_record_not_found_returns_none(self):
    kv, mock_http = self._make_kvstore()
    mock_http.request.return_value = _make_response(404)
    result = kv.get_record("my_coll", "missing-key")
    self.assertIsNone(result)

def test_batch_insert_chunks_correctly(self):
    """batch_insert splits 1100 records into 3 batches of 500/500/100."""
    kv, mock_http = self._make_kvstore()
    mock_http.request.return_value = _make_response(200, [])
    records = [{"field": str(i)} for i in range(1100)]
    kv.batch_insert("my_coll", records, batch_size=500)
    self.assertEqual(mock_http.request.call_count, 3)
```

# ═════════════════════════════════════════════════════════════════════════════

# SplunkSTIXMapper tests

# ═════════════════════════════════════════════════════════════════════════════

class TestSplunkSTIXMapper(unittest.TestCase):

```
def setUp(self):
    self.mapper = SplunkSTIXMapper()

# ── STIX → Splunk ──────────────────────────────────────────────────────

def test_ipv4_sco_maps_to_ip_collection(self):
    obj = {"type": "ipv4-addr", "id": "ipv4-addr--abc", "value": "192.168.1.1"}
    records = self.mapper.stix_objects_to_splunk_records([obj])
    self.assertEqual(len(records), 1)
    self.assertEqual(records[0]["collection"], "ip")
    self.assertEqual(records[0]["record"]["ip"], "192.168.1.1")

def test_ipv6_sco_maps_to_ip_collection(self):
    obj = {"type": "ipv6-addr", "id": "ipv6-addr--abc", "value": "::1"}
    records = self.mapper.stix_objects_to_splunk_records([obj])
    self.assertEqual(records[0]["collection"], "ip")

def test_domain_sco_maps_to_domain_collection(self):
    obj = {"type": "domain-name", "id": "domain-name--abc", "value": "evil.com"}
    records = self.mapper.stix_objects_to_splunk_records([obj])
    self.assertEqual(records[0]["collection"], "domain")
    self.assertEqual(records[0]["record"]["domain"], "evil.com")

def test_url_sco_maps_to_url_collection(self):
    obj = {"type": "url", "id": "url--abc", "value": "https://evil.com/payload"}
    records = self.mapper.stix_objects_to_splunk_records([obj])
    self.assertEqual(records[0]["collection"], "url")

def test_file_sco_maps_hashes(self):
    obj = {
        "type": "file",
        "id": "file--abc",
        "name": "malware.exe",
        "hashes": {
            "MD5": "d41d8cd98f00b204e9800998ecf8427e",
            "SHA-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
    }
    records = self.mapper.stix_objects_to_splunk_records([obj])
    self.assertEqual(records[0]["collection"], "file")
    record = records[0]["record"]
    self.assertEqual(record["md5"], "d41d8cd98f00b204e9800998ecf8427e")
    self.assertIn("sha256", record)
    self.assertEqual(record["file_name"], "malware.exe")

def test_email_sco_maps_to_email_collection(self):
    obj = {
        "type": "email-addr",
        "id": "email-addr--abc",
        "value": "attacker@evil.com",
    }
    records = self.mapper.stix_objects_to_splunk_records([obj])
    self.assertEqual(records[0]["collection"], "email")

def test_unsupported_type_raises(self):
    obj = {"type": "threat-actor", "id": "threat-actor--abc", "name": "APT1"}
    with self.assertRaises(SplunkSTIXError):
        self.mapper.stix_objects_to_splunk_records([obj])

def test_indicator_sdo_stored_with_pattern(self):
    """STIX indicator SDO is stored with pattern string; no evaluation."""
    obj = {
        "type": "indicator",
        "id": "indicator--abc",
        "name": "Malicious IP",
        "pattern": "[ipv4-addr:value = '10.0.0.99']",
        "pattern_type": "stix",
        "indicator_types": ["malicious-activity"],
        "valid_from": "2024-01-01T00:00:00Z",
    }
    records = self.mapper.stix_objects_to_splunk_records([obj])
    self.assertEqual(len(records), 1)
    record = records[0]["record"]
    self.assertIn("stix_pattern", record)
    # Should have extracted the IP from the pattern
    self.assertEqual(record.get("ip"), "10.0.0.99")

def test_bundle_mapping(self):
    """stix_bundle_to_splunk_records processes bundle objects."""
    bundle = {
        "type": "bundle",
        "id": "bundle--xyz",
        "spec_version": "2.1",
        "objects": [
            {"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "1.2.3.4"},
            {"type": "domain-name", "id": "domain-name--1", "value": "test.com"},
        ],
    }
    records = self.mapper.stix_bundle_to_splunk_records(bundle)
    self.assertEqual(len(records), 2)

def test_invalid_bundle_type_raises(self):
    with self.assertRaises(SplunkSTIXError):
        self.mapper.stix_bundle_to_splunk_records({"type": "indicator"})

def test_default_weight_applied(self):
    obj = {"type": "ipv4-addr", "id": "ipv4-addr--abc", "value": "1.2.3.4"}
    records = self.mapper.stix_objects_to_splunk_records([obj], default_weight=75)
    self.assertEqual(records[0]["record"]["weight"], "75")

# ── Splunk → STIX ──────────────────────────────────────────────────────

def test_notable_to_stix_bundle_structure(self):
    notable = {
        "event_id": "evt-001",
        "rule_name": "Brute Force Detected",
        "urgency": "high",
        "severity": 3,
        "src": "192.168.1.100",
        "dest": "10.0.0.5",
        "user": "jdoe",
        "timestamp": "2024-03-10T00:00:00Z",
    }
    bundle = self.mapper.splunk_notable_to_stix_bundle(notable)
    self.assertEqual(bundle["type"], "bundle")
    self.assertEqual(bundle["spec_version"], "2.1")
    objects = bundle["objects"]
    types = [o["type"] for o in objects]
    self.assertIn("ipv4-addr", types)
    self.assertIn("user-account", types)
    self.assertIn("observed-data", types)

def test_notable_to_stix_src_dest_deduplication(self):
    """Same src and dest should not produce duplicate ipv4-addr objects."""
    notable = {"src": "1.2.3.4", "dest": "1.2.3.4"}
    bundle = self.mapper.splunk_notable_to_stix_bundle(notable)
    ip_objects = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
    self.assertEqual(len(ip_objects), 1)

def test_search_rows_to_stix_bundle(self):
    rows = [
        {"src_ip": "10.0.0.1", "dest_ip": "8.8.8.8", "domain": "google.com"},
        {"src": "172.16.0.1", "sha256": "abc123def456", "file_name": "bad.exe"},
    ]
    bundle = self.mapper.splunk_search_rows_to_stix_bundle(rows)
    self.assertEqual(bundle["type"], "bundle")
    types = [o["type"] for o in bundle["objects"]]
    self.assertIn("ipv4-addr", types)
    self.assertIn("domain-name", types)
    self.assertIn("file", types)
    self.assertIn("observed-data", types)

def test_search_rows_ip_deduplication(self):
    """Same IP in multiple rows produces only one ipv4-addr object."""
    rows = [
        {"src": "10.0.0.1"},
        {"src": "10.0.0.1"},  # duplicate
        {"src": "10.0.0.2"},
    ]
    bundle = self.mapper.splunk_search_rows_to_stix_bundle(rows)
    ip_objects = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
    values = [o["value"] for o in ip_objects]
    self.assertEqual(values.count("10.0.0.1"), 1)
    self.assertEqual(values.count("10.0.0.2"), 1)

def test_empty_rows_produces_empty_bundle(self):
    bundle = self.mapper.splunk_search_rows_to_stix_bundle([])
    self.assertEqual(bundle["objects"], [])
```

# ═════════════════════════════════════════════════════════════════════════════

# Exception hierarchy tests

# ═════════════════════════════════════════════════════════════════════════════

class TestSplunkExceptions(unittest.TestCase):

```
def test_all_exceptions_inherit_from_base(self):
    from gnat.connectors.splunk.exceptions import SplunkError
    for exc_cls in [
        SplunkConfigError,
        SplunkAuthError,
        SplunkAPIError,
        SplunkRateLimitError,
        SplunkNotFoundError,
        SplunkSearchError,
        SplunkThreatIntelError,
        SplunkSTIXError,
    ]:
        self.assertTrue(issubclass(exc_cls, SplunkError))

def test_api_error_str_includes_status(self):
    exc = SplunkAPIError("msg", status_code=500, endpoint="/api/test")
    self.assertIn("500", str(exc))
    self.assertIn("/api/test", str(exc))

def test_search_error_str_includes_sid(self):
    exc = SplunkSearchError("failed", job_sid="abc123", dispatch_state="FAILED")
    self.assertIn("abc123", str(exc))
    self.assertIn("FAILED", str(exc))

def test_rate_limit_is_api_error(self):
    self.assertTrue(issubclass(SplunkRateLimitError, SplunkAPIError))

def test_not_found_is_api_error(self):
    self.assertTrue(issubclass(SplunkNotFoundError, SplunkAPIError))
```

if **name** == “**main**”:
unittest.main(verbosity=2)
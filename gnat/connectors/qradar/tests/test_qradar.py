"""
tests/connectors/test_qradar.py
==================================
Unit tests for the GNAT QRadar connector.

All HTTP is mocked via unittest.mock on urllib3.PoolManager.
No live QRadar instance required.

Architecture note
-----------------
QRadar's defining quirk is Range-header pagination. Tests verify that:
  - Range: items=0-49 is sent on the first page
  - Content-Range response headers are parsed for total count
  - Iteration stops correctly when offset >= total

Coverage
--------
- QRadarConfig: validation, INI loading, header construction
- QRadarAuthManager: verify, token header
- QRadarClient: GET/POST/PUT/DELETE, Range pagination, error mapping
- QRadarOffenseCommands: list, get, update, notes, normalise
- QRadarArielCommands: create, poll, cancel, results, query builders
- QRadarReferenceDataCommands: set/map CRUD, bulk load, IOC helpers
- QRadarRulesCommands: list, get, search
- QRadarAssetCommands: list, get, search by IP
- QRadarLogSourceCommands: list, get
- QRadarSTIXMapper: offense→STIX, event→STIX, STIX→reference sets

Running
-------
    pytest tests/connectors/test_qradar.py -v
"""

import configparser
import json
import unittest
from unittest.mock import MagicMock, patch

from gnat.connectors.qradar.config import QRadarConfig, load_qradar_config
from gnat.connectors.qradar.exceptions import (
    QRadarAPIError,
    QRadarArielError,
    QRadarAuthError,
    QRadarConfigError,
    QRadarConflictError,
    QRadarNotFoundError,
    QRadarRateLimitError,
    QRadarSTIXError,
)
from gnat.connectors.qradar.auth import QRadarAuthManager
from gnat.connectors.qradar.client import QRadarClient
from gnat.connectors.qradar.offenses import (
    QRadarOffenseCommands,
    _magnitude_to_severity,
    _epoch_ms_to_iso,
)
from gnat.connectors.qradar.ariel import QRadarArielCommands
from gnat.connectors.qradar.reference_data import QRadarReferenceDataCommands
from gnat.connectors.qradar.rules import QRadarRulesCommands
from gnat.connectors.qradar.assets import QRadarAssetCommands
from gnat.connectors.qradar.log_sources import QRadarLogSourceCommands
from gnat.connectors.qradar.stix_mapper import QRadarSTIXMapper


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_config(**overrides) -> QRadarConfig:
    defaults = dict(host="qradar.test.local", token="test-uuid-token")
    defaults.update(overrides)
    return QRadarConfig(**defaults)


def _make_response(
    status: int = 200,
    body=None,
    content_range: str | None = None,
) -> MagicMock:
    """Build a mock urllib3 HTTPResponse."""
    resp = MagicMock()
    resp.status = status
    payload = body if body is not None else {}
    resp.data = json.dumps(payload).encode("utf-8")
    # Simulate urllib3 headers dict
    headers_dict = {}
    if content_range:
        headers_dict["Content-Range"] = content_range
    resp.headers = headers_dict
    return resp


def _make_client(config: QRadarConfig | None = None) -> tuple[QRadarClient, MagicMock]:
    cfg = config or _make_config()
    with patch("gnat.connectors.qradar.client.urllib3.PoolManager") as pm_cls:
        mock_pm = MagicMock()
        pm_cls.return_value = mock_pm
        client = QRadarClient(cfg)
        client._http = mock_pm
        client.auth._http = mock_pm
    return client, mock_pm


# ── Sample data ───────────────────────────────────────────────────────────────

_SAMPLE_OFFENSE = {
    "id": 42,
    "description": "Multiple Login Failures Followed By Success",
    "status": "OPEN",
    "magnitude": 7,
    "severity": 7,
    "credibility": 8,
    "relevance": 9,
    "offense_type": 3,
    "offense_source": "jdoe",
    "event_count": 150,
    "flow_count": 0,
    "device_count": 2,
    "start_time": 1709640000000,
    "last_updated_time": 1709643600000,
    "close_time": None,
    "assigned_to": "analyst1",
    "categories": ["Authentication", "Credential Abuse"],
    "source_address_ids": [101, 102],
    "destination_networks": ["10.0.0.0/8"],
    "domain_id": 0,
}

_SAMPLE_ARIEL_JOB = {
    "search_id": "search-uuid-001",
    "status": "COMPLETED",
    "progress": 100,
    "completed": True,
    "error_messages": [],
    "query_string": "SELECT sourceip FROM events LAST 1 HOURS",
    "record_count": 5,
}

_SAMPLE_EVENT_ROW = {
    "starttime": "2024-03-10 12:00:00",
    "logsourceid": 73,
    "logsource": "Windows Auth",
    "category": 4001,
    "categoryname": "Authentication",
    "severity": 5,
    "sourceip": "10.0.0.1",
    "destinationip": "192.168.1.100",
    "sourceport": 49152,
    "destinationport": 445,
    "protocol": "TCP",
    "username": "jdoe",
    "eventname": "User Login Failed",
    "eventcount": 1,
}


# ═════════════════════════════════════════════════════════════════════════════
# QRadarConfig
# ═════════════════════════════════════════════════════════════════════════════

class TestQRadarConfig(unittest.TestCase):

    def test_minimal_config(self):
        cfg = _make_config()
        self.assertEqual(cfg.host, "qradar.test.local")
        self.assertEqual(cfg.token, "test-uuid-token")
        self.assertEqual(cfg.api_version, "20.0")

    def test_base_url(self):
        cfg = _make_config()
        self.assertEqual(cfg.base_url, "https://qradar.test.local/api")

    def test_endpoint_helper(self):
        cfg = _make_config()
        self.assertEqual(
            cfg.endpoint("siem/offenses"),
            "https://qradar.test.local/api/siem/offenses",
        )

    def test_base_headers_sec_token(self):
        cfg = _make_config()
        headers = cfg.base_headers
        self.assertEqual(headers["SEC"], "test-uuid-token")
        self.assertEqual(headers["Version"], "20.0")
        self.assertEqual(headers["Accept"], "application/json")

    def test_json_headers_has_content_type(self):
        cfg = _make_config()
        headers = cfg.json_headers
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertIn("SEC", headers)

    def test_no_bearer_in_headers(self):
        """QRadar uses SEC, not Authorization: Bearer."""
        cfg = _make_config()
        headers = cfg.base_headers
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("Bearer", str(headers))

    def test_missing_host_raises(self):
        with self.assertRaises(QRadarConfigError):
            QRadarConfig(host="", token="t")

    def test_missing_token_raises(self):
        with self.assertRaises(QRadarConfigError):
            QRadarConfig(host="h", token="")

    def test_invalid_scheme_raises(self):
        with self.assertRaises(QRadarConfigError):
            QRadarConfig(host="h", token="t", scheme="ftp")

    def test_load_from_configparser(self):
        parser = configparser.ConfigParser()
        parser.read_dict({
            "qradar": {
                "host": "qradar.corp",
                "token": "my-token",
                "verify_ssl": "false",
                "api_version": "19.0",
                "max_results": "100",
            }
        })
        cfg = load_qradar_config(parser)
        self.assertEqual(cfg.host, "qradar.corp")
        self.assertFalse(cfg.verify_ssl)
        self.assertEqual(cfg.api_version, "19.0")
        self.assertEqual(cfg.max_results, 100)

    def test_load_missing_section_raises(self):
        with self.assertRaises(QRadarConfigError):
            load_qradar_config(configparser.ConfigParser())

    def test_load_missing_token_raises(self):
        parser = configparser.ConfigParser()
        parser.read_dict({"qradar": {"host": "h"}})
        with self.assertRaises(QRadarConfigError):
            load_qradar_config(parser)


# ═════════════════════════════════════════════════════════════════════════════
# QRadarAuthManager
# ═════════════════════════════════════════════════════════════════════════════

class TestQRadarAuthManager(unittest.TestCase):

    def _make_auth(self, config=None):
        cfg = config or _make_config()
        mock_http = MagicMock()
        return QRadarAuthManager(cfg, mock_http), mock_http

    def test_get_headers_includes_sec(self):
        auth, _ = self._make_auth()
        headers = auth.get_headers()
        self.assertEqual(headers["SEC"], "test-uuid-token")

    def test_get_headers_with_body_includes_content_type(self):
        auth, _ = self._make_auth()
        headers = auth.get_headers(with_body=True)
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_verify_success(self):
        auth, mock_http = self._make_auth()
        mock_http.request.return_value = _make_response(
            200, {"id": "20.0", "deprecated": False}
        )
        result = auth.verify()
        self.assertIsInstance(result, dict)

    def test_verify_401_raises(self):
        auth, mock_http = self._make_auth()
        mock_http.request.return_value = _make_response(401)
        with self.assertRaises(QRadarAuthError):
            auth.verify()

    def test_verify_403_raises(self):
        auth, mock_http = self._make_auth()
        mock_http.request.return_value = _make_response(403)
        with self.assertRaises(QRadarAuthError):
            auth.verify()


# ═════════════════════════════════════════════════════════════════════════════
# QRadarClient
# ═════════════════════════════════════════════════════════════════════════════

class TestQRadarClient(unittest.TestCase):

    def test_get_returns_dict(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(200, {"id": 42})
        result = client.get("siem/offenses/42")
        self.assertEqual(result["id"], 42)

    def test_get_sends_sec_header(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(200, {})
        client.get("siem/offenses")
        call_args = mock_http.request.call_args
        headers = call_args[1]["headers"]
        self.assertEqual(headers["SEC"], "test-uuid-token")

    def test_get_sends_version_header(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(200, {})
        client.get("siem/offenses")
        headers = mock_http.request.call_args[1]["headers"]
        self.assertEqual(headers["Version"], "20.0")

    def test_get_with_range_header(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(200, [])
        client.get("siem/offenses", range_header="items=0-49")
        headers = mock_http.request.call_args[1]["headers"]
        self.assertEqual(headers["Range"], "items=0-49")

    def test_401_raises_auth_error(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(401)
        with self.assertRaises(QRadarAuthError):
            client.get("siem/offenses")

    def test_403_raises_auth_error(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(403, {
            "code": 1002, "description": "Not authorized"
        })
        with self.assertRaises(QRadarAuthError):
            client.get("siem/offenses")

    def test_404_raises_not_found(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(404, {
            "code": 1003, "description": "Offense not found"
        })
        with self.assertRaises(QRadarNotFoundError) as ctx:
            client.get("siem/offenses/9999")
        self.assertEqual(ctx.exception.qradar_code, 1003)

    def test_409_raises_conflict(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(409, {
            "description": "Duplicate reference set name"
        })
        with self.assertRaises(QRadarConflictError):
            client.post("reference_data/sets", params={"name": "dup"})

    def test_429_retries_then_raises(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(429)
        with patch("time.sleep"):
            with self.assertRaises(QRadarRateLimitError):
                client.get("siem/offenses")

    def test_context_manager(self):
        cfg = _make_config()
        with patch("gnat.connectors.qradar.client.urllib3.PoolManager"):
            with QRadarClient(cfg) as c:
                self.assertIsInstance(c, QRadarClient)

    def test_paginate_sends_range_header(self):
        """paginate() sends Range: items=0-49 on first call."""
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(
            200, [{"id": 1}], content_range="items 0-0/1"
        )
        list(client.paginate("siem/offenses", page_size=50))
        headers = mock_http.request.call_args[1]["headers"]
        self.assertIn("Range", headers)
        self.assertIn("items=0-", headers["Range"])

    def test_paginate_reads_content_range_total(self):
        """paginate() parses Content-Range total to know when to stop."""
        client, mock_http = _make_client()
        page1 = [{"id": i} for i in range(50)]
        page2 = [{"id": i} for i in range(50, 75)]
        mock_http.request.side_effect = [
            _make_response(200, page1, content_range="items 0-49/75"),
            _make_response(200, page2, content_range="items 50-74/75"),
        ]
        items = list(client.paginate("siem/offenses", page_size=50))
        self.assertEqual(len(items), 75)
        self.assertEqual(mock_http.request.call_count, 2)

    def test_paginate_stops_on_empty_page(self):
        """paginate() stops when an empty page is returned."""
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(200, [], content_range="items 0-0/0")
        items = list(client.paginate("siem/offenses"))
        self.assertEqual(items, [])

    def test_parse_content_range_total(self):
        self.assertEqual(QRadarClient._parse_content_range_total("items 0-49/1234"), 1234)
        self.assertEqual(QRadarClient._parse_content_range_total(""), 0)
        self.assertEqual(QRadarClient._parse_content_range_total("items 0-0/1"), 1)

    def test_get_total_count(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(
            200, [{"id": 1}], content_range="items 0-0/999"
        )
        count = client.get_total_count("siem/offenses")
        self.assertEqual(count, 999)
        headers = mock_http.request.call_args[1]["headers"]
        self.assertEqual(headers["Range"], "items=0-0")


# ═════════════════════════════════════════════════════════════════════════════
# QRadarOffenseCommands
# ═════════════════════════════════════════════════════════════════════════════

class TestQRadarOffenseCommands(unittest.TestCase):

    def _make_offenses(self):
        client, mock_http = _make_client()
        return QRadarOffenseCommands(client), mock_http

    def test_list_offenses(self):
        off_cmd, mock_http = self._make_offenses()
        mock_http.request.return_value = _make_response(
            200, [_SAMPLE_OFFENSE], content_range="items 0-0/1"
        )
        results = off_cmd.list_offenses()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], 42)

    def test_list_offenses_default_status_filter(self):
        """list_offenses() applies config.offense_status by default."""
        off_cmd, mock_http = self._make_offenses()
        mock_http.request.return_value = _make_response(
            200, [], content_range="items 0-0/0"
        )
        off_cmd.list_offenses()
        call_url = mock_http.request.call_args[0][1]
        self.assertIn("OPEN", call_url)

    def test_get_offense(self):
        off_cmd, mock_http = self._make_offenses()
        mock_http.request.return_value = _make_response(200, _SAMPLE_OFFENSE)
        result = off_cmd.get_offense(42)
        self.assertEqual(result["id"], 42)

    def test_update_offense_status(self):
        off_cmd, mock_http = self._make_offenses()
        mock_http.request.return_value = _make_response(
            200, {**_SAMPLE_OFFENSE, "status": "CLOSED"}
        )
        result = off_cmd.update_offense(42, status="CLOSED", closing_reason_id=1)
        self.assertIsNotNone(result)
        call_url = mock_http.request.call_args[0][1]
        self.assertIn("status=CLOSED", call_url)

    def test_close_offense(self):
        off_cmd, mock_http = self._make_offenses()
        mock_http.request.return_value = _make_response(200, _SAMPLE_OFFENSE)
        off_cmd.close_offense(42, closing_reason_id=2)
        call_url = mock_http.request.call_args[0][1]
        self.assertIn("CLOSED", call_url)

    def test_add_note(self):
        off_cmd, mock_http = self._make_offenses()
        mock_http.request.return_value = _make_response(
            201, {"id": 1, "note_text": "Investigating"}
        )
        result = off_cmd.add_note(42, "Investigating")
        self.assertIsNotNone(result)

    def test_normalise_offense(self):
        result = QRadarOffenseCommands.normalise_offense(_SAMPLE_OFFENSE)
        self.assertEqual(result["id"], 42)
        self.assertEqual(result["offense_type_label"], "Username")
        self.assertEqual(result["offense_source"], "jdoe")
        self.assertEqual(result["severity"], 3)   # magnitude 7 → high
        self.assertEqual(result["severity_label"], "high")
        self.assertIsNotNone(result["start_time"])
        # Verify epoch ms converted to ISO 8601
        self.assertIn("2024", result["start_time"])

    def test_magnitude_to_severity_mapping(self):
        self.assertEqual(_magnitude_to_severity(0), 0)
        self.assertEqual(_magnitude_to_severity(2), 0)
        self.assertEqual(_magnitude_to_severity(3), 1)
        self.assertEqual(_magnitude_to_severity(5), 2)
        self.assertEqual(_magnitude_to_severity(7), 3)
        self.assertEqual(_magnitude_to_severity(9), 4)
        self.assertEqual(_magnitude_to_severity(10), 4)

    def test_epoch_ms_to_iso(self):
        ts = _epoch_ms_to_iso(1709640000000)
        self.assertIsNotNone(ts)
        self.assertIn("2024", ts)
        self.assertTrue(ts.endswith("Z"))

    def test_epoch_ms_to_iso_none(self):
        self.assertIsNone(_epoch_ms_to_iso(None))
        self.assertIsNone(_epoch_ms_to_iso(0))


# ═════════════════════════════════════════════════════════════════════════════
# QRadarArielCommands
# ═════════════════════════════════════════════════════════════════════════════

class TestQRadarArielCommands(unittest.TestCase):

    def _make_ariel(self):
        client, mock_http = _make_client()
        return QRadarArielCommands(client), mock_http

    def test_create_search(self):
        ariel, mock_http = self._make_ariel()
        mock_http.request.return_value = _make_response(201, {
            "search_id": "search-001",
            "status": "EXECUTE",
        })
        search_id = ariel.create_search("SELECT sourceip FROM events LAST 1 HOURS")
        self.assertEqual(search_id, "search-001")

    def test_get_search_status(self):
        ariel, mock_http = self._make_ariel()
        mock_http.request.return_value = _make_response(200, _SAMPLE_ARIEL_JOB)
        result = ariel.get_search_status("search-uuid-001")
        self.assertEqual(result["status"], "COMPLETED")

    def test_wait_for_completion_succeeds(self):
        ariel, mock_http = self._make_ariel()
        mock_http.request.return_value = _make_response(200, _SAMPLE_ARIEL_JOB)
        result = ariel.wait_for_completion("search-uuid-001")
        self.assertEqual(result["status"], "COMPLETED")

    def test_wait_for_completion_polls_until_done(self):
        ariel, mock_http = self._make_ariel()
        mock_http.request.side_effect = [
            _make_response(200, {**_SAMPLE_ARIEL_JOB, "status": "EXECUTE"}),
            _make_response(200, {**_SAMPLE_ARIEL_JOB, "status": "SORTING"}),
            _make_response(200, {**_SAMPLE_ARIEL_JOB, "status": "COMPLETED"}),
        ]
        with patch("time.sleep"):
            result = ariel.wait_for_completion("search-uuid-001", poll_interval=0.01)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(mock_http.request.call_count, 3)

    def test_wait_for_completion_error_raises(self):
        ariel, mock_http = self._make_ariel()
        mock_http.request.return_value = _make_response(200, {
            **_SAMPLE_ARIEL_JOB,
            "status": "ERROR",
            "error_messages": ["AQL syntax error near 'FORM'"],
        })
        with self.assertRaises(QRadarArielError) as ctx:
            ariel.wait_for_completion("search-001")
        self.assertEqual(ctx.exception.status, "ERROR")
        self.assertIn("syntax error", str(ctx.exception.error_messages[0]))

    def test_wait_for_completion_cancelled_raises(self):
        ariel, mock_http = self._make_ariel()
        mock_http.request.return_value = _make_response(200, {
            **_SAMPLE_ARIEL_JOB, "status": "CANCELLED"
        })
        with self.assertRaises(QRadarArielError) as ctx:
            ariel.wait_for_completion("search-001")
        self.assertEqual(ctx.exception.status, "CANCELLED")

    def test_wait_for_completion_timeout_raises(self):
        ariel, mock_http = self._make_ariel()
        mock_http.request.return_value = _make_response(200, {
            **_SAMPLE_ARIEL_JOB, "status": "EXECUTE"
        })
        with patch("time.sleep"), patch("time.time", side_effect=[0, 0, 9999]):
            with self.assertRaises(QRadarArielError) as ctx:
                ariel.wait_for_completion("search-001", timeout_secs=1)
        self.assertIn("timed out", str(ctx.exception))

    def test_iter_results_yields_events(self):
        ariel, mock_http = self._make_ariel()
        results_body = {
            "events": [_SAMPLE_EVENT_ROW, {**_SAMPLE_EVENT_ROW, "sourceip": "10.0.0.2"}],
            "record_count": 2,
        }
        mock_http.request.return_value = _make_response(
            200, results_body, content_range="items 0-1/2"
        )
        rows = list(ariel.iter_results("search-uuid-001"))
        self.assertEqual(len(rows), 2)

    def test_build_event_query_defaults(self):
        aql = QRadarArielCommands.build_event_query()
        self.assertIn("SELECT", aql)
        self.assertIn("FROM events", aql)
        self.assertIn("LAST 1 HOURS", aql)

    def test_build_event_query_with_where(self):
        aql = QRadarArielCommands.build_event_query(
            where="category=4001",
            time_range="LAST 24 HOURS",
            limit=1000,
        )
        self.assertIn("WHERE category=4001", aql)
        self.assertIn("LAST 24 HOURS", aql)
        self.assertIn("LIMIT 1000", aql)

    def test_build_flow_query(self):
        aql = QRadarArielCommands.build_flow_query(
            where="sourcebytes > 1000000",
            time_range="LAST 30 MINUTES",
        )
        self.assertIn("FROM flows", aql)
        self.assertIn("sourcebytes > 1000000", aql)

    def test_normalise_event_row(self):
        result = QRadarArielCommands.normalise_event_row(_SAMPLE_EVENT_ROW)
        self.assertEqual(result["src_ip"], "10.0.0.1")
        self.assertEqual(result["dst_ip"], "192.168.1.100")
        self.assertEqual(result["src_port"], 49152)
        self.assertEqual(result["username"], "jdoe")
        self.assertEqual(result["category_name"], "Authentication")


# ═════════════════════════════════════════════════════════════════════════════
# QRadarReferenceDataCommands
# ═════════════════════════════════════════════════════════════════════════════

class TestQRadarReferenceDataCommands(unittest.TestCase):

    def _make_rd(self):
        client, mock_http = _make_client()
        return QRadarReferenceDataCommands(client), mock_http

    def test_list_sets(self):
        rd, mock_http = self._make_rd()
        mock_http.request.return_value = _make_response(
            200, [{"name": "gnat_ips", "element_type": "IP"}],
            content_range="items 0-0/1"
        )
        results = rd.list_sets()
        self.assertEqual(len(results), 1)

    def test_create_set(self):
        rd, mock_http = self._make_rd()
        mock_http.request.return_value = _make_response(201, {
            "name": "my_set", "element_type": "IP", "number_of_elements": 0
        })
        result = rd.create_set("my_set", element_type="IP")
        self.assertEqual(result["name"], "my_set")
        call_url = mock_http.request.call_args[0][1]
        self.assertIn("reference_data/sets", call_url)
        self.assertIn("IP", call_url)

    def test_add_set_values_bulk(self):
        rd, mock_http = self._make_rd()
        mock_http.request.return_value = _make_response(200, {
            "name": "my_ips", "number_of_elements": 3
        })
        result = rd.add_set_values_bulk("my_ips", ["1.2.3.4", "5.6.7.8", "9.10.11.12"])
        self.assertIsNotNone(result)
        # Verify the body was a list of IPs
        body = json.loads(mock_http.request.call_args[1]["body"])
        self.assertIn("1.2.3.4", body)

    def test_ensure_set_exists_creates_if_missing(self):
        rd, mock_http = self._make_rd()
        # First call = 404 (not found), second call = 201 (created)
        mock_http.request.side_effect = [
            _make_response(404, {"code": 1003, "description": "Not found"}),
            _make_response(201, {"name": "new_set", "element_type": "IP"}),
        ]
        result = rd.ensure_set_exists("new_set", element_type="IP")
        self.assertEqual(result["name"], "new_set")
        self.assertEqual(mock_http.request.call_count, 2)

    def test_ensure_set_exists_returns_existing(self):
        rd, mock_http = self._make_rd()
        mock_http.request.return_value = _make_response(200, {
            "name": "existing_set", "element_type": "IP"
        })
        result = rd.ensure_set_exists("existing_set")
        self.assertEqual(result["name"], "existing_set")
        self.assertEqual(mock_http.request.call_count, 1)

    def test_push_ip_iocs(self):
        rd, mock_http = self._make_rd()
        # ensure_set_exists → 200 (exists), bulk_load → 200
        mock_http.request.side_effect = [
            _make_response(200, {"name": "gnat_ips"}),
            _make_response(200, {"name": "gnat_ips", "number_of_elements": 2}),
        ]
        result = rd.push_ip_iocs("gnat_ips", ["1.2.3.4", "5.6.7.8"])
        self.assertIsNotNone(result)

    def test_create_map(self):
        rd, mock_http = self._make_rd()
        mock_http.request.return_value = _make_response(201, {
            "name": "ioc_map", "element_type": "ALN"
        })
        result = rd.create_map("ioc_map")
        self.assertIsNotNone(result)

    def test_add_map_entry(self):
        rd, mock_http = self._make_rd()
        mock_http.request.return_value = _make_response(200, {"name": "my_map"})
        rd.add_map_entry("my_map", "1.2.3.4", "C2 Server")
        call_url = mock_http.request.call_args[0][1]
        self.assertIn("maps/my_map", call_url)


# ═════════════════════════════════════════════════════════════════════════════
# QRadarRulesCommands
# ═════════════════════════════════════════════════════════════════════════════

class TestQRadarRulesCommands(unittest.TestCase):

    def _make_rules(self):
        client, mock_http = _make_client()
        return QRadarRulesCommands(client), mock_http

    def test_list_rules(self):
        rules_cmd, mock_http = self._make_rules()
        mock_http.request.return_value = _make_response(
            200,
            [{"id": 100, "name": "Brute Force Attempt", "type": "COMMON", "enabled": True}],
            content_range="items 0-0/1",
        )
        results = rules_cmd.list_rules()
        self.assertEqual(results[0]["name"], "Brute Force Attempt")

    def test_get_rule(self):
        rules_cmd, mock_http = self._make_rules()
        mock_http.request.return_value = _make_response(200, {"id": 100, "name": "My Rule"})
        result = rules_cmd.get_rule(100)
        self.assertEqual(result["id"], 100)

    def test_list_rules_enabled_only(self):
        rules_cmd, mock_http = self._make_rules()
        mock_http.request.return_value = _make_response(
            200, [], content_range="items 0-0/0"
        )
        rules_cmd.list_rules(enabled_only=True)
        call_url = mock_http.request.call_args[0][1]
        # urllib may percent-encode the '=' in the filter value
        self.assertTrue(
            "enabled=true" in call_url or "enabled%3Dtrue" in call_url,
            f"expected filter in URL, got: {call_url}",
        )


# ═════════════════════════════════════════════════════════════════════════════
# QRadarAssetCommands
# ═════════════════════════════════════════════════════════════════════════════

class TestQRadarAssetCommands(unittest.TestCase):

    def _make_assets(self):
        client, mock_http = _make_client()
        return QRadarAssetCommands(client), mock_http

    def test_list_assets(self):
        assets_cmd, mock_http = self._make_assets()
        mock_http.request.return_value = _make_response(
            200, [{"id": 1, "domain_id": 0}],
            content_range="items 0-0/1"
        )
        results = assets_cmd.list_assets()
        self.assertEqual(len(results), 1)

    def test_get_asset(self):
        assets_cmd, mock_http = self._make_assets()
        mock_http.request.return_value = _make_response(200, {"id": 1})
        result = assets_cmd.get_asset(1)
        self.assertEqual(result["id"], 1)

    def test_search_by_ip(self):
        assets_cmd, mock_http = self._make_assets()
        mock_http.request.return_value = _make_response(
            200, [], content_range="items 0-0/0"
        )
        assets_cmd.search_by_ip("10.0.0.1")
        call_url = mock_http.request.call_args[0][1]
        self.assertIn("10.0.0.1", call_url)


# ═════════════════════════════════════════════════════════════════════════════
# QRadarLogSourceCommands
# ═════════════════════════════════════════════════════════════════════════════

class TestQRadarLogSourceCommands(unittest.TestCase):

    def _make_ls(self):
        client, mock_http = _make_client()
        return QRadarLogSourceCommands(client), mock_http

    def test_list_log_sources(self):
        ls_cmd, mock_http = self._make_ls()
        mock_http.request.return_value = _make_response(
            200, [{"id": 73, "name": "Windows Auth"}],
            content_range="items 0-0/1"
        )
        results = ls_cmd.list_log_sources()
        self.assertEqual(results[0]["name"], "Windows Auth")

    def test_get_log_source(self):
        ls_cmd, mock_http = self._make_ls()
        mock_http.request.return_value = _make_response(200, {"id": 73})
        result = ls_cmd.get_log_source(73)
        self.assertEqual(result["id"], 73)

    def test_get_log_source_count(self):
        ls_cmd, mock_http = self._make_ls()
        mock_http.request.return_value = _make_response(
            200, [{"id": 1}], content_range="items 0-0/42"
        )
        count = ls_cmd.get_log_source_count()
        self.assertEqual(count, 42)


# ═════════════════════════════════════════════════════════════════════════════
# QRadarSTIXMapper
# ═════════════════════════════════════════════════════════════════════════════

class TestQRadarSTIXMapper(unittest.TestCase):

    def setUp(self):
        self.mapper = QRadarSTIXMapper()

    # ── A: Offense → STIX ─────────────────────────────────────────────────

    def test_offense_to_stix_bundle_structure(self):
        offense = QRadarOffenseCommands.normalise_offense(_SAMPLE_OFFENSE)
        bundle = self.mapper.offense_to_stix_bundle(offense)
        self.assertEqual(bundle["type"], "bundle")
        self.assertEqual(bundle["spec_version"], "2.1")
        types = {o["type"] for o in bundle["objects"]}
        self.assertIn("observed-data", types)

    def test_offense_type_username_creates_user_account(self):
        """Offense type 3 (Username) → user-account SCO."""
        offense = QRadarOffenseCommands.normalise_offense(_SAMPLE_OFFENSE)
        bundle = self.mapper.offense_to_stix_bundle(offense)
        types = [o["type"] for o in bundle["objects"]]
        self.assertIn("user-account", types)
        ua = next(o for o in bundle["objects"] if o["type"] == "user-account")
        self.assertEqual(ua["user_id"], "jdoe")

    def test_offense_type_source_ip_creates_ipv4(self):
        """Offense type 0 (Source IP) → ipv4-addr SCO."""
        ip_offense = {**_SAMPLE_OFFENSE, "offense_type": 0, "offense_source": "1.2.3.4"}
        offense = QRadarOffenseCommands.normalise_offense(ip_offense)
        bundle = self.mapper.offense_to_stix_bundle(offense)
        types = [o["type"] for o in bundle["objects"]]
        self.assertIn("ipv4-addr", types)
        ip_obj = next(o for o in bundle["objects"] if o["type"] == "ipv4-addr")
        self.assertEqual(ip_obj["value"], "1.2.3.4")

    def test_offense_type_hostname_creates_domain(self):
        """Offense type 6 (Hostname) → domain-name SCO."""
        host_offense = {**_SAMPLE_OFFENSE, "offense_type": 6, "offense_source": "evil.corp"}
        offense = QRadarOffenseCommands.normalise_offense(host_offense)
        bundle = self.mapper.offense_to_stix_bundle(offense)
        types = [o["type"] for o in bundle["objects"]]
        self.assertIn("domain-name", types)

    def test_observed_data_has_qradar_extension(self):
        offense = QRadarOffenseCommands.normalise_offense(_SAMPLE_OFFENSE)
        bundle = self.mapper.offense_to_stix_bundle(offense)
        obs = next(o for o in bundle["objects"] if o["type"] == "observed-data")
        self.assertIn("x_qradar_offense", obs)
        ext = obs["x_qradar_offense"]
        self.assertEqual(ext["offense_id"], 42)
        self.assertEqual(ext["offense_source"], "jdoe")

    def test_offenses_bundle_deduplicates_scos(self):
        """Same offense_source in two offenses appears once in merged bundle."""
        offense = QRadarOffenseCommands.normalise_offense(_SAMPLE_OFFENSE)
        bundle = self.mapper.offenses_to_stix_bundle([offense, offense])
        ua_objects = [o for o in bundle["objects"] if o["type"] == "user-account"]
        jdoe_count = sum(1 for o in ua_objects if o["user_id"] == "jdoe")
        self.assertEqual(jdoe_count, 1)

    def test_offense_number_observed_uses_event_count(self):
        offense = QRadarOffenseCommands.normalise_offense(_SAMPLE_OFFENSE)
        bundle = self.mapper.offense_to_stix_bundle(offense)
        obs = next(o for o in bundle["objects"] if o["type"] == "observed-data")
        self.assertEqual(obs["number_observed"], 150)

    # ── A: Ariel event → STIX ─────────────────────────────────────────────

    def test_event_to_stix_bundle_structure(self):
        event = QRadarArielCommands.normalise_event_row(_SAMPLE_EVENT_ROW)
        bundle = self.mapper.event_to_stix_bundle(event)
        types = {o["type"] for o in bundle["objects"]}
        self.assertIn("ipv4-addr", types)
        self.assertIn("network-traffic", types)
        self.assertIn("user-account", types)
        self.assertIn("observed-data", types)

    def test_event_observed_data_has_qradar_extension(self):
        event = QRadarArielCommands.normalise_event_row(_SAMPLE_EVENT_ROW)
        bundle = self.mapper.event_to_stix_bundle(event)
        obs = next(o for o in bundle["objects"] if o["type"] == "observed-data")
        self.assertIn("x_qradar_event", obs)
        self.assertEqual(obs["x_qradar_event"]["category_name"], "Authentication")

    def test_event_network_traffic_ports(self):
        event = QRadarArielCommands.normalise_event_row(_SAMPLE_EVENT_ROW)
        bundle = self.mapper.event_to_stix_bundle(event)
        nt = next(o for o in bundle["objects"] if o["type"] == "network-traffic")
        self.assertEqual(nt.get("src_port"), 49152)
        self.assertEqual(nt.get("dst_port"), 445)

    def test_events_bundle_deduplication(self):
        event = QRadarArielCommands.normalise_event_row(_SAMPLE_EVENT_ROW)
        bundle = self.mapper.events_to_stix_bundle([event, event])
        ip_objects = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
        values = [o["value"] for o in ip_objects]
        self.assertEqual(values.count("10.0.0.1"), 1)

    # ── B: STIX → reference sets ───────────────────────────────────────────

    def test_stix_bundle_to_reference_sets_ipv4(self):
        bundle = {
            "type": "bundle", "spec_version": "2.1",
            "objects": [
                {"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "1.2.3.4"},
                {"type": "ipv4-addr", "id": "ipv4-addr--2", "value": "5.6.7.8"},
            ]
        }
        groups = self.mapper.stix_bundle_to_reference_sets(bundle)
        self.assertIn("1.2.3.4", groups["ip"])
        self.assertIn("5.6.7.8", groups["ip"])
        self.assertEqual(len(groups["domain"]), 0)

    def test_stix_bundle_to_reference_sets_mixed(self):
        bundle = {
            "type": "bundle", "spec_version": "2.1",
            "objects": [
                {"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "1.2.3.4"},
                {"type": "domain-name", "id": "domain-name--1", "value": "evil.com"},
                {"type": "url", "id": "url--1", "value": "https://evil.com/path"},
                {"type": "email-addr", "id": "email-addr--1", "value": "atk@evil.com"},
                {"type": "file", "id": "file--1",
                 "hashes": {"SHA-256": "abc123", "MD5": "def456"}},
            ]
        }
        groups = self.mapper.stix_bundle_to_reference_sets(bundle)
        self.assertIn("1.2.3.4", groups["ip"])
        self.assertIn("evil.com", groups["domain"])
        self.assertIn("https://evil.com/path", groups["url"])
        self.assertIn("atk@evil.com", groups["email"])
        self.assertIn("abc123", groups["hash"])  # SHA-256 preferred

    def test_stix_bundle_to_reference_sets_deduplication(self):
        bundle = {
            "type": "bundle", "spec_version": "2.1",
            "objects": [
                {"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "1.2.3.4"},
                {"type": "ipv4-addr", "id": "ipv4-addr--2", "value": "1.2.3.4"},  # dup
            ]
        }
        groups = self.mapper.stix_bundle_to_reference_sets(bundle)
        self.assertEqual(groups["ip"].count("1.2.3.4"), 1)

    def test_stix_bundle_to_reference_sets_indicator_pattern(self):
        bundle = {
            "type": "bundle", "spec_version": "2.1",
            "objects": [{
                "type": "indicator",
                "id": "indicator--1",
                "pattern": "[ipv4-addr:value = '10.0.0.99']",
                "pattern_type": "stix",
                "valid_from": "2024-01-01T00:00:00Z",
            }]
        }
        groups = self.mapper.stix_bundle_to_reference_sets(bundle)
        self.assertIn("10.0.0.99", groups["ip"])

    def test_invalid_bundle_raises(self):
        with self.assertRaises(QRadarSTIXError):
            self.mapper.stix_bundle_to_reference_sets({"type": "indicator"})


# ═════════════════════════════════════════════════════════════════════════════
# Exception hierarchy
# ═════════════════════════════════════════════════════════════════════════════

class TestQRadarExceptions(unittest.TestCase):

    def test_all_inherit_from_base(self):
        from gnat.connectors.qradar.exceptions import QRadarError
        for exc_cls in [
            QRadarConfigError, QRadarAuthError, QRadarAPIError,
            QRadarNotFoundError, QRadarConflictError, QRadarRateLimitError,
            QRadarArielError, QRadarSTIXError,
        ]:
            self.assertTrue(issubclass(exc_cls, QRadarError))

    def test_api_error_str_includes_context(self):
        exc = QRadarAPIError(
            "msg", status_code=403, qradar_code=1002,
            description="Not authorized", endpoint="/api/siem/offenses"
        )
        s = str(exc)
        self.assertIn("403", s)
        self.assertIn("1002", s)
        self.assertIn("Not authorized", s)

    def test_ariel_error_str(self):
        exc = QRadarArielError(
            "Job failed", search_id="srch-001",
            status="ERROR", error_messages=["AQL syntax error"]
        )
        s = str(exc)
        self.assertIn("srch-001", s)
        self.assertIn("ERROR", s)

    def test_not_found_is_api_error(self):
        self.assertTrue(issubclass(QRadarNotFoundError, QRadarAPIError))

    def test_conflict_is_api_error(self):
        self.assertTrue(issubclass(QRadarConflictError, QRadarAPIError))


if __name__ == "__main__":
    unittest.main(verbosity=2)

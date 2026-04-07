# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""tests for OSSIM connector"""

import configparser
import json
import unittest
from unittest.mock import MagicMock, patch

from gnat.connectors.ossim import (
    OSSIMAlarmCommands,
    OSSIMAssetCommands,
    OSSIMAuthError,
    OSSIMClient,
    OSSIMConfig,
    OSSIMConfigError,
    OSSIMNotFoundError,
    OSSIMSTIXMapper,
    load_ossim_config,
)


def _cfg(**kw):
    d = {"url": "https://ossim.test", "api_key": "test-key"}
    d.update(kw)
    return OSSIMConfig(**d)


def _resp(status=200, body=None):
    r = MagicMock()
    r.status = status
    r.data = json.dumps(body if body is not None else {}).encode()
    return r


def _make_client():
    cfg = _cfg()
    with patch("gnat.connectors.ossim.urllib3.PoolManager") as pm:
        mock_http = MagicMock()
        pm.return_value = mock_http
        c = OSSIMClient(cfg)
        c._http = mock_http
    return c, mock_http


_ALARM = {
    "uuid": "alarm-1",
    "timestamp": "2024-03-10T12:00:00Z",
    "rule_name": "Brute Force Detected",
    "priority": 4,
    "status": "open",
    "src_ip": "1.2.3.4",
    "dst_ip": "10.0.0.1",
    "src_port": "49152",
    "dst_port": "22",
    "protocol": "TCP",
    "sensor": "sensor01",
    "event_count": 50,
}


class TestOSSIMConfig(unittest.TestCase):
    def test_basic(self):
        cfg = _cfg()
        self.assertEqual(cfg.base_url, "https://ossim.test")

    def test_api_key_header(self):
        cfg = _cfg()
        self.assertEqual(cfg.base_headers["X-USM-API-KEY"], "test-key")

    def test_endpoint(self):
        cfg = _cfg()
        self.assertEqual(cfg.endpoint("alarms"), "https://ossim.test/api/1.0/alarms")

    def test_missing_url_raises(self):
        with self.assertRaises(OSSIMConfigError):
            OSSIMConfig(url="", api_key="k")

    def test_missing_api_key_raises(self):
        with self.assertRaises(OSSIMConfigError):
            OSSIMConfig(url="https://h", api_key="")

    def test_load_from_ini(self):
        p = configparser.ConfigParser()
        p.read_dict({"ossim": {"url": "https://ossim", "api_key": "k"}})
        cfg = load_ossim_config(p)
        self.assertEqual(cfg.api_key, "k")

    def test_verify_ssl_defaults_false(self):
        # OSSIM commonly uses self-signed certs
        cfg = _cfg()
        self.assertFalse(cfg.verify_ssl)


class TestOSSIMClient(unittest.TestCase):
    def test_get_sends_api_key_header(self):
        c, mock_http = _make_client()
        mock_http.request.return_value = _resp(200, {"data": []})
        c.get("alarms")
        headers = mock_http.request.call_args[1]["headers"]
        self.assertEqual(headers["X-USM-API-KEY"], "test-key")

    def test_401_raises_auth_error(self):
        c, mock_http = _make_client()
        mock_http.request.return_value = _resp(401)
        with self.assertRaises(OSSIMAuthError):
            c.get("alarms")

    def test_404_raises_not_found(self):
        c, mock_http = _make_client()
        mock_http.request.return_value = _resp(404)
        with self.assertRaises(OSSIMNotFoundError):
            c.get("alarms/missing")

    def test_context_manager(self):
        cfg = _cfg()
        with patch("gnat.connectors.ossim.urllib3.PoolManager"), OSSIMClient(cfg) as client:
            self.assertIsInstance(client, OSSIMClient)


class TestOSSIMAlarmCommands(unittest.TestCase):
    def _make_alarms(self):
        c, mock_http = _make_client()
        return OSSIMAlarmCommands(c), mock_http

    def test_list_alarms(self):
        cmd, mock_http = self._make_alarms()
        mock_http.request.return_value = _resp(200, {"data": [_ALARM], "total": 1})
        results = cmd.list_alarms()
        self.assertEqual(len(results), 1)

    def test_close_alarm(self):
        cmd, mock_http = self._make_alarms()
        mock_http.request.return_value = _resp(200, {"status": "closed"})
        cmd.close_alarm("alarm-1")
        body = json.loads(mock_http.request.call_args[1]["body"])
        self.assertEqual(body["status"], "closed")

    def test_normalise_alarm(self):
        norm = OSSIMAlarmCommands.normalise_alarm(_ALARM)
        self.assertEqual(norm["id"], "alarm-1")
        self.assertEqual(norm["priority"], 4)
        self.assertEqual(norm["severity"], 3)  # priority 4 → high
        self.assertEqual(norm["src_ip"], "1.2.3.4")
        self.assertEqual(norm["event_count"], 50)

    def test_priority_to_severity_mapping(self):
        for prio, expected_sev in [(1, 0), (2, 1), (3, 2), (4, 3), (5, 4)]:
            alarm = {**_ALARM, "priority": prio}
            result = OSSIMAlarmCommands.normalise_alarm(alarm)
            self.assertEqual(result["severity"], expected_sev)

    def test_get_alarm_events(self):
        cmd, mock_http = self._make_alarms()
        mock_http.request.return_value = _resp(200, {"data": [{"event_id": "e1"}]})
        events = cmd.get_alarm_events("alarm-1")
        self.assertEqual(len(events), 1)


class TestOSSIMAssetCommands(unittest.TestCase):
    def _make_assets(self):
        c, mock_http = _make_client()
        return OSSIMAssetCommands(c), mock_http

    def test_list_assets(self):
        cmd, mock_http = self._make_assets()
        mock_http.request.return_value = _resp(
            200, {"data": [{"id": "a1", "ip": "10.0.0.5"}], "total": 1}
        )
        results = cmd.list_assets()
        self.assertEqual(len(results), 1)

    def test_search_by_ip(self):
        cmd, mock_http = self._make_assets()
        mock_http.request.return_value = _resp(200, {"data": []})
        cmd.search_by_ip("10.0.0.5")
        url = mock_http.request.call_args[0][1]
        self.assertIn("10.0.0.5", url)


class TestOSSIMSTIXMapper(unittest.TestCase):
    def setUp(self):
        self.mapper = OSSIMSTIXMapper()
        self._alarm = OSSIMAlarmCommands.normalise_alarm(_ALARM)

    def test_bundle_structure(self):
        bundle = self.mapper.alarm_to_stix_bundle(self._alarm)
        types = {o["type"] for o in bundle["objects"]}
        self.assertIn("ipv4-addr", types)
        self.assertIn("network-traffic", types)
        self.assertIn("observed-data", types)

    def test_observed_data_extension(self):
        bundle = self.mapper.alarm_to_stix_bundle(self._alarm)
        obs = next(o for o in bundle["objects"] if o["type"] == "observed-data")
        self.assertIn("x_ossim_alarm", obs)
        self.assertEqual(obs["x_ossim_alarm"]["priority"], 4)

    def test_number_observed_uses_event_count(self):
        bundle = self.mapper.alarm_to_stix_bundle(self._alarm)
        obs = next(o for o in bundle["objects"] if o["type"] == "observed-data")
        self.assertEqual(obs["number_observed"], 50)

    def test_deduplication(self):
        bundle = self.mapper.alarms_to_stix_bundle([self._alarm, self._alarm])
        ip_objs = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
        self.assertEqual(len([o for o in ip_objs if o["value"] == "1.2.3.4"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

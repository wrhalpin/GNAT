"""tests for Security Onion connector"""
import configparser
import json
import time
import unittest
from unittest.mock import MagicMock, patch

from gnat.connectors.security_onion import (
    SecurityOnionAlertCommands,
    SecurityOnionAuthError,
    SecurityOnionCaseCommands,
    SecurityOnionClient,
    SecurityOnionConfig,
    SecurityOnionConfigError,
    SecurityOnionNotFoundError,
    SecurityOnionSTIXMapper,
    load_security_onion_config,
)


def _cfg(**kw):
    d = {"url": "https://so.test", "username": "admin", "password": "pass"}
    d.update(kw)
    return SecurityOnionConfig(**d)

def _resp(status=200, body=None):
    r = MagicMock()
    r.status = status
    r.data = json.dumps(body if body is not None else {}).encode()
    return r

def _make_client():
    cfg = _cfg()
    with patch("gnat.connectors.security_onion.urllib3.PoolManager") as pm:
        mock_http = MagicMock()
        pm.return_value = mock_http
        c = SecurityOnionClient(cfg)
        c._http = mock_http
        c.auth._http = mock_http
    c.auth._token = "test-token"
    c.auth._acquired_at = time.time()
    return c, mock_http


class TestSecurityOnionConfig(unittest.TestCase):
    def test_basic(self):
        cfg = _cfg()
        self.assertEqual(cfg.base_url, "https://so.test")
        self.assertEqual(cfg.login_url, "https://so.test/api/login")

    def test_endpoint(self):
        cfg = _cfg()
        self.assertEqual(cfg.endpoint("alerts"), "https://so.test/api/alerts")

    def test_missing_url_raises(self):
        with self.assertRaises(SecurityOnionConfigError):
            SecurityOnionConfig(url="", username="u", password="p")

    def test_load_from_ini(self):
        p = configparser.ConfigParser()
        p.read_dict({"security_onion": {"url": "https://so", "username": "u", "password": "p"}})
        cfg = load_security_onion_config(p)
        self.assertEqual(cfg.username, "u")

    def test_load_missing_section_raises(self):
        with self.assertRaises(SecurityOnionConfigError):
            load_security_onion_config(configparser.ConfigParser())


class TestSecurityOnionAuth(unittest.TestCase):
    def test_login_success(self):
        c, mock_http = _make_client()
        c.auth._token = None
        mock_http.request.return_value = _resp(200, {"token": "new-tok"})
        headers = c.auth.get_headers()
        self.assertEqual(headers["Authorization"], "Bearer new-tok")

    def test_login_401_raises(self):
        c, mock_http = _make_client()
        c.auth._token = None
        mock_http.request.return_value = _resp(401)
        with self.assertRaises(SecurityOnionAuthError):
            c.auth.get_headers()


class TestSecurityOnionClient(unittest.TestCase):
    def test_get_returns_dict(self):
        c, mock_http = _make_client()
        mock_http.request.return_value = _resp(200, {"hits": {"hits": []}})
        result = c.get("alerts")
        self.assertIsInstance(result, dict)

    def test_401_triggers_reauth(self):
        c, mock_http = _make_client()
        mock_http.request.side_effect = [
            _resp(401),
            _resp(200, {"token": "new-tok"}),  # re-login
            _resp(200, {"data": []}),
        ]
        result = c.get("cases")
        self.assertIsInstance(result, dict)

    def test_404_raises_not_found(self):
        c, mock_http = _make_client()
        mock_http.request.return_value = _resp(404)
        with self.assertRaises(SecurityOnionNotFoundError):
            c.get("alerts/missing")

    def test_context_manager(self):
        cfg = _cfg()
        with patch("gnat.connectors.security_onion.urllib3.PoolManager"):
            with SecurityOnionClient(cfg) as client:
                self.assertIsInstance(client, SecurityOnionClient)

    def test_paginate_stops_when_empty(self):
        c, mock_http = _make_client()
        mock_http.request.side_effect = [
            _resp(200, {"data": [{"id": "1"}, {"id": "2"}]}),
            _resp(200, {"data": []}),
        ]
        items = list(c.paginate("cases", page_size=2))
        self.assertEqual(len(items), 2)


class TestSecurityOnionAlertCommands(unittest.TestCase):
    _ALERT = {
        "uid": "abc123", "@timestamp": "2024-03-10T12:00:00Z",
        "rule": {"name": "ET MALWARE", "uuid": "r1"},
        "event": {"category": "intrusion_detection", "severity": 2},
        "source": {"ip": "1.2.3.4", "port": 49152},
        "destination": {"ip": "10.0.0.1", "port": 80},
        "network": {"transport": "tcp"},
        "observer": {"name": "sensor01"},
    }

    def _make_alerts(self):
        c, mock_http = _make_client()
        return SecurityOnionAlertCommands(c), mock_http

    def test_search_alerts(self):
        cmd, mock_http = self._make_alerts()
        mock_http.request.return_value = _resp(200, {"hits": {"hits": [{"_source": self._ALERT}]}})
        result = cmd.search_alerts()
        self.assertIn("hits", result)

    def test_get_alert_hits(self):
        cmd, mock_http = self._make_alerts()
        mock_http.request.return_value = _resp(200, {"hits": {"hits": [{"_source": self._ALERT}]}})
        hits = cmd.get_alert_hits()
        self.assertEqual(len(hits), 1)

    def test_normalise_alert(self):
        norm = SecurityOnionAlertCommands.normalise_alert(self._ALERT)
        self.assertEqual(norm["id"], "abc123")
        self.assertEqual(norm["src_ip"], "1.2.3.4")
        self.assertEqual(norm["severity"], 3)  # event.severity=2 → high=3
        self.assertEqual(norm["sensor"], "sensor01")

    def test_get_alert_count(self):
        cmd, mock_http = self._make_alerts()
        mock_http.request.return_value = _resp(200, {"count": 42})
        self.assertEqual(cmd.get_alert_count(), 42)


class TestSecurityOnionCaseCommands(unittest.TestCase):
    def _make_cases(self):
        c, mock_http = _make_client()
        return SecurityOnionCaseCommands(c), mock_http

    def test_list_cases(self):
        cmd, mock_http = self._make_cases()
        mock_http.request.return_value = _resp(200, [{"id": "c1", "title": "Test"}])
        results = cmd.list_cases()
        self.assertEqual(len(results), 1)

    def test_create_case(self):
        cmd, mock_http = self._make_cases()
        mock_http.request.return_value = _resp(201, {"id": "c-new", "title": "New Case"})
        result = cmd.create_case("New Case", severity=3)
        self.assertEqual(result["id"], "c-new")
        body = json.loads(mock_http.request.call_args[1]["body"])
        self.assertEqual(body["title"], "New Case")
        self.assertEqual(body["severity"], 3)

    def test_add_comment(self):
        cmd, mock_http = self._make_cases()
        mock_http.request.return_value = _resp(201, {"id": "cm1"})
        cmd.add_comment("c1", "Investigating")
        body = json.loads(mock_http.request.call_args[1]["body"])
        self.assertEqual(body["value"], "Investigating")


class TestSecurityOnionSTIXMapper(unittest.TestCase):
    def setUp(self):
        self.mapper = SecurityOnionSTIXMapper()
        self._alert = {
            "id": "abc123", "timestamp": "2024-03-10T12:00:00Z",
            "rule_name": "ET MALWARE", "rule_id": "r1",
            "category": "intrusion_detection", "severity": 3,
            "src_ip": "1.2.3.4", "dst_ip": "10.0.0.1",
            "src_port": 49152, "dst_port": 80, "proto": "tcp",
            "sensor": "sensor01",
        }

    def test_bundle_structure(self):
        bundle = self.mapper.alert_to_stix_bundle(self._alert)
        self.assertEqual(bundle["type"], "bundle")
        types = {o["type"] for o in bundle["objects"]}
        self.assertIn("ipv4-addr", types)
        self.assertIn("network-traffic", types)
        self.assertIn("observed-data", types)

    def test_observed_data_extension(self):
        bundle = self.mapper.alert_to_stix_bundle(self._alert)
        obs = next(o for o in bundle["objects"] if o["type"] == "observed-data")
        self.assertIn("x_security_onion_alert", obs)
        self.assertEqual(obs["x_security_onion_alert"]["rule_name"], "ET MALWARE")

    def test_alerts_bundle_deduplication(self):
        bundle = self.mapper.alerts_to_stix_bundle([self._alert, self._alert])
        ip_objs = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
        self.assertEqual(len([o for o in ip_objs if o["value"] == "1.2.3.4"]), 1)

    def test_network_traffic_ports(self):
        bundle = self.mapper.alert_to_stix_bundle(self._alert)
        nt = next(o for o in bundle["objects"] if o["type"] == "network-traffic")
        self.assertEqual(nt["src_port"], 49152)
        self.assertEqual(nt["dst_port"], 80)


if __name__ == "__main__":
    unittest.main(verbosity=2)

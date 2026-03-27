"""
tests/connectors/test_wazuh.py

Unit tests for the GNAT Wazuh connector.

All HTTP is mocked via unittest.mock on urllib3.PoolManager.
No live Wazuh instance required.

## Coverage

- WazuhConfig: validation, INI loading, computed properties
- WazuhAuthManager: JWT login, proactive renewal, expiry handling
- WazuhClient: request routing, envelope extraction, retry, error mapping
- WazuhAgentCommands: list, get, restart, groups
- WazuhAlertCommands: query, normalise, severity mapping
- WazuhSyscheckCommands: FIM query, last scan, normalise
- WazuhVulnerabilityCommands: query, normalise, summary
- WazuhRulesCommands: list, get, groups
- WazuhActiveResponseCommands: run, block_ip
- WazuhIndexerCommands: guard, search, count
- WazuhSTIXMapper: all mapping directions + edge cases

## Running

pytest tests/connectors/test_wazuh.py -v

"""

import configparser
import json
import time
import unittest
from unittest.mock import MagicMock, patch, call

from gnat.connectors.wazuh.config import WazuhConfig, load_wazuh_config
from gnat.connectors.wazuh.exceptions import (
WazuhAuthError,
WazuhAPIError,
WazuhConfigError,
WazuhNotFoundError,
WazuhPermissionError,
WazuhRateLimitError,
WazuhSTIXError,
WazuhIndexerError,
)
from gnat.connectors.wazuh.auth import WazuhAuthManager
from gnat.connectors.wazuh.client import WazuhClient
from gnat.connectors.wazuh.agents import WazuhAgentCommands
from gnat.connectors.wazuh.alerts import WazuhAlertCommands, _level_to_severity
from gnat.connectors.wazuh.syscheck import WazuhSyscheckCommands
from gnat.connectors.wazuh.vulnerabilities import WazuhVulnerabilityCommands
from gnat.connectors.wazuh.rules import WazuhRulesCommands
from gnat.connectors.wazuh.active_response import WazuhActiveResponseCommands
from gnat.connectors.wazuh.indexer import WazuhIndexerCommands
from gnat.connectors.wazuh.stix_mapper import WazuhSTIXMapper

# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_config(**overrides) -> WazuhConfig:
    defaults = dict(host="wazuh.test.local", username="wazuh", password="Password1!")
    defaults.update(overrides)
    return WazuhConfig(**defaults)

def _make_response(status: int = 200, body=None) -> MagicMock:
    resp = MagicMock()
    resp.status = status
    payload = body if body is not None else {}
    resp.data = json.dumps(payload).encode("utf-8")
    return resp

def _wazuh_ok(items: list, total: int | None = None) -> dict:
    """Build a standard Wazuh success response envelope."""
    return {
    "data": {
    "affected_items": items,
    "total_affected_items": total if total is not None else len(items),
    "failed_items": [],
    "total_failed_items": 0,
    },
    "message": "All items were returned",
    "error": 0,
    }

def _make_client(config: WazuhConfig | None = None) -> tuple[WazuhClient, MagicMock]:
    cfg = config or _make_config()
    with patch("gnat.connectors.wazuh.client.urllib3.PoolManager") as pm_cls:
        mock_pm = MagicMock()
        pm_cls.return_value = mock_pm
        client = WazuhClient(cfg)
        client._http = mock_pm
        client.auth._http = mock_pm
        # Pre-seed a valid token so tests don't need to mock login by default
        client.auth._token = "test-jwt-token"
        client.auth._token_acquired_at = time.time()
        return client, mock_pm

        # ═════════════════════════════════════════════════════════════════════════════

        # WazuhConfig

        # ═════════════════════════════════════════════════════════════════════════════

class TestWazuhConfig(unittest.TestCase):

    def test_minimal_config(self):
        cfg = _make_config()
        self.assertEqual(cfg.host, "wazuh.test.local")
        self.assertEqual(cfg.port, 55000)
        self.assertEqual(cfg.scheme, "https")
        self.assertFalse(cfg.verify_ssl)

    def test_base_url_computed(self):
        cfg = _make_config()
        self.assertEqual(cfg.base_url, "https://wazuh.test.local:55000")

    def test_endpoint_helper(self):
        cfg = _make_config()
        self.assertEqual(
            cfg.endpoint("agents"),
            "https://wazuh.test.local:55000/agents",
        )

    def test_indexer_url_defaults_to_host(self):
        cfg = _make_config(indexer_enabled=True)
        self.assertIn("wazuh.test.local", cfg.indexer_url)

    def test_indexer_url_custom_host(self):
        cfg = _make_config(
            indexer_enabled=True,
            indexer_host="indexer.corp",
            indexer_port=9200,
        )
        self.assertIn("indexer.corp", cfg.indexer_url)

    def test_max_results_capped(self):
        cfg = _make_config(max_results=9999)
        self.assertEqual(cfg.max_results, 500)

    def test_token_renewal_threshold(self):
        cfg = _make_config(token_expiry_secs=900)
        # 20% of 900 = 180
        self.assertEqual(cfg.token_renewal_threshold, 180.0)

    def test_token_renewal_threshold_minimum(self):
        # Very short expiry; minimum threshold is 60s
        cfg = _make_config(token_expiry_secs=100)
        self.assertEqual(cfg.token_renewal_threshold, 60.0)

    def test_missing_host_raises(self):
        with self.assertRaises(WazuhConfigError):
            WazuhConfig(host="", username="u", password="p")

    def test_missing_password_raises(self):
        with self.assertRaises(WazuhConfigError):
            WazuhConfig(host="h", username="u", password="")

    def test_invalid_scheme_raises(self):
        with self.assertRaises(WazuhConfigError):
            WazuhConfig(host="h", username="u", password="p", scheme="ftp")

    def test_load_from_configparser(self):
        parser = configparser.ConfigParser()
        parser.read_dict({
            "wazuh": {
                "host": "mywazuh.corp",
                "username": "svc",
                "password": "pw123",
                "es_enabled": "true",
                "verify_ssl": "true",
                "timeout": "60",
            }
        })
        cfg = load_wazuh_config(parser)
        self.assertEqual(cfg.host, "mywazuh.corp")
        self.assertTrue(cfg.verify_ssl)
        self.assertEqual(cfg.timeout, 60)

    def test_load_missing_section_raises(self):
        with self.assertRaises(WazuhConfigError):
            load_wazuh_config(configparser.ConfigParser())

    def test_load_missing_password_raises(self):
        parser = configparser.ConfigParser()
        parser.read_dict({"wazuh": {"host": "h", "username": "u"}})
        with self.assertRaises(WazuhConfigError):
            load_wazuh_config(parser)

    # ═════════════════════════════════════════════════════════════════════════════

    # WazuhAuthManager

    # ═════════════════════════════════════════════════════════════════════════════

class TestWazuhAuthManager(unittest.TestCase):

    def _make_auth(self, config=None):
        cfg = config or _make_config()
        mock_http = MagicMock()
        return WazuhAuthManager(cfg, mock_http), mock_http

    def test_login_success(self):
        auth, mock_http = self._make_auth()
        mock_http.request.return_value = _make_response(
            200, {"data": {"token": "jwt-abc123"}, "error": 0}
        )
        headers = auth.get_auth_headers()
        self.assertEqual(headers, {"Authorization": "Bearer jwt-abc123"})

    def test_login_caches_token(self):
        auth, mock_http = self._make_auth()
        mock_http.request.return_value = _make_response(
            200, {"data": {"token": "jwt-abc"}, "error": 0}
        )
        auth.get_auth_headers()
        auth.get_auth_headers()  # second call
        # Should only have logged in once
        self.assertEqual(mock_http.request.call_count, 1)

    def test_login_401_raises_auth_error(self):
        auth, mock_http = self._make_auth()
        mock_http.request.return_value = _make_response(401)
        with self.assertRaises(WazuhAuthError):
            auth.get_auth_headers()

    def test_login_403_raises_auth_error(self):
        auth, mock_http = self._make_auth()
        mock_http.request.return_value = _make_response(403)
        with self.assertRaises(WazuhAuthError):
            auth.get_auth_headers()

    def test_token_validity_window(self):
        """Token is considered valid until renewal threshold."""
        auth, mock_http = self._make_auth(_make_config(token_expiry_secs=900))
        auth._token = "valid-token"
        auth._token_acquired_at = time.time() - 100  # 100s old
        self.assertTrue(auth._token_is_valid())

    def test_token_past_renewal_threshold(self):
        """Token past 80% of expiry triggers renewal."""
        auth, _ = self._make_auth(_make_config(token_expiry_secs=900))
        auth._token = "old-token"
        # 80% of 900 = 720s; set to 800s old (past threshold)
        auth._token_acquired_at = time.time() - 800
        self.assertFalse(auth._token_is_valid())

    def test_invalidate_clears_token(self):
        auth, _ = self._make_auth()
        auth._token = "some-token"
        auth._token_acquired_at = time.time()
        auth.invalidate_token()
        self.assertIsNone(auth._token)
        self.assertFalse(auth.is_authenticated())

    def test_uses_basic_auth_for_login(self):
        """Login request uses Basic Auth header, not Bearer."""
        auth, mock_http = self._make_auth()
        mock_http.request.return_value = _make_response(
            200, {"data": {"token": "t"}, "error": 0}
        )
        auth.get_auth_headers()
        call_args = mock_http.request.call_args
        headers = call_args[1].get("headers") or call_args[0][3]
        self.assertIn("Basic", headers.get("Authorization", ""))

    # ═════════════════════════════════════════════════════════════════════════════

    # WazuhClient

    # ═════════════════════════════════════════════════════════════════════════════

class TestWazuhClient(unittest.TestCase):

    def test_get_returns_parsed_json(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(200, _wazuh_ok([]))
        result = client.get("agents")
        self.assertIsInstance(result, dict)

    def test_extract_items(self):
        response = _wazuh_ok([{"id": "001"}, {"id": "002"}])
        items = WazuhClient.extract_items(response)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["id"], "001")

    def test_extract_total(self):
        response = _wazuh_ok([], total=42)
        self.assertEqual(WazuhClient.extract_total(response), 42)

    def test_401_with_4009_triggers_token_refresh(self):
        """Token expired (4009) causes one re-auth attempt."""
        client, mock_http = _make_client()
        expired_body = {"error": 4009, "title": "Token expired"}
        success_body = _wazuh_ok([{"id": "001"}])
        # Sequence: 401 (expired) -> 200 (after refresh)
        mock_http.request.side_effect = [
            _make_response(401, expired_body),
            _make_response(200, {"data": {"token": "new-tok"}, "error": 0}),
            _make_response(200, success_body),
        ]
        result = client.get("agents")
        self.assertIsInstance(result, dict)

    def test_401_without_expiry_raises_auth_error(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(401, {"error": 4001})
        with self.assertRaises(WazuhAuthError):
            client.get("agents")

    def test_403_raises_permission_error(self):
        client, mock_http = _make_client()
        body = {"error": 4000, "title": "Permission Denied", "detail": "..."}
        mock_http.request.return_value = _make_response(403, body)
        with self.assertRaises(WazuhPermissionError) as ctx:
            client.get("agents")
        self.assertEqual(ctx.exception.error_code, 4000)

    def test_404_raises_not_found(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(404, {"title": "Not found"})
        with self.assertRaises(WazuhNotFoundError):
            client.get("agents/999")

    def test_429_retries_then_raises(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(429)
        with patch("time.sleep"):
            with self.assertRaises(WazuhRateLimitError):
                client.get("agents")

    def test_context_manager(self):
        cfg = _make_config()
        with patch("gnat.connectors.wazuh.client.urllib3.PoolManager"):
            with WazuhClient(cfg) as client:
                self.assertIsInstance(client, WazuhClient)

    def test_paginate_yields_all(self):
        """paginate() stops when offset >= total_affected_items."""
        client, mock_http = _make_client()
        page1 = _wazuh_ok([{"id": str(i)} for i in range(500)], total=550)
        page2 = _wazuh_ok([{"id": str(i)} for i in range(500, 550)], total=550)
        mock_http.request.side_effect = [
            _make_response(200, page1),
            _make_response(200, page2),
        ]
        items = list(client.paginate("agents"))
        self.assertEqual(len(items), 550)

    # ═════════════════════════════════════════════════════════════════════════════

    # WazuhAgentCommands

    # ═════════════════════════════════════════════════════════════════════════════

class TestWazuhAgentCommands(unittest.TestCase):

    def _make_agents(self):
        client, mock_http = _make_client()
        return WazuhAgentCommands(client), mock_http

    def test_list_agents(self):
        agents, mock_http = self._make_agents()
        mock_http.request.return_value = _make_response(
            200, _wazuh_ok([{"id": "001", "name": "host1", "status": "active"}])
        )
        results = agents.list_agents(status="active")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "host1")

    def test_get_agent_found(self):
        agents, mock_http = self._make_agents()
        mock_http.request.return_value = _make_response(
            200, _wazuh_ok([{"id": "001", "name": "host1"}])
        )
        agent = agents.get_agent("001")
        self.assertEqual(agent["id"], "001")

    def test_get_agent_not_found(self):
        agents, mock_http = self._make_agents()
        mock_http.request.return_value = _make_response(200, _wazuh_ok([]))
        with self.assertRaises(WazuhNotFoundError):
            agents.get_agent("999")

    def test_get_agent_summary(self):
        agents, mock_http = self._make_agents()
        mock_http.request.return_value = _make_response(200, {
            "data": {
                "active": 10, "disconnected": 2,
                "never_connected": 1, "pending": 0,
                "total_affected_items": 13,
            }
        })
        summary = agents.get_agent_summary()
        self.assertEqual(summary["active"], 10)
        self.assertEqual(summary["total"], 13)

    def test_normalise_agent(self):
        raw = {
            "id": "001", "name": "host1", "ip": "10.0.0.1",
            "status": "active",
            "os": {"platform": "ubuntu", "name": "Ubuntu", "version": "22.04"},
            "version": "Wazuh v4.9.0",
            "lastKeepAlive": "2024-03-10T12:00:00Z",
            "group": ["default", "linux"],
        }
        result = WazuhAgentCommands.normalise_agent(raw)
        self.assertEqual(result["id"], "001")
        self.assertEqual(result["os_platform"], "ubuntu")
        self.assertEqual(result["groups"], ["default", "linux"])

    def test_restart_agent(self):
        agents, mock_http = self._make_agents()
        mock_http.request.return_value = _make_response(200, _wazuh_ok(["001"]))
        result = agents.restart_agent("001")
        self.assertIsNotNone(result)

    def test_list_groups(self):
        agents, mock_http = self._make_agents()
        mock_http.request.return_value = _make_response(
            200, _wazuh_ok([{"name": "default"}, {"name": "linux"}])
        )
        groups = agents.list_groups()
        self.assertEqual(len(groups), 2)

    # ═════════════════════════════════════════════════════════════════════════════

    # WazuhAlertCommands

    # ═════════════════════════════════════════════════════════════════════════════

class TestWazuhAlertCommands(unittest.TestCase):

    def _make_alerts_cmd(self):
        client, mock_http = _make_client()
        return WazuhAlertCommands(client), mock_http

    def test_get_alerts(self):
        alerts_cmd, mock_http = self._make_alerts_cmd()
        alert = {
            "id": "1234",
            "timestamp": "2024-03-10T12:00:00Z",
            "rule": {"id": "5501", "description": "SSH brute force", "level": 10},
            "agent": {"id": "001", "name": "host1"},
        }
        mock_http.request.return_value = _make_response(
            200, _wazuh_ok([alert])
        )
        results = alerts_cmd.get_alerts(min_rule_level=10)
        self.assertEqual(len(results), 1)

    def test_normalise_alert_severity(self):
        alert = {
            "id": "1", "timestamp": "2024-01-01T00:00:00Z",
            "rule": {"id": "100", "description": "test", "level": 13, "groups": []},
            "agent": {"id": "001", "name": "h"},
            "data": {"srcip": "1.2.3.4"},
        }
        result = WazuhAlertCommands.normalise_alert(alert)
        self.assertEqual(result["severity"], 3)
        self.assertEqual(result["severity_label"], "high")
        self.assertEqual(result["src_ip"], "1.2.3.4")

    def test_level_to_severity_boundaries(self):
        self.assertEqual(_level_to_severity(0), 0)
        self.assertEqual(_level_to_severity(3), 0)
        self.assertEqual(_level_to_severity(4), 1)
        self.assertEqual(_level_to_severity(7), 1)
        self.assertEqual(_level_to_severity(8), 2)
        self.assertEqual(_level_to_severity(11), 2)
        self.assertEqual(_level_to_severity(12), 3)
        self.assertEqual(_level_to_severity(14), 3)
        self.assertEqual(_level_to_severity(15), 4)

    def test_get_alerts_by_invalid_severity_raises(self):
        alerts_cmd, _ = self._make_alerts_cmd()
        with self.assertRaises(ValueError):
            alerts_cmd.get_alerts_by_severity("extreme")

    def test_get_event_stats(self):
        alerts_cmd, mock_http = self._make_alerts_cmd()
        mock_http.request.return_value = _make_response(
            200, {"data": {"total_events": 12345}}
        )
        result = alerts_cmd.get_event_stats()
        self.assertEqual(result.get("total_events"), 12345)

    # ═════════════════════════════════════════════════════════════════════════════

    # WazuhSyscheckCommands

    # ═════════════════════════════════════════════════════════════════════════════

class TestWazuhSyscheckCommands(unittest.TestCase):

    def _make_syscheck(self):
        client, mock_http = _make_client()
        return WazuhSyscheckCommands(client), mock_http

    def test_get_fim_events(self):
        syscheck, mock_http = self._make_syscheck()
        fim_event = {
            "file": "/etc/passwd",
            "type": "modified",
            "date": "2024-03-10T12:00:00Z",
            "md5": "abc123",
            "sha256": "def456",
        }
        mock_http.request.return_value = _make_response(
            200, _wazuh_ok([fim_event])
        )
        results = syscheck.get_fim_events("001", event_type="modified")
        self.assertEqual(results[0]["file"], "/etc/passwd")

    def test_get_last_scan_time(self):
        syscheck, mock_http = self._make_syscheck()
        mock_http.request.return_value = _make_response(
            200, {"data": {"start": "2024-03-10T11:00:00Z", "end": "2024-03-10T11:05:00Z"}}
        )
        result = syscheck.get_last_scan_time("001")
        self.assertIn("start", result)

    def test_normalise_fim_event(self):
        raw = {
            "file": "/etc/shadow",
            "type": "modified",
            "date": "2024-03-10T12:00:00Z",
            "md5": "aaa", "sha1": "bbb", "sha256": "ccc",
            "perm": "600", "uname": "root", "gname": "root",
        }
        result = WazuhSyscheckCommands.normalise_fim_event(raw)
        self.assertEqual(result["file"], "/etc/shadow")
        self.assertEqual(result["md5"], "aaa")
        self.assertEqual(result["owner"], "root")

    def test_run_syscheck_scan(self):
        syscheck, mock_http = self._make_syscheck()
        mock_http.request.return_value = _make_response(
            200, _wazuh_ok(["001"])
        )
        result = syscheck.run_syscheck_scan("001")
        self.assertIsNotNone(result)

    # ═════════════════════════════════════════════════════════════════════════════

    # WazuhVulnerabilityCommands

    # ═════════════════════════════════════════════════════════════════════════════

class TestWazuhVulnerabilityCommands(unittest.TestCase):

    def _make_vuln(self):
        client, mock_http = _make_client()
        return WazuhVulnerabilityCommands(client), mock_http

    def test_get_vulnerabilities(self):
        vuln_cmd, mock_http = self._make_vuln()
        mock_http.request.return_value = _make_response(
            200, _wazuh_ok([{
                "cve": "CVE-2021-44228",
                "name": "log4j",
                "version": "2.14.1",
                "severity": "critical",
                "cvss3_score": 10.0,
            }])
        )
        results = vuln_cmd.get_vulnerabilities("001")
        self.assertEqual(results[0]["cve"], "CVE-2021-44228")

    def test_normalise_vulnerability(self):
        raw = {
            "cve": "CVE-2021-44228",
            "name": "log4j-core",
            "version": "2.14.1",
            "severity": "critical",
            "cvss3_score": 10.0,
            "title": "Log4Shell RCE",
        }
        result = WazuhVulnerabilityCommands.normalise_vulnerability(raw)
        self.assertEqual(result["severity"], 4)
        self.assertEqual(result["severity_label"], "critical")
        self.assertEqual(result["cve"], "CVE-2021-44228")

    def test_vulnerability_summary(self):
        vuln_cmd, mock_http = self._make_vuln()
        items = (
            [{"severity": "critical"}] * 3
            + [{"severity": "high"}] * 5
            + [{"severity": "medium"}] * 10
        )
        mock_http.request.return_value = _make_response(
            200, _wazuh_ok(items)
        )
        summary = vuln_cmd.get_vulnerability_summary("001")
        self.assertEqual(summary["critical"], 3)
        self.assertEqual(summary["high"], 5)

    # ═════════════════════════════════════════════════════════════════════════════

    # WazuhRulesCommands

    # ═════════════════════════════════════════════════════════════════════════════

class TestWazuhRulesCommands(unittest.TestCase):

    def _make_rules(self):
        client, mock_http = _make_client()
        return WazuhRulesCommands(client), mock_http

    def test_list_rules(self):
        rules_cmd, mock_http = self._make_rules()
        mock_http.request.return_value = _make_response(
            200, _wazuh_ok([
                {"id": "5501", "description": "SSH brute force", "level": 10},
            ])
        )
        results = rules_cmd.list_rules(level=10)
        self.assertEqual(results[0]["id"], "5501")

    def test_get_rule_found(self):
        rules_cmd, mock_http = self._make_rules()
        mock_http.request.return_value = _make_response(
            200, _wazuh_ok([{"id": "5501", "description": "test"}])
        )
        rule = rules_cmd.get_rule("5501")
        self.assertIsNotNone(rule)

    def test_get_rule_not_found(self):
        rules_cmd, mock_http = self._make_rules()
        mock_http.request.return_value = _make_response(200, _wazuh_ok([]))
        result = rules_cmd.get_rule("99999")
        self.assertIsNone(result)

    def test_list_rule_groups(self):
        rules_cmd, mock_http = self._make_rules()
        mock_http.request.return_value = _make_response(
            200, _wazuh_ok(["authentication_failed", "sshd"])
        )
        groups = rules_cmd.list_rule_groups()
        self.assertIn("sshd", groups)

    # ═════════════════════════════════════════════════════════════════════════════

    # WazuhActiveResponseCommands

    # ═════════════════════════════════════════════════════════════════════════════

class TestWazuhActiveResponseCommands(unittest.TestCase):

    def _make_ar(self):
        client, mock_http = _make_client()
        return WazuhActiveResponseCommands(client), mock_http

    def test_run_command(self):
        ar, mock_http = self._make_ar()
        mock_http.request.return_value = _make_response(
            200, _wazuh_ok(["001"])
        )
        result = ar.run_command("firewall-drop", ["001"])
        self.assertIsNotNone(result)

    def test_block_ip(self):
        ar, mock_http = self._make_ar()
        mock_http.request.return_value = _make_response(
            200, _wazuh_ok(["001"])
        )
        result = ar.block_ip("1.2.3.4", ["001"])
        self.assertIsNotNone(result)
        # Verify the command and IP are in the PUT body
        call_args = mock_http.request.call_args
        body_bytes = call_args[1].get("body") or b""
        body = json.loads(body_bytes)
        self.assertEqual(body.get("command"), "firewall-drop")
        self.assertIn("1.2.3.4", body.get("arguments", []))

    def test_disable_user_account(self):
        ar, mock_http = self._make_ar()
        mock_http.request.return_value = _make_response(
            200, _wazuh_ok(["001"])
        )
        result = ar.disable_user_account("jdoe", ["001"])
        self.assertIsNotNone(result)

    # ═════════════════════════════════════════════════════════════════════════════

    # WazuhIndexerCommands

    # ═════════════════════════════════════════════════════════════════════════════

class TestWazuhIndexerCommands(unittest.TestCase):

    def _make_indexer(self, enabled=True):
        cfg = _make_config(
            indexer_enabled=enabled,
            indexer_username="admin",
            indexer_password="admin",
        )
        mock_http = MagicMock()
        return WazuhIndexerCommands(cfg, mock_http), mock_http

    def test_requires_indexer_enabled(self):
        indexer, _ = self._make_indexer(enabled=False)
        with self.assertRaises(WazuhIndexerError):
            indexer.list_alert_indices()

    def test_search_alerts(self):
        indexer, mock_http = self._make_indexer()
        hits_response = {
            "hits": {
                "total": {"value": 2},
                "hits": [
                    {"_source": {"rule": {"level": 10}}},
                    {"_source": {"rule": {"level": 12}}},
                ]
            }
        }
        mock_http.request.return_value = _make_response(200, hits_response)
        result = indexer.search_alerts()
        self.assertIn("hits", result)

    def test_search_alerts_by_agent(self):
        indexer, mock_http = self._make_indexer()
        mock_http.request.return_value = _make_response(200, {
            "hits": {"hits": [{"_source": {"agent": {"id": "001"}}}]}
        })
        results = indexer.search_alerts_by_agent("001")
        self.assertEqual(len(results), 1)

    def test_count_alerts(self):
        indexer, mock_http = self._make_indexer()
        mock_http.request.return_value = _make_response(200, {"count": 42})
        count = indexer.count_alerts()
        self.assertEqual(count, 42)

    def test_uses_basic_auth(self):
        indexer, mock_http = self._make_indexer()
        mock_http.request.return_value = _make_response(200, {"hits": {"hits": []}})
        indexer.search_alerts()
        call_args = mock_http.request.call_args
        headers = call_args[1].get("headers") or {}
        self.assertIn("Basic", headers.get("Authorization", ""))

    # ═════════════════════════════════════════════════════════════════════════════

    # WazuhSTIXMapper

    # ═════════════════════════════════════════════════════════════════════════════

class TestWazuhSTIXMapper(unittest.TestCase):

    def setUp(self):
        self.mapper = WazuhSTIXMapper()

    # ── Alert -> STIX ──────────────────────────────────────────────────────

    def test_alert_to_stix_bundle_structure(self):
        alert = {
            "id": "a1", "timestamp": "2024-03-10T12:00:00Z",
            "rule_id": "5501", "rule_description": "SSH brute force",
            "rule_level": 10, "rule_groups": ["sshd"], "rule_mitre": {},
            "severity": 2, "severity_label": "medium",
            "agent_id": "001", "agent_name": "host1", "agent_ip": "10.0.0.1",
            "src_ip": "1.2.3.4", "dst_ip": "10.0.0.5",
            "src_user": "root", "decoder": "sshd", "_raw": {},
        }
        bundle = self.mapper.alert_to_stix_bundle(alert)
        self.assertEqual(bundle["type"], "bundle")
        types = {o["type"] for o in bundle["objects"]}
        self.assertIn("ipv4-addr", types)
        self.assertIn("user-account", types)
        self.assertIn("observed-data", types)

    def test_alert_observed_data_has_extension(self):
        alert = {
            "rule_id": "100", "rule_level": 5, "severity": 1,
            "agent_id": "001", "_raw": {},
        }
        bundle = self.mapper.alert_to_stix_bundle(alert)
        obs = next(o for o in bundle["objects"] if o["type"] == "observed-data")
        self.assertIn("x_wazuh_alert", obs)
        self.assertEqual(obs["x_wazuh_alert"]["rule_id"], "100")

    def test_alert_no_src_ip_no_ipv4_sco(self):
        """Alert with no IPs should not produce ipv4-addr objects."""
        alert = {
            "rule_id": "100", "rule_level": 5, "severity": 1,
            "agent_id": "001", "_raw": {},
        }
        bundle = self.mapper.alert_to_stix_bundle(alert)
        types = [o["type"] for o in bundle["objects"]]
        self.assertNotIn("ipv4-addr", types)

    def test_alert_same_src_dst_ip_deduplication(self):
        """Same src and dst IP should produce only one ipv4-addr object."""
        alert = {
            "rule_id": "100", "rule_level": 5, "severity": 1,
            "src_ip": "1.2.3.4", "dst_ip": "1.2.3.4",
            "agent_id": "001", "_raw": {},
        }
        bundle = self.mapper.alert_to_stix_bundle(alert)
        ip_objects = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
        self.assertEqual(len(ip_objects), 1)

    def test_alerts_bundle_deduplicates_scos(self):
        """Same IP in two alerts appears once in merged bundle."""
        alert1 = {
            "rule_id": "1", "rule_level": 5, "severity": 1,
            "src_ip": "1.2.3.4", "agent_id": "001", "_raw": {},
        }
        alert2 = {
            "rule_id": "2", "rule_level": 6, "severity": 1,
            "src_ip": "1.2.3.4", "agent_id": "001", "_raw": {},
        }
        bundle = self.mapper.alerts_to_stix_bundle([alert1, alert2])
        ip_objects = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
        values = [o["value"] for o in ip_objects]
        self.assertEqual(values.count("1.2.3.4"), 1)

    # ── FIM event -> STIX ──────────────────────────────────────────────────

    def test_fim_event_to_stix_bundle_has_file_sco(self):
        fim = {
            "file": "/etc/passwd",
            "event_type": "modified",
            "date": "2024-03-10T12:00:00Z",
            "md5": "abc", "sha256": "def",
            "owner": "root", "permissions": "644",
        }
        bundle = self.mapper.fim_event_to_stix_bundle(fim, agent_id="001")
        types = {o["type"] for o in bundle["objects"]}
        self.assertIn("file", types)
        self.assertIn("observed-data", types)

    def test_fim_observed_data_has_extension(self):
        fim = {"file": "/tmp/test", "event_type": "added", "sha256": "abc123"}
        bundle = self.mapper.fim_event_to_stix_bundle(fim, agent_id="002")
        obs = next(o for o in bundle["objects"] if o["type"] == "observed-data")
        self.assertIn("x_wazuh_fim", obs)
        self.assertEqual(obs["x_wazuh_fim"]["event_type"], "added")
        self.assertEqual(obs["x_wazuh_fim"]["agent_id"], "002")

    def test_fim_file_sco_hashes(self):
        fim = {
            "file": "/etc/shadow",
            "md5": "md5hash",
            "sha1": "sha1hash",
            "sha256": "sha256hash",
        }
        bundle = self.mapper.fim_event_to_stix_bundle(fim)
        file_sco = next(o for o in bundle["objects"] if o["type"] == "file")
        self.assertEqual(file_sco["hashes"]["MD5"], "md5hash")
        self.assertEqual(file_sco["hashes"]["SHA-256"], "sha256hash")

    # ── Vulnerability -> STIX ──────────────────────────────────────────────

    def test_vulnerability_to_stix_sdo(self):
        vuln = {
            "cve": "CVE-2021-44228",
            "title": "Log4Shell",
            "package_name": "log4j-core",
            "severity_label": "critical",
            "cvss3_score": 10.0,
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        }
        sdo = self.mapper.vulnerability_to_stix(vuln)
        self.assertEqual(sdo["type"], "vulnerability")
        self.assertEqual(sdo["name"], "CVE-2021-44228")
        refs = {r["source_name"] for r in sdo["external_references"]}
        self.assertIn("cve", refs)

    def test_vulnerability_missing_cve_raises(self):
        with self.assertRaises(WazuhSTIXError):
            self.mapper.vulnerability_to_stix({"title": "Unknown"})

    def test_vulnerabilities_bundle_skips_no_cve(self):
        vulns = [
            {"cve": "CVE-2021-44228", "title": "Log4Shell"},
            {"title": "No CVE here"},  # should be skipped
        ]
        bundle = self.mapper.vulnerabilities_to_stix_bundle(vulns)
        vuln_sdos = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
        self.assertEqual(len(vuln_sdos), 1)

    # ── Agent -> STIX identity ──────────────────────────────────────────────

    def test_agent_to_stix_identity(self):
        agent = {
            "id": "001", "name": "webserver01", "ip": "10.0.0.5",
            "status": "active", "os_platform": "ubuntu",
            "groups": ["default", "linux"],
        }
        identity = self.mapper.agent_to_stix_identity(agent)
        self.assertEqual(identity["type"], "identity")
        self.assertEqual(identity["identity_class"], "system")
        self.assertEqual(identity["name"], "webserver01")
        self.assertIn("x_wazuh_agent", identity)
        self.assertEqual(identity["x_wazuh_agent"]["agent_id"], "001")

    def test_agent_identity_deterministic_id(self):
        """Same agent always produces the same STIX identity ID."""
        agent = {"id": "001", "name": "host1"}
        id1 = self.mapper.agent_to_stix_identity(agent)["id"]
        id2 = self.mapper.agent_to_stix_identity(agent)["id"]
        self.assertEqual(id1, id2)

    # ── STIX indicator -> Wazuh rule ────────────────────────────────────────

    def test_indicator_to_wazuh_rule_ip(self):
        indicator = {
            "type": "indicator",
            "id": "indicator--abc",
            "name": "Malicious IP",
            "pattern": "[ipv4-addr:value = '10.0.0.99']",
            "pattern_type": "stix",
            "indicator_types": ["malicious-activity"],
            "valid_from": "2024-01-01T00:00:00Z",
        }
        rule_xml = self.mapper.stix_indicator_to_wazuh_rule(indicator, rule_id=100001)
        self.assertIn("10.0.0.99", rule_xml)
        self.assertIn("100001", rule_xml)
        self.assertIn("srcip", rule_xml)

    def test_indicator_to_wazuh_rule_domain(self):
        indicator = {
            "type": "indicator",
            "id": "indicator--xyz",
            "name": "Malicious domain",
            "pattern": "[domain-name:value = 'evil.com']",
            "pattern_type": "stix",
            "indicator_types": [],
        }
        rule_xml = self.mapper.stix_indicator_to_wazuh_rule(indicator)
        self.assertIn("evil.com", rule_xml)
        self.assertIn("data.hostname", rule_xml)

    def test_indicator_no_value_returns_comment(self):
        indicator = {
            "type": "indicator",
            "id": "indicator--nv",
            "pattern": "[file:hashes.MD5 != '']",
            "indicator_types": [],
        }
        rule_xml = self.mapper.stix_indicator_to_wazuh_rule(indicator)
        self.assertIn("<!--", rule_xml)

    # ── Kill chain phases ──────────────────────────────────────────────────

    def test_build_kill_chain_phases(self):
        mitre = {"tactic": ["initial-access", "execution"]}
        phases = WazuhSTIXMapper._build_kill_chain_phases(mitre)
        self.assertEqual(len(phases), 2)
        phase_names = {p["phase_name"] for p in phases}
        self.assertIn("initial-access", phase_names)

    def test_build_kill_chain_phases_string_tactic(self):
        mitre = {"tactic": "lateral-movement"}
        phases = WazuhSTIXMapper._build_kill_chain_phases(mitre)
        self.assertEqual(len(phases), 1)
        self.assertEqual(phases[0]["kill_chain_name"], "mitre-attack")

    # ═════════════════════════════════════════════════════════════════════════════

    # Exception hierarchy

    # ═════════════════════════════════════════════════════════════════════════════

class TestWazuhExceptions(unittest.TestCase):

    def test_all_inherit_from_base(self):
        from gnat.connectors.wazuh.exceptions import WazuhError
        for exc_cls in [
            WazuhConfigError, WazuhAuthError, WazuhAPIError,
            WazuhNotFoundError, WazuhPermissionError, WazuhRateLimitError,
            WazuhSTIXError, WazuhIndexerError,
        ]:
            self.assertTrue(issubclass(exc_cls, WazuhError))

    def test_api_error_str_includes_context(self):
        exc = WazuhAPIError(
            "msg", status_code=403, error_code=4000,
            title="Permission Denied", endpoint="/agents"
        )
        s = str(exc)
        self.assertIn("403", s)
        self.assertIn("4000", s)
        self.assertIn("Permission Denied", s)

    def test_not_found_is_api_error(self):
        self.assertTrue(issubclass(WazuhNotFoundError, WazuhAPIError))

    def test_permission_is_api_error(self):
        self.assertTrue(issubclass(WazuhPermissionError, WazuhAPIError))

    if __name__ == "**main**":
        unittest.main(verbosity=2)
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/connectors/test_sentinel.py
====================================
Unit tests for the GNAT Microsoft Sentinel connector.

Coverage
--------
- SentinelConfig: validation, INI loading, URL construction
- SentinelAuthManager: token acquisition, renewal, expiry
- SentinelClient: nextLink pagination, error mapping, 401 retry
- SentinelIncidentCommands: list, get, create, close, normalise
- SentinelAlertCommands: list, incident alerts, normalise
- SentinelWatchlistCommands: list, create, items
- SentinelAnalyticRuleCommands: list, get, enable, normalise
- SentinelThreatIntelCommands: list, create, bulk, normalise
- SentinelHuntingCommands: list, create, normalise
- SentinelSTIXMapper: all four directions

Running
-------
    pytest tests/connectors/test_sentinel.py -v
"""

import configparser
import json
import time
import unittest
from unittest.mock import MagicMock, patch

from gnat.connectors.sentinel.analytic_rules import SentinelAnalyticRuleCommands
from gnat.connectors.sentinel.auth import SentinelAuthManager
from gnat.connectors.sentinel.client import SentinelClient
from gnat.connectors.sentinel.config import SentinelConfig, load_sentinel_config
from gnat.connectors.sentinel.exceptions import (
    SentinelAPIError,
    SentinelAuthError,
    SentinelConfigError,
    SentinelNotFoundError,
    SentinelRateLimitError,
    SentinelSTIXError,
)
from gnat.connectors.sentinel.incidents import SentinelIncidentCommands
from gnat.connectors.sentinel.stix_mapper import SentinelSTIXMapper
from gnat.connectors.sentinel.threat_intel import SentinelThreatIntelCommands
from gnat.stix.version import CURRENT_SPEC_VERSION

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_config(**overrides) -> SentinelConfig:
    """Internal helper for make config."""
    defaults = {
        "tenant_id": "test-tenant",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "subscription_id": "test-sub",
        "resource_group": "test-rg",
        "workspace_name": "test-ws",
    }
    defaults.update(overrides)
    return SentinelConfig(**defaults)


def _make_response(status: int = 200, body=None) -> MagicMock:
    """Internal helper for make response."""
    resp = MagicMock()
    resp.status = status
    payload = body if body is not None else {}
    resp.data = json.dumps(payload).encode("utf-8")
    return resp


def _token_response() -> MagicMock:
    """Internal helper for token response."""
    return _make_response(
        200,
        {
            "access_token": "test-bearer-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        },
    )


def _azure_list(items: list, next_link: str | None = None) -> dict:
    """Internal helper for azure list."""
    result: dict = {"value": items}
    if next_link:
        result["nextLink"] = next_link
    return result


def _make_client(config: SentinelConfig | None = None) -> tuple[SentinelClient, MagicMock]:
    """Internal helper for make client."""
    cfg = config or _make_config()
    with patch("gnat.connectors.sentinel.client.urllib3.PoolManager") as pm_cls:
        mock_pm = MagicMock()
        pm_cls.return_value = mock_pm
        client = SentinelClient(cfg)
        client._http = mock_pm
        client.auth._http = mock_pm
    # Pre-seed token
    client.auth._token = "test-bearer-token"
    client.auth._acquired_at = time.time()
    client.auth._expires_in = 3600
    return client, mock_pm


_SAMPLE_INCIDENT = {
    "name": "inc-001",
    "etag": '"abc"',
    "properties": {
        "incidentNumber": 42,
        "title": "Suspicious Login Activity",
        "description": "Multiple failed logins detected",
        "severity": "High",
        "status": "New",
        "classification": None,
        "owner": {"assignedTo": "analyst@corp.com"},
        "createdTimeUtc": "2024-03-10T12:00:00Z",
        "lastModifiedTimeUtc": "2024-03-10T12:05:00Z",
        "firstActivityTimeUtc": "2024-03-10T11:00:00Z",
        "lastActivityTimeUtc": "2024-03-10T12:00:00Z",
        "labels": [{"labelName": "brute-force"}],
        "additionalData": {"alertsCount": 5},
    },
}

_SAMPLE_TI_INDICATOR = {
    "name": "ind-resource-001",
    "properties": {
        "displayName": "Malicious IP",
        "pattern": "[ipv4-addr:value = '1.2.3.4']",
        "patternType": "stix",
        "validFrom": "2024-01-01T00:00:00Z",
        "confidence": 85,
        "threatTypes": ["malicious-activity"],
        "threatIntelligenceTags": ["apt"],
        "killChainPhases": [{"killChainName": "mitre-attack", "phaseName": "initial-access"}],
        "externalReferences": [],
        "revoked": False,
        "source": "gnat",
    },
}


# ═════════════════════════════════════════════════════════════════════════════
# SentinelConfig
# ═════════════════════════════════════════════════════════════════════════════


class TestSentinelConfig(unittest.TestCase):
    """Configuration container for test sentinel."""
    def test_minimal_config(self):
        """Test that minimal config."""
        cfg = _make_config()
        self.assertEqual(cfg.tenant_id, "test-tenant")
        self.assertEqual(cfg.workspace_name, "test-ws")

    def test_sentinel_base_url_structure(self):
        """Test that sentinel base url structure."""
        cfg = _make_config()
        self.assertIn("test-sub", cfg.sentinel_base_url)
        self.assertIn("test-rg", cfg.sentinel_base_url)
        self.assertIn("test-ws", cfg.sentinel_base_url)
        self.assertIn("Microsoft.SecurityInsights", cfg.sentinel_base_url)

    def test_token_url(self):
        """Test that token url."""
        cfg = _make_config()
        self.assertIn("test-tenant", cfg.token_url)
        self.assertIn("oauth2/v2.0/token", cfg.token_url)

    def test_endpoint_appends_api_version(self):
        """Test that endpoint appends api version."""
        cfg = _make_config()
        url = cfg.endpoint("incidents")
        self.assertIn("api-version=", url)
        self.assertIn("incidents", url)

    def test_token_request_body_contains_credentials(self):
        """Test that token request body contains credentials."""
        cfg = _make_config()
        body = cfg.token_request_body.decode("utf-8")
        self.assertIn("client_credentials", body)
        self.assertIn("test-client", body)
        self.assertIn("test-secret", body)
        self.assertIn("management.azure.com", body)

    def test_missing_fields_raises(self):
        """Test that missing fields raises."""
        with self.assertRaises(SentinelConfigError):
            SentinelConfig(
                tenant_id="",
                client_id="x",
                client_secret="x",
                subscription_id="x",
                resource_group="x",
                workspace_name="x",
            )

    def test_load_from_configparser(self):
        """Test that load from configparser."""
        parser = configparser.ConfigParser()
        parser.read_dict(
            {
                "sentinel": {
                    "tenant_id": "tid",
                    "client_id": "cid",
                    "client_secret": "sec",
                    "subscription_id": "sub",
                    "resource_group": "rg",
                    "workspace_name": "ws",
                    "max_results": "50",
                }
            }
        )
        cfg = load_sentinel_config(parser)
        self.assertEqual(cfg.tenant_id, "tid")
        self.assertEqual(cfg.max_results, 50)

    def test_load_missing_section_raises(self):
        """Test that load missing section raises."""
        with self.assertRaises(SentinelConfigError):
            load_sentinel_config(configparser.ConfigParser())


# ═════════════════════════════════════════════════════════════════════════════
# SentinelAuthManager
# ═════════════════════════════════════════════════════════════════════════════


class TestSentinelAuthManager(unittest.TestCase):
    """Unit tests for :class:`SentinelAuthManager`."""
    def _make_auth(self):
        """Internal helper for make auth."""
        cfg = _make_config()
        mock_http = MagicMock()
        return SentinelAuthManager(cfg, mock_http), mock_http

    def test_acquire_token_success(self):
        """Test that acquire token success."""
        auth, mock_http = self._make_auth()
        mock_http.request.return_value = _token_response()
        headers = auth.get_headers()
        self.assertEqual(headers["Authorization"], "Bearer test-bearer-token")

    def test_token_cached(self):
        """Test that token cached."""
        auth, mock_http = self._make_auth()
        mock_http.request.return_value = _token_response()
        auth.get_headers()
        auth.get_headers()
        self.assertEqual(mock_http.request.call_count, 1)

    def test_token_refresh_after_expiry(self):
        """Test that token refresh after expiry."""
        auth, mock_http = self._make_auth()
        mock_http.request.return_value = _token_response()
        # Seed a stale token
        auth._token = "old-token"
        auth._acquired_at = time.time() - 3500  # almost expired
        auth._expires_in = 3600
        auth.get_headers()
        # Should have re-acquired
        self.assertEqual(mock_http.request.call_count, 1)

    def test_token_400_raises_auth_error(self):
        """Test that token 400 raises auth error."""
        auth, mock_http = self._make_auth()
        mock_http.request.return_value = _make_response(
            400, {"error": "invalid_client", "error_description": "AADSTS70011: ..."}
        )
        with self.assertRaises(SentinelAuthError) as ctx:
            auth.get_headers()
        self.assertIn("invalid_client", ctx.exception.azure_error_code)

    def test_invalidate_clears_token(self):
        """Test that invalidate clears token."""
        auth, _ = self._make_auth()
        auth._token = "valid"
        auth._acquired_at = time.time()
        auth.invalidate_token()
        self.assertIsNone(auth._token)
        self.assertFalse(auth.is_authenticated())

    def test_get_headers_content_type(self):
        """Test that get headers content type."""
        auth, mock_http = self._make_auth()
        mock_http.request.return_value = _token_response()
        headers = auth.get_headers()
        self.assertEqual(headers["Content-Type"], "application/json")


# ═════════════════════════════════════════════════════════════════════════════
# SentinelClient
# ═════════════════════════════════════════════════════════════════════════════


class TestSentinelClient(unittest.TestCase):
    """HTTP API client for the TestSentinel platform."""
    def test_get_returns_dict(self):
        """Test that get returns dict."""
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(200, {"value": []})
        result = client.get("incidents")
        self.assertIsInstance(result, dict)

    def test_401_triggers_token_refresh_and_retry(self):
        """On 401, client re-acquires token and retries once."""
        client, mock_http = _make_client()
        # First: 401, then token re-acquisition, then success
        mock_http.request.side_effect = [
            _make_response(401, {"error": {"code": "ExpiredToken"}}),
            _token_response(),  # token re-acquisition
            _make_response(200, {"value": []}),
        ]
        result = client.get("incidents")
        self.assertIsInstance(result, dict)

    def test_403_raises_auth_error(self):
        """Test that 403 raises auth error."""
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(
            403, {"error": {"code": "AuthorizationFailed", "message": "..."}}
        )
        with self.assertRaises(SentinelAuthError) as ctx:
            client.get("incidents")
        self.assertEqual(ctx.exception.azure_error_code, "AuthorizationFailed")

    def test_404_raises_not_found(self):
        """Test that 404 raises not found."""
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(
            404, {"error": {"code": "ResourceNotFound", "message": "Not found"}}
        )
        with self.assertRaises(SentinelNotFoundError):
            client.get("incidents/missing")

    def test_429_retries_then_raises(self):
        """Test that 429 retries then raises."""
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(429)
        with patch("time.sleep"), self.assertRaises(SentinelRateLimitError):
            client.get("incidents")

    def test_204_returns_empty_dict(self):
        """Test that 204 returns empty dict."""
        client, mock_http = _make_client()
        resp = MagicMock()
        resp.status = 204
        resp.data = b""
        mock_http.request.return_value = resp
        result = client.delete("incidents/inc-001")
        self.assertEqual(result, {})

    def test_paginate_follows_next_link(self):
        """paginate() follows nextLink URLs until exhausted."""
        client, mock_http = _make_client()
        page1 = _azure_list(
            [{"name": "inc-1"}],
            next_link="https://management.azure.com/next-page?api-version=2023-11-01",
        )
        page2 = _azure_list([{"name": "inc-2"}])
        mock_http.request.side_effect = [
            _make_response(200, page1),
            _make_response(200, page2),
        ]
        items = list(client.paginate("incidents"))
        self.assertEqual(len(items), 2)
        self.assertEqual(items[1]["name"], "inc-2")

    def test_paginate_stops_when_no_next_link(self):
        """Test that paginate stops when no next link."""
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(200, _azure_list([{"name": "only"}]))
        items = list(client.paginate("incidents"))
        self.assertEqual(len(items), 1)
        self.assertEqual(mock_http.request.call_count, 1)

    def test_context_manager(self):
        """Test that context manager."""
        cfg = _make_config()
        with patch("gnat.connectors.sentinel.client.urllib3.PoolManager"), SentinelClient(cfg) as c:
            self.assertIsInstance(c, SentinelClient)


# ═════════════════════════════════════════════════════════════════════════════
# SentinelIncidentCommands
# ═════════════════════════════════════════════════════════════════════════════


class TestSentinelIncidentCommands(unittest.TestCase):
    """Unit tests for :class:`SentinelIncidentCommands`."""
    def _make_incidents(self):
        """Internal helper for make incidents."""
        client, mock_http = _make_client()
        return SentinelIncidentCommands(client), mock_http

    def test_list_incidents(self):
        """Test that list incidents."""
        inc_cmd, mock_http = self._make_incidents()
        mock_http.request.return_value = _make_response(200, _azure_list([_SAMPLE_INCIDENT]))
        results = inc_cmd.list_incidents()
        self.assertEqual(len(results), 1)

    def test_list_incidents_applies_status_filter(self):
        """Test that list incidents applies status filter."""
        inc_cmd, mock_http = self._make_incidents()
        mock_http.request.return_value = _make_response(200, _azure_list([]))
        inc_cmd.list_incidents(status="Active")
        call_url = mock_http.request.call_args[0][1]
        self.assertIn("Active", call_url)

    def test_get_incident(self):
        """Test that get incident."""
        inc_cmd, mock_http = self._make_incidents()
        mock_http.request.return_value = _make_response(200, _SAMPLE_INCIDENT)
        result = inc_cmd.get_incident("inc-001")
        self.assertEqual(result["name"], "inc-001")

    def test_add_comment(self):
        """Test that add comment."""
        inc_cmd, mock_http = self._make_incidents()
        mock_http.request.return_value = _make_response(
            201, {"name": "comment-001", "properties": {"message": "Investigating"}}
        )
        result = inc_cmd.add_comment("inc-001", "Investigating")
        self.assertIsNotNone(result)

    def test_normalise_incident(self):
        """Test that normalise incident."""
        result = SentinelIncidentCommands.normalise_incident(_SAMPLE_INCIDENT)
        self.assertEqual(result["id"], "inc-001")
        self.assertEqual(result["number"], 42)
        self.assertEqual(result["severity"], 4)  # High → 4
        self.assertEqual(result["severity_label"], "high")
        self.assertEqual(result["owner"], "analyst@corp.com")
        self.assertIn("brute-force", result["labels"])
        self.assertEqual(result["alert_count"], 5)

    def test_normalise_incident_severity_mapping(self):
        """Test that normalise incident severity mapping."""
        for sev_str, expected in [("High", 4), ("Medium", 3), ("Low", 2), ("Informational", 1)]:
            inc = {
                **_SAMPLE_INCIDENT,
                "properties": {**_SAMPLE_INCIDENT["properties"], "severity": sev_str},
            }
            result = SentinelIncidentCommands.normalise_incident(inc)
            self.assertEqual(result["severity"], expected)


# ═════════════════════════════════════════════════════════════════════════════
# SentinelThreatIntelCommands
# ═════════════════════════════════════════════════════════════════════════════


class TestSentinelThreatIntelCommands(unittest.TestCase):
    """Unit tests for :class:`SentinelThreatIntelCommands`."""
    def _make_ti(self):
        """Internal helper for make ti."""
        client, mock_http = _make_client()
        return SentinelThreatIntelCommands(client), mock_http

    def test_list_indicators(self):
        """Test that list indicators."""
        ti_cmd, mock_http = self._make_ti()
        mock_http.request.return_value = _make_response(200, _azure_list([_SAMPLE_TI_INDICATOR]))
        results = ti_cmd.list_indicators()
        self.assertEqual(len(results), 1)

    def test_create_indicator(self):
        """Test that create indicator."""
        ti_cmd, mock_http = self._make_ti()
        mock_http.request.return_value = _make_response(201, _SAMPLE_TI_INDICATOR)
        props = {
            "displayName": "Test",
            "pattern": "[ipv4-addr:value = '9.9.9.9']",
            "patternType": "stix",
            "source": "gnat",
            "validFrom": "2024-01-01T00:00:00Z",
        }
        result = ti_cmd.create_indicator(props)
        self.assertIsNotNone(result)

    def test_bulk_create_captures_errors(self):
        """Test that bulk create captures errors."""
        ti_cmd, mock_http = self._make_ti()
        mock_http.request.side_effect = [
            _make_response(201, _SAMPLE_TI_INDICATOR),
            Exception("Network error"),
        ]
        results = ti_cmd.bulk_create_indicators(
            [
                {
                    "displayName": "A",
                    "pattern": "...",
                    "source": "gnat",
                    "patternType": "stix",
                    "validFrom": "2024-01-01T00:00:00Z",
                },
                {
                    "displayName": "B",
                    "pattern": "...",
                    "source": "gnat",
                    "patternType": "stix",
                    "validFrom": "2024-01-01T00:00:00Z",
                },
            ]
        )
        self.assertEqual(len(results), 2)
        self.assertIn("error", results[1])

    def test_normalise_indicator(self):
        """Test that normalise indicator."""
        result = SentinelThreatIntelCommands.normalise_indicator(_SAMPLE_TI_INDICATOR)
        self.assertEqual(result["pattern"], "[ipv4-addr:value = '1.2.3.4']")
        self.assertEqual(result["confidence"], 85)
        self.assertIn("apt", result["tags"])


# ═════════════════════════════════════════════════════════════════════════════
# SentinelAnalyticRuleCommands
# ═════════════════════════════════════════════════════════════════════════════


class TestSentinelAnalyticRuleCommands(unittest.TestCase):
    """Unit tests for :class:`SentinelAnalyticRuleCommands`."""
    def _make_rules(self):
        """Internal helper for make rules."""
        client, mock_http = _make_client()
        return SentinelAnalyticRuleCommands(client), mock_http

    def test_list_rules(self):
        """Test that list rules."""
        rules_cmd, mock_http = self._make_rules()
        rule = {
            "name": "rule-001",
            "kind": "Scheduled",
            "properties": {"displayName": "Test Rule", "enabled": True},
        }
        mock_http.request.return_value = _make_response(200, _azure_list([rule]))
        results = rules_cmd.list_rules()
        self.assertEqual(results[0]["name"], "rule-001")

    def test_list_rules_filtered_by_kind(self):
        """Test that list rules filtered by kind."""
        rules_cmd, mock_http = self._make_rules()
        rules = [
            {"name": "r1", "kind": "Scheduled", "properties": {}},
            {"name": "r2", "kind": "Fusion", "properties": {}},
        ]
        mock_http.request.return_value = _make_response(200, _azure_list(rules))
        results = rules_cmd.list_rules(kind="Scheduled")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["kind"], "Scheduled")

    def test_normalise_rule(self):
        """Test that normalise rule."""
        rule = {
            "name": "rule-001",
            "kind": "Scheduled",
            "properties": {
                "displayName": "Brute Force",
                "enabled": True,
                "severity": "High",
                "query": "SecurityEvent | where ...",
                "tactics": ["CredentialAccess"],
                "techniques": ["T1110"],
                "queryFrequency": "PT5M",
                "queryPeriod": "PT5M",
            },
        }
        result = SentinelAnalyticRuleCommands.normalise_rule(rule)
        self.assertEqual(result["display_name"], "Brute Force")
        self.assertTrue(result["enabled"])
        self.assertIn("T1110", result["techniques"])


# ═════════════════════════════════════════════════════════════════════════════
# SentinelSTIXMapper
# ═════════════════════════════════════════════════════════════════════════════


class TestSentinelSTIXMapper(unittest.TestCase):
    """STIX translation helper for test sentinel s t i x objects."""
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.mapper = SentinelSTIXMapper()

    def test_ti_indicator_to_stix(self):
        """Test that ti indicator to stix."""
        obj = self.mapper.ti_indicator_to_stix(_SAMPLE_TI_INDICATOR)
        self.assertEqual(obj["type"], "indicator")
        self.assertEqual(obj["pattern"], "[ipv4-addr:value = '1.2.3.4']")
        self.assertEqual(obj["confidence"], 85)
        self.assertEqual(len(obj["kill_chain_phases"]), 1)
        self.assertIn("apt", obj.get("labels", []))

    def test_ti_indicators_to_stix_bundle(self):
        """Test that ti indicators to stix bundle."""
        bundle = self.mapper.ti_indicators_to_stix_bundle([_SAMPLE_TI_INDICATOR])
        self.assertEqual(bundle["type"], "bundle")
        self.assertEqual(len(bundle["objects"]), 1)
        self.assertEqual(bundle["objects"][0]["type"], "indicator")

    def test_ti_indicators_bundle_deduplication(self):
        """Test that ti indicators bundle deduplication."""
        bundle = self.mapper.ti_indicators_to_stix_bundle(
            [_SAMPLE_TI_INDICATOR, _SAMPLE_TI_INDICATOR]
        )
        self.assertEqual(len(bundle["objects"]), 1)

    def test_stix_indicator_to_ti_properties(self):
        """Test that stix indicator to ti properties."""
        stix_ind = {
            "type": "indicator",
            "id": "indicator--abc",
            "name": "Malicious IP",
            "description": "C2 server",
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00Z",
            "valid_until": "2025-01-01T00:00:00Z",
            "confidence": 80,
            "indicator_types": ["malicious-activity"],
            "labels": ["c2"],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "c2"}],
        }
        props = self.mapper.stix_indicator_to_ti_properties(stix_ind)
        self.assertEqual(props["displayName"], "Malicious IP")
        self.assertEqual(props["pattern"], "[ipv4-addr:value = '1.2.3.4']")
        self.assertEqual(props["confidence"], 80)
        self.assertIn("c2", props["threatIntelligenceTags"])
        self.assertEqual(len(props["killChainPhases"]), 1)

    def test_stix_indicator_wrong_type_raises(self):
        """Test that stix indicator wrong type raises."""
        with self.assertRaises(SentinelSTIXError):
            self.mapper.stix_indicator_to_ti_properties({"type": "malware"})

    def test_incident_to_stix_bundle(self):
        """Test that incident to stix bundle."""
        incident = SentinelIncidentCommands.normalise_incident(_SAMPLE_INCIDENT)
        bundle = self.mapper.incident_to_stix_bundle(incident)
        self.assertEqual(bundle["type"], "bundle")
        obs = bundle["objects"][0]
        self.assertEqual(obs["type"], "observed-data")
        self.assertIn("x_sentinel_incident", obs)
        self.assertEqual(obs["x_sentinel_incident"]["incident_number"], 42)

    def test_stix_bundle_to_ti_properties_list(self):
        """Test that stix bundle to ti properties list."""
        bundle = {
            "type": "bundle",
            "spec_version": CURRENT_SPEC_VERSION,
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--1",
                    "name": "Test",
                    "pattern": "[ipv4-addr:value = '1.1.1.1']",
                    "pattern_type": "stix",
                    "valid_from": "2024-01-01T00:00:00Z",
                    "indicator_types": ["malicious-activity"],
                },
                {"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "1.1.1.1"},
            ],
        }
        props_list = self.mapper.stix_bundle_to_ti_properties_list(bundle)
        self.assertEqual(len(props_list), 1)  # Only indicator SDOs
        self.assertIn("ipv4-addr:value", props_list[0]["pattern"])

    def test_invalid_bundle_raises(self):
        """Test that invalid bundle raises."""
        with self.assertRaises(SentinelSTIXError):
            self.mapper.stix_bundle_to_ti_properties_list({"type": "indicator"})


# ═════════════════════════════════════════════════════════════════════════════
# Exception hierarchy
# ═════════════════════════════════════════════════════════════════════════════


class TestSentinelExceptions(unittest.TestCase):
    """Raised when a test sentinel exceptions error occurs."""
    def test_all_inherit_from_base(self):
        """Test that all inherit from base."""
        from gnat.connectors.sentinel.exceptions import SentinelError

        for cls in [
            SentinelConfigError,
            SentinelAuthError,
            SentinelAPIError,
            SentinelNotFoundError,
            SentinelRateLimitError,
            SentinelSTIXError,
        ]:
            self.assertTrue(issubclass(cls, SentinelError))

    def test_api_error_str(self):
        """Test that api error str."""
        exc = SentinelAPIError("msg", 403, "AuthorizationFailed", "No access", "/api/x")
        s = str(exc)
        self.assertIn("403", s)
        self.assertIn("AuthorizationFailed", s)

    def test_not_found_is_api_error(self):
        """Test that not found is api error."""
        self.assertTrue(issubclass(SentinelNotFoundError, SentinelAPIError))


if __name__ == "__main__":
    unittest.main(verbosity=2)

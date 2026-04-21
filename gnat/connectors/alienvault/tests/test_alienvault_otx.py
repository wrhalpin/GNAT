# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""tests for AlienVault OTX connector"""

import configparser
import json
import unittest
from unittest.mock import MagicMock, patch

from gnat.connectors.alienvault import (
    OTXAPIError,
    OTXAuthError,
    OTXClient,
    OTXConfig,
    OTXConfigError,
    OTXError,
    OTXIndicatorCommands,
    OTXNotFoundError,
    OTXPulseCommands,
    OTXRateLimitError,
    OTXSTIXMapper,
    load_otx_config,
)


def _cfg(**kw):
    """Internal helper for cfg."""
    d = {"api_key": "test-otx-key"}
    d.update(kw)
    return OTXConfig(**d)


def _resp(status=200, body=None):
    """Internal helper for resp."""
    r = MagicMock()
    r.status = status
    r.data = json.dumps(body if body is not None else {}).encode()
    return r


def _make_client():
    """Internal helper for make client."""
    cfg = _cfg()
    with patch("gnat.connectors.alienvault_otx.urllib3.PoolManager") as pm:
        mock_http = MagicMock()
        pm.return_value = mock_http
        c = OTXClient(cfg)
        c._http = mock_http
    return c, mock_http


_PULSE = {
    "id": "pulse-abc",
    "name": "APT Campaign IOCs",
    "description": "Indicators from APT campaign",
    "author_name": "researcher1",
    "TLP": "white",
    "tags": ["apt", "c2"],
    "created": "2024-03-01T00:00:00Z",
    "modified": "2024-03-10T00:00:00Z",
    "indicator_count": 3,
    "public": True,
    "adversary": "APT28",
    "targeted_countries": ["US"],
    "industries": [],
    "malware_families": ["Sofacy"],
    "attack_ids": [{"id": "T1059"}],
    "indicators": [
        {
            "id": "i1",
            "type": "IPv4",
            "indicator": "1.2.3.4",
            "created": "2024-03-01T00:00:00Z",
            "description": "C2 IP",
            "is_active": True,
        },
        {
            "id": "i2",
            "type": "domain",
            "indicator": "evil.com",
            "created": "2024-03-01T00:00:00Z",
            "description": "",
            "is_active": True,
        },
        {
            "id": "i3",
            "type": "FileHash-SHA256",
            "indicator": "abc123def456",
            "created": "2024-03-01T00:00:00Z",
            "description": "",
            "is_active": True,
        },
    ],
}


class TestOTXConfig(unittest.TestCase):
    """Configuration container for test o t x."""

    def test_basic(self):
        """Test that basic."""
        cfg = _cfg()
        self.assertEqual(cfg.api_key, "test-otx-key")
        self.assertIn("otx.alienvault.com", cfg.base_url)

    def test_api_key_header(self):
        """Test that api key header."""
        cfg = _cfg()
        self.assertEqual(cfg.base_headers["X-OTX-API-KEY"], "test-otx-key")

    def test_missing_api_key_raises(self):
        """Test that missing api key raises."""
        with self.assertRaises(OTXConfigError):
            OTXConfig(api_key="")

    def test_load_from_ini(self):
        """Test that load from ini."""
        p = configparser.ConfigParser()
        p.read_dict({"alienvault_otx": {"api_key": "my-key"}})
        cfg = load_otx_config(p)
        self.assertEqual(cfg.api_key, "my-key")

    def test_load_missing_section_raises(self):
        """Test that load missing section raises."""
        with self.assertRaises(OTXConfigError):
            load_otx_config(configparser.ConfigParser())


class TestOTXClient(unittest.TestCase):
    """HTTP API client for the TestOTX platform."""

    def test_get_sends_api_key_header(self):
        """Test that get sends api key header."""
        c, mock_http = _make_client()
        mock_http.request.return_value = _resp(200, {"results": []})
        c.get("pulses/subscribed")
        headers = mock_http.request.call_args[1]["headers"]
        self.assertEqual(headers["X-OTX-API-KEY"], "test-otx-key")

    def test_401_raises_auth_error(self):
        """Test that 401 raises auth error."""
        c, mock_http = _make_client()
        mock_http.request.return_value = _resp(401)
        with self.assertRaises(OTXAuthError):
            c.get("pulses/subscribed")

    def test_404_raises_not_found(self):
        """Test that 404 raises not found."""
        c, mock_http = _make_client()
        mock_http.request.return_value = _resp(404)
        with self.assertRaises(OTXNotFoundError):
            c.get("pulses/missing-id")

    def test_429_raises_rate_limit(self):
        """Test that 429 raises rate limit."""
        c, mock_http = _make_client()
        mock_http.request.return_value = _resp(429)
        with patch("time.sleep"), self.assertRaises(OTXRateLimitError):
            c.get("pulses/subscribed")

    def test_paginate_follows_next(self):
        """Test that paginate follows next."""
        c, mock_http = _make_client()
        page1 = {
            "results": [{"id": "p1"}],
            "count": 2,
            "next": "https://otx.alienvault.com/api/v1/pulses/subscribed?page=2",
        }
        page2 = {"results": [{"id": "p2"}], "count": 2, "next": None}
        mock_http.request.side_effect = [_resp(200, page1), _resp(200, page2)]
        items = list(c.paginate("pulses/subscribed"))
        self.assertEqual(len(items), 2)

    def test_paginate_stops_without_next(self):
        """Test that paginate stops without next."""
        c, mock_http = _make_client()
        mock_http.request.return_value = _resp(200, {"results": [{"id": "p1"}], "next": None})
        items = list(c.paginate("pulses/subscribed"))
        self.assertEqual(len(items), 1)
        self.assertEqual(mock_http.request.call_count, 1)


class TestOTXPulseCommands(unittest.TestCase):
    """Unit tests for :class:`OTXPulseCommands`."""

    def _make_pulses(self):
        """Internal helper for make pulses."""
        c, mock_http = _make_client()
        return OTXPulseCommands(c), mock_http

    def test_list_subscribed_pulses(self):
        """Test that list subscribed pulses."""
        cmd, mock_http = self._make_pulses()
        mock_http.request.return_value = _resp(200, {"results": [_PULSE], "count": 1})
        results = cmd.list_subscribed_pulses()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "APT Campaign IOCs")

    def test_get_pulse(self):
        """Test that get pulse."""
        cmd, mock_http = self._make_pulses()
        mock_http.request.return_value = _resp(200, _PULSE)
        result = cmd.get_pulse("pulse-abc")
        self.assertEqual(result["id"], "pulse-abc")

    def test_get_pulse_indicators(self):
        """Test that get pulse indicators."""
        cmd, mock_http = self._make_pulses()
        mock_http.request.return_value = _resp(200, {"results": _PULSE["indicators"], "count": 3})
        inds = cmd.get_pulse_indicators("pulse-abc")
        self.assertEqual(len(inds), 3)

    def test_normalise_pulse(self):
        """Test that normalise pulse."""
        norm = OTXPulseCommands.normalise_pulse(_PULSE)
        self.assertEqual(norm["id"], "pulse-abc")
        self.assertEqual(norm["author"], "researcher1")
        self.assertEqual(norm["tlp"], "white")
        self.assertEqual(norm["adversary"], "APT28")
        self.assertIn("apt", norm["tags"])


class TestOTXIndicatorCommands(unittest.TestCase):
    """Unit tests for :class:`OTXIndicatorCommands`."""

    def _make_inds(self):
        """Internal helper for make inds."""
        c, mock_http = _make_client()
        return OTXIndicatorCommands(c), mock_http

    def test_get_ip_details(self):
        """Test that get ip details."""
        cmd, mock_http = self._make_inds()
        mock_http.request.return_value = _resp(200, {"pulse_info": {"count": 5}, "reputation": 2})
        result = cmd.get_ip_details("1.2.3.4")
        self.assertIn("pulse_info", result)

    def test_get_domain_details(self):
        """Test that get domain details."""
        cmd, mock_http = self._make_inds()
        mock_http.request.return_value = _resp(200, {"pulse_info": {"count": 3}})
        result = cmd.get_domain_details("evil.com")
        self.assertIsInstance(result, dict)

    def test_normalise_indicator(self):
        """Test that normalise indicator."""
        raw = _PULSE["indicators"][0]
        norm = OTXIndicatorCommands.normalise_indicator(raw)
        self.assertEqual(norm["type"], "IPv4")
        self.assertEqual(norm["value"], "1.2.3.4")
        self.assertEqual(norm["stix_type"], "ipv4-addr")
        self.assertTrue(norm["is_active"])

    def test_stix_type_mapping(self):
        """Test that stix type mapping."""
        for otx_type, expected in [
            ("IPv4", "ipv4-addr"),
            ("domain", "domain-name"),
            ("URL", "url"),
            ("FileHash-SHA256", "file"),
            ("email", "email-addr"),
        ]:
            ind = {"type": otx_type, "indicator": "test", "id": "x"}
            norm = OTXIndicatorCommands.normalise_indicator(ind)
            self.assertEqual(norm["stix_type"], expected)


class TestOTXSTIXMapper(unittest.TestCase):
    """STIX translation helper for test o t x s t i x objects."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.mapper = OTXSTIXMapper()
        self.norm_pulse = OTXPulseCommands.normalise_pulse(_PULSE)
        self.norm_indicators = [
            OTXIndicatorCommands.normalise_indicator(i) for i in _PULSE["indicators"]
        ]

    def test_indicator_ipv4_to_stix(self):
        """Test that indicator ipv4 to stix."""
        ind = OTXIndicatorCommands.normalise_indicator(_PULSE["indicators"][0])
        objects = self.mapper.indicator_to_stix_objects(ind)
        types = {o["type"] for o in objects}
        self.assertIn("ipv4-addr", types)
        self.assertIn("indicator", types)

    def test_indicator_domain_to_stix(self):
        """Test that indicator domain to stix."""
        ind = OTXIndicatorCommands.normalise_indicator(_PULSE["indicators"][1])
        objects = self.mapper.indicator_to_stix_objects(ind)
        types = {o["type"] for o in objects}
        self.assertIn("domain-name", types)

    def test_indicator_sha256_to_stix(self):
        """Test that indicator sha256 to stix."""
        ind = OTXIndicatorCommands.normalise_indicator(_PULSE["indicators"][2])
        objects = self.mapper.indicator_to_stix_objects(ind)
        file_obj = next((o for o in objects if o["type"] == "file"), None)
        self.assertIsNotNone(file_obj)
        self.assertEqual(file_obj["hashes"]["SHA-256"], "abc123def456")

    def test_pulse_to_stix_bundle(self):
        """Test that pulse to stix bundle."""
        bundle = self.mapper.pulse_to_stix_bundle(self.norm_pulse, self.norm_indicators)
        self.assertEqual(bundle["type"], "bundle")
        types = {o["type"] for o in bundle["objects"]}
        self.assertIn("report", types)
        self.assertIn("ipv4-addr", types)
        self.assertIn("domain-name", types)
        self.assertIn("file", types)

    def test_report_has_otx_extension(self):
        """Test that report has otx extension."""
        bundle = self.mapper.pulse_to_stix_bundle(self.norm_pulse, self.norm_indicators)
        report = next(o for o in bundle["objects"] if o["type"] == "report")
        self.assertIn("x_otx_pulse", report)
        self.assertEqual(report["x_otx_pulse"]["adversary"], "APT28")

    def test_indicators_bundle(self):
        """Test that indicators bundle."""
        bundle = self.mapper.indicators_to_stix_bundle(self.norm_indicators)
        self.assertEqual(bundle["type"], "bundle")

    def test_deduplication(self):
        """Test that deduplication."""
        bundle = self.mapper.indicators_to_stix_bundle(self.norm_indicators + self.norm_indicators)
        ip_objs = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
        self.assertEqual(len([o for o in ip_objs if o["value"] == "1.2.3.4"]), 1)

    def test_indicator_pattern_ipv4(self):
        """Test that indicator pattern ipv4."""
        ind = OTXIndicatorCommands.normalise_indicator(_PULSE["indicators"][0])
        objects = self.mapper.indicator_to_stix_objects(ind)
        ind_obj = next(o for o in objects if o["type"] == "indicator")
        self.assertEqual(ind_obj["pattern"], "[ipv4-addr:value = '1.2.3.4']")


class TestOTXExceptions(unittest.TestCase):
    """Raised when a test o t x exceptions error occurs."""

    def test_hierarchy(self):
        """Test that hierarchy."""
        for cls in [OTXConfigError, OTXAuthError, OTXAPIError, OTXNotFoundError, OTXRateLimitError]:
            self.assertTrue(issubclass(cls, OTXError))


if __name__ == "__main__":
    unittest.main(verbosity=2)

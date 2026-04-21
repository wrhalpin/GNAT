# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""tests for Graylog connector"""

import base64
import configparser
import json
import unittest
from unittest.mock import MagicMock, patch

from gnat.connectors.graylog import (
    GraylogAPIError,
    GraylogAuthError,
    GraylogClient,
    GraylogConfig,
    GraylogConfigError,
    GraylogNotFoundError,
    GraylogSearchCommands,
    GraylogSTIXMapper,
    GraylogStreamCommands,
    GraylogSystemCommands,
    load_graylog_config,
)


def _cfg(**kw):
    """Internal helper for cfg."""
    d = {"url": "https://graylog.test:9000", "username": "admin", "password": "pass"}
    d.update(kw)
    return GraylogConfig(**d)


def _resp(status=200, body=None):
    """Internal helper for resp."""
    r = MagicMock()
    r.status = status
    r.data = json.dumps(body if body is not None else {}).encode()
    return r


def _make_client():
    """Internal helper for make client."""
    cfg = _cfg()
    with patch("gnat.connectors.graylog.urllib3.PoolManager") as pm:
        mock_http = MagicMock()
        pm.return_value = mock_http
        c = GraylogClient(cfg)
        c._http = mock_http
    return c, mock_http


class TestGraylogConfig(unittest.TestCase):
    """Configuration container for test graylog."""

    def test_basic(self):
        """Test that basic."""
        cfg = _cfg()
        self.assertEqual(cfg.base_url, "https://graylog.test:9000")

    def test_auth_header_is_basic(self):
        """Test that auth header is basic."""
        cfg = _cfg()
        self.assertTrue(cfg.auth_header.startswith("Basic "))
        decoded = base64.b64decode(cfg.auth_header.split(" ")[1]).decode()
        self.assertEqual(decoded, "admin:pass")

    def test_write_headers_has_x_requested_by(self):
        """Test that write headers has x requested by."""
        cfg = _cfg()
        self.assertIn("X-Requested-By", cfg.write_headers)

    def test_endpoint(self):
        """Test that endpoint."""
        cfg = _cfg()
        self.assertEqual(
            cfg.endpoint("search/universal/relative"),
            "https://graylog.test:9000/api/search/universal/relative",
        )

    def test_missing_url_raises(self):
        """Test that missing url raises."""
        with self.assertRaises(GraylogConfigError):
            GraylogConfig(url="", username="u", password="p")

    def test_load_from_ini(self):
        """Test that load from ini."""
        p = configparser.ConfigParser()
        p.read_dict({"graylog": {"url": "https://gl", "username": "u", "password": "p"}})
        cfg = load_graylog_config(p)
        self.assertEqual(cfg.username, "u")

    def test_load_missing_section_raises(self):
        """Test that load missing section raises."""
        with self.assertRaises(GraylogConfigError):
            load_graylog_config(configparser.ConfigParser())


class TestGraylogClient(unittest.TestCase):
    """HTTP API client for the TestGraylog platform."""

    def test_get_returns_dict(self):
        """Test that get returns dict."""
        c, mock_http = _make_client()
        mock_http.request.return_value = _resp(200, {"total": 1, "messages": []})
        result = c.get("streams")
        self.assertIsInstance(result, dict)

    def test_get_sends_basic_auth(self):
        """Test that get sends basic auth."""
        c, mock_http = _make_client()
        mock_http.request.return_value = _resp(200, {})
        c.get("system")
        headers = mock_http.request.call_args[1]["headers"]
        self.assertTrue(headers["Authorization"].startswith("Basic "))

    def test_post_sends_x_requested_by(self):
        """Test that post sends x requested by."""
        c, mock_http = _make_client()
        mock_http.request.return_value = _resp(200, {})
        c.post("streams/s1/pause")
        headers = mock_http.request.call_args[1]["headers"]
        self.assertIn("X-Requested-By", headers)

    def test_401_raises_auth_error(self):
        """Test that 401 raises auth error."""
        c, mock_http = _make_client()
        mock_http.request.return_value = _resp(401)
        with self.assertRaises(GraylogAuthError):
            c.get("streams")

    def test_404_raises_not_found(self):
        """Test that 404 raises not found."""
        c, mock_http = _make_client()
        mock_http.request.return_value = _resp(404)
        with self.assertRaises(GraylogNotFoundError):
            c.get("streams/missing")

    def test_204_returns_empty_dict(self):
        """Test that 204 returns empty dict."""
        c, mock_http = _make_client()
        r = MagicMock()
        r.status = 204
        r.data = b""
        mock_http.request.return_value = r
        result = c.delete("streams/s1")
        self.assertEqual(result, {})

    def test_paginate_stops_when_total_reached(self):
        """Test that paginate stops when total reached."""
        c, mock_http = _make_client()
        mock_http.request.side_effect = [
            _resp(200, {"total": 3, "messages": [{"m": 1}, {"m": 2}]}),
            _resp(200, {"total": 3, "messages": [{"m": 3}]}),
        ]
        items = list(c.paginate("search/universal/relative", page_size=2))
        self.assertEqual(len(items), 3)

    def test_context_manager(self):
        """Test that context manager."""
        cfg = _cfg()
        with patch("gnat.connectors.graylog.urllib3.PoolManager"), GraylogClient(cfg) as client:
            self.assertIsInstance(client, GraylogClient)


class TestGraylogSearchCommands(unittest.TestCase):
    """Unit tests for :class:`GraylogSearchCommands`."""

    _MSG = {
        "message": {
            "_id": "msg-1",
            "timestamp": "2024-03-10T12:00:00.000Z",
            "source": "server01",
            "message": "Failed login",
            "level": 4,
            "facility": "auth",
            "src_ip": "1.2.3.4",
            "username": "jdoe",
        },
        "stream_ids": ["s1"],
    }

    def _make_search(self):
        """Internal helper for make search."""
        c, mock_http = _make_client()
        return GraylogSearchCommands(c), mock_http

    def test_search(self):
        """Test that search."""
        cmd, mock_http = self._make_search()
        mock_http.request.return_value = _resp(200, {"total_results": 1, "messages": [self._MSG]})
        result = cmd.search(query="source:server01")
        self.assertEqual(result["total_results"], 1)

    def test_get_messages(self):
        """Test that get messages."""
        cmd, mock_http = self._make_search()
        mock_http.request.return_value = _resp(200, {"total_results": 1, "messages": [self._MSG]})
        msgs = cmd.get_messages()
        self.assertEqual(len(msgs), 1)

    def test_search_absolute_passes_timestamps(self):
        """Test that search absolute passes timestamps."""
        cmd, mock_http = self._make_search()
        mock_http.request.return_value = _resp(200, {"messages": []})
        cmd.search_absolute("*", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z")
        url = mock_http.request.call_args[0][1]
        self.assertIn("from=", url)
        self.assertIn("to=", url)

    def test_normalise_message(self):
        """Test that normalise message."""
        norm = GraylogSearchCommands.normalise_message(self._MSG)
        self.assertEqual(norm["id"], "msg-1")
        self.assertEqual(norm["source"], "server01")
        self.assertEqual(norm["src_ip"], "1.2.3.4")
        self.assertEqual(norm["username"], "jdoe")
        self.assertEqual(norm["level"], 4)


class TestGraylogStreamCommands(unittest.TestCase):
    """Unit tests for :class:`GraylogStreamCommands`."""

    def _make_streams(self):
        """Internal helper for make streams."""
        c, mock_http = _make_client()
        return GraylogStreamCommands(c), mock_http

    def test_list_streams(self):
        """Test that list streams."""
        cmd, mock_http = self._make_streams()
        mock_http.request.return_value = _resp(
            200, {"streams": [{"id": "s1", "title": "All Messages"}]}
        )
        results = cmd.list_streams()
        self.assertEqual(len(results), 1)

    def test_pause_stream(self):
        """Test that pause stream."""
        cmd, mock_http = self._make_streams()
        mock_http.request.return_value = _resp(200, {})
        cmd.pause_stream("s1")
        url = mock_http.request.call_args[0][1]
        self.assertIn("pause", url)


class TestGraylogSystemCommands(unittest.TestCase):
    """Unit tests for :class:`GraylogSystemCommands`."""

    def _make_system(self):
        """Internal helper for make system."""
        c, mock_http = _make_client()
        return GraylogSystemCommands(c), mock_http

    def test_get_system_info(self):
        """Test that get system info."""
        cmd, mock_http = self._make_system()
        mock_http.request.return_value = _resp(200, {"version": "5.1.0"})
        result = cmd.get_system_info()
        self.assertEqual(result["version"], "5.1.0")

    def test_get_cluster_nodes(self):
        """Test that get cluster nodes."""
        cmd, mock_http = self._make_system()
        mock_http.request.return_value = _resp(200, {"nodes": [{"node_id": "n1"}]})
        nodes = cmd.get_cluster_nodes()
        self.assertEqual(len(nodes), 1)


class TestGraylogSTIXMapper(unittest.TestCase):
    """STIX translation helper for test graylog s t i x objects."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.mapper = GraylogSTIXMapper()
        self._msg = {
            "id": "msg-1",
            "timestamp": "2024-03-10T12:00:00Z",
            "source": "server01",
            "message": "Failed login",
            "level": 4,
            "facility": "auth",
            "src_ip": "1.2.3.4",
            "username": "jdoe",
        }

    def test_bundle_structure(self):
        """Test that bundle structure."""
        bundle = self.mapper.message_to_stix_bundle(self._msg)
        self.assertEqual(bundle["type"], "bundle")
        types = {o["type"] for o in bundle["objects"]}
        self.assertIn("ipv4-addr", types)
        self.assertIn("user-account", types)
        self.assertIn("observed-data", types)

    def test_observed_data_extension(self):
        """Test that observed data extension."""
        bundle = self.mapper.message_to_stix_bundle(self._msg)
        obs = next(o for o in bundle["objects"] if o["type"] == "observed-data")
        self.assertIn("x_graylog_message", obs)
        self.assertEqual(obs["x_graylog_message"]["source"], "server01")

    def test_deduplication(self):
        """Test that deduplication."""
        bundle = self.mapper.messages_to_stix_bundle([self._msg, self._msg])
        ip_objs = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
        self.assertEqual(len([o for o in ip_objs if o["value"] == "1.2.3.4"]), 1)

    def test_no_ip_no_ipv4_sco(self):
        """Test that no ip no ipv4 sco."""
        msg = {**self._msg, "src_ip": None}
        bundle = self.mapper.message_to_stix_bundle(msg)
        types = [o["type"] for o in bundle["objects"]]
        self.assertNotIn("ipv4-addr", types)


class TestGraylogExceptions(unittest.TestCase):
    """Raised when a test graylog exceptions error occurs."""

    def test_hierarchy(self):
        """Test that hierarchy."""
        from gnat.connectors.graylog import GraylogError

        for cls in [GraylogConfigError, GraylogAuthError, GraylogAPIError, GraylogNotFoundError]:
            self.assertTrue(issubclass(cls, GraylogError))


if __name__ == "__main__":
    unittest.main(verbosity=2)

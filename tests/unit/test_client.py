"""
tests/unit/test_client.py
=========================

Unit tests for GNATClient, GNATConfig, and the BaseClient HTTP layer.
"""

import json
import pytest
from unittest.mock import MagicMock

from gnat.config import GNATConfig
from gnat.client import GNATClient
from gnat.clients.base import BaseClient, GNATClientError


# ---------------------------------------------------------------------------
# GNATConfig
# ---------------------------------------------------------------------------

class TestGNATConfig:

    def test_loads_valid_ini(self, minimal_config):
        cfg = GNATConfig(minimal_config)
        assert "threatq" in cfg.sections

    def test_get_returns_dict(self, minimal_config):
        cfg = GNATConfig(minimal_config)
        d = cfg.get("threatq")
        assert d["host"] == "https://fake-threatq.example.com"
        assert d["client_id"] == "test-id"

    def test_get_unknown_section_raises(self, minimal_config):
        cfg = GNATConfig(minimal_config)
        with pytest.raises(KeyError, match="nosuchplatform"):
            cfg.get("nosuchplatform")

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            GNATConfig(str(tmp_path / "nonexistent.ini"))

    def test_sections_property(self, minimal_config):
        cfg = GNATConfig(minimal_config)
        for target in ("threatq", "crowdstrike", "proofpoint", "netskope", "xsoar", "recordedfuture"):
            assert target in cfg.sections

    def test_config_path_property(self, minimal_config):
        cfg = GNATConfig(minimal_config)
        assert str(cfg.config_path) == minimal_config

    def test_env_var_resolution(self, minimal_config, monkeypatch):
        monkeypatch.setenv("GNAT_CONFIG", minimal_config)
        cfg = GNATConfig()   # no explicit path
        assert "threatq" in cfg.sections

    def test_default_values_inherited(self, minimal_config):
        cfg = GNATConfig(minimal_config)
        d = cfg.get("threatq")
        # DEFAULT section provides timeout and verify_ssl
        assert d["timeout"] == "10"
        assert d["verify_ssl"] == "false"


# ---------------------------------------------------------------------------
# GNATClient
# ---------------------------------------------------------------------------

class TestGNATClient:

    def test_connect_returns_self(self, minimal_config, monkeypatch):
        monkeypatch.setattr(
            "gnat.connectors.threatq.client.ThreatQClient.authenticate",
            lambda self: None,
        )
        cli = GNATClient(config_path=minimal_config)
        result = cli.connect("threatq")
        assert result is cli

    def test_connect_sets_target(self, minimal_config, monkeypatch):
        monkeypatch.setattr(
            "gnat.connectors.threatq.client.ThreatQClient.authenticate",
            lambda self: None,
        )
        cli = GNATClient(config_path=minimal_config)
        cli.connect("threatq")
        assert cli.target == "threatq"

    def test_connect_case_insensitive(self, minimal_config, monkeypatch):
        monkeypatch.setattr(
            "gnat.connectors.threatq.client.ThreatQClient.authenticate",
            lambda self: None,
        )
        cli = GNATClient(config_path=minimal_config)
        cli.connect("ThreatQ")
        assert cli.target == "threatq"

    def test_connect_unknown_target_raises(self, minimal_config):
        cli = GNATClient(config_path=minimal_config)
        with pytest.raises(KeyError, match="nosuchplatform"):
            cli.connect("nosuchplatform")

    def test_connect_no_host_raises(self, tmp_path):
        cfg = tmp_path / "bad.ini"
        cfg.write_text("[threatq]\nclient_id = x\n")
        cli = GNATClient(config_path=str(cfg))
        with pytest.raises(GNATClientError, match="host"):
            cli.connect("threatq")

    def test_disconnect_clears_client(self, minimal_config, monkeypatch):
        monkeypatch.setattr(
            "gnat.connectors.threatq.client.ThreatQClient.authenticate",
            lambda self: None,
        )
        cli = GNATClient(config_path=minimal_config)
        cli.connect("threatq")
        cli.disconnect()
        assert cli.client is None
        assert cli.target is None

    def test_ping_returns_false_when_not_connected(self):
        cli = GNATClient()
        assert cli.ping() is False

    def test_ping_returns_true_on_healthy_client(self, minimal_config, monkeypatch):
        monkeypatch.setattr(
            "gnat.connectors.threatq.client.ThreatQClient.authenticate",
            lambda self: None,
        )
        monkeypatch.setattr(
            "gnat.connectors.threatq.client.ThreatQClient.health_check",
            lambda self: True,
        )
        cli = GNATClient(config_path=minimal_config)
        cli.connect("threatq")
        assert cli.ping() is True

    def test_ping_returns_false_on_exception(self, minimal_config, monkeypatch):
        monkeypatch.setattr(
            "gnat.connectors.threatq.client.ThreatQClient.authenticate",
            lambda self: None,
        )
        monkeypatch.setattr(
            "gnat.connectors.threatq.client.ThreatQClient.health_check",
            MagicMock(side_effect=Exception("unreachable")),
        )
        cli = GNATClient(config_path=minimal_config)
        cli.connect("threatq")
        assert cli.ping() is False

    def test_override_kwargs_win_over_config(self, minimal_config, monkeypatch):
        monkeypatch.setattr(
            "gnat.connectors.threatq.client.ThreatQClient.authenticate",
            lambda self: None,
        )
        cli = GNATClient(config_path=minimal_config)
        cli.connect("threatq", client_id="override-id")
        assert cli.client._client_id == "override-id"

    @pytest.mark.parametrize("target", [
        "threatq", "proofpoint", "netskope", "crowdstrike", "xsoar", "recordedfuture"
    ])
    def test_all_targets_connect(self, target, minimal_config, monkeypatch):
        """Smoke test: every registered connector can be instantiated."""
        from gnat.clients import CLIENT_REGISTRY
        connector_cls = CLIENT_REGISTRY[target]
        monkeypatch.setattr(connector_cls, "authenticate", lambda self: None)
        cli = GNATClient(config_path=minimal_config)
        cli.connect(target)
        assert cli.target == target
        assert cli.client is not None


# ---------------------------------------------------------------------------
# BaseClient HTTP layer
# ---------------------------------------------------------------------------

class TestBaseClient:

    def _make_client(self):
        c = BaseClient(host="https://api.example.com")
        c._authenticated = True   # skip authenticate() for HTTP tests
        return c

    def _mock_response(self, status, body):
        resp = MagicMock()
        resp.status = status
        resp.data = json.dumps(body).encode()
        return resp

    def test_get_calls_pool_manager(self):
        c = self._make_client()
        c._http.request = MagicMock(
            return_value=self._mock_response(200, {"ok": True})
        )
        result = c.get("/test")
        assert result == {"ok": True}
        c._http.request.assert_called_once()

    def test_post_serialises_json(self):
        c = self._make_client()
        c._http.request = MagicMock(
            return_value=self._mock_response(200, {"created": True})
        )
        result = c.post("/test", json={"key": "value"})
        assert result == {"created": True}
        call_kwargs = c._http.request.call_args
        assert b'"key"' in call_kwargs[1].get("body", b"")

    def test_4xx_raises_sak_client_error(self):
        c = self._make_client()
        c._http.request = MagicMock(
            return_value=self._mock_response(404, {"error": "not found"})
        )
        with pytest.raises(GNATClientError) as exc_info:
            c.get("/missing")
        assert exc_info.value.status == 404

    def test_5xx_raises_sak_client_error(self):
        c = self._make_client()
        c._http.request = MagicMock(
            return_value=self._mock_response(500, {"error": "server error"})
        )
        with pytest.raises(GNATClientError) as exc_info:
            c.get("/broken")
        assert exc_info.value.status == 500

    def test_empty_response_returns_none(self):
        c = self._make_client()
        resp = MagicMock()
        resp.status = 204
        resp.data = b""
        c._http.request = MagicMock(return_value=resp)
        assert c.delete("/item/1") is None

    def test_authenticate_raises_not_implemented(self):
        c = BaseClient(host="https://example.com")
        with pytest.raises(NotImplementedError):
            c.authenticate()

    def test_query_params_appended_to_url(self):
        c = self._make_client()
        c._http.request = MagicMock(
            return_value=self._mock_response(200, {})
        )
        c.get("/search", params={"q": "evil", "limit": 10})
        url = c._http.request.call_args[0][1]
        assert "q=evil" in url
        assert "limit=10" in url

    def test_auth_header_injected(self):
        c = self._make_client()
        c._auth_headers["Authorization"] = "Bearer tok123"
        c._http.request = MagicMock(
            return_value=self._mock_response(200, {})
        )
        c.get("/secure")
        headers = c._http.request.call_args[1]["headers"]
        assert headers.get("Authorization") == "Bearer tok123"

    def test_authenticate_called_on_first_request(self):
        c = BaseClient(host="https://example.com")
        c.authenticate = MagicMock()
        c._http.request = MagicMock(
            return_value=self._mock_response(200, {})
        )
        c.get("/any")
        c.authenticate.assert_called_once()
        c.get("/any-again")
        c.authenticate.assert_called_once()   # only once

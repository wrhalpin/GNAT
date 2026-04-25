# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/auth/test_device_code.py
====================================

Unit tests for :class:`~gnat.auth.device_code.DeviceCodeFlow`.

All HTTP calls to the authorization server are mocked — no real IdP
or network traffic is required.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from gnat.auth.device_code import DeviceCodeError, DeviceCodeFlow

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ISSUER = "https://idp.example.com"
_CLIENT_ID = "test-client-id"
_DEVICE_ENDPOINT = f"{_ISSUER}/oauth2/v1/device/authorize"
_TOKEN_ENDPOINT = f"{_ISSUER}/oauth2/v1/token"

_OIDC_DISCOVERY = {
    "issuer": _ISSUER,
    "authorization_endpoint": f"{_ISSUER}/oauth2/v1/authorize",
    "token_endpoint": _TOKEN_ENDPOINT,
    "device_authorization_endpoint": _DEVICE_ENDPOINT,
    "jwks_uri": f"{_ISSUER}/oauth2/v1/keys",
}

_DEVICE_CODE_RESPONSE = {
    "device_code": "device-code-abc123",
    "user_code": "ABCD-1234",
    "verification_uri": "https://idp.example.com/activate",
    "verification_uri_complete": "https://idp.example.com/activate?user_code=ABCD-1234",
    "expires_in": 600,
    "interval": 5,
}

_TOKEN_SUCCESS = {
    "access_token": "eyJ-access-token",
    "id_token": "eyJ-id-token",
    "token_type": "Bearer",
    "expires_in": 3600,
}


def _mock_response(status: int = 200, body: dict | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status = status
    resp.data = json.dumps(body or {}).encode("utf-8")
    return resp


def _make_flow() -> DeviceCodeFlow:
    return DeviceCodeFlow(
        issuer=_ISSUER,
        client_id=_CLIENT_ID,
        scopes=["openid", "profile", "email"],
    )


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


class TestDiscoverEndpoints:
    """Endpoint discovery from OIDC configuration."""

    def test_discover_sets_endpoints(self):
        flow = _make_flow()
        with patch("urllib3.PoolManager") as MockPM:
            mock_http = MockPM.return_value
            mock_http.request.return_value = _mock_response(200, _OIDC_DISCOVERY)
            flow._discover_endpoints()

        assert flow._device_authorization_endpoint == _DEVICE_ENDPOINT
        assert flow._token_endpoint == _TOKEN_ENDPOINT

    def test_discover_raises_on_http_error(self):
        flow = _make_flow()
        with patch("urllib3.PoolManager") as MockPM:
            mock_http = MockPM.return_value
            mock_http.request.return_value = _mock_response(500, {"error": "server"})
            with pytest.raises(DeviceCodeError, match="OIDC discovery failed"):
                flow._discover_endpoints()

    def test_discover_raises_when_no_device_endpoint(self):
        flow = _make_flow()
        disco_no_device = {
            k: v for k, v in _OIDC_DISCOVERY.items() if k != "device_authorization_endpoint"
        }
        with patch("urllib3.PoolManager") as MockPM:
            mock_http = MockPM.return_value
            mock_http.request.return_value = _mock_response(200, disco_no_device)
            with pytest.raises(DeviceCodeError, match="device authorization"):
                flow._discover_endpoints()


# ---------------------------------------------------------------------------
# Device code request
# ---------------------------------------------------------------------------


class TestRequestDeviceCode:
    """Step 1: requesting a device code."""

    def test_returns_verification_uri_and_user_code(self):
        flow = _make_flow()
        flow._device_authorization_endpoint = _DEVICE_ENDPOINT
        with patch("urllib3.PoolManager") as MockPM:
            mock_http = MockPM.return_value
            mock_http.request.return_value = _mock_response(200, _DEVICE_CODE_RESPONSE)
            result = flow._request_device_code()

        assert result["verification_uri"] == "https://idp.example.com/activate"
        assert result["user_code"] == "ABCD-1234"
        assert result["device_code"] == "device-code-abc123"

    def test_raises_on_http_error(self):
        flow = _make_flow()
        flow._device_authorization_endpoint = _DEVICE_ENDPOINT
        with patch("urllib3.PoolManager") as MockPM:
            mock_http = MockPM.return_value
            mock_http.request.return_value = _mock_response(400, {"error": "invalid_client"})
            with pytest.raises(DeviceCodeError, match="Device code request failed"):
                flow._request_device_code()


# ---------------------------------------------------------------------------
# Poll for token
# ---------------------------------------------------------------------------


class TestPollForToken:
    """Step 2: polling the token endpoint."""

    def test_returns_token_after_pending_then_success(self):
        """Simulate authorization_pending followed by success."""
        flow = _make_flow()
        flow._token_endpoint = _TOKEN_ENDPOINT

        pending_resp = _mock_response(400, {"error": "authorization_pending"})
        success_resp = _mock_response(200, _TOKEN_SUCCESS)

        with patch("urllib3.PoolManager") as MockPM, patch("time.sleep"):  # skip real sleeps
            mock_http = MockPM.return_value
            mock_http.request.side_effect = [pending_resp, success_resp]
            result = flow._poll_for_token(
                device_code="device-code-abc123",
                interval=1,
                expires_in=30,
            )

        assert result["access_token"] == "eyJ-access-token"
        assert result["id_token"] == "eyJ-id-token"

    def test_raises_on_expired_token(self):
        flow = _make_flow()
        flow._token_endpoint = _TOKEN_ENDPOINT

        expired_resp = _mock_response(400, {"error": "expired_token"})

        with patch("urllib3.PoolManager") as MockPM, patch("time.sleep"):
            mock_http = MockPM.return_value
            mock_http.request.side_effect = [expired_resp]
            with pytest.raises(DeviceCodeError, match="expired_token"):
                flow._poll_for_token(
                    device_code="device-code-abc123",
                    interval=1,
                    expires_in=30,
                )

    def test_raises_on_access_denied(self):
        flow = _make_flow()
        flow._token_endpoint = _TOKEN_ENDPOINT

        denied_resp = _mock_response(400, {"error": "access_denied"})

        with patch("urllib3.PoolManager") as MockPM, patch("time.sleep"):
            mock_http = MockPM.return_value
            mock_http.request.side_effect = [denied_resp]
            with pytest.raises(DeviceCodeError, match="access_denied"):
                flow._poll_for_token(
                    device_code="device-code-abc123",
                    interval=1,
                    expires_in=30,
                )

    def test_slow_down_increases_interval(self):
        """When the server says slow_down, interval should increase."""
        flow = _make_flow()
        flow._token_endpoint = _TOKEN_ENDPOINT

        slow_resp = _mock_response(400, {"error": "slow_down"})
        success_resp = _mock_response(200, _TOKEN_SUCCESS)

        with patch("urllib3.PoolManager") as MockPM, patch("time.sleep") as mock_sleep:
            mock_http = MockPM.return_value
            mock_http.request.side_effect = [slow_resp, success_resp]
            flow._poll_for_token(
                device_code="device-code-abc123",
                interval=5,
                expires_in=60,
            )
            # After slow_down, interval should have been bumped (5 + 5 = 10).
            # Verify sleep was called with the increased interval.
            sleep_args = [c.args[0] for c in mock_sleep.call_args_list]
            assert any(s >= 10 for s in sleep_args)


# ---------------------------------------------------------------------------
# Credential storage
# ---------------------------------------------------------------------------


class TestCredentialStorage:
    """Persisting tokens to disk."""

    def test_save_credentials_writes_file(self, tmp_path):
        cred_path = tmp_path / ".gnat" / "credentials.json"
        # Directly call the static method after patching the module-level path.
        with patch("gnat.auth.device_code._CREDENTIALS_PATH", cred_path):
            DeviceCodeFlow._save_credentials(_TOKEN_SUCCESS)

        assert cred_path.exists()
        data = json.loads(cred_path.read_text())
        assert data["access_token"] == "eyJ-access-token"

    def test_save_credentials_creates_parent_dir(self, tmp_path):
        cred_path = tmp_path / "deep" / "nested" / "credentials.json"
        with patch("gnat.auth.device_code._CREDENTIALS_PATH", cred_path):
            DeviceCodeFlow._save_credentials(_TOKEN_SUCCESS)

        assert cred_path.parent.is_dir()
        assert cred_path.exists()

    def test_save_credentials_sets_permissions(self, tmp_path):
        cred_path = tmp_path / ".gnat" / "credentials.json"
        with patch("gnat.auth.device_code._CREDENTIALS_PATH", cred_path):
            DeviceCodeFlow._save_credentials(_TOKEN_SUCCESS)

        mode = oct(cred_path.stat().st_mode & 0o777)
        assert mode == "0o600"

    def test_load_credentials_returns_none_when_missing(self, tmp_path):
        cred_path = tmp_path / "nonexistent" / "credentials.json"
        with patch("gnat.auth.device_code._CREDENTIALS_PATH", cred_path):
            result = DeviceCodeFlow.load_credentials()
        assert result is None

    def test_load_credentials_returns_data(self, tmp_path):
        cred_path = tmp_path / ".gnat" / "credentials.json"
        cred_path.parent.mkdir(parents=True)
        cred_path.write_text(json.dumps(_TOKEN_SUCCESS))
        with patch("gnat.auth.device_code._CREDENTIALS_PATH", cred_path):
            result = DeviceCodeFlow.load_credentials()
        assert result is not None
        assert result["access_token"] == "eyJ-access-token"

    def test_load_credentials_returns_none_on_bad_json(self, tmp_path):
        cred_path = tmp_path / ".gnat" / "credentials.json"
        cred_path.parent.mkdir(parents=True)
        cred_path.write_text("not-json{{{")
        with patch("gnat.auth.device_code._CREDENTIALS_PATH", cred_path):
            result = DeviceCodeFlow.load_credentials()
        assert result is None

    def test_clear_credentials_removes_file(self, tmp_path):
        cred_path = tmp_path / ".gnat" / "credentials.json"
        cred_path.parent.mkdir(parents=True)
        cred_path.write_text("{}")
        with patch("gnat.auth.device_code._CREDENTIALS_PATH", cred_path):
            DeviceCodeFlow.clear_credentials()
        assert not cred_path.exists()

    def test_clear_credentials_noop_when_missing(self, tmp_path):
        cred_path = tmp_path / "nope" / "credentials.json"
        with patch("gnat.auth.device_code._CREDENTIALS_PATH", cred_path):
            # Should not raise.
            DeviceCodeFlow.clear_credentials()


# ---------------------------------------------------------------------------
# Full authenticate() flow
# ---------------------------------------------------------------------------


class TestAuthenticateIntegration:
    """End-to-end authenticate() with all HTTP mocked."""

    def test_authenticate_returns_token(self, tmp_path):
        flow = _make_flow()
        cred_path = tmp_path / ".gnat" / "credentials.json"

        disco_resp = _mock_response(200, _OIDC_DISCOVERY)
        device_resp = _mock_response(200, _DEVICE_CODE_RESPONSE)
        # Discovery is fetched again inside _poll_for_token (separate
        # urllib3.PoolManager instance), so we provide it twice plus
        # the token success.
        token_resp = _mock_response(200, _TOKEN_SUCCESS)

        with (
            patch("urllib3.PoolManager") as MockPM,
            patch("time.sleep"),
            patch("gnat.auth.device_code._CREDENTIALS_PATH", cred_path),
            patch("builtins.print"),
        ):  # suppress interactive output
            mock_http = MockPM.return_value
            mock_http.request.side_effect = [disco_resp, device_resp, token_resp]
            result = flow.authenticate()

        assert result["access_token"] == "eyJ-access-token"
        assert cred_path.exists()

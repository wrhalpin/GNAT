# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.auth.device_code
======================

OAuth 2.0 Device Authorization Grant (RFC 8628) for CLI authentication.

This flow allows terminal users to authenticate via their browser
without embedding a web server in the CLI::

    from gnat.auth.device_code import DeviceCodeFlow

    flow = DeviceCodeFlow(
        issuer="https://your-tenant.okta.com",
        client_id="0oa...",
        scopes=["openid", "profile", "email", "groups"],
    )

    result = flow.authenticate()
    # User sees: "Visit https://... and enter code: ABCD-1234"
    # After browser auth completes:
    print(result["access_token"])
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_CREDENTIALS_PATH = Path.home() / ".gnat" / "credentials.json"


class DeviceCodeError(Exception):
    """Raised when the device code flow fails."""


class DeviceCodeFlow:
    """
    OAuth 2.0 Device Authorization Grant for CLI login.

    Parameters
    ----------
    issuer : str
        OIDC issuer URL.
    client_id : str
        OAuth2 client ID.
    scopes : list of str
        OAuth2 scopes to request.
    """

    def __init__(
        self,
        issuer: str,
        client_id: str,
        scopes: list[str] | None = None,
    ) -> None:
        self._issuer = issuer.rstrip("/")
        self._client_id = client_id
        self._scopes = scopes or ["openid", "profile", "email", "groups"]
        self._device_authorization_endpoint: str | None = None
        self._token_endpoint: str | None = None

    def authenticate(self) -> dict[str, Any]:
        """
        Run the device code flow interactively.

        Prints the verification URI and user code to stdout, then polls
        the token endpoint until the user completes browser authentication.

        Returns
        -------
        dict
            Token response with ``access_token``, ``id_token`` (if present),
            ``token_type``, ``expires_in``.

        Raises
        ------
        DeviceCodeError
            If the flow fails (expired, denied, or network error).
        """
        self._discover_endpoints()
        device_resp = self._request_device_code()

        verification_uri = device_resp.get(
            "verification_uri_complete",
            device_resp.get("verification_uri", ""),
        )
        user_code = device_resp.get("user_code", "")
        device_code = device_resp.get("device_code", "")
        interval = device_resp.get("interval", 5)
        expires_in = device_resp.get("expires_in", 600)

        print()
        print(f"  Visit:  {verification_uri}")
        print(f"  Code:   {user_code}")
        print()
        print("  Waiting for browser authentication...")

        token_resp = self._poll_for_token(device_code, interval, expires_in)
        self._save_credentials(token_resp)
        return token_resp

    def _discover_endpoints(self) -> None:
        import urllib3

        http = urllib3.PoolManager(timeout=urllib3.Timeout(connect=10, read=10))
        url = f"{self._issuer}/.well-known/openid-configuration"
        resp = http.request("GET", url)
        if resp.status != 200:
            raise DeviceCodeError(f"OIDC discovery failed: HTTP {resp.status}")
        config = json.loads(resp.data.decode("utf-8"))

        self._device_authorization_endpoint = config.get("device_authorization_endpoint")
        self._token_endpoint = config.get("token_endpoint")

        if not self._device_authorization_endpoint:
            raise DeviceCodeError(
                "IdP does not support device authorization grant "
                f"(no device_authorization_endpoint in {url})"
            )
        if not self._token_endpoint:
            raise DeviceCodeError("No token_endpoint in OIDC discovery document")

    def _request_device_code(self) -> dict[str, Any]:
        import urllib3

        http = urllib3.PoolManager(timeout=urllib3.Timeout(connect=10, read=10))
        body = (
            f"client_id={self._client_id}"
            f"&scope={'+'.join(self._scopes)}"
        )
        resp = http.request(
            "POST",
            self._device_authorization_endpoint,
            body=body.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status != 200:
            raise DeviceCodeError(
                f"Device code request failed: HTTP {resp.status} — {resp.data.decode()}"
            )
        return json.loads(resp.data.decode("utf-8"))

    def _poll_for_token(
        self,
        device_code: str,
        interval: int,
        expires_in: int,
    ) -> dict[str, Any]:
        import urllib3

        http = urllib3.PoolManager(timeout=urllib3.Timeout(connect=10, read=10))
        deadline = time.monotonic() + expires_in

        while time.monotonic() < deadline:
            time.sleep(interval)
            body = (
                f"grant_type=urn:ietf:params:oauth:grant-type:device_code"
                f"&device_code={device_code}"
                f"&client_id={self._client_id}"
            )
            resp = http.request(
                "POST",
                self._token_endpoint,
                body=body.encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            data = json.loads(resp.data.decode("utf-8"))

            if resp.status == 200:
                return data

            error = data.get("error", "")
            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval = min(interval + 5, 30)
                continue
            if error in ("expired_token", "access_denied"):
                raise DeviceCodeError(f"Device code flow failed: {error}")
            raise DeviceCodeError(
                f"Unexpected token response: {resp.status} {data}"
            )

        raise DeviceCodeError("Device code expired — user did not complete authentication")

    @staticmethod
    def _save_credentials(token_resp: dict[str, Any]) -> None:
        cred_path = _CREDENTIALS_PATH
        cred_path.parent.mkdir(parents=True, exist_ok=True)
        cred_path.write_text(json.dumps(token_resp, indent=2))
        os.chmod(cred_path, 0o600)
        logger.info("Credentials saved to %s", cred_path)

    @staticmethod
    def load_credentials() -> dict[str, Any] | None:
        if not _CREDENTIALS_PATH.exists():
            return None
        try:
            data = json.loads(_CREDENTIALS_PATH.read_text())
            return data if isinstance(data, dict) and "access_token" in data else None
        except (json.JSONDecodeError, OSError):
            return None

    @staticmethod
    def clear_credentials() -> None:
        if _CREDENTIALS_PATH.exists():
            _CREDENTIALS_PATH.unlink()

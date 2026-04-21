# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.security.secrets.providers.cyberark
===================================================

CyberArk Central Credential Provider (CCP) integration.

Resolves secrets from CyberArk via the CCP REST endpoint::

    GET https://<host>/AIMWebService/api/Accounts
        ?AppID=<app_id>&Safe=<safe>&Object=<object>

``describe()`` returns metadata without revealing the secret value.
Write operations are not supported — CCP is a read-only retrieval API;
use the PVWA REST API directly for vault management.

Configuration
-------------
Pass ``host``, ``app_id``, and optionally ``cert`` (path to client
certificate PEM file) when constructing the provider::

    provider = CyberArkProvider(
        host="https://cyberark.corp.example.com",
        app_id="GNAT",
        cert="/etc/gnat/cyberark-client.pem",
    )
"""

from __future__ import annotations

import json
import logging
import urllib.parse
from datetime import datetime, timezone
from typing import Any

from ..exceptions import SecretProviderError, UnsupportedProviderAction
from ..models import (
    ProviderCapabilities,
    SecretLease,
    SecretMetadata,
    SecretRef,
    SecretValue,
    SecretVersionInfo,
    StoreSecretRequest,
)

logger = logging.getLogger(__name__)

_CCP_PATH = "/AIMWebService/api/Accounts"


class CyberArkProvider:
    """
    CyberArk Central Credential Provider (CCP) secret provider.

    Supports read and checkout operations via the CCP REST endpoint.
    Write operations are not available through CCP; use the PVWA API
    for vault management tasks.

    Parameters
    ----------
    host : str
        Base URL of the CCP server, e.g. ``"https://cyberark.corp.example.com"``.
    app_id : str
        Application ID registered in CyberArk for GNAT.
    cert : str or None
        Path to a client certificate PEM file for mutual TLS.  Required
        when the CCP is configured to authenticate callers by certificate.
    timeout : float
        HTTP request timeout in seconds.  Defaults to 10.
    """

    name = "cyberark"

    def __init__(
        self,
        host: str = "",
        app_id: str = "GNAT",
        cert: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        """Initialize CyberArkProvider."""
        self._host = host.rstrip("/")
        self._app_id = app_id
        self._cert = cert
        self._timeout = timeout
        self._pool: Any = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_pool(self) -> Any:
        """Lazy-initialise a urllib3 connection pool."""
        if self._pool is None:
            import urllib3

            if self._cert:
                self._pool = urllib3.HTTPSConnectionPool(
                    self._host.split("://", 1)[-1],
                    cert_file=self._cert,
                    key_file=self._cert,
                )
            else:
                self._pool = urllib3.PoolManager()
        return self._pool

    def _ccp_request(self, safe: str, object_name: str) -> dict[str, Any]:
        """
        Call the CCP REST endpoint and return the parsed JSON response.

        Raises
        ------
        SecretProviderError
            On HTTP errors or missing required fields in the response.
        """
        if not self._host:
            raise SecretProviderError("CyberArkProvider requires host to be set")

        params = urllib.parse.urlencode(
            {"AppID": self._app_id, "Safe": safe, "Object": object_name}
        )
        url = f"{self._host}{_CCP_PATH}?{params}"

        try:
            pool = self._get_pool()
            resp = pool.request("GET", url, timeout=self._timeout)
        except Exception as exc:
            raise SecretProviderError(f"CyberArk CCP request failed: {exc}") from exc

        if resp.status != 200:
            body = resp.data.decode("utf-8", errors="replace")
            raise SecretProviderError(f"CyberArk CCP returned HTTP {resp.status}: {body[:256]}")

        try:
            return json.loads(resp.data)
        except json.JSONDecodeError as exc:
            raise SecretProviderError(f"CyberArk CCP response is not valid JSON: {exc}") from exc

    @staticmethod
    def _parse_ts(value: str | None) -> datetime | None:
        """Parse an ISO-8601 or Unix-epoch timestamp from CCP, or return None."""
        if not value:
            return None
        try:
            # CCP may return Unix epoch as an integer string
            return datetime.fromtimestamp(int(value), tz=timezone.utc)
        except (ValueError, TypeError):
            pass
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    # ------------------------------------------------------------------
    # Provider interface
    # ------------------------------------------------------------------

    def capabilities(self) -> ProviderCapabilities:
        """Capabilities — CCP supports read and checkout; write is not available."""
        return ProviderCapabilities(
            supports_read=True,
            supports_write=False,
            supports_rotation=True,
            supports_checkout=True,
        )

    def resolve(self, ref: SecretRef) -> SecretValue:
        """
        Retrieve the secret value from CyberArk CCP.

        Parameters
        ----------
        ref : SecretRef
            ``ref.vault`` is used as the CyberArk Safe name.
            ``ref.path`` is used as the CyberArk Object name.

        Raises
        ------
        SecretProviderError
            If ``ref.vault`` is not set or the CCP call fails.
        """
        if not ref.vault:
            raise SecretProviderError("CyberArkProvider.resolve() requires ref.vault (Safe name)")

        data = self._ccp_request(safe=ref.vault, object_name=ref.path)
        secret_value = data.get("Content") or data.get("Password") or data.get("Value")
        if secret_value is None:
            raise SecretProviderError("CyberArk CCP response missing Content/Password/Value field")

        metadata = SecretMetadata(
            path=ref.path,
            provider=self.name,
            vault=ref.vault,
            version=data.get("PolicyID") or data.get("Version"),
            tags={
                k: str(v)
                for k, v in data.items()
                if k not in {"Content", "Password", "Value"} and isinstance(v, (str, int, float))
            },
            created_at=self._parse_ts(data.get("CreationDate")),
            updated_at=self._parse_ts(data.get("LastModifiedDate") or data.get("ModificationDate")),
        )

        return SecretValue(
            ref=SecretRef(
                provider=self.name,
                vault=ref.vault,
                path=ref.path,
                version=metadata.version,
            ),
            value=str(secret_value),
            metadata=metadata,
        )

    def store(self, request: StoreSecretRequest) -> SecretVersionInfo:
        """
        Not supported — CCP is a read-only retrieval interface.

        Use the CyberArk PVWA REST API for write operations.

        Raises
        ------
        UnsupportedProviderAction
            Always.
        """
        raise UnsupportedProviderAction(
            "CyberArkProvider does not support write operations via CCP. "
            "Use the PVWA REST API (/PasswordVault/api/Accounts) for vault management."
        )

    def describe(self, ref: SecretRef) -> SecretMetadata:
        """
        Return metadata for a CyberArk account object without exposing the value.

        Makes a CCP request and strips the secret value from the response,
        returning only account metadata (safe, policy, timestamps, custom properties).

        Parameters
        ----------
        ref : SecretRef
            ``ref.vault`` is the Safe name; ``ref.path`` is the Object name.

        Raises
        ------
        SecretProviderError
            If ``ref.vault`` is not set or the CCP call fails.
        """
        if not ref.vault:
            raise SecretProviderError("CyberArkProvider.describe() requires ref.vault (Safe name)")

        data = self._ccp_request(safe=ref.vault, object_name=ref.path)

        # Strip sensitive fields before building metadata
        safe_data = {
            k: str(v)
            for k, v in data.items()
            if k not in {"Content", "Password", "Value"} and isinstance(v, (str, int, float))
        }

        return SecretMetadata(
            path=ref.path,
            provider=self.name,
            vault=ref.vault,
            version=data.get("PolicyID") or data.get("Version"),
            tags=safe_data,
            created_at=self._parse_ts(data.get("CreationDate")),
            updated_at=self._parse_ts(data.get("LastModifiedDate") or data.get("ModificationDate")),
        )

    def list_refs(self, prefix: str | None = None) -> list[SecretRef]:
        """
        List is not supported via CCP — returns empty list.

        CCP is object-level retrieval only; Safe enumeration requires
        the PVWA Safes API.
        """
        logger.debug("CyberArkProvider.list_refs() is not implemented via CCP; returning []")
        return []

    def checkout(self, ref: SecretRef) -> SecretLease | None:
        """
        Check out an exclusive-use account from CyberArk (CPM managed).

        This calls CCP with the standard retrieval endpoint; CyberArk
        automatically records the checkout when the account policy requires
        exclusive access.  Returns a :class:`~..models.SecretLease` populated
        from the response, or ``None`` if the account does not require checkout.

        Raises
        ------
        SecretProviderError
            If ``ref.vault`` is not set or the CCP call fails.
        """
        if not ref.vault:
            raise SecretProviderError("CyberArkProvider.checkout() requires ref.vault (Safe name)")

        data = self._ccp_request(safe=ref.vault, object_name=ref.path)
        secret_value = data.get("Content") or data.get("Password") or data.get("Value")
        if secret_value is None:
            return None

        return SecretLease(
            ref=SecretRef(
                provider=self.name,
                vault=ref.vault,
                path=ref.path,
                version=data.get("PolicyID") or data.get("Version"),
            ),
            secret=str(secret_value),
            username=data.get("UserName") or data.get("Username"),
            lease_id=data.get("RequestId") or data.get("TicketID"),
            expires_at=self._parse_ts(data.get("ExpirationDate")),
            metadata={
                k: str(v)
                for k, v in data.items()
                if k not in {"Content", "Password", "Value"} and isinstance(v, (str, int, float))
            },
        )

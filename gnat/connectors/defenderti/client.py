"""
gnat.connectors.defenderti.client
=====================================
Microsoft Defender Threat Intelligence (MSTI) connector.

Uses the Microsoft Graph Security API ``tiIndicators`` endpoint.
Authentication follows the same Azure AD OAuth2 ``client_credentials``
pattern as the Sentinel connector.

INI config::

    [defenderti]
    host          = https://graph.microsoft.com
    tenant_id     = YOUR_TENANT_ID
    client_id     = YOUR_APP_CLIENT_ID
    client_secret = YOUR_APP_CLIENT_SECRET
    auth_type     = oauth2

Required Azure AD app permissions (application, not delegated):

* ``ThreatIndicators.ReadWrite.OwnedBy``  (MS Graph)

References
----------
https://learn.microsoft.com/en-us/graph/api/resources/tiindicator
"""

import json as _json
import urllib.parse
from typing import Any, Optional

import urllib3

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_GRAPH = "https://graph.microsoft.com"
_LOGIN = "https://login.microsoftonline.com"
_SCOPE = "https://graph.microsoft.com/.default"
_TI = "/v1.0/security/tiIndicators"


class DefenderTIClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Microsoft Defender Threat Intelligence via MS Graph.

    Parameters
    ----------
    host : str
        Graph API base URL.  Default ``https://graph.microsoft.com``.
    tenant_id : str
        Azure AD tenant ID (directory ID).
    client_id : str
        Service principal application (client) ID.
    client_secret : str
        Service principal client secret.
    """

    stix_type_map: dict[str, str] = {
        "indicator": "tiIndicators",
        "threat-actor": "tiIndicators",
        "malware": "tiIndicators",
    }

    def __init__(
        self,
        host: str = _GRAPH,
        tenant_id: str = "",
        client_id: str = "",
        client_secret: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret

    # ------------------------------------------------------------------
    # ConnectorMixin interface
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """
        Obtain an Azure AD Bearer token via ``client_credentials`` grant.

        Posts directly to ``login.microsoftonline.com`` via urllib3 so the
        Graph base URL is unaffected.
        """
        url = f"{_LOGIN}/{self._tenant_id}/oauth2/v2.0/token"
        body = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": _SCOPE,
            }
        ).encode("utf-8")

        http = urllib3.PoolManager(timeout=urllib3.Timeout(connect=10.0, read=30.0))
        response = http.request(
            "POST",
            url,
            body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            data = _json.loads(response.data.decode("utf-8"))  # type: ignore[union-attr]
        except Exception:
            data = {}

        token = data.get("access_token")
        if not token:
            raise GNATClientError("DefenderTI: failed to obtain Azure AD access token")
        self._auth_headers["Authorization"] = f"Bearer {token}"
        self._auth_headers["Content-Type"] = "application/json"

    def health_check(self) -> bool:
        """Verify Graph connectivity with a minimal tiIndicators query."""
        resp = self.get(_TI, params={"$top": 1})
        return isinstance(resp, dict) and "value" in resp

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve a TI indicator by its Graph object ID."""
        resp = self.get(f"{_TI}/{object_id}")
        return resp if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List TI indicators.

        ``filters`` may include:

        * ``$filter`` (str): OData filter expression,
          e.g. ``"threatType eq 'Malware'"``
        * ``$search`` (str): OData search expression
        """
        params: dict[str, Any] = {"$top": min(page_size, 1000)}
        if page > 1:
            params["$skip"] = (page - 1) * page_size
        if filters:
            params.update(filters)

        resp = self.get(_TI, params=params)
        if not isinstance(resp, dict):
            return []
        return resp.get("value", [])

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Create or update a TI indicator in MS Graph.

        If ``payload`` contains ``"id"`` (a Graph object ID) the indicator
        is updated via ``PATCH``; otherwise it is created via ``POST``.
        """
        obj_id = payload.pop("id", None)
        if obj_id:
            resp = self.patch(f"{_TI}/{obj_id}", json=payload)
        else:
            resp = self.post(_TI, json=payload)
        return resp if isinstance(resp, dict) else {}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete a TI indicator by its Graph object ID."""
        self.delete(f"{_TI}/{object_id}")

    # ------------------------------------------------------------------
    # STIX translation
    # ------------------------------------------------------------------

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Graph ``tiIndicator`` object to a STIX Indicator SDO."""
        value = (
            native.get("networkIPv4")
            or native.get("domainName")
            or native.get("url")
            or native.get("fileHashValue")
            or native.get("emailSenderAddress")
            or ""
        )
        pattern = self._make_pattern(native, value)
        conf = native.get("confidence", 0)
        return {
            "type": "indicator",
            "id": f"indicator--msti-{native.get('id', '')}",
            "name": value or native.get("description", "")[:80],
            "description": native.get("description", "")[:500],
            "pattern": pattern,
            "pattern_type": "stix",
            "created": native.get("createdDateTime", ""),
            "modified": native.get("lastReportedDateTime", ""),
            "confidence": conf,
            "indicator_types": [native.get("threatType", "unknown").lower()],
            "x_source_platform": "defenderti",
            "x_msti_id": native.get("id", ""),
            "x_msti_action": native.get("action", ""),
            "x_msti_tlp": native.get("tlpLevel", ""),
            "x_target_sectors": native.get("targetProduct", [])
            if isinstance(native.get("targetProduct"), list)
            else [],
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Build a Graph ``tiIndicator`` POST payload from a STIX Indicator."""
        import re

        pattern = stix_dict.get("pattern", "")
        m = re.search(r"= '([^']+)'", pattern)
        value = m.group(1) if m else stix_dict.get("name", "")
        payload = self._stix_pattern_to_ti_payload(pattern, value)
        payload.update(
            {
                "action": "alert",
                "confidence": stix_dict.get("confidence", 0),
                "description": stix_dict.get("description", stix_dict.get("name", ""))[:500],
                "tlpLevel": "white",
                "targetProduct": "Microsoft Defender ATP",
            }
        )
        return payload

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_pattern(native: dict[str, Any], value: str) -> str:
        if native.get("networkIPv4"):
            return f"[ipv4-addr:value = '{native['networkIPv4']}']"
        if native.get("networkIPv6"):
            return f"[ipv6-addr:value = '{native['networkIPv6']}']"
        if native.get("domainName"):
            return f"[domain-name:value = '{native['domainName']}']"
        if native.get("url"):
            return f"[url:value = '{native['url']}']"
        if native.get("fileHashValue"):
            htype = native.get("fileHashType", "sha256").upper()
            return f"[file:hashes.'{htype}' = '{native['fileHashValue']}']"
        if native.get("emailSenderAddress"):
            return f"[email-message:from_ref.value = '{native['emailSenderAddress']}']"
        return f"[domain-name:value = '{value}']"

    @staticmethod
    def _stix_pattern_to_ti_payload(pattern: str, value: str) -> dict[str, Any]:
        if "ipv4-addr" in pattern:
            return {"networkIPv4": value}
        if "ipv6-addr" in pattern:
            return {"networkIPv6": value}
        if "domain-name" in pattern:
            return {"domainName": value}
        if "url:" in pattern:
            return {"url": value}
        if "SHA-256" in pattern:
            return {"fileHashType": "sha256", "fileHashValue": value}
        if "SHA-1" in pattern:
            return {"fileHashType": "sha1", "fileHashValue": value}
        if "MD5" in pattern:
            return {"fileHashType": "md5", "fileHashValue": value}
        if "email" in pattern:
            return {"emailSenderAddress": value}
        return {"domainName": value}

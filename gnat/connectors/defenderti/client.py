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

    # ── TI Indicators (enhanced) ──────────────────────────────────────────────

    def list_indicators(
        self,
        filter_expr: str = "",
        top: int = 100,
        skip: int = 0,
        select: str = "",
    ) -> list[dict[str, Any]]:
        """
        List threat indicators with optional OData filtering.

        Parameters
        ----------
        filter_expr : str
            OData ``$filter`` expression, e.g.
            ``"threatType eq 'Malware' and confidence ge 75"``.
        select : str
            Comma-separated field list for ``$select``.
        """
        params: dict[str, Any] = {"$top": min(top, 1000), "$skip": skip}
        if filter_expr:
            params["$filter"] = filter_expr
        if select:
            params["$select"] = select
        resp = self.get(_TI, params=params)
        return resp.get("value", []) if isinstance(resp, dict) else []

    def get_indicator(self, indicator_id: str) -> dict[str, Any]:
        """Retrieve a single TI indicator by Graph object ID."""
        resp = self.get(f"{_TI}/{indicator_id}")
        return resp if isinstance(resp, dict) else {}

    def create_indicator(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Create a new TI indicator.

        Required fields: ``action``, ``expirationDateTime``,
        ``targetProduct``, and at least one observable
        (``networkIPv4``, ``domainName``, ``url``, ``fileHashValue``, etc.).
        """
        resp = self.post(_TI, json=payload)
        return resp if isinstance(resp, dict) else {}

    def update_indicator(
        self, indicator_id: str, updates: dict[str, Any]
    ) -> dict[str, Any]:
        """Update an existing TI indicator by ID (PATCH)."""
        resp = self.patch(f"{_TI}/{indicator_id}", json=updates)
        return resp if isinstance(resp, dict) else {}

    def bulk_create_indicators(
        self, indicators: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        Submit multiple indicators in a single batch POST.

        Uses ``POST /v1.0/security/tiIndicators/submitTiIndicators``.
        Each indicator in ``indicators`` must be a full indicator payload dict.
        """
        resp = self.post(
            "/v1.0/security/tiIndicators/submitTiIndicators",
            json={"value": indicators},
        )
        return resp.get("value", []) if isinstance(resp, dict) else []

    def bulk_update_indicators(
        self, indicator_updates: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        Batch update multiple indicators.

        Each item in ``indicator_updates`` must include ``"id"`` plus the
        fields to update.
        """
        resp = self.post(
            "/v1.0/security/tiIndicators/updateTiIndicators",
            json={"value": indicator_updates},
        )
        return resp.get("value", []) if isinstance(resp, dict) else []

    def bulk_delete_indicators(self, indicator_ids: list[str]) -> dict[str, Any]:
        """Delete multiple TI indicators by ID in one batch request."""
        resp = self.post(
            "/v1.0/security/tiIndicators/deleteTiIndicators",
            json={"value": indicator_ids},
        )
        return resp if isinstance(resp, dict) else {}

    # ── Defender TI — Threat Intelligence articles ────────────────────────────

    def list_articles(
        self,
        top: int = 50,
        filter_expr: str = "",
        search: str = "",
    ) -> list[dict[str, Any]]:
        """
        List Microsoft Defender TI intelligence articles.

        Requires ``ThreatIntelligence.Read.All`` Graph permission.
        """
        params: dict[str, Any] = {"$top": min(top, 100)}
        if filter_expr:
            params["$filter"] = filter_expr
        if search:
            params["$search"] = search
        resp = self.get("/v1.0/security/threatIntelligence/articles", params=params)
        return resp.get("value", []) if isinstance(resp, dict) else []

    def get_article(self, article_id: str) -> dict[str, Any]:
        """Retrieve a specific Defender TI intelligence article."""
        resp = self.get(f"/v1.0/security/threatIntelligence/articles/{article_id}")
        return resp if isinstance(resp, dict) else {}

    def get_article_indicators(self, article_id: str) -> list[dict[str, Any]]:
        """List IOC indicators mentioned in a Defender TI article."""
        resp = self.get(
            f"/v1.0/security/threatIntelligence/articles/{article_id}/indicators"
        )
        return resp.get("value", []) if isinstance(resp, dict) else []

    # ── Defender TI — Host intelligence ──────────────────────────────────────

    def get_host(self, hostname: str) -> dict[str, Any]:
        """
        Retrieve Defender TI host intelligence for a hostname or IP.

        Returns reputation, first seen, last seen, and risk score.
        """
        resp = self.get(
            "/v1.0/security/threatIntelligence/hosts",
            params={"$filter": f"id eq '{hostname}'"},
        )
        items = resp.get("value", []) if isinstance(resp, dict) else []
        return items[0] if items else {}

    def get_host_trackers(self, host_id: str) -> list[dict[str, Any]]:
        """Get web trackers (Google Analytics, Facebook Pixel, etc.) for a host."""
        resp = self.get(
            f"/v1.0/security/threatIntelligence/hosts/{host_id}/trackers"
        )
        return resp.get("value", []) if isinstance(resp, dict) else []

    def get_host_components(self, host_id: str) -> list[dict[str, Any]]:
        """Get web technology components detected on a host."""
        resp = self.get(
            f"/v1.0/security/threatIntelligence/hosts/{host_id}/components"
        )
        return resp.get("value", []) if isinstance(resp, dict) else []

    def get_host_cookies(self, host_id: str) -> list[dict[str, Any]]:
        """Get cookies observed on a host."""
        resp = self.get(
            f"/v1.0/security/threatIntelligence/hosts/{host_id}/cookies"
        )
        return resp.get("value", []) if isinstance(resp, dict) else []

    def get_host_ssl_certificates(self, host_id: str) -> list[dict[str, Any]]:
        """Get SSL/TLS certificates associated with a host."""
        resp = self.get(
            f"/v1.0/security/threatIntelligence/hosts/{host_id}/sslCertificates"
        )
        return resp.get("value", []) if isinstance(resp, dict) else []

    def get_host_resolutions(self, host_id: str) -> list[dict[str, Any]]:
        """Get passive DNS resolution records for a host."""
        resp = self.get(
            f"/v1.0/security/threatIntelligence/hosts/{host_id}/resolutions"
        )
        return resp.get("value", []) if isinstance(resp, dict) else []

    def get_host_subdomains(self, host_id: str) -> list[dict[str, Any]]:
        """Get known subdomains of a host."""
        resp = self.get(
            f"/v1.0/security/threatIntelligence/hosts/{host_id}/subdomains"
        )
        return resp.get("value", []) if isinstance(resp, dict) else []

    # ── Defender TI — SSL Certificates ───────────────────────────────────────

    def get_ssl_certificate(self, cert_id: str) -> dict[str, Any]:
        """Retrieve details for a specific SSL certificate by fingerprint."""
        resp = self.get(
            f"/v1.0/security/threatIntelligence/sslCertificates/{cert_id}"
        )
        return resp if isinstance(resp, dict) else {}

    def get_ssl_certificate_hosts(self, cert_id: str) -> list[dict[str, Any]]:
        """List hosts that have used a specific SSL certificate."""
        resp = self.get(
            f"/v1.0/security/threatIntelligence/sslCertificates/{cert_id}/relatedHosts"
        )
        return resp.get("value", []) if isinstance(resp, dict) else []

    # ── Defender TI — WHOIS ───────────────────────────────────────────────────

    def get_whois_record(self, host_id: str) -> dict[str, Any]:
        """Retrieve the WHOIS registration record for a domain."""
        resp = self.get(
            f"/v1.0/security/threatIntelligence/hosts/{host_id}/whois"
        )
        return resp if isinstance(resp, dict) else {}

    def search_whois_by_registrant(self, registrant: str, top: int = 20) -> list[dict[str, Any]]:
        """
        Search WHOIS records by registrant name or email.

        Returns domains registered by or containing the given string.
        """
        resp = self.get(
            "/v1.0/security/threatIntelligence/whoisRecords",
            params={
                "$filter": f"contains(registrant/email, '{registrant}')",
                "$top": top,
            },
        )
        return resp.get("value", []) if isinstance(resp, dict) else []

    # ── Defender TI — Vulnerability intelligence ──────────────────────────────

    def get_vulnerability(self, cve_id: str) -> dict[str, Any]:
        """
        Retrieve Defender TI intelligence for a CVE.

        Returns CVSS scores, affected components, exploitation status,
        and related indicators and articles.
        """
        resp = self.get(
            f"/v1.0/security/threatIntelligence/vulnerabilities/{cve_id}"
        )
        return resp if isinstance(resp, dict) else {}

    def get_vulnerability_components(self, cve_id: str) -> list[dict[str, Any]]:
        """List affected software components for a vulnerability."""
        resp = self.get(
            f"/v1.0/security/threatIntelligence/vulnerabilities/{cve_id}/components"
        )
        return resp.get("value", []) if isinstance(resp, dict) else []

    def get_vulnerability_articles(self, cve_id: str) -> list[dict[str, Any]]:
        """List Defender TI articles mentioning a vulnerability."""
        resp = self.get(
            f"/v1.0/security/threatIntelligence/vulnerabilities/{cve_id}/articles"
        )
        return resp.get("value", []) if isinstance(resp, dict) else []

    # ── Defender TI — Intelligence profiles (threat actors) ──────────────────

    def list_intelligence_profiles(
        self,
        kind: str = "",
        top: int = 50,
    ) -> list[dict[str, Any]]:
        """
        List Defender TI threat actor intelligence profiles.

        ``kind`` filter options: ``"actor"``, ``"tool"``.
        """
        params: dict[str, Any] = {"$top": min(top, 100)}
        if kind:
            params["$filter"] = f"kind eq '{kind}'"
        resp = self.get(
            "/v1.0/security/threatIntelligence/intelligenceProfiles",
            params=params,
        )
        return resp.get("value", []) if isinstance(resp, dict) else []

    def get_intelligence_profile(self, profile_id: str) -> dict[str, Any]:
        """Retrieve a specific Defender TI intelligence profile."""
        resp = self.get(
            f"/v1.0/security/threatIntelligence/intelligenceProfiles/{profile_id}"
        )
        return resp if isinstance(resp, dict) else {}

    def get_profile_indicators(self, profile_id: str) -> list[dict[str, Any]]:
        """List IOC indicators associated with a Defender TI intelligence profile."""
        resp = self.get(
            f"/v1.0/security/threatIntelligence/intelligenceProfiles/{profile_id}/indicators"
        )
        return resp.get("value", []) if isinstance(resp, dict) else []

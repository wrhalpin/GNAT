"""
gnat.connectors.elastic.auth

Authentication manager for the Elastic Security connector.

## Elastic API Key Authentication

Unlike Splunk (session key) and Wazuh (JWT with expiry), Elastic uses
static API keys that do not expire unless explicitly configured to do so
at creation time (`expiration` field).

The API key header format is:
Authorization: ApiKey <base64(id:secret)>

This is distinct from Basic Auth (base64(user:password)) even though
both are base64-encoded -- the prefix "ApiKey" vs "Basic" disambiguates.

## API key privileges

For GNAT's full connector surface the API key needs:

Cluster privileges:
- monitor (health, info)

Index privileges on .alerts-security.*, logs-ti_*, logs-*:
- read, view_index_metadata

Kibana privileges (via role assigned to key):
- Security: All
- Cases: All

## Key rotation

Elastic does not provide a refresh flow for API keys.
If a key is revoked or expires, the connector raises ElasticAuthError
and the key must be replaced in gnat.ini manually.

WazuhAuthManager pattern note: there is no equivalent token-renewal
loop here. The auth object is intentionally lightweight -- it just
encapsulates header construction and provides a verify() method for
connectivity testing.

## References

- https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html
- https://www.elastic.co/guide/en/kibana/current/api-keys.html
  """

import json

import urllib3

from .config import ElasticConfig
from .exceptions import ElasticAuthError


class ElasticAuthManager:
    """
    Manages Elastic API key authentication.

    API keys are static -- no renewal loop is needed. This class
    provides a thin wrapper for header construction and a verify()
    method that tests connectivity against the ES cluster info endpoint.

    Parameters
    ----------
    config : ElasticConfig
        Validated connector configuration.
    http : urllib3.PoolManager
        Shared connection pool (owned by ElasticClient).
    """

    def __init__(self, config: ElasticConfig, http: urllib3.PoolManager) -> None:
        self._config = config
        self._http = http

    # ── Public ─────────────────────────────────────────────────────────────

    def get_es_headers(self, extra: dict | None = None) -> dict[str, str]:
        """
        Return headers for an Elasticsearch API request.

        Parameters
        ----------
        extra : dict | None
            Additional headers to merge in.

        Returns
        -------
        dict[str, str]
            ``{"Authorization": "ApiKey ...", "Content-Type": "application/json"}``
        """
        headers = {
            **self._config.auth_headers,
            "Content-Type": "application/json",
        }
        if extra:
            headers.update(extra)
        return headers

    def get_kibana_headers(self, method: str = "POST") -> dict[str, str]:
        """
        Return headers for a Kibana API request.

        GET requests do not require ``kbn-xsrf``; all other verbs do.

        Parameters
        ----------
        method : str
            HTTP method ('GET', 'POST', 'PUT', 'PATCH', 'DELETE').

        Returns
        -------
        dict[str, str]
        """
        if method.upper() == "GET":
            return self._config.kibana_get_headers
        return self._config.kibana_headers

    def verify_es(self) -> dict:
        """
        Verify Elasticsearch connectivity by hitting the cluster info endpoint.

        Returns
        -------
        dict
            Cluster info response including name, version, cluster_uuid.

        Raises
        ------
        ElasticAuthError
            If authentication fails (401/403) or connection cannot be established.
        """
        url = self._config.es_url("")
        try:
            response = self._http.request(
                "GET",
                url,
                headers=self.get_es_headers(),
                timeout=self._config.timeout,
            )
        except urllib3.exceptions.HTTPError as exc:
            raise ElasticAuthError(
                f"Cannot connect to Elasticsearch at {url}: {exc}"
            ) from exc

        if response.status == 401:
            raise ElasticAuthError(
                "Elasticsearch API key authentication failed (HTTP 401). "
                "Check api_key_id and api_key_secret in [elastic] config."
            )
        if response.status == 403:
            raise ElasticAuthError(
                "Elasticsearch API key lacks required cluster privileges (HTTP 403)."
            )
        if response.status != 200:
            raise ElasticAuthError(
                f"Unexpected response from Elasticsearch: HTTP {response.status}"
            )

        try:
            return json.loads(response.data.decode("utf-8"))
        except Exception:
            return {}

    def verify_kibana(self) -> dict:
        """
        Verify Kibana connectivity by hitting the status API.

        Returns
        -------
        dict
            Kibana status info.

        Raises
        ------
        ElasticAuthError
            If authentication fails or Kibana is unreachable.
        """
        url = self._config.kibana_url("api/status")
        try:
            response = self._http.request(
                "GET",
                url,
                headers=self.get_kibana_headers("GET"),
                timeout=self._config.timeout,
            )
        except urllib3.exceptions.HTTPError as exc:
            raise ElasticAuthError(
                f"Cannot connect to Kibana at {url}: {exc}"
            ) from exc

        if response.status in (401, 403):
            raise ElasticAuthError(
                f"Kibana authentication failed (HTTP {response.status}). "
                "Ensure the API key has Kibana Security privileges."
            )
        if response.status != 200:
            raise ElasticAuthError(
                f"Unexpected response from Kibana: HTTP {response.status}"
            )

        try:
            return json.loads(response.data.decode("utf-8"))
        except Exception:
            return {}

    def get_api_key_info(self) -> dict:
        """
        Retrieve metadata about the current API key from Elasticsearch.

        Useful for checking expiry, privileges, and ownership.

        Returns
        -------
        dict
            API key info from GET /_security/api_key?id=<id>

        Raises
        ------
        ElasticAuthError
            If the key info cannot be retrieved.
        """
        url = self._config.es_url(f"_security/api_key?id={self._config.api_key_id}")
        try:
            response = self._http.request(
                "GET",
                url,
                headers=self.get_es_headers(),
                timeout=self._config.timeout,
            )
        except urllib3.exceptions.HTTPError as exc:
            raise ElasticAuthError(f"Failed to retrieve API key info: {exc}") from exc

        if response.status != 200:
            raise ElasticAuthError(
                f"Could not retrieve API key info: HTTP {response.status}"
            )
        try:
            body = json.loads(response.data.decode("utf-8"))
            keys = body.get("api_keys", [])
            return keys[0] if keys else {}
        except Exception:
            return {}

"""
gnat.connectors.splunk.client

Core HTTP client for the Splunk connector.

Wraps urllib3.PoolManager with:

- Automatic auth header injection via SplunkAuthManager
- JSON request/response handling
- Splunk-specific error parsing and exception mapping
- Retry logic with exponential backoff for transient errors
- output_mode=json enforcement on all requests
- Context manager support for connection lifecycle

## Splunk REST conventions

- Management port: 8089 (splunkd)
- All endpoints return JSON when `?output_mode=json` is appended
- POST bodies are `application/x-www-form-urlencoded` unless sending
  raw file content (threat intel upload uses multipart/form-data)
- Pagination: `count` + `offset` parameters; no cursor tokens
- Error body shape:
  {"messages": [{"type": "ERROR", "text": "…"}]}

## Usage

cfg = load_splunk_config(parser)
client = SplunkClient(cfg)
with client:
    jobs = client.get("search/jobs", params={"count": 10})

"""

import json
import re
import time
import urllib.parse
from typing import Any, Optional

import urllib3

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

from .auth import SplunkAuthManager
from .config import SplunkConfig
from .exceptions import (
    SplunkAPIError,
    SplunkAuthError,
    SplunkNotFoundError,
    SplunkRateLimitError,
)

# ── Retry configuration ───────────────────────────────────────────────────────

_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 1.0  # seconds
_RETRY_BACKOFF = 2.0  # multiplier


class SplunkClient(BaseClient, ConnectorMixin):
    """
    urllib3-based HTTP client for the Splunk REST API.

    Can be constructed either with a :class:`.SplunkConfig` object
    (legacy) or with keyword arguments matching the connector pattern::

        SplunkClient(host="https://splunk.example.com:8089", api_token="tok")
        SplunkClient(host="https://splunk.example.com:8089",
                     username="admin", password="pass")

    Parameters
    ----------
    host : str
        Splunk management URL including scheme and port.
    api_token : str, optional
        Pre-generated Splunk auth token.
    username : str, optional
        Splunk username for session-key auth.
    password : str, optional
        Splunk password for session-key auth.
    config : SplunkConfig, optional
        Fully-constructed config object (alternative to keyword args).
    """

    def __init__(
        self,
        host: str = "",
        api_token: str = "",
        username: str = "",
        password: str = "",
        config: Optional[SplunkConfig] = None,
        **kwargs: Any,
    ) -> None:
        # Build SplunkConfig from kwargs when not supplied directly
        if config is None:
            token = api_token
            config = SplunkConfig.__new__(SplunkConfig)
            # Bypass validation — we allow no-credential construction for
            # testing; authenticate() will raise if no credentials present.
            import urllib.parse as _up

            parsed = _up.urlparse(host) if host else None
            config.host = (parsed.hostname or host) if parsed else host
            config.port = parsed.port or 8089 if parsed else 8089
            config.scheme = (parsed.scheme or "https") if parsed else "https"
            config.username = username
            config.password = password
            config.token = token
            config.verify_ssl = True
            config.app_context = "search"
            config.es_enabled = False
            config.default_index = "main"
            config.timeout = 30
            config.max_results = 10000
            config.base_url = f"{config.scheme}://{config.host}:{config.port}"

        # Initialise BaseClient (sets self.host, self._auth_headers, etc.)
        effective_host = host or config.base_url
        super().__init__(host=effective_host, **kwargs)

        self.config = config
        self._splunk_http = self._build_pool_manager()
        self._splunk_auth = SplunkAuthManager(config, self._splunk_http)

    # ── Context manager ───────────────────────────────────────────────────

    def __enter__(self) -> "SplunkClient":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ── ConnectorMixin interface ──────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject auth headers — Bearer token or Splunk session key."""
        if self.config.token:
            self._auth_headers["Authorization"] = f"Bearer {self.config.token}"
            self._authenticated = True
        elif self.config.username and self.config.password:
            resp = self.post(
                "/services/auth/login",
                data={
                    "username": self.config.username,
                    "password": self.config.password,
                    "output_mode": "json",
                },
            )
            session_key = (resp or {}).get("sessionKey", "")
            self._auth_headers["Authorization"] = f"Splunk {session_key}"
            self._authenticated = True
        else:
            raise GNATClientError(
                "SplunkClient: no credentials provided (no token or username/password)."
            )

    def post_raw(self, url: str, data: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """POST form-encoded data to an absolute URL and return parsed JSON."""
        import urllib3 as _urllib3

        encoded = urllib.parse.urlencode(data or {}).encode("utf-8")
        pool = _urllib3.PoolManager()
        resp = pool.request(
            "POST",
            url,
            body=encoded,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            return json.loads(resp.data.decode("utf-8"))
        except Exception:
            return {}

    def health_check(self) -> bool:
        """Return True if the Splunk management API is reachable."""
        try:
            self.get("server/info", namespaced=False)
            return True
        except Exception:
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single Splunk object by ID and return as a STIX dict.

        For ``stix_type="indicator"`` the object_id is a threat-intel entry
        key; fetches from the Splunk threat-intel framework (IP or URL intel).
        For ``stix_type="observed-data"`` the object_id is a notable event ID;
        runs a search for ``event_id=<object_id>``.
        """
        if stix_type == "indicator":
            result = self.get(
                f"data/threat_intel/ip_intel/{object_id}",
                namespaced=False,
            )
            entries = (result or {}).get("entry", [])
            if not entries:
                raise GNATClientError(
                    f"Splunk threat-intel entry {object_id!r} not found.", status=404
                )
            return self.to_stix(entries[0].get("content", entries[0]))
        # observed-data: search for notable event by ID
        spl = f'search index=notable event_id="{object_id}" | head 1'
        rows = self._run_oneshot_search(spl)
        if not rows:
            raise GNATClientError(f"Splunk notable event {object_id!r} not found.", status=404)
        return self.to_stix(rows[0])

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Return a list of STIX objects from Splunk.

        For ``stix_type="indicator"`` fetches threat-intel IP entries from the
        Splunk threat-intelligence framework.
        For other types runs a saved-search or notable-event search.
        """
        if stix_type == "indicator":
            result = self.get(
                "data/threat_intel/ip_intel",
                params={"count": page_size, "offset": (page - 1) * page_size},
                namespaced=False,
            )
            entries = (result or {}).get("entry", [])
            return [self.to_stix(e.get("content", e)) for e in entries]
        # observed-data / default: search notable events
        spl = f"search index=notable | head {page_size}"
        rows = self._run_oneshot_search(spl)
        return [self.to_stix(row) for row in rows]

    def _run_oneshot_search(self, spl: str) -> list[dict[str, Any]]:
        """
        Execute a blocking Splunk one-shot search and return result rows.

        Uses POST /services/search/jobs/oneshot which runs the search
        synchronously and returns results directly.
        """
        resp = self.post(
            "search/jobs/oneshot",
            data={"search": spl, "output_mode": "json"},
            namespaced=False,
        )
        return (resp or {}).get("results", [])

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise GNATClientError("SplunkClient: upsert not supported via generic interface.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("SplunkClient: delete not supported via generic interface.")

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Splunk event row to a minimal STIX dict."""
        import uuid

        # Notable event (rule_name present)
        if "rule_name" in native:
            uid = str(
                uuid.uuid5(
                    uuid.NAMESPACE_DNS, str(native.get("event_id", native.get("rule_name", "")))
                )
            )
            return {
                "type": "indicator",
                "id": f"indicator--{uid}",
                "name": native.get("rule_name", ""),
                "pattern": "[network-traffic:dst_ref.type = 'ipv4-addr']",
                "pattern_type": "stix",
                "created": native.get("_time", ""),
                "modified": native.get("_time", ""),
                "x_splunk_severity": native.get("severity", native.get("urgency", "")),
                "x_splunk_src": native.get("src", ""),
                "x_splunk_dest": native.get("dest", ""),
            }
        # Threat-intel row (ip field)
        ip = native.get("ip", "")
        domain = native.get("domain", "")
        uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, ip or domain or "unknown"))
        if ip:
            pattern = f"[ipv4-addr:value = '{ip}']"
        elif domain:
            pattern = f"[domain-name:value = '{domain}']"
        else:
            pattern = "[network-traffic:dst_ref.type = 'ipv4-addr']"
        return {
            "type": "indicator",
            "id": f"indicator--{uid}",
            "name": ip or domain or "unknown",
            "pattern": pattern,
            "pattern_type": "stix",
            "created": native.get("_time", ""),
            "modified": native.get("_time", ""),
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Convert a STIX indicator dict to a Splunk threat-intel row."""
        pattern = stix_dict.get("pattern", "")
        ioc_type = "unknown"
        value = stix_dict.get("name", "")
        if "ipv4-addr" in pattern:
            ioc_type = "ip"
            m = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
            if m:
                value = m.group(1)
        elif "domain-name" in pattern:
            ioc_type = "domain"
            m = re.search(r"domain-name:value\s*=\s*'([^']+)'", pattern)
            if m:
                value = m.group(1)
        elif "url" in pattern:
            ioc_type = "url"
        elif "file:hashes" in pattern:
            ioc_type = "hash"
        return {"ioc_type": ioc_type, "value": value}

    # ── Splunk HTTP helpers (use _splunk_http pool, not BaseClient pool) ───

    def close(self) -> None:
        """Logout from Splunk (session key auth) and release connections."""
        try:
            self._splunk_auth.logout()
        finally:
            self._splunk_http.clear()

    # ── Public HTTP verbs ──────────────────────────────────────────────────

    def get(
        self,
        endpoint: str,
        params: dict | None = None,
        namespaced: bool = True,
        raw: bool = False,
    ) -> dict | bytes:
        """
        HTTP GET against a Splunk REST endpoint.

        Parameters
        ----------
        endpoint : str
            Path relative to the namespace root, e.g. ``"search/jobs"``.
        params : dict | None
            Query parameters. ``output_mode=json`` is always appended.
        namespaced : bool
            If True, uses /servicesNS/<owner>/<app>/<endpoint>.
            If False, uses /services/<endpoint> (global scope).
        raw : bool
            If True, return the raw response bytes instead of parsed JSON.

        Returns
        -------
        dict | bytes
            Parsed JSON dict, or raw bytes when ``raw=True``.
        """
        url = self._build_url(endpoint, namespaced)
        qp = self._inject_output_mode(params)
        return self._request("GET", url, fields=qp, raw=raw)

    def post(
        self,
        endpoint: str,
        data: dict | None = None,
        params: dict | None = None,
        namespaced: bool = True,
        content_type: str = "application/x-www-form-urlencoded",
        raw_body: bytes | None = None,
    ) -> dict:
        """
        HTTP POST against a Splunk REST endpoint.

        Parameters
        ----------
        endpoint : str
            Path relative to the namespace root.
        data : dict | None
            Form data (encoded as x-www-form-urlencoded by default).
        params : dict | None
            Query parameters appended to the URL.
        namespaced : bool
            Namespace vs global scope toggle.
        content_type : str
            Override Content-Type header.
        raw_body : bytes | None
            Send a raw body (e.g. multipart for file upload).
            Mutually exclusive with ``data``.

        Returns
        -------
        dict
            Parsed JSON response.
        """
        url = self._build_url(endpoint, namespaced)
        qp = self._inject_output_mode(params)
        if qp:
            url = f"{url}?{urllib.parse.urlencode(qp)}"

        if raw_body is not None:
            body = raw_body
            headers = {"Content-Type": content_type}
        elif data:
            body = urllib.parse.urlencode(data).encode("utf-8")
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
        else:
            body = b""
            headers = {}

        return self._request("POST", url, body=body, extra_headers=headers)

    def delete(self, endpoint: str, namespaced: bool = True) -> dict:
        """HTTP DELETE against a Splunk REST endpoint."""
        url = self._build_url(endpoint, namespaced)
        url = f"{url}?output_mode=json"
        return self._request("DELETE", url)

    def put(
        self,
        endpoint: str,
        data: dict | None = None,
        namespaced: bool = True,
    ) -> dict:
        """HTTP PUT (used for KV Store document updates)."""
        url = self._build_url(endpoint, namespaced)
        url = f"{url}?output_mode=json"
        body = json.dumps(data or {}).encode("utf-8")
        return self._request(
            "PUT",
            url,
            body=body,
            extra_headers={"Content-Type": "application/json"},
        )

    # ── Pagination helper ──────────────────────────────────────────────────

    def paginate(
        self,
        endpoint: str,
        params: dict | None = None,
        namespaced: bool = True,
        page_size: int = 100,
        result_key: str = "entry",
    ):
        """
        Generator that yields all pages of a list endpoint.

        Splunk paginates via ``count`` + ``offset``. Iterates until
        the response contains fewer results than ``page_size``.

        Parameters
        ----------
        endpoint : str
            REST endpoint path.
        params : dict | None
            Additional query parameters.
        namespaced : bool
            Namespace vs global scope.
        page_size : int
            Results per page (Splunk ``count`` parameter).
        result_key : str
            Top-level JSON key that contains the list (usually 'entry').

        Yields
        ------
        dict
            Individual result entries.
        """
        offset = 0
        base_params = dict(params or {})
        base_params["count"] = page_size

        while True:
            base_params["offset"] = offset
            response = self.get(endpoint, params=base_params, namespaced=namespaced)
            entries = response.get(result_key, [])
            yield from entries

            if len(entries) < page_size:
                break
            offset += page_size

    # ── Internal ───────────────────────────────────────────────────────────

    def _build_pool_manager(self) -> urllib3.PoolManager:
        """Create urllib3.PoolManager with TLS and retry configuration."""
        kwargs: dict = {
            "num_pools": 4,
            "maxsize": 10,
            "timeout": urllib3.Timeout(
                connect=10.0,
                read=float(self.config.timeout),
            ),
            "retries": urllib3.Retry(
                total=0,  # GNAT handles retries manually for full control
                raise_on_status=False,
            ),
        }

        if not self.config.verify_ssl:
            kwargs["cert_reqs"] = "CERT_NONE"
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        else:
            kwargs["cert_reqs"] = "CERT_REQUIRED"

        return urllib3.PoolManager(**kwargs)

    def _build_url(self, endpoint: str, namespaced: bool) -> str:
        endpoint = endpoint.lstrip("/")
        if namespaced:
            return self.config.namespace_path(endpoint)
        return self.config.services_path(endpoint)

    @staticmethod
    def _inject_output_mode(params: dict | None) -> dict:
        result = dict(params or {})
        result.setdefault("output_mode", "json")
        return result

    def _request(
        self,
        method: str,
        url: str,
        fields: dict | None = None,
        body: bytes | None = None,
        extra_headers: dict | None = None,
        raw: bool = False,
    ) -> dict | bytes:
        """
        Execute an HTTP request with auth injection, retries, and error mapping.

        Parameters
        ----------
        method : str
            HTTP verb.
        url : str
            Fully qualified URL.
        fields : dict | None
            Query parameters for GET; form fields for POST when body is None.
        body : bytes | None
            Raw request body.
        extra_headers : dict | None
            Headers to merge with auth headers.
        raw : bool
            Return raw bytes instead of parsed JSON.

        Returns
        -------
        dict | bytes

        Raises
        ------
        SplunkAuthError, SplunkRateLimitError, SplunkNotFoundError,
        SplunkAPIError
        """
        headers = self._splunk_auth.get_auth_headers()
        if extra_headers:
            headers.update(extra_headers)

        delay = _RETRY_BASE_DELAY
        last_exc: Exception | None = None

        for attempt in range(_MAX_RETRIES + 1):
            try:
                if body is not None:
                    response = self._splunk_http.request(
                        method,
                        url,
                        body=body,
                        headers=headers,
                    )
                else:
                    response = self._splunk_http.request(
                        method,
                        url,
                        fields=fields,
                        headers=headers,
                    )
            except urllib3.exceptions.HTTPError as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES:
                    time.sleep(delay)
                    delay *= _RETRY_BACKOFF
                    continue
                raise SplunkAPIError(
                    f"Connection error after {_MAX_RETRIES} retries: {exc}",
                    endpoint=url,
                ) from exc

            # ── Auth retry on 401 ──────────────────────────────────────
            if response.status == 401:
                if attempt == 0:
                    # Token may have expired -- invalidate and retry once
                    self._splunk_auth.invalidate_session()
                    headers = self._splunk_auth.get_auth_headers()
                    if extra_headers:
                        headers.update(extra_headers)
                    continue
                raise SplunkAuthError(
                    "Splunk returned 401 after token refresh. Check credentials or token expiry."
                )

            # ── Rate limit ─────────────────────────────────────────────
            if response.status == 429:
                if attempt < _MAX_RETRIES:
                    time.sleep(delay)
                    delay *= _RETRY_BACKOFF
                    continue
                raise SplunkRateLimitError(
                    "Splunk rate limit exceeded.",
                    status_code=429,
                    endpoint=url,
                )

            # ── Transient server errors ────────────────────────────────
            if response.status in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
                time.sleep(delay)
                delay *= _RETRY_BACKOFF
                continue

            # ── Map remaining error codes ──────────────────────────────
            if response.status == 404:
                raise SplunkNotFoundError(
                    f"Resource not found: {url}",
                    status_code=404,
                    endpoint=url,
                )

            if response.status == 403:
                raise SplunkAuthError(
                    f"Permission denied: {url} (HTTP 403). Check the token's capability set."
                )

            if response.status not in (200, 201):
                messages = self._extract_error_messages(response.data)
                raise SplunkAPIError(
                    "Unexpected response from Splunk.",
                    status_code=response.status,
                    endpoint=url,
                    messages=messages,
                )

            # ── Success ────────────────────────────────────────────────
            if raw:
                return response.data

            return self._parse_json(response.data, url)

        # Should not reach here, but satisfy the type checker.
        if last_exc:
            raise SplunkAPIError(str(last_exc), endpoint=url) from last_exc
        raise SplunkAPIError("Request failed after retries.", endpoint=url)  # noqa: RET504

    @staticmethod
    def _parse_json(data: bytes, url: str) -> dict:
        try:
            return json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SplunkAPIError(
                f"Failed to parse JSON response from {url}: {exc}",
                endpoint=url,
            ) from exc

    @staticmethod
    def _extract_error_messages(data: bytes) -> list[str]:
        try:
            body = json.loads(data.decode("utf-8"))
            return [m.get("text", "") for m in body.get("messages", [])]
        except Exception:
            return []


@staticmethod
def _parse_json(data: bytes, url: str) -> dict:
    try:
        return json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SplunkAPIError(
            f"Failed to parse JSON response from {url}: {exc}",
            endpoint=url,
        ) from exc


@staticmethod
def _extract_error_messages(data: bytes) -> list[str]:
    try:
        body = json.loads(data.decode("utf-8"))
        return [m.get("text", "") for m in body.get("messages", [])]
    except Exception:
        return []

"""
gnat.connectors.osint_feed.connector
=====================================

Generic OSINT feed connector that can ingest indicators from any TAXII 2.x
server or direct STIX-JSON HTTP endpoint without requiring custom Python code.
New feeds are configured entirely via ``config.ini`` sections.

Authentication
--------------
* ``auth_type = none``    — public feeds (no credentials)
* ``auth_type = basic``   — HTTP Basic (``username`` + ``password``)
* ``auth_type = api_key`` — API key in a request header
* ``auth_type = bearer``  — Bearer token in ``Authorization`` header
* ``auth_type = oauth2``  — OAuth2 client-credentials (``client_id`` + ``client_secret``)

Feed Types
----------
* ``feed_type = taxii``      — TAXII 2.x server; walks discovery → collections
* ``feed_type = stix_json``  — Direct URL returning a STIX 2.1 Bundle JSON

Configuration Example
---------------------
::

    # Generic TAXII 2.x feed (Anomali LIMO)
    [osint_feed_limo]
    host            = https://limo.anomali.com
    feed_type       = taxii
    taxii_path      = /api/v1/taxii2/
    auth_type       = basic
    username        = guest
    password        = guest
    collection_title = Phish Tank
    stix_types      = indicator

    # Direct STIX-JSON HTTP endpoint (e.g. CIRCL MISP export)
    [osint_feed_circl]
    host       = https://www.circl.lu
    feed_type  = stix_json
    feed_path  = /doc/misp/feed-osint/manifest.json
    auth_type  = none
    stix_types = indicator,malware

Notes
-----
* TAXII support requires ``taxii2-client`` (``pip install taxii2-client`` or
  install with the ``[taxii]`` extra).
* All feeds are read-only; ``upsert_object`` and ``delete_object`` raise
  :class:`~gnat.clients.base.GNATClientError`.
* ``to_stix`` and ``from_stix`` are pass-through operations because feed
  objects are already expressed in STIX 2.1 format.
"""

from __future__ import annotations

import logging
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

logger = logging.getLogger(__name__)

# Auth-type constants
_AUTH_NONE = "none"
_AUTH_BASIC = "basic"
_AUTH_API_KEY = "api_key"
_AUTH_BEARER = "bearer"
_AUTH_OAUTH2 = "oauth2"

# Feed-type constants
_FEED_TAXII = "taxii"
_FEED_STIX_JSON = "stix_json"


class OsintFeedConnector(BaseClient, ConnectorMixin):
    """
    Configurable read-only connector for TAXII 2.x and direct STIX-JSON feeds.

    Every instance is driven by configuration key-value pairs that are
    normally read from an INI section (e.g. ``[osint_feed_limo]``).  All
    objects returned by the feed are already expressed as STIX 2.1 dicts so
    :meth:`to_stix` and :meth:`from_stix` are identity operations.

    Parameters
    ----------
    host : str
        Base URL of the feed server (e.g. ``"https://limo.anomali.com"``).
    feed_type : str
        ``"taxii"`` or ``"stix_json"``.  Default ``"stix_json"``.
    taxii_path : str
        URL path to the TAXII discovery endpoint.
        Required when *feed_type* is ``"taxii"``.
        Default ``"/taxii2/"`` (TAXII 2.1 spec).
    collection_id : str, optional
        TAXII collection ID to use.  Takes precedence over *collection_title*.
    collection_title : str, optional
        Human-readable TAXII collection title (case-insensitive match).
        Used when *collection_id* is absent.
    feed_path : str
        URL path for a direct STIX-JSON endpoint.
        Required when *feed_type* is ``"stix_json"``.
    auth_type : str
        Authentication method; see module docstring for valid values.
    username : str, optional
        Username for ``basic`` auth or TAXII server auth.
    password : str, optional
        Password for ``basic`` auth or TAXII server auth.
    api_key : str, optional
        API key value for ``api_key`` auth.
    api_key_header : str
        HTTP header name used to send the API key.  Default ``"X-Api-Key"``.
    bearer_token : str, optional
        Token value for ``bearer`` auth.
    client_id : str, optional
        OAuth2 client ID (``oauth2`` auth only).
    client_secret : str, optional
        OAuth2 client secret (``oauth2`` auth only).
    token_url : str, optional
        OAuth2 token endpoint path (relative to *host*).
        Default ``"/oauth2/token"``.
    stix_types : str or list of str, optional
        Comma-separated string or list of STIX type strings to include.
        When omitted all object types are returned.
    added_after : str, optional
        ISO 8601 timestamp; only objects added after this date are fetched
        (TAXII feeds only).
    feed_name : str, optional
        Human-readable label for this feed; used in log messages and STIX
        source references.  Defaults to the class name.
    """

    stix_type_map: dict[str, str] = {
        "indicator": "indicator",
        "malware": "malware",
        "threat-actor": "threat-actor",
        "attack-pattern": "attack-pattern",
        "vulnerability": "vulnerability",
        "observed-data": "observed-data",
        "campaign": "campaign",
        "course-of-action": "course-of-action",
        "intrusion-set": "intrusion-set",
        "report": "report",
        "tool": "tool",
        "relationship": "relationship",
        "sighting": "sighting",
        "identity": "identity",
    }

    def __init__(
        self,
        host: str,
        feed_type: str = _FEED_STIX_JSON,
        taxii_path: str = "/taxii2/",
        collection_id: str | None = None,
        collection_title: str | None = None,
        feed_path: str = "",
        auth_type: str = _AUTH_NONE,
        username: str = "",
        password: str = "",
        api_key: str = "",
        api_key_header: str = "X-Api-Key",
        bearer_token: str = "",
        client_id: str = "",
        client_secret: str = "",
        token_url: str = "/oauth2/token",
        stix_types: str | list[str] | None = None,
        added_after: str | None = None,
        feed_name: str = "",
        **kwargs: Any,
    ):
        super().__init__(host=host, **kwargs)
        self._feed_type = feed_type.lower()
        self._taxii_path = taxii_path
        self._collection_id = collection_id
        self._collection_title = collection_title
        self._feed_path = feed_path
        self._auth_type = auth_type.lower()
        self._username = username
        self._password = password
        self._api_key = api_key
        self._api_key_header = api_key_header
        self._bearer_token = bearer_token
        self._client_id = client_id
        self._client_secret = client_secret
        self._token_url = token_url
        self._added_after = added_after
        self._feed_name = feed_name or type(self).__name__

        # Normalise stix_types to a frozenset or None
        if isinstance(stix_types, str) and stix_types.strip():
            self._stix_types: frozenset[str] | None = frozenset(
                t.strip() for t in stix_types.split(",") if t.strip()
            )
        elif isinstance(stix_types, (list, tuple, set)):
            self._stix_types = frozenset(stix_types)
        else:
            self._stix_types = None

    # ── Authentication ──────────────────────────────────────────────────

    def authenticate(self) -> None:
        """
        Configure auth headers based on *auth_type*.

        For ``oauth2`` a token-request is made immediately.  All other types
        simply pre-populate ``_auth_headers`` from the supplied credentials.
        """
        auth = self._auth_type

        if auth == _AUTH_NONE:
            self._auth_headers["Accept"] = "application/json"

        elif auth == _AUTH_API_KEY:
            if not self._api_key:
                raise GNATClientError(
                    f"[{self._feed_name}] auth_type=api_key requires 'api_key' in config."
                )
            self._auth_headers[self._api_key_header] = self._api_key
            self._auth_headers["Accept"] = "application/json"

        elif auth == _AUTH_BEARER:
            token = self._bearer_token or self._api_key
            if not token:
                raise GNATClientError(
                    f"[{self._feed_name}] auth_type=bearer requires 'bearer_token' or 'api_key'."
                )
            self._auth_headers["Authorization"] = f"Bearer {token}"
            self._auth_headers["Accept"] = "application/json"

        elif auth == _AUTH_BASIC:
            import base64

            if not self._username:
                raise GNATClientError(
                    f"[{self._feed_name}] auth_type=basic requires 'username' and 'password'."
                )
            creds = base64.b64encode(
                f"{self._username}:{self._password}".encode()
            ).decode()
            self._auth_headers["Authorization"] = f"Basic {creds}"
            self._auth_headers["Accept"] = "application/json"

        elif auth == _AUTH_OAUTH2:
            if not self._client_id or not self._client_secret:
                raise GNATClientError(
                    f"[{self._feed_name}] auth_type=oauth2 requires 'client_id' and 'client_secret'."
                )
            resp = self.post(
                self._token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
            )
            token = resp.get("access_token") if isinstance(resp, dict) else None
            if not token:
                raise GNATClientError(
                    f"[{self._feed_name}] OAuth2 token request did not return an access_token."
                )
            self._auth_headers["Authorization"] = f"Bearer {token}"
            self._auth_headers["Accept"] = "application/json"

        else:
            raise GNATClientError(
                f"[{self._feed_name}] Unknown auth_type={self._auth_type!r}. "
                f"Valid values: none, basic, api_key, bearer, oauth2."
            )

        self._authenticated = True

    # ── ConnectorMixin — CRUD ───────────────────────────────────────────

    def health_check(self) -> bool:
        """
        Verify reachability by fetching a small number of objects.

        For TAXII feeds the discovery endpoint is probed; for STIX-JSON feeds
        the configured *feed_path* is fetched.  Returns ``True`` on success.
        """
        if self._feed_type == _FEED_TAXII:
            self._get_taxii_collection()  # raises on failure
        else:
            self.get(self._feed_path or "/")
        return True

    def get_object(
        self, stix_type: str, object_id: str
    ) -> dict[str, Any]:
        """
        Return the first STIX object whose ``id`` matches *object_id*.

        Parameters
        ----------
        stix_type : str
            STIX type string (used to pre-filter results for efficiency).
        object_id : str
            Full STIX ID (``<type>--<uuid>``).
        """
        for obj in self._fetch_objects(stix_types={stix_type}):
            if obj.get("id") == object_id:
                return obj
        raise GNATClientError(
            f"[{self._feed_name}] Object {object_id!r} not found in feed."
        )

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 500,
    ) -> list[dict[str, Any]]:
        """
        Return a paginated list of STIX objects of *stix_type*.

        Parameters
        ----------
        stix_type : str
            STIX type to filter by.
        filters : dict, optional
            Key/value pairs applied as substring-match filters on the
            top-level fields of each STIX object.
        page : int
            1-based page number.
        page_size : int
            Number of objects per page.
        """
        all_objects = list(self._fetch_objects(stix_types={stix_type}))

        if filters:
            all_objects = [
                obj for obj in all_objects
                if all(
                    str(v).lower() in str(obj.get(k, "")).lower()
                    for k, v in filters.items()
                )
            ]

        start = (page - 1) * page_size
        return all_objects[start: start + page_size]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Not supported — OSINT feeds are read-only."""
        raise GNATClientError(
            f"[{self._feed_name}] OSINT feed connector is read-only; "
            "upsert_object is not supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Not supported — OSINT feeds are read-only."""
        raise GNATClientError(
            f"[{self._feed_name}] OSINT feed connector is read-only; "
            "delete_object is not supported."
        )

    # ── STIX translation — pass-through ────────────────────────────────

    def to_stix(self, native_object: dict[str, Any]) -> dict[str, Any]:
        """
        Return the native object unchanged — feed objects are already STIX 2.1.

        A ``x_feed_source`` extension key is added to record the origin feed.
        """
        enriched = dict(native_object)
        enriched.setdefault("x_feed_source", self._feed_name)
        return enriched

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Return the STIX dict unchanged — no native format conversion needed.
        """
        return dict(stix_dict)

    # ── Feed-specific helpers ───────────────────────────────────────────

    def iter_feed(self) -> Any:
        """
        Yield all STIX objects from the feed respecting *stix_types* filter.

        This is a convenience iterator for use with
        :class:`~gnat.ingest.pipeline.IngestPipeline` or standalone scripts.
        Each yielded value is a plain STIX 2.1 dict enriched with
        ``x_feed_source``.
        """
        for obj in self._fetch_objects():
            yield self.to_stix(obj)

    # ── Internal helpers ────────────────────────────────────────────────

    def _fetch_objects(
        self, stix_types: set[str] | None = None
    ) -> Any:
        """
        Fetch and yield raw STIX objects from the feed.

        Applies the instance-level *stix_types* filter first, then the
        caller-supplied *stix_types* set.
        """
        effective_types: set[str] | None = None
        if self._stix_types is not None and stix_types is not None:
            effective_types = self._stix_types & stix_types
        elif self._stix_types is not None:
            effective_types = set(self._stix_types)
        elif stix_types is not None:
            effective_types = stix_types

        if self._feed_type == _FEED_TAXII:
            yield from self._fetch_taxii(effective_types)
        else:
            yield from self._fetch_stix_json(effective_types)

    def _fetch_stix_json(
        self, stix_types: set[str] | None = None
    ) -> Any:
        """Fetch a STIX 2.1 bundle from a plain HTTP endpoint."""
        if not self._feed_path:
            raise GNATClientError(
                f"[{self._feed_name}] 'feed_path' must be set for feed_type=stix_json."
            )
        bundle = self.get(self._feed_path)
        if not isinstance(bundle, dict):
            raise GNATClientError(
                f"[{self._feed_name}] Expected a JSON object from {self._feed_path!r}; "
                f"got {type(bundle).__name__}."
            )
        objects = bundle.get("objects", [])
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            if stix_types and obj.get("type") not in stix_types:
                continue
            yield obj

    def _fetch_taxii(
        self, stix_types: set[str] | None = None
    ) -> Any:
        """Connect to a TAXII 2.x server and yield objects from the target collection."""
        collection = self._get_taxii_collection()
        kwargs: dict[str, Any] = {}
        if self._added_after:
            kwargs["added_after"] = self._added_after

        try:
            bundle = collection.get_objects(**kwargs)
        except Exception as exc:
            raise GNATClientError(
                f"[{self._feed_name}] Failed to fetch TAXII objects: {exc}"
            ) from exc

        objects = bundle.get("objects", []) if isinstance(bundle, dict) else []
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            if stix_types and obj.get("type") not in stix_types:
                continue
            yield obj

    def _get_taxii_collection(self) -> Any:
        """
        Resolve and return the configured TAXII collection object.

        Raises
        ------
        GNATClientError
            If ``taxii2-client`` is not installed or the collection cannot
            be found.
        """
        try:
            from taxii2client.v21 import Server as Server21  # type: ignore[import]
        except ImportError:
            try:
                from taxii2client.v20 import Server as Server21  # type: ignore[import]
            except ImportError as exc:
                raise GNATClientError(
                    "TAXII feeds require the 'taxii2-client' package. "
                    "Install it with: pip install taxii2-client"
                ) from exc

        discovery_url = self.host.rstrip("/") + "/" + self._taxii_path.lstrip("/")

        # Build taxii2client auth kwargs
        server_kwargs: dict[str, Any] = {}
        if self._auth_type == _AUTH_BASIC:
            server_kwargs["user"] = self._username
            server_kwargs["password"] = self._password
        elif self._auth_type in (_AUTH_BEARER, _AUTH_API_KEY):
            token = self._bearer_token or self._api_key
            server_kwargs["auth"] = _BearerAuth(token)

        try:
            server = Server21(discovery_url, **server_kwargs)
        except Exception as exc:
            raise GNATClientError(
                f"[{self._feed_name}] TAXII discovery failed at {discovery_url!r}: {exc}"
            ) from exc

        for root in server.api_roots:
            for col in root.collections:
                if self._collection_id and col.id == self._collection_id:
                    return col
                if (
                    self._collection_title
                    and col.title.lower() == self._collection_title.lower()
                ):
                    return col
                if not self._collection_id and not self._collection_title:
                    return col  # Return first available collection

        raise GNATClientError(
            f"[{self._feed_name}] No matching TAXII collection found. "
            f"id={self._collection_id!r}, title={self._collection_title!r}"
        )


# ---------------------------------------------------------------------------
# Minimal bearer-auth helper for taxii2client compatibility
# ---------------------------------------------------------------------------

class _BearerAuth:
    """
    Minimal auth object compatible with ``requests.auth.AuthBase`` interface
    so it can be passed to ``taxii2client`` (which uses requests internally).
    """

    def __init__(self, token: str) -> None:
        self._token = token

    def __call__(self, req: Any) -> Any:
        req.headers["Authorization"] = f"Bearer {self._token}"
        return req

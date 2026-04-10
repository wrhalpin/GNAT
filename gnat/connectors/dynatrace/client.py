# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.dynatrace.client
=====================================
Dynatrace connector client.

Covers:
  - Environment API v2 (entities, problems, security problems, attacks,
    events, metrics, settings, tags)
  - Grail / Platform Storage API (DQL query execution, log export,
    security events, business events)

Auth model
----------
Environment API v2:  static ``Api-Token`` header (set in authenticate())
Grail Storage API:   OAuth2 Bearer token via DynatraceOAuthManager

Pagination (Environment API v2)
---------------------------------
The v2 API uses cursor-based pagination with a ``nextPageKey`` field:
  {
    "totalCount": 150,
    "pageSize": 50,
    "nextPageKey": "___abcxyz",
    "<items_key>": [...]
  }

CRITICAL: Subsequent page requests MUST send ONLY ``nextPageKey`` + ``pageSize``.
Sending the original filter params alongside ``nextPageKey`` returns HTTP 400.

Grail DQL execution
--------------------
Grail uses an async execute-then-poll pattern:
  1. POST /platform/storage/query/v1/query:execute → requestToken
  2. GET  /platform/storage/query/v1/query:poll?requestToken=... → state
  3. state == "SUCCEEDED" → return result["records"]
  4. state == "FAILED"    → raise DynatraceAPIError
  5. elapsed > max_wait   → raise DynatraceQueryTimeoutError
"""

import json
import logging
import time
import warnings
from typing import Any

import urllib3

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

from .auth import DynatraceOAuthManager
from .config import DynatraceConfig
from .exceptions import (
    DynatraceAPIError,
    DynatraceConfigError,
    DynatraceConflictError,
    DynatraceNotFoundError,
    DynatraceQueryTimeoutError,
    DynatraceRateLimitError,
)
from .stix_mapper import DynatraceSTIXMapper

log = logging.getLogger(__name__)


class DynatraceClient(BaseClient, ConnectorMixin):
    """
    Dynatrace connector for GNAT.

    Supports Dynatrace Environment API v2 and Grail Platform Storage API.

    Parameters
    ----------
    host : str
        Dynatrace environment URL, e.g.
        ``"https://YOUR_ENV_ID.live.dynatrace.com"``.
    api_token : str
        Static API token with required scopes (entities.read, problems.read,
        securityProblems.read, attacks.read, events.read, events.ingest,
        metrics.read, logs.read, settings.read, settings.write).
    oauth_client_id : str, optional
        OAuth2 client ID for Grail API access.
    oauth_client_secret : str, optional
        OAuth2 client secret for Grail API access.
    oauth_token_url : str, optional
        OAuth2 token URL override (auto-detected from host if omitted).
    verify_ssl : bool
        Whether to verify TLS certificates.
    timeout : float
        Request timeout in seconds.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v2"
    API_PREFIX: str = "/api/v2"
    COST_UNIT: int = 3

    stix_type_map: dict[str, str] = {
        "infrastructure": "entities",
        "vulnerability": "securityProblems",
        "indicator": "attacks",
        "observed-data": "events",
        "malware": "problems",
    }

    def __init__(
        self,
        host: str = "",
        api_token: str = "",
        oauth_client_id: str = "",
        oauth_client_secret: str = "",
        oauth_token_url: str = "",
        verify_ssl: bool = True,
        timeout: float = 30.0,
        **kwargs: Any,
    ) -> None:
        """Initialize DynatraceClient."""
        self._cfg = DynatraceConfig(
            host=host,
            api_token=api_token,
            oauth_client_id=oauth_client_id,
            oauth_client_secret=oauth_client_secret,
            oauth_token_url=oauth_token_url,
            verify_ssl=verify_ssl,
            timeout=timeout,
        )
        super().__init__(
            host=self._cfg.host,
            verify_ssl=verify_ssl,
            timeout=timeout,
            **kwargs,
        )
        self._oauth = DynatraceOAuthManager(self._cfg, self._http)
        self._mapper = DynatraceSTIXMapper()

    # ── ConnectorMixin contract ────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set the static Api-Token header for Environment API v2."""
        self._auth_headers["Authorization"] = f"Api-Token {self._cfg.api_token}"
        self._authenticated = True

    def health_check(self) -> bool:
        """
        Ping the entities endpoint to verify connectivity.

        Returns
        -------
        bool
            True if the API is reachable and returns a valid response.
        """
        try:
            self.get(
                "/api/v2/entities",
                params={"entitySelector": "type(HOST)", "from": "now-1h", "pageSize": "1"},
            )
            return True
        except Exception as exc:
            log.debug("Dynatrace health check failed: %s", exc)
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict:
        """
        Fetch a single Dynatrace object by STIX type and ID.

        Parameters
        ----------
        stix_type : str
            STIX type ('infrastructure', 'vulnerability', 'indicator',
            'observed-data', 'malware').
        object_id : str
            Platform-native object ID (Dynatrace entity/problem/etc. ID).

        Returns
        -------
        dict
            Native Dynatrace object dict.
        """
        resource = self.stix_type_map.get(stix_type, "")
        if resource == "entities":
            return self.get_entity(object_id)
        elif resource == "securityProblems":
            return self.get_security_problem(object_id)
        elif resource == "attacks":
            return self.get_attack(object_id)
        elif resource == "problems":
            return self.get_problem(object_id)
        elif resource == "events":
            return self.get_event(object_id)
        raise GNATClientError(f"Unsupported STIX type for get_object: {stix_type!r}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict]:
        """
        List Dynatrace objects by STIX type.

        Parameters
        ----------
        stix_type : str
            STIX type to list.
        filters : dict, optional
            Platform-specific filter kwargs forwarded to the underlying method.
        page : int
            Page number (1-indexed). Pages beyond 1 warn — use cursor-based
            generators for multi-page results.
        page_size : int
            Number of results per page.

        Returns
        -------
        list[dict]
            List of native Dynatrace object dicts.
        """
        if page > 1:
            warnings.warn(
                "DynatraceClient.list_objects page>1 not directly supported. "
                "Use platform-specific cursor-based list methods instead.",
                stacklevel=2,
            )

        filters = filters or {}
        resource = self.stix_type_map.get(stix_type, "")
        if resource == "entities":
            return self.list_entities(page_size=page_size, **filters)
        elif resource == "securityProblems":
            return self.list_security_problems(page_size=page_size, **filters)
        elif resource == "attacks":
            return self.list_attacks(page_size=page_size, **filters)
        elif resource == "problems":
            return self.list_problems(page_size=page_size, **filters)
        elif resource == "events":
            return self.list_events(page_size=page_size, **filters)
        raise GNATClientError(f"Unsupported STIX type for list_objects: {stix_type!r}")

    def upsert_object(self, stix_type: str, payload: dict) -> dict:
        """
        Create or update a Dynatrace object from a STIX-like payload.

        Routing:
          observed-data  → ingest_event
          infrastructure → tag_entity
          vulnerability  → mute or unmute security problem

        Parameters
        ----------
        stix_type : str
            STIX type of the payload.
        payload : dict
            STIX-like payload dict.

        Returns
        -------
        dict
            API response dict.
        """
        if stix_type == "observed-data":
            event_payload = self._mapper.from_stix_to_event(payload)
            return self.ingest_event(
                event_type=event_payload.get("eventType", "CUSTOM_INFO"),
                title=event_payload.get("title", "GNAT event"),
                entity_selector=event_payload.get("entitySelector"),
                properties=event_payload.get("properties", {}),
            )
        elif stix_type == "infrastructure":
            entity_sel = payload.get("x_dt_entity_id", "")
            if entity_sel:
                entity_sel = f"entityId({entity_sel})"
            tags = payload.get("x_dt_tags", [])
            if not entity_sel or not tags:
                raise GNATClientError(
                    "upsert_object for infrastructure requires x_dt_entity_id and x_dt_tags "
                    "in the payload."
                )
            return self.tag_entity(entity_sel, tags)
        elif stix_type == "vulnerability":
            sp_id = payload.get("x_dt_security_problem_id", "")
            if not sp_id:
                raise GNATClientError(
                    "upsert_object for vulnerability requires x_dt_security_problem_id "
                    "in the payload."
                )
            status = payload.get("x_dt_status", "OPEN").upper()
            if status in ("RESOLVED", "MUTED"):
                self.mute_security_problem(sp_id, "OTHER", comment="Muted via GNAT upsert")
                return {"securityProblemId": sp_id, "status": "MUTED"}
            else:
                self.unmute_security_problem(sp_id, "OTHER", comment="Unmuted via GNAT upsert")
                return {"securityProblemId": sp_id, "status": "OPEN"}
        raise GNATClientError(
            f"upsert_object is not supported for STIX type {stix_type!r} on Dynatrace. "
            f"Supported: observed-data, infrastructure, vulnerability."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """
        Delete (or effectively suppress) a Dynatrace object.

        For vulnerability, mutes the security problem with reason WONT_FIX.
        Other types raise GNATClientError.

        Parameters
        ----------
        stix_type : str
            STIX type of the object.
        object_id : str
            Platform-native object ID.
        """
        if stix_type == "vulnerability":
            self.mute_security_problem(object_id, "WONT_FIX")
            return
        raise GNATClientError(
            f"delete_object is not supported for STIX type {stix_type!r} on Dynatrace. "
            f"Supported: vulnerability."
        )

    def to_stix(self, native: dict) -> dict:
        """
        Auto-detect native object type and convert to STIX 2.1.

        Detection is based on key presence:
          securityProblemId → vulnerability
          attackId          → indicator
          problemId         → observed-data (problem)
          eventId           → observed-data (event)
          entityId          → infrastructure

        Parameters
        ----------
        native : dict
            Raw Dynatrace object dict.

        Returns
        -------
        dict
            STIX 2.1 object dict.
        """
        if "securityProblemId" in native:
            return self._mapper.security_problem_to_stix(native)
        if "attackId" in native:
            return self._mapper.attack_to_stix(native)
        if "problemId" in native:
            return self._mapper.problem_to_stix(native)
        if "eventId" in native:
            return self._mapper.event_to_stix(native)
        if "entityId" in native:
            return self._mapper.entity_to_stix(native)
        raise GNATClientError(
            "Cannot auto-detect Dynatrace object type. "
            "Expected one of: securityProblemId, attackId, problemId, eventId, entityId."
        )

    def from_stix(self, stix_dict: dict) -> dict:
        """
        Convert a STIX dict to a Dynatrace event ingest payload.

        Parameters
        ----------
        stix_dict : dict
            STIX 2.1 object dict.

        Returns
        -------
        dict
            Dynatrace event ingest payload.
        """
        return self._mapper.from_stix_to_event(stix_dict)

    # ── Pagination helper ─────────────────────────────────────────────────

    def _paginate_v2(
        self,
        path: str,
        params: dict,
        items_key: str,
    ) -> list[dict]:
        """
        Fetch all pages from a Dynatrace v2 paginated endpoint.

        CRITICAL: Subsequent pages MUST send ONLY nextPageKey + pageSize.
        Sending the original filter params with nextPageKey causes HTTP 400.

        Parameters
        ----------
        path : str
            API path, e.g. '/api/v2/entities'.
        params : dict
            Initial query parameters (entity selectors, from/to, etc.).
        items_key : str
            JSON key that holds the list of items, e.g. 'entities'.

        Returns
        -------
        list[dict]
            All items across all pages.
        """
        results: list[dict] = []
        # First page — full params
        response = self.get(path, params=params)
        items = response.get(items_key, [])
        results.extend(items)

        page_size = params.get("pageSize", 50)
        next_key = response.get("nextPageKey")
        while next_key:
            # Subsequent pages — ONLY nextPageKey + pageSize (Dynatrace requirement)
            page_params = {"nextPageKey": next_key, "pageSize": page_size}
            response = self.get(path, params=page_params)
            items = response.get(items_key, [])
            results.extend(items)
            next_key = response.get("nextPageKey")

        return results

    # ── Grail request helper ──────────────────────────────────────────────

    def _grail_request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> Any:
        """
        Issue a request to the Grail / Platform Storage API.

        Uses OAuth2 Bearer token (not the static Api-Token).
        Handles 401 by invalidating token and retrying once.

        Parameters
        ----------
        method : str
            HTTP method ('GET', 'POST').
        path : str
            Path relative to host, e.g. '/platform/storage/query/v1/query:execute'.
        **kwargs
            Passed to urllib3 request (body, headers, etc.).

        Returns
        -------
        Any
            Parsed JSON response body.
        """
        url = f"{self.host}/{path.lstrip('/')}"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        headers.update(self._oauth.get_headers())
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))

        response = self._http.request(method, url, headers=headers, **kwargs)

        if response.status == 401:
            # Invalidate and retry once
            self._oauth.invalidate_token()
            headers.update(self._oauth.get_headers())
            response = self._http.request(method, url, headers=headers, **kwargs)

        if response.status not in (200, 202):
            try:
                body = json.loads(response.data.decode("utf-8"))
                msg = body.get("error", {}).get("message", "") if isinstance(body, dict) else ""
            except Exception:
                msg = ""
            self._raise_for_status(response.status, msg, url)

        if not response.data:
            return {}

        return json.loads(response.data.decode("utf-8"))

    def _raise_for_status(self, status: int, message: str, endpoint: str) -> None:
        """Raise the appropriate DynatraceAPIError subclass for an HTTP error status."""
        if status == 404:
            raise DynatraceNotFoundError(
                message or f"Not found: {endpoint}",
                status_code=404,
                endpoint=endpoint,
            )
        if status == 429:
            raise DynatraceRateLimitError(
                message or "Rate limit exceeded",
                status_code=429,
                endpoint=endpoint,
            )
        if status == 409:
            raise DynatraceConflictError(
                message or f"Conflict: {endpoint}",
                status_code=409,
                endpoint=endpoint,
            )
        raise DynatraceAPIError(
            message or f"Unexpected HTTP {status}",
            status_code=status,
            endpoint=endpoint,
        )

    # ── Entities ──────────────────────────────────────────────────────────

    def list_entities(
        self,
        entity_type: str | None = None,
        entity_selector: str | None = None,
        fields: str | None = None,
        from_ts: str | None = None,
        to_ts: str | None = None,
        page_size: int = 500,
    ) -> list[dict]:
        """
        List Dynatrace monitored entities.

        Parameters
        ----------
        entity_type : str, optional
            Entity type filter, e.g. 'HOST', 'SERVICE'.
        entity_selector : str, optional
            Full entity selector expression (overrides entity_type).
        fields : str, optional
            Additional fields to include (comma-separated), e.g. 'tags,properties'.
        from_ts : str, optional
            Start of the timeframe, e.g. 'now-3d'.
        to_ts : str, optional
            End of the timeframe.
        page_size : int
            Results per page (max 4000).

        Returns
        -------
        list[dict]
        """
        params: dict[str, Any] = {"pageSize": page_size}
        if entity_selector:
            params["entitySelector"] = entity_selector
        elif entity_type:
            params["entitySelector"] = f"type({entity_type})"
        if fields:
            params["fields"] = fields
        if from_ts:
            params["from"] = from_ts
        if to_ts:
            params["to"] = to_ts
        return self._paginate_v2("/api/v2/entities", params, "entities")

    def get_entity(self, entity_id: str) -> dict:
        """
        Fetch a single entity by its entity ID.

        Parameters
        ----------
        entity_id : str
            Dynatrace entity ID, e.g. 'HOST-1234567890ABCDEF'.

        Returns
        -------
        dict
        """
        return self.get(f"/api/v2/entities/{entity_id}")

    def tag_entity(self, entity_selector: str, tags: list[str]) -> dict:
        """
        Apply tags to entities matching the given selector.

        Parameters
        ----------
        entity_selector : str
            Entity selector expression.
        tags : list[str]
            Tag keys to apply.

        Returns
        -------
        dict
            API response with applied tags.
        """
        body = {
            "tags": [{"key": t} for t in tags],
        }
        return self.post(
            "/api/v2/tags",
            json=body,
            params={"entitySelector": entity_selector},
        )

    # ── Problems ──────────────────────────────────────────────────────────

    def list_problems(
        self,
        problem_selector: str | None = None,
        entity_selector: str | None = None,
        from_ts: str | None = None,
        to_ts: str | None = None,
        sort: str | None = None,
        fields: str | None = None,
        page_size: int = 50,
    ) -> list[dict]:
        """
        List Dynatrace problems.

        Parameters
        ----------
        problem_selector : str, optional
            Problem selector expression.
        entity_selector : str, optional
            Entity selector to filter by affected entity.
        from_ts : str, optional
            Start of the timeframe.
        to_ts : str, optional
            End of the timeframe.
        sort : str, optional
            Sort field, e.g. '-startTime'.
        fields : str, optional
            Additional fields to include.
        page_size : int
            Results per page.

        Returns
        -------
        list[dict]
        """
        params: dict[str, Any] = {"pageSize": page_size}
        if problem_selector:
            params["problemSelector"] = problem_selector
        if entity_selector:
            params["entitySelector"] = entity_selector
        if from_ts:
            params["from"] = from_ts
        if to_ts:
            params["to"] = to_ts
        if sort:
            params["sort"] = sort
        if fields:
            params["fields"] = fields
        return self._paginate_v2("/api/v2/problems", params, "problems")

    def get_problem(self, problem_id: str) -> dict:
        """
        Fetch a single problem by ID.

        Parameters
        ----------
        problem_id : str
            Dynatrace problem ID, e.g. 'P-1234567890ABCDEF'.

        Returns
        -------
        dict
        """
        return self.get(f"/api/v2/problems/{problem_id}")

    def close_problem(self, problem_id: str, message: str) -> dict:
        """
        Close a problem with a message.

        Parameters
        ----------
        problem_id : str
            Dynatrace problem ID.
        message : str
            Close message/comment.

        Returns
        -------
        dict
        """
        return self.post(
            f"/api/v2/problems/{problem_id}/close",
            json={"message": message},
        )

    # ── Security Problems ─────────────────────────────────────────────────

    def list_security_problems(
        self,
        security_problem_selector: str | None = None,
        sort: str | None = None,
        fields: str | None = None,
        from_ts: str | None = None,
        to_ts: str | None = None,
        page_size: int = 50,
    ) -> list[dict]:
        """
        List Dynatrace security problems (vulnerabilities).

        Parameters
        ----------
        security_problem_selector : str, optional
            Security problem selector expression.
        sort : str, optional
            Sort field.
        fields : str, optional
            Additional fields to include (e.g. 'cveIds,riskAssessment').
        from_ts : str, optional
            Start of the timeframe.
        to_ts : str, optional
            End of the timeframe.
        page_size : int
            Results per page.

        Returns
        -------
        list[dict]
        """
        params: dict[str, Any] = {"pageSize": page_size}
        if security_problem_selector:
            params["securityProblemSelector"] = security_problem_selector
        if sort:
            params["sort"] = sort
        if fields:
            params["fields"] = fields
        if from_ts:
            params["from"] = from_ts
        if to_ts:
            params["to"] = to_ts
        return self._paginate_v2(
            "/api/v2/securityProblems", params, "securityProblems"
        )

    def get_security_problem(
        self,
        security_problem_id: str,
        fields: str | None = None,
    ) -> dict:
        """
        Fetch a single security problem by ID.

        Parameters
        ----------
        security_problem_id : str
            Security problem ID, e.g. 'S-1234567890ABCDEF'.
        fields : str, optional
            Additional fields to include.

        Returns
        -------
        dict
        """
        params = {}
        if fields:
            params["fields"] = fields
        return self.get(
            f"/api/v2/securityProblems/{security_problem_id}",
            params=params or None,
        )

    def get_security_problem_affected_entities(
        self,
        security_problem_id: str,
    ) -> list[dict]:
        """
        List entities affected by a security problem.

        Parameters
        ----------
        security_problem_id : str

        Returns
        -------
        list[dict]
        """
        response = self.get(
            f"/api/v2/securityProblems/{security_problem_id}/affectedEntities"
        )
        return response.get("entities", response if isinstance(response, list) else [])

    def get_security_problem_remediation_items(
        self,
        security_problem_id: str,
    ) -> list[dict]:
        """
        List remediation items for a security problem.

        Parameters
        ----------
        security_problem_id : str

        Returns
        -------
        list[dict]
        """
        response = self.get(
            f"/api/v2/securityProblems/{security_problem_id}/remediationItems"
        )
        return response.get("remediationItems", [])

    def mute_security_problem(
        self,
        security_problem_id: str,
        reason: str,
        comment: str = "",
    ) -> None:
        """
        Mute a security problem.

        Parameters
        ----------
        security_problem_id : str
        reason : str
            Mute reason: 'FALSE_POSITIVE', 'ACCEPTED', 'WONT_FIX', 'OTHER'.
        comment : str, optional
            Human-readable comment.
        """
        body: dict[str, Any] = {"reason": reason}
        if comment:
            body["comment"] = comment
        self.post(
            f"/api/v2/securityProblems/{security_problem_id}/mute",
            json=body,
        )

    def unmute_security_problem(
        self,
        security_problem_id: str,
        reason: str,
        comment: str = "",
    ) -> None:
        """
        Unmute a security problem.

        Parameters
        ----------
        security_problem_id : str
        reason : str
            Unmute reason.
        comment : str, optional
            Human-readable comment.
        """
        body: dict[str, Any] = {"reason": reason}
        if comment:
            body["comment"] = comment
        self.post(
            f"/api/v2/securityProblems/{security_problem_id}/unmute",
            json=body,
        )

    # ── Attacks ───────────────────────────────────────────────────────────

    def list_attacks(
        self,
        attack_selector: str | None = None,
        sort: str | None = None,
        fields: str | None = None,
        from_ts: str | None = None,
        to_ts: str | None = None,
        page_size: int = 50,
    ) -> list[dict]:
        """
        List Dynatrace runtime attacks (Application Security).

        Parameters
        ----------
        attack_selector : str, optional
            Attack selector expression.
        sort : str, optional
            Sort field.
        fields : str, optional
            Additional fields to include.
        from_ts : str, optional
            Start of the timeframe.
        to_ts : str, optional
            End of the timeframe.
        page_size : int
            Results per page.

        Returns
        -------
        list[dict]
        """
        params: dict[str, Any] = {"pageSize": page_size}
        if attack_selector:
            params["attackSelector"] = attack_selector
        if sort:
            params["sort"] = sort
        if fields:
            params["fields"] = fields
        if from_ts:
            params["from"] = from_ts
        if to_ts:
            params["to"] = to_ts
        return self._paginate_v2("/api/v2/attacks", params, "attacks")

    def get_attack(self, attack_id: str, fields: str | None = None) -> dict:
        """
        Fetch a single attack by ID.

        Parameters
        ----------
        attack_id : str
        fields : str, optional
            Additional fields to include.

        Returns
        -------
        dict
        """
        params = {}
        if fields:
            params["fields"] = fields
        return self.get(f"/api/v2/attacks/{attack_id}", params=params or None)

    def set_attack_handling(self, attack_id: str, handling: str) -> dict:
        """
        Update the handling mode of an attack.

        Parameters
        ----------
        attack_id : str
        handling : str
            Handling mode: 'BLOCK', 'DETECT', or 'OFF'.

        Returns
        -------
        dict
        """
        return self.put(
            f"/api/v2/attacks/{attack_id}",
            json={"attackHandling": {"blockingStrategy": handling}},
        )

    # ── Events ────────────────────────────────────────────────────────────

    def list_events(
        self,
        event_selector: str | None = None,
        entity_selector: str | None = None,
        from_ts: str | None = None,
        to_ts: str | None = None,
        page_size: int = 50,
    ) -> list[dict]:
        """
        List Dynatrace events.

        Parameters
        ----------
        event_selector : str, optional
            Event selector expression.
        entity_selector : str, optional
            Entity selector to filter by affected entity.
        from_ts : str, optional
            Start of the timeframe.
        to_ts : str, optional
            End of the timeframe.
        page_size : int
            Results per page.

        Returns
        -------
        list[dict]
        """
        params: dict[str, Any] = {"pageSize": page_size}
        if event_selector:
            params["eventSelector"] = event_selector
        if entity_selector:
            params["entitySelector"] = entity_selector
        if from_ts:
            params["from"] = from_ts
        if to_ts:
            params["to"] = to_ts
        return self._paginate_v2("/api/v2/events", params, "events")

    def get_event(self, event_id: str) -> dict:
        """
        Fetch a single event by ID.

        Parameters
        ----------
        event_id : str

        Returns
        -------
        dict
        """
        return self.get(f"/api/v2/events/{event_id}")

    def ingest_event(
        self,
        event_type: str,
        title: str,
        entity_selector: str | None = None,
        properties: dict | None = None,
        timeout_minutes: int = 0,
    ) -> dict:
        """
        Ingest a custom event into Dynatrace.

        Parameters
        ----------
        event_type : str
            Event type, e.g. 'CUSTOM_INFO', 'CUSTOM_ALERT', 'CUSTOM_ANNOTATION'.
        title : str
            Event title.
        entity_selector : str, optional
            Entity selector to attach the event to a specific entity.
        properties : dict, optional
            Custom event properties.
        timeout_minutes : int
            Duration in minutes (0 = snapshot event).

        Returns
        -------
        dict
            API response with event IDs.
        """
        body: dict[str, Any] = {
            "eventType": event_type,
            "title": title,
            "properties": properties or {},
        }
        if entity_selector:
            body["entitySelector"] = entity_selector
        if timeout_minutes:
            body["timeout"] = timeout_minutes
        return self.post("/api/v2/events/ingest", json=body)

    # ── Metrics ───────────────────────────────────────────────────────────

    def list_metric_descriptors(
        self,
        metric_selector: str | None = None,
        page_size: int = 100,
    ) -> list[dict]:
        """
        List available metric descriptors.

        Parameters
        ----------
        metric_selector : str, optional
            Metric selector filter.
        page_size : int
            Results per page.

        Returns
        -------
        list[dict]
        """
        params: dict[str, Any] = {"pageSize": page_size}
        if metric_selector:
            params["metricSelector"] = metric_selector
        return self._paginate_v2("/api/v2/metrics", params, "metrics")

    def query_metrics(
        self,
        metric_selector: str,
        resolution: str = "Inf",
        from_ts: str = "now-2h",
        to_ts: str = "now",
        entity_selector: str | None = None,
    ) -> dict:
        """
        Query metric data points.

        Parameters
        ----------
        metric_selector : str
            Metric selector expression, e.g. 'builtin:host.cpu.usage'.
        resolution : str
            Data resolution, e.g. '1m', '1h', 'Inf'.
        from_ts : str
            Start of the timeframe.
        to_ts : str
            End of the timeframe.
        entity_selector : str, optional
            Narrow results to a specific entity.

        Returns
        -------
        dict
            Metric query result with resolution and data series.
        """
        params: dict[str, Any] = {
            "metricSelector": metric_selector,
            "resolution": resolution,
            "from": from_ts,
            "to": to_ts,
        }
        if entity_selector:
            params["entitySelector"] = entity_selector
        return self.get("/api/v2/metrics/query", params=params)

    # ── Settings ──────────────────────────────────────────────────────────

    def list_settings_objects(
        self,
        schema_ids: list[str],
        scope: str | None = None,
        page_size: int = 500,
    ) -> list[dict]:
        """
        List settings objects for the given schema IDs.

        Parameters
        ----------
        schema_ids : list[str]
            One or more schema IDs to query.
        scope : str, optional
            Scope filter (e.g. 'environment', 'HOST-xxx').
        page_size : int
            Results per page.

        Returns
        -------
        list[dict]
        """
        params: dict[str, Any] = {
            "schemaIds": ",".join(schema_ids),
            "pageSize": page_size,
        }
        if scope:
            params["scope"] = scope
        return self._paginate_v2("/api/v2/settings/objects", params, "items")

    def get_settings_object(self, object_id: str) -> dict:
        """
        Fetch a single settings object by its object ID.

        Parameters
        ----------
        object_id : str

        Returns
        -------
        dict
        """
        return self.get(f"/api/v2/settings/objects/{object_id}")

    def create_settings_object(
        self,
        schema_id: str,
        scope: str,
        value: dict,
    ) -> dict:
        """
        Create a new settings object.

        Parameters
        ----------
        schema_id : str
            Schema ID for the new object.
        scope : str
            Scope for the new object.
        value : dict
            Settings value payload.

        Returns
        -------
        dict
        """
        body = [{"schemaId": schema_id, "scope": scope, "value": value}]
        return self.post("/api/v2/settings/objects", json=body)

    def delete_settings_object(self, object_id: str) -> None:
        """
        Delete a settings object by its object ID.

        Parameters
        ----------
        object_id : str
        """
        self.delete(f"/api/v2/settings/objects/{object_id}")

    # ── Grail / Platform Storage API ─────────────────────────────────────

    def query_grail(
        self,
        dql: str,
        max_results: int | None = None,
        timeout_secs: float | None = None,
    ) -> list[dict]:
        """
        Execute a DQL query against Grail and return all result records.

        Uses async execute-then-poll pattern:
          1. POST /platform/storage/query/v1/query:execute
          2. Poll GET /platform/storage/query/v1/query:poll?requestToken=...
          3. Return records when state == 'SUCCEEDED'

        Requires OAuth2 Grail credentials (oauth_client_id, oauth_client_secret).

        Parameters
        ----------
        dql : str
            DQL query string, e.g. 'fetch logs | limit 100'.
        max_results : int, optional
            Override for grail_max_records config value.
        timeout_secs : float, optional
            Override for grail_max_wait_secs config value.

        Returns
        -------
        list[dict]
            Query result records.

        Raises
        ------
        DynatraceConfigError
            If OAuth2 credentials are not configured.
        DynatraceAPIError
            If the query fails.
        DynatraceQueryTimeoutError
            If the query does not complete within the timeout.
        """
        if not self._cfg.oauth_client_id:
            raise DynatraceConfigError(
                "Grail DQL requires OAuth2 credentials. "
                "Set oauth_client_id and oauth_client_secret in [dynatrace] config."
            )

        limit = max_results or self._cfg.grail_max_records
        max_wait = timeout_secs or self._cfg.grail_max_wait_secs
        poll_interval = self._cfg.grail_poll_interval_secs

        execute_body = json.dumps({
            "query": dql,
            "maxResultRecords": limit,
            "requestTimeoutMilliseconds": int(max_wait * 1000),
        }).encode("utf-8")

        execute_resp = self._grail_request(
            "POST",
            "/platform/storage/query/v1/query:execute",
            body=execute_body,
        )
        request_token = execute_resp.get("requestToken")
        if not request_token:
            # Query may have completed synchronously
            state = execute_resp.get("state", "")
            if state == "SUCCEEDED":
                return execute_resp.get("result", {}).get("records", [])
            raise DynatraceAPIError(
                "Grail query execute did not return a requestToken.",
                endpoint="/platform/storage/query/v1/query:execute",
            )

        # Poll for completion
        start = time.monotonic()
        while True:
            elapsed = time.monotonic() - start
            if elapsed > max_wait:
                raise DynatraceQueryTimeoutError(
                    f"Grail DQL query timed out after {max_wait:.0f}s. "
                    f"requestToken={request_token}"
                )

            poll_resp = self._grail_request(
                "GET",
                "/platform/storage/query/v1/query:poll",
                fields=urllib3.request.urlencode({"requestToken": request_token}),
            )
            state = poll_resp.get("state", "RUNNING")

            if state == "SUCCEEDED":
                return poll_resp.get("result", {}).get("records", [])
            if state == "FAILED":
                error_msg = poll_resp.get("error", {}).get("message", "DQL query failed")
                raise DynatraceAPIError(
                    f"Grail DQL query failed: {error_msg}",
                    endpoint="/platform/storage/query/v1/query:poll",
                )

            time.sleep(poll_interval)

    def export_logs(
        self,
        dql_filter: str | None = None,
        from_ts: str = "now-1h",
        to_ts: str = "now",
        limit: int = 1000,
    ) -> list[dict]:
        """
        Export log records from Grail using DQL.

        Requires OAuth2 Grail credentials.

        Parameters
        ----------
        dql_filter : str, optional
            Additional DQL filter expression, e.g. '| filter loglevel == "ERROR"'.
        from_ts : str
            Start of the timeframe.
        to_ts : str
            End of the timeframe.
        limit : int
            Maximum number of log records to return.

        Returns
        -------
        list[dict]
        """
        filter_clause = f"\n{dql_filter}" if dql_filter else ""
        dql = (
            f"fetch logs, from:{from_ts}, to:{to_ts}"
            f"{filter_clause}"
            f"\n| limit {limit}"
        )
        return self.query_grail(dql, max_results=limit)

    def query_security_events_grail(
        self,
        dql_filter: str | None = None,
        from_ts: str = "now-24h",
        to_ts: str = "now",
        limit: int = 1000,
    ) -> list[dict]:
        """
        Query security-related events from Grail using DQL.

        Requires OAuth2 Grail credentials.

        Parameters
        ----------
        dql_filter : str, optional
            Additional DQL filter expression.
        from_ts : str
            Start of the timeframe.
        to_ts : str
            End of the timeframe.
        limit : int
            Maximum number of records to return.

        Returns
        -------
        list[dict]
        """
        filter_clause = f"\n{dql_filter}" if dql_filter else ""
        dql = (
            f"fetch events, from:{from_ts}, to:{to_ts}"
            f"\n| filter event.type == \"VULNERABILITY_OPEN\" "
            f"or event.type == \"ATTACK_CANDIDATE\" "
            f"or event.type == \"SECURITY_PROBLEM\""
            f"{filter_clause}"
            f"\n| limit {limit}"
        )
        return self.query_grail(dql, max_results=limit)

    def ingest_bizevents(self, events: list[dict]) -> dict:
        """
        Ingest business events into Grail.

        Requires OAuth2 Grail credentials.

        Parameters
        ----------
        events : list[dict]
            List of business event dicts to ingest.

        Returns
        -------
        dict
            API response.
        """
        if not self._cfg.oauth_client_id:
            raise DynatraceConfigError(
                "Grail bizevents ingest requires OAuth2 credentials. "
                "Set oauth_client_id and oauth_client_secret in [dynatrace] config."
            )
        body = json.dumps(events).encode("utf-8")
        return self._grail_request(
            "POST",
            "/platform/storage/bizevents/v1/ingest",
            body=body,
        )

    def export_bizevents(
        self,
        dql: str,
        limit: int = 1000,
    ) -> list[dict]:
        """
        Export business events from Grail using DQL.

        Requires OAuth2 Grail credentials.

        Parameters
        ----------
        dql : str
            DQL query for business events, e.g. 'fetch bizevents | limit 100'.
        limit : int
            Maximum number of records to return.

        Returns
        -------
        list[dict]
        """
        return self.query_grail(dql, max_results=limit)

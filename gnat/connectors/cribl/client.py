"""
gnat.connectors.cribl.client
====================================

Cribl Stream / Edge REST API v1 connector.

Authentication
--------------
Two modes are supported:

1. **Username / password** — POST ``/api/v1/auth/login`` with
   ``{"username": ..., "password": ...}`` returns a short-lived Bearer token.
2. **Direct token** — Supply a pre-obtained API token via the ``token``
   constructor argument; no login request is made.

STIX Type Mapping
-----------------
+--------------------+-------------------------------+
| STIX Type          | Cribl Resource                |
+====================+===============================+
| course-of-action   | Pipeline                      |
+--------------------+-------------------------------+
| observed-data      | Search job / event            |
+--------------------+-------------------------------+
| indicator          | Lookup table                  |
+--------------------+-------------------------------+

Key Endpoints
-------------
* ``/api/v1/m/{group}/pipelines``  — pipeline management
* ``/api/v1/m/{group}/inputs``     — input sources
* ``/api/v1/m/{group}/outputs``    — output destinations
* ``/api/v1/m/{group}/lookups``    — lookup tables
* ``/api/v1/searches``             — search jobs
* ``/api/v1/system/health``        — health probe
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.connectors.cribl.exceptions import CriblAuthError
from gnat.connectors.cribl.stix_mapper import CriblSTIXMapper


class CriblClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Cribl Stream / Edge REST API v1.

    Parameters
    ----------
    host : str
        Base URL of the Cribl leader node,
        e.g. ``"https://cribl-leader.example.com"``.
    username : str
        Username for login-based authentication.
    password : str
        Password for login-based authentication.
    token : str
        Pre-obtained API token (skips the login request when set).
    worker_group : str
        Default worker-group for all management-plane requests.
        Defaults to ``"default"``.
    **kwargs :
        Extra keyword arguments forwarded to
        :class:`~gnat.clients.base.BaseClient`.
    """

    stix_type_map: Dict[str, str] = {
        "course-of-action": "pipelines",
        "observed-data": "searches",
        "indicator": "lookups",
    }

    def __init__(
        self,
        host: str,
        username: str = "",
        password: str = "",
        token: str = "",
        worker_group: str = "default",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._username = username
        self._password = password
        self._token = token
        self._worker_group = worker_group
        self._mapper = CriblSTIXMapper()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _group(self, group: Optional[str] = None) -> str:
        """Return *group* if given, otherwise the configured worker group."""
        return group or self._worker_group

    # ------------------------------------------------------------------
    # ConnectorMixin — authentication
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """
        Authenticate against the Cribl API.

        If a ``token`` was supplied at construction the token is used
        directly.  Otherwise, a POST to ``/api/v1/auth/login`` is made
        with the configured username and password.

        Raises
        ------
        CriblAuthError
            If the login response does not contain a token.
        """
        if self._token:
            self._auth_headers["Authorization"] = f"Bearer {self._token}"
            return

        try:
            resp = self.post(
                "/api/v1/auth/login",
                json={"username": self._username, "password": self._password},
            )
        except GNATClientError as exc:
            raise CriblAuthError(
                f"Cribl login failed: {exc}", status_code=exc.status, response_body=exc.body
            ) from exc

        token = resp.get("token") if isinstance(resp, dict) else None
        if not token:
            raise CriblAuthError("Cribl login response did not contain a token.")

        self._token = token
        self._auth_headers["Authorization"] = f"Bearer {self._token}"

    def health_check(self) -> bool:
        """
        Verify connectivity by probing the Cribl health endpoint.

        Returns
        -------
        bool
            ``True`` when the API is reachable and reports a healthy status.
        """
        self.get("/api/v1/system/health")
        return True

    # ------------------------------------------------------------------
    # ConnectorMixin — CRUD
    # ------------------------------------------------------------------

    def get_object(self, stix_type: str, object_id: str, **kwargs: Any) -> Dict[str, Any]:
        """
        Fetch a single Cribl object by STIX type and native id.

        Parameters
        ----------
        stix_type : str
            One of ``"observed-data"``, ``"course-of-action"``,
            ``"indicator"``.
        object_id : str
            Native Cribl object id.

        Returns
        -------
        dict
            Raw Cribl API response for the object.

        Raises
        ------
        GNATClientError
            If *stix_type* is not supported.
        """
        if stix_type == "observed-data":
            return self.get_search_job(object_id)
        if stix_type == "course-of-action":
            return self.get_pipeline(object_id, **kwargs)
        if stix_type == "indicator":
            return self.get_lookup(object_id, **kwargs)
        raise GNATClientError(f"Unsupported stix_type for CriblClient.get_object: {stix_type!r}")

    def list_objects(
        self,
        stix_type: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        """
        List Cribl objects of the given STIX type.

        Parameters
        ----------
        stix_type : str, optional
            STIX type filter.  ``None`` or ``"course-of-action"`` returns
            pipelines; ``"observed-data"`` returns search jobs;
            ``"indicator"`` returns lookups.
        filters : dict, optional
            Unused — reserved for future filter support.
        page : int
            Page number (1-based).
        page_size : int
            Number of results per page.

        Returns
        -------
        list of dict
            List of Cribl native objects.

        Raises
        ------
        GNATClientError
            If *stix_type* is not supported.
        """
        if stix_type is None or stix_type == "course-of-action":
            items = self.list_pipelines(**kwargs)
        elif stix_type == "observed-data":
            items = self.list_search_jobs()
        elif stix_type == "indicator":
            items = self.list_lookups(**kwargs)
        else:
            raise GNATClientError(
                f"Unsupported stix_type for CriblClient.list_objects: {stix_type!r}"
            )
        start = (page - 1) * page_size
        return items[start : start + page_size]

    def upsert_object(
        self, stix_type: str, payload: Dict[str, Any], **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Create or update a Cribl object.

        Parameters
        ----------
        stix_type : str
            ``"course-of-action"`` (pipeline) or ``"indicator"`` (lookup).
        payload : dict
            Cribl native payload.  If it contains an ``"id"`` key the
            object is updated; otherwise it is created.

        Returns
        -------
        dict
            API response for the created / updated object.

        Raises
        ------
        GNATClientError
            If *stix_type* is not supported.
        """
        if stix_type == "course-of-action":
            obj_id = payload.get("id")
            if obj_id:
                return self.update_pipeline(obj_id, payload, **kwargs)
            return self.create_pipeline(payload, **kwargs)
        if stix_type == "indicator":
            obj_id = payload.get("id")
            if obj_id:
                return self.update_lookup(obj_id, payload, **kwargs)
            return self.create_lookup(payload, **kwargs)
        raise GNATClientError(
            f"Unsupported stix_type for CriblClient.upsert_object: {stix_type!r}"
        )

    def delete_object(self, stix_type: str, object_id: str, **kwargs: Any) -> None:
        """
        Delete a Cribl object.

        Parameters
        ----------
        stix_type : str
            ``"course-of-action"`` (pipeline) or ``"indicator"`` (lookup).
        object_id : str
            Native Cribl object id.

        Raises
        ------
        GNATClientError
            If *stix_type* is not supported.
        """
        if stix_type == "course-of-action":
            self.delete_pipeline(object_id, **kwargs)
            return
        if stix_type == "indicator":
            self.delete_lookup(object_id, **kwargs)
            return
        raise GNATClientError(
            f"Unsupported stix_type for CriblClient.delete_object: {stix_type!r}"
        )

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a Cribl-native object to STIX 2.1.

        Parameters
        ----------
        native : dict
            Cribl event or pipeline config dict.

        Returns
        -------
        dict
            STIX 2.1 representation.
        """
        return self._mapper.node_to_stix(native)

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a STIX 2.1 object to a Cribl-native payload.

        Parameters
        ----------
        stix_dict : dict
            STIX 2.1 object dict.

        Returns
        -------
        dict
            Cribl-native payload (lookup config for indicators).
        """
        return self._mapper.stix_to_native(stix_dict)

    # ------------------------------------------------------------------
    # System methods
    # ------------------------------------------------------------------

    def get_system_info(self) -> Dict[str, Any]:
        """Fetch Cribl system information."""
        return self.get("/api/v1/system/info")

    def get_system_health(self) -> Dict[str, Any]:
        """Fetch Cribl system health status."""
        return self.get("/api/v1/system/health")

    def list_worker_groups(self) -> List[Dict[str, Any]]:
        """
        List all Cribl worker groups.

        Returns
        -------
        list of dict
        """
        resp = self.get("/api/v1/master/groups")
        return resp.get("items", []) if isinstance(resp, dict) else []

    def get_worker_group(self, group: str) -> Dict[str, Any]:
        """
        Fetch a specific worker group by name.

        Parameters
        ----------
        group : str
            Worker group name.
        """
        return self.get(f"/api/v1/master/groups/{group}")

    def list_workers(self) -> List[Dict[str, Any]]:
        """
        List all Cribl worker instances.

        Returns
        -------
        list of dict
        """
        resp = self.get("/api/v1/system/instances")
        return resp.get("items", []) if isinstance(resp, dict) else []

    # ------------------------------------------------------------------
    # Pipeline methods
    # ------------------------------------------------------------------

    def list_pipelines(self, group: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List pipelines in a worker group.

        Parameters
        ----------
        group : str, optional
            Worker group name.  Defaults to the configured worker group.

        Returns
        -------
        list of dict
        """
        resp = self.get(f"/api/v1/m/{self._group(group)}/pipelines")
        return resp.get("items", []) if isinstance(resp, dict) else []

    def get_pipeline(self, pipeline_id: str, group: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch a pipeline by id.

        Parameters
        ----------
        pipeline_id : str
            Pipeline id.
        group : str, optional
            Worker group name.
        """
        return self.get(f"/api/v1/m/{self._group(group)}/pipelines/{pipeline_id}")

    def create_pipeline(
        self, config: Dict[str, Any], group: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a new pipeline.

        Parameters
        ----------
        config : dict
            Cribl pipeline configuration payload.
        group : str, optional
            Target worker group.
        """
        return self.post(f"/api/v1/m/{self._group(group)}/pipelines", json=config)

    def update_pipeline(
        self, pipeline_id: str, config: Dict[str, Any], group: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update an existing pipeline.

        Parameters
        ----------
        pipeline_id : str
            Pipeline id.
        config : dict
            Updated pipeline configuration payload.
        group : str, optional
            Worker group name.
        """
        return self.patch(
            f"/api/v1/m/{self._group(group)}/pipelines/{pipeline_id}", json=config
        )

    def delete_pipeline(self, pipeline_id: str, group: Optional[str] = None) -> None:
        """
        Delete a pipeline.

        Parameters
        ----------
        pipeline_id : str
            Pipeline id.
        group : str, optional
            Worker group name.
        """
        self.delete(f"/api/v1/m/{self._group(group)}/pipelines/{pipeline_id}")

    # ------------------------------------------------------------------
    # Route methods
    # ------------------------------------------------------------------

    def list_routes(self, group: Optional[str] = None) -> Any:
        """
        List routes in a worker group.

        Parameters
        ----------
        group : str, optional
            Worker group name.

        Returns
        -------
        list of dict or dict
        """
        resp = self.get(f"/api/v1/m/{self._group(group)}/routes")
        if isinstance(resp, dict):
            return resp.get("items", resp)
        return resp

    def get_route(self, route_id: str, group: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch a route by id.

        Parameters
        ----------
        route_id : str
            Route id.
        group : str, optional
            Worker group name.
        """
        return self.get(f"/api/v1/m/{self._group(group)}/routes/{route_id}")

    def update_routes(
        self, routes_config: Dict[str, Any], group: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Replace the entire routes configuration.

        Parameters
        ----------
        routes_config : dict
            Full routes configuration payload.
        group : str, optional
            Worker group name.
        """
        return self.put(f"/api/v1/m/{self._group(group)}/routes", json=routes_config)

    # ------------------------------------------------------------------
    # Input methods
    # ------------------------------------------------------------------

    def list_inputs(self, group: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List inputs in a worker group.

        Parameters
        ----------
        group : str, optional
            Worker group name.

        Returns
        -------
        list of dict
        """
        resp = self.get(f"/api/v1/m/{self._group(group)}/inputs")
        return resp.get("items", []) if isinstance(resp, dict) else []

    def get_input(self, input_id: str, group: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch an input source by id.

        Parameters
        ----------
        input_id : str
            Input id.
        group : str, optional
            Worker group name.
        """
        return self.get(f"/api/v1/m/{self._group(group)}/inputs/{input_id}")

    def create_input(
        self, config: Dict[str, Any], group: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a new input source.

        Parameters
        ----------
        config : dict
            Input configuration payload.
        group : str, optional
            Target worker group.
        """
        return self.post(f"/api/v1/m/{self._group(group)}/inputs", json=config)

    def update_input(
        self, input_id: str, config: Dict[str, Any], group: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update an existing input source.

        Parameters
        ----------
        input_id : str
            Input id.
        config : dict
            Updated input configuration.
        group : str, optional
            Worker group name.
        """
        return self.patch(
            f"/api/v1/m/{self._group(group)}/inputs/{input_id}", json=config
        )

    def delete_input(self, input_id: str, group: Optional[str] = None) -> None:
        """
        Delete an input source.

        Parameters
        ----------
        input_id : str
            Input id.
        group : str, optional
            Worker group name.
        """
        self.delete(f"/api/v1/m/{self._group(group)}/inputs/{input_id}")

    # ------------------------------------------------------------------
    # Output methods
    # ------------------------------------------------------------------

    def list_outputs(self, group: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List outputs in a worker group.

        Parameters
        ----------
        group : str, optional
            Worker group name.

        Returns
        -------
        list of dict
        """
        resp = self.get(f"/api/v1/m/{self._group(group)}/outputs")
        return resp.get("items", []) if isinstance(resp, dict) else []

    def get_output(self, output_id: str, group: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch an output destination by id.

        Parameters
        ----------
        output_id : str
            Output id.
        group : str, optional
            Worker group name.
        """
        return self.get(f"/api/v1/m/{self._group(group)}/outputs/{output_id}")

    def create_output(
        self, config: Dict[str, Any], group: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a new output destination.

        Parameters
        ----------
        config : dict
            Output configuration payload.
        group : str, optional
            Target worker group.
        """
        return self.post(f"/api/v1/m/{self._group(group)}/outputs", json=config)

    def update_output(
        self, output_id: str, config: Dict[str, Any], group: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update an existing output destination.

        Parameters
        ----------
        output_id : str
            Output id.
        config : dict
            Updated output configuration.
        group : str, optional
            Worker group name.
        """
        return self.patch(
            f"/api/v1/m/{self._group(group)}/outputs/{output_id}", json=config
        )

    def delete_output(self, output_id: str, group: Optional[str] = None) -> None:
        """
        Delete an output destination.

        Parameters
        ----------
        output_id : str
            Output id.
        group : str, optional
            Worker group name.
        """
        self.delete(f"/api/v1/m/{self._group(group)}/outputs/{output_id}")

    # ------------------------------------------------------------------
    # Pack methods
    # ------------------------------------------------------------------

    def list_packs(self, group: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List installed packs in a worker group.

        Parameters
        ----------
        group : str, optional
            Worker group name.

        Returns
        -------
        list of dict
        """
        resp = self.get(f"/api/v1/m/{self._group(group)}/packs")
        return resp.get("items", []) if isinstance(resp, dict) else []

    def get_pack(self, pack_id: str, group: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch a pack by id.

        Parameters
        ----------
        pack_id : str
            Pack id.
        group : str, optional
            Worker group name.
        """
        return self.get(f"/api/v1/m/{self._group(group)}/packs/{pack_id}")

    def install_pack(
        self, pack_id: str, source: str, group: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Install a pack from a source URL.

        Parameters
        ----------
        pack_id : str
            Pack id.
        source : str
            URL or path of the pack source.
        group : str, optional
            Target worker group.
        """
        return self.post(
            f"/api/v1/m/{self._group(group)}/packs",
            json={"id": pack_id, "source": source},
        )

    def uninstall_pack(self, pack_id: str, group: Optional[str] = None) -> None:
        """
        Uninstall a pack.

        Parameters
        ----------
        pack_id : str
            Pack id.
        group : str, optional
            Worker group name.
        """
        self.delete(f"/api/v1/m/{self._group(group)}/packs/{pack_id}")

    def upgrade_pack(
        self, pack_id: str, source: str, group: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Upgrade an installed pack from a new source.

        Parameters
        ----------
        pack_id : str
            Pack id.
        source : str
            Updated source URL or path.
        group : str, optional
            Worker group name.
        """
        return self.patch(
            f"/api/v1/m/{self._group(group)}/packs/{pack_id}", json={"source": source}
        )

    # ------------------------------------------------------------------
    # Lookup methods
    # ------------------------------------------------------------------

    def list_lookups(self, group: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List lookup tables in a worker group.

        Parameters
        ----------
        group : str, optional
            Worker group name.

        Returns
        -------
        list of dict
        """
        resp = self.get(f"/api/v1/m/{self._group(group)}/lookups")
        return resp.get("items", []) if isinstance(resp, dict) else []

    def get_lookup(self, lookup_id: str, group: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch a lookup table by id.

        Parameters
        ----------
        lookup_id : str
            Lookup id.
        group : str, optional
            Worker group name.
        """
        return self.get(f"/api/v1/m/{self._group(group)}/lookups/{lookup_id}")

    def create_lookup(
        self, config: Dict[str, Any], group: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a new lookup table.

        Parameters
        ----------
        config : dict
            Lookup configuration payload.
        group : str, optional
            Target worker group.
        """
        return self.post(f"/api/v1/m/{self._group(group)}/lookups", json=config)

    def update_lookup(
        self, lookup_id: str, config: Dict[str, Any], group: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update an existing lookup table.

        Parameters
        ----------
        lookup_id : str
            Lookup id.
        config : dict
            Updated lookup configuration.
        group : str, optional
            Worker group name.
        """
        return self.patch(
            f"/api/v1/m/{self._group(group)}/lookups/{lookup_id}", json=config
        )

    def delete_lookup(self, lookup_id: str, group: Optional[str] = None) -> None:
        """
        Delete a lookup table.

        Parameters
        ----------
        lookup_id : str
            Lookup id.
        group : str, optional
            Worker group name.
        """
        self.delete(f"/api/v1/m/{self._group(group)}/lookups/{lookup_id}")

    # ------------------------------------------------------------------
    # Search methods
    # ------------------------------------------------------------------

    def search(
        self,
        query: str,
        earliest: Optional[str] = None,
        latest: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Submit a Cribl search job.

        Parameters
        ----------
        query : str
            Cribl search query string.
        earliest : str, optional
            Earliest time bound (ISO-8601 or relative).
        latest : str, optional
            Latest time bound (ISO-8601 or relative).
        limit : int
            Maximum number of events to return.

        Returns
        -------
        dict
            Search job descriptor (includes ``id`` and ``status``).
        """
        payload: Dict[str, Any] = {"query": query, "limit": limit}
        if earliest is not None:
            payload["earliest"] = earliest
        if latest is not None:
            payload["latest"] = latest
        return self.post("/api/v1/searches", json=payload)

    def get_search_job(self, job_id: str) -> Dict[str, Any]:
        """
        Fetch the status and results of a search job.

        Parameters
        ----------
        job_id : str
            Search job id.
        """
        return self.get(f"/api/v1/searches/{job_id}")

    def list_search_jobs(self) -> List[Dict[str, Any]]:
        """
        List all search jobs.

        Returns
        -------
        list of dict
        """
        resp = self.get("/api/v1/searches")
        if isinstance(resp, dict):
            return resp.get("items", [])
        return resp if isinstance(resp, list) else []

    def cancel_search(self, job_id: str) -> None:
        """
        Cancel a running search job.

        Parameters
        ----------
        job_id : str
            Search job id.
        """
        self.delete(f"/api/v1/searches/{job_id}")

    # ------------------------------------------------------------------
    # Dataset methods
    # ------------------------------------------------------------------

    def list_datasets(self) -> List[Dict[str, Any]]:
        """
        List all Cribl datasets.

        Returns
        -------
        list of dict
        """
        resp = self.get("/api/v1/datasets")
        return resp.get("items", []) if isinstance(resp, dict) else []

    def get_dataset(self, dataset_id: str) -> Dict[str, Any]:
        """
        Fetch a dataset by id.

        Parameters
        ----------
        dataset_id : str
            Dataset id.
        """
        return self.get(f"/api/v1/datasets/{dataset_id}")

    def create_dataset(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new dataset.

        Parameters
        ----------
        config : dict
            Dataset configuration payload.
        """
        return self.post("/api/v1/datasets", json=config)

    def delete_dataset(self, dataset_id: str) -> None:
        """
        Delete a dataset.

        Parameters
        ----------
        dataset_id : str
            Dataset id.
        """
        self.delete(f"/api/v1/datasets/{dataset_id}")

    # ------------------------------------------------------------------
    # Notification methods
    # ------------------------------------------------------------------

    def list_notifications(self) -> List[Dict[str, Any]]:
        """
        List notification objects.

        Returns
        -------
        list of dict
        """
        resp = self.get("/api/v1/notifications/objects")
        return resp.get("items", []) if isinstance(resp, dict) else []

    def get_notification(self, notification_id: str) -> Dict[str, Any]:
        """
        Fetch a notification object by id.

        Parameters
        ----------
        notification_id : str
            Notification id.
        """
        return self.get(f"/api/v1/notifications/objects/{notification_id}")

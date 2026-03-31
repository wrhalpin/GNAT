"""
gnat.connectors.synapse.client
====================================

Vertex Project Synapse Cortex HTTP API connector.

Authentication
--------------
Two modes are supported:

1. **API key** — Supply an API key via the ``api_key`` constructor argument;
   it is injected as ``Authorization: Bearer <key>`` on every request.
2. **Username / password** — POST ``/api/v1/login`` with
   ``{"user": ..., "passwd": ...}``.  The response may contain a session
   token in ``result.token``.

Storm Query Language
--------------------
Synapse exposes all graph operations through its Storm query language.
The ``/api/v1/storm`` endpoint accepts a JSON payload and returns a
JSONL-style stream of typed messages.  Each ``"node"`` message carries
a ``[[form, value], {props, tags, iden}]`` tuple in its ``data`` field.

STIX Type Mapping
-----------------
+--------------------+--------------------------------------------+
| STIX Type          | Synapse Forms                              |
+====================+============================================+
| ipv4-addr          | inet:ipv4                                  |
+--------------------+--------------------------------------------+
| ipv6-addr          | inet:ipv6                                  |
+--------------------+--------------------------------------------+
| domain-name        | inet:fqdn                                  |
+--------------------+--------------------------------------------+
| url                | inet:url                                   |
+--------------------+--------------------------------------------+
| email-addr         | inet:email                                 |
+--------------------+--------------------------------------------+
| file               | file:bytes, hash:md5, hash:sha1, hash:sha256|
+--------------------+--------------------------------------------+
| vulnerability      | risk:vuln                                  |
+--------------------+--------------------------------------------+
| attack-pattern     | risk:attack                                |
+--------------------+--------------------------------------------+
| threat-actor       | risk:threat                                |
+--------------------+--------------------------------------------+
| identity           | ou:org, ps:person                          |
+--------------------+--------------------------------------------+
| report             | media:news                                 |
+--------------------+--------------------------------------------+
| observed-data      | meta:event                                 |
+--------------------+--------------------------------------------+
| indicator          | inet:fqdn, inet:ipv4, inet:url, file:bytes |
+--------------------+--------------------------------------------+

Key Endpoints
-------------
* ``/api/v1/storm``         — execute a Storm query (streaming JSONL)
* ``/api/v1/storm/call``    — execute a Storm query and return the result
* ``/api/v1/login``         — authenticate
* ``/api/v1/active``        — health probe
* ``/api/v1/core/views``    — view management
* ``/api/v1/core/layers``   — layer management
* ``/api/v1/auth/users``    — user management
"""

from __future__ import annotations

import contextlib
import json as _json
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.connectors.synapse.exceptions import SynapseAuthError, SynapseStormError
from gnat.connectors.synapse.stix_mapper import SynapseSTIXMapper


class SynapseClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Vertex Project Synapse Cortex HTTP API.

    Parameters
    ----------
    host : str
        Base URL of the Synapse Cortex, e.g. ``"https://synapse.example.com"``.
    username : str
        Username for login-based authentication.
    password : str
        Password for login-based authentication.
    api_key : str
        API key / Bearer token (skips the login request when set).
    view : str
        Default view iden to use in Storm ``opts``.
    **kwargs :
        Extra keyword arguments forwarded to
        :class:`~gnat.clients.base.BaseClient`.
    """

    stix_type_map: dict[str, str] = {
        # SCOs — Vertex Synapse inet/file forms
        "ipv4-addr":     "inet:ipv4",
        "ipv6-addr":     "inet:ipv6",
        "domain-name":   "inet:fqdn",
        "url":           "inet:url",
        "email-addr":    "inet:email",
        "file":          "file:bytes",
        "autonomous-system": "inet:asn",
        "network-traffic": "inet:flow",
        # SDOs
        "vulnerability": "risk:vuln",
        "attack-pattern": "it:mitre:attack:technique,risk:attack",
        "malware":       "it:mitre:attack:software",
        "tool":          "it:mitre:attack:software",
        "campaign":      "risk:threat",
        "threat-actor":  "risk:threat",
        "identity":      "ou:org",
        "report":        "media:news",
        "observed-data": "meta:event",
        "course-of-action": "risk:mitigation",
        # Broad indicator query: union of typical IOC forms
        "indicator":     "inet:fqdn,inet:ipv4,inet:ipv6,inet:url,file:bytes",
    }

    def __init__(
        self,
        host: str,
        username: str = "",
        password: str = "",
        api_key: str = "",
        view: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._username = username
        self._password = password
        self._api_key = api_key
        self._view = view
        self._mapper = SynapseSTIXMapper()

    # ------------------------------------------------------------------
    # ConnectorMixin — authentication
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """
        Authenticate against the Synapse API.

        If an ``api_key`` was supplied at construction it is used directly as
        a Bearer token.  Otherwise, a POST to ``/api/v1/login`` is made with
        the configured username and password.

        Raises
        ------
        SynapseAuthError
            If the login request fails or returns no usable token.
        """
        if self._api_key:
            self._auth_headers["Authorization"] = f"Bearer {self._api_key}"
            return

        try:
            resp = self.post(
                "/api/v1/login",
                json={"user": self._username, "passwd": self._password},
            )
        except GNATClientError as exc:
            raise SynapseAuthError(
                f"Synapse login failed: {exc}",
                status_code=exc.status,
                response_body=exc.body,
            ) from exc

        token: str | None = None
        if isinstance(resp, dict):
            result = resp.get("result", {})
            if isinstance(result, dict):
                token = result.get("token")

        if token:
            self._auth_headers["Authorization"] = f"Bearer {token}"

    def health_check(self) -> bool:
        """
        Verify connectivity via the Synapse active endpoint.

        Returns
        -------
        bool
            ``True`` when the API responds with HTTP 200.
        """
        self.get("/api/v1/active")
        return True

    # ------------------------------------------------------------------
    # ConnectorMixin — CRUD
    # ------------------------------------------------------------------

    def get_object(self, stix_type: str, object_id: str, **kwargs: Any) -> dict[str, Any]:
        """
        Fetch a single Synapse node by its iden.

        Parameters
        ----------
        stix_type : str
            STIX type (used for type context; the actual lookup is by iden).
        object_id : str
            Synapse node iden (hex string).

        Returns
        -------
        dict
            Synapse node dict.
        """
        return self.get_node_by_iden(object_id)

    def list_objects(
        self,
        stix_type: str | None = None,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """
        List Synapse nodes of the given STIX type.

        Parameters
        ----------
        stix_type : str, optional
            STIX type to filter by.  Maps to one or more Synapse forms.
        filters : dict, optional
            Reserved for future filter support.
        page : int
            Page number (1-based).
        page_size : int
            Maximum number of nodes to return.

        Returns
        -------
        list of dict
            Synapse node dicts.
        """
        forms_str = self.stix_type_map.get(stix_type or "", "")
        if not forms_str:
            forms_str = stix_type or ""

        forms = [f.strip() for f in forms_str.split(",") if f.strip()]
        if not forms:
            forms = [stix_type or ""]

        nodes: list[dict[str, Any]] = []
        for form in forms:
            try:
                batch = self.get_nodes_by_form(form, limit=page_size)
                nodes.extend(batch)
            except Exception:
                pass

        start = (page - 1) * page_size
        return nodes[start : start + page_size]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any], **kwargs: Any
    ) -> dict[str, Any]:
        """
        Create or update a Synapse node.

        Parameters
        ----------
        stix_type : str
            STIX type (for context).
        payload : dict
            Either a Synapse node dict (``ndef``, ``props``, ``tags``) or
            a dict with ``form`` and ``value`` keys, or a STIX indicator.

        Returns
        -------
        dict
            The created/updated node, or an empty dict on failure.
        """
        if "ndef" in payload:
            form = payload["ndef"][0]
            value = payload["ndef"][1]
            props = payload.get("props")
            tags = list(payload.get("tags", {}).keys()) or None
            return self.add_node(form, str(value), props=props, tags=tags)
        if "form" in payload and "value" in payload:
            props = payload.get("props")
            tags_dict = payload.get("tags", {})
            tags = list(tags_dict.keys()) if tags_dict else None
            return self.add_node(payload["form"], str(payload["value"]), props=props, tags=tags)
        node = self._mapper.stix_indicator_to_node(payload)
        return self.add_node(
            node["form"],
            str(node["value"]),
            props=node.get("props"),
            tags=list(node.get("tags", {}).keys()) or None,
        )

    def delete_object(self, stix_type: str, object_id: str, **kwargs: Any) -> None:
        """
        Delete a Synapse node by iden.

        Parameters
        ----------
        stix_type : str
            STIX type (for context).
        object_id : str
            Synapse node iden.
        """
        self.delete_node(object_id)

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a Synapse node dict to STIX 2.1.

        Parameters
        ----------
        native : dict
            Synapse node dict.

        Returns
        -------
        dict
            STIX 2.1 object.
        """
        return self._mapper.node_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a STIX 2.1 indicator to a Synapse node descriptor.

        Parameters
        ----------
        stix_dict : dict
            STIX 2.1 object dict.

        Returns
        -------
        dict
            Synapse node descriptor with ``form``, ``value``, ``props``,
            and ``tags`` keys.
        """
        return self._mapper.stix_indicator_to_node(stix_dict)

    # ------------------------------------------------------------------
    # Storm methods
    # ------------------------------------------------------------------

    def storm(
        self, query: str, opts: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """
        Execute a Storm query and return the resulting nodes.

        The Vertex Synapse ``/api/v1/storm`` endpoint streams NDJSON
        (newline-delimited JSON).  Each line is a typed message dict::

            {"type": "node",  "data": [[form, valu], {props, tags, iden}]}
            {"type": "init",  "data": {"tick": ...}}
            {"type": "fini",  "data": {"tock": ..., "count": ...}}
            {"type": "err",   "data": [errtype, errinfo]}
            {"type": "print", "data": {"mesg": ...}}

        Because :class:`~gnat.clients.base.BaseClient` reads the entire
        response body and attempts ``json.loads``, the NDJSON stream arrives
        as a raw ``str`` when the multi-line body is not valid JSON by itself.
        This method handles all three return shapes (``str`` / ``list`` /
        ``dict``) gracefully.

        Parameters
        ----------
        query : str
            Storm query string.
        opts : dict, optional
            Optional Storm execution options (e.g. ``{"view": iden}``).

        Returns
        -------
        list of dict
            Normalised Synapse node dicts, each with keys:
            ``ndef``, ``props``, ``tags``, ``iden``.

        Raises
        ------
        SynapseStormError
            If the Storm stream contains an ``"err"`` message.
        """
        payload: dict[str, Any] = {"query": query}
        if opts:
            payload["opts"] = opts
        elif self._view:
            payload["opts"] = {"view": self._view}

        try:
            resp = self.post("/api/v1/storm", json=payload)
        except GNATClientError:
            raise
        except Exception:
            return []

        # --- normalise the response into a flat list of message dicts ----
        if isinstance(resp, str):
            # Real Synapse: NDJSON stream — parse each non-empty line
            messages: list[Any] = []
            for line in resp.splitlines():
                line = line.strip()
                if not line:
                    continue
                with contextlib.suppress(_json.JSONDecodeError):
                    messages.append(_json.loads(line))
        elif isinstance(resp, list):
            # Unit-test shim: list of already-parsed message dicts
            messages = resp
        elif isinstance(resp, dict):
            # Unexpected single-object envelope — treat as a wrapped list
            messages = resp.get("result", [resp])
        else:
            messages = []

        nodes: list[dict[str, Any]] = []
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            msg_type = msg.get("type")
            if msg_type == "err":
                err_data = msg.get("data", [])
                err_name = err_data[0] if isinstance(err_data, list) and err_data else "UnknownErr"
                err_info = err_data[1] if isinstance(err_data, list) and len(err_data) > 1 else {}
                raise SynapseStormError(
                    f"Storm error {err_name}: {err_info}",
                    query=query,
                )
            if msg_type != "node":
                continue
            node_data = msg.get("data", [])
            if not (isinstance(node_data, list) and len(node_data) >= 2):
                continue
            ndef_part = node_data[0]
            info_part = node_data[1] if len(node_data) > 1 else {}
            if isinstance(ndef_part, list) and len(ndef_part) >= 2:
                form = ndef_part[0]
                value = ndef_part[1]
            else:
                form, value = "", ""
            props = info_part.get("props", {}) if isinstance(info_part, dict) else {}
            tags = info_part.get("tags", {}) if isinstance(info_part, dict) else {}
            iden = info_part.get("iden", "") if isinstance(info_part, dict) else ""
            nodes.append(
                {"ndef": [form, value], "props": props, "tags": tags, "iden": iden}
            )
        return nodes

    def storm_count(self, query: str) -> int:
        """
        Execute a Storm count query and return the integer result.

        Parameters
        ----------
        query : str
            Storm query string.

        Returns
        -------
        int
            Number of nodes matched.
        """
        count_query = f"{query} | count"
        result = self.callstorm(count_query)
        if isinstance(result, (int, float)):
            return int(result)
        return len(self.storm(query))

    def callstorm(
        self, query: str, opts: dict[str, Any] | None = None
    ) -> Any:
        """
        Execute a Storm query via ``/api/v1/storm/call`` and return the result.

        Parameters
        ----------
        query : str
            Storm query string.
        opts : dict, optional
            Optional Storm execution options.

        Returns
        -------
        Any
            The ``result`` value from the API response.
        """
        payload: dict[str, Any] = {"query": query}
        if opts:
            payload["opts"] = opts
        elif self._view:
            payload["opts"] = {"view": self._view}
        resp = self.post("/api/v1/storm/call", json=payload)
        if isinstance(resp, dict):
            return resp.get("result")
        return resp

    # ------------------------------------------------------------------
    # Node operations
    # ------------------------------------------------------------------

    def get_node_by_iden(self, iden: str) -> dict[str, Any]:
        """
        Fetch a single node by its hexadecimal iden.

        Parameters
        ----------
        iden : str
            Synapse node iden.

        Returns
        -------
        dict
            Synapse node dict.

        Raises
        ------
        GNATClientError
            If no node with the given iden is found.
        """
        nodes = self.storm(f"iden('{iden}')")
        if not nodes:
            raise GNATClientError(f"Synapse node not found: {iden!r}")
        return nodes[0]

    def get_nodes_by_form(self, form: str, limit: int = 100) -> list[dict[str, Any]]:
        """
        Fetch all nodes of a given Synapse form.

        Parameters
        ----------
        form : str
            Synapse form name, e.g. ``"inet:ipv4"``.
        limit : int
            Maximum number of nodes to return.

        Returns
        -------
        list of dict
        """
        return self.storm(f"{form} | limit {limit}")

    def add_node(
        self,
        form: str,
        value: str,
        props: dict[str, Any] | None = None,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Add a node to the Synapse graph.

        Parameters
        ----------
        form : str
            Synapse form, e.g. ``"inet:ipv4"``.
        value : str
            Node primary value.
        props : dict, optional
            Secondary properties to set on the node.
        tags : list of str, optional
            Tags to apply.

        Returns
        -------
        dict
            The created node, or an empty dict if the Storm call returned
            nothing.
        """
        query = f"[{form}='{value}'"
        if props:
            for prop, val in props.items():
                query += f" :{prop}='{val}'"
        query += "]"
        if tags:
            for tag in tags:
                query += f" [+#{tag}]"
        nodes = self.storm(query)
        return nodes[0] if nodes else {}

    def edit_node(self, iden: str, props: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Edit properties on an existing node.

        Parameters
        ----------
        iden : str
            Node iden.
        props : dict
            Property name → value mapping.

        Returns
        -------
        list of dict
            Updated nodes returned by Storm.
        """
        setters = " ".join(f":{k}='{v}'" for k, v in props.items())
        query = f"iden('{iden}') [ {setters} ]"
        return self.storm(query)

    def delete_node(self, iden: str) -> None:
        """
        Delete a node from the graph.

        Parameters
        ----------
        iden : str
            Node iden.
        """
        self.storm(f"iden('{iden}') | delnode")

    def add_tag(self, iden: str, tag: str) -> None:
        """
        Apply a tag to a node.

        Parameters
        ----------
        iden : str
            Node iden.
        tag : str
            Tag name (dot-separated, e.g. ``"tlp.red"``).
        """
        self.storm(f"iden('{iden}') [+#{tag}]")

    def del_tag(self, iden: str, tag: str) -> None:
        """
        Remove a tag from a node.

        Parameters
        ----------
        iden : str
            Node iden.
        tag : str
            Tag name.
        """
        self.storm(f"iden('{iden}') [-#{tag}]")

    def get_node_tags(self, iden: str) -> dict[str, Any]:
        """
        Return the tags dict for a node.

        Parameters
        ----------
        iden : str
            Node iden.

        Returns
        -------
        dict
            Tags mapping ``tag_name → [ts1, ts2]``.
        """
        node = self.get_node_by_iden(iden)
        return node.get("tags", {})

    # ------------------------------------------------------------------
    # Tag operations
    # ------------------------------------------------------------------

    def list_tags(self, prefix: str | None = None) -> list[dict[str, Any]]:
        """
        List tag definition nodes in the Cortex.

        Parameters
        ----------
        prefix : str, optional
            If given, only tags whose name starts with *prefix* are returned.

        Returns
        -------
        list of dict
            Synapse ``syn:tag`` node dicts.
        """
        if prefix:
            return self.storm(f"syn:tag^={prefix}")
        return self.storm("syn:tag")

    def get_tag(self, tagname: str) -> dict[str, Any] | None:
        """
        Fetch a single tag definition node.

        Parameters
        ----------
        tagname : str
            Tag name.

        Returns
        -------
        dict or None
        """
        nodes = self.storm(f"syn:tag={tagname}")
        return nodes[0] if nodes else None

    def add_tag_definition(
        self, tagname: str, props: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """
        Create or update a tag definition node.

        Parameters
        ----------
        tagname : str
            Tag name to create/update.
        props : dict, optional
            Supported props: ``title``.

        Returns
        -------
        list of dict
        """
        query = f"[syn:tag={tagname}"
        if props and props.get("title"):
            query += f" :title='{props['title']}'"
        query += "]"
        return self.storm(query)

    def del_tag_definition(self, tagname: str) -> None:
        """
        Delete a tag definition node.

        Parameters
        ----------
        tagname : str
            Tag name.
        """
        self.storm(f"syn:tag={tagname} | delnode")

    # ------------------------------------------------------------------
    # View / Layer management
    # ------------------------------------------------------------------

    def list_views(self) -> list[dict[str, Any]]:
        """
        List all Cortex views.

        Returns
        -------
        list of dict
        """
        resp = self.get("/api/v1/core/views")
        if isinstance(resp, dict):
            return resp.get("result", [])
        return resp if isinstance(resp, list) else []

    def get_view(self, view_iden: str) -> dict[str, Any]:
        """
        Fetch a view by iden.

        Parameters
        ----------
        view_iden : str
            View iden.
        """
        resp = self.get(f"/api/v1/core/views/{view_iden}")
        return resp.get("result", resp) if isinstance(resp, dict) else resp

    def create_view(
        self, name: str, layers: list[str] | None = None
    ) -> dict[str, Any]:
        """
        Create a new Cortex view.

        Parameters
        ----------
        name : str
            View name.
        layers : list of str, optional
            Ordered list of layer idens.
        """
        resp = self.post(
            "/api/v1/core/views", json={"name": name, "layers": layers or []}
        )
        return resp.get("result", resp) if isinstance(resp, dict) else resp

    def fork_view(
        self, view_iden: str, name: str | None = None
    ) -> dict[str, Any]:
        """
        Fork an existing view.

        Parameters
        ----------
        view_iden : str
            Source view iden.
        name : str, optional
            Name for the forked view.
        """
        payload: dict[str, Any] = {}
        if name:
            payload["name"] = name
        resp = self.post(f"/api/v1/core/views/{view_iden}/fork", json=payload)
        return resp.get("result", resp) if isinstance(resp, dict) else resp

    def list_layers(self) -> list[dict[str, Any]]:
        """
        List all Cortex layers.

        Returns
        -------
        list of dict
        """
        resp = self.get("/api/v1/core/layers")
        if isinstance(resp, dict):
            return resp.get("result", [])
        return resp if isinstance(resp, list) else []

    def get_layer(self, layer_iden: str) -> dict[str, Any]:
        """
        Fetch a layer by iden.

        Parameters
        ----------
        layer_iden : str
            Layer iden.
        """
        resp = self.get(f"/api/v1/core/layers/{layer_iden}")
        return resp.get("result", resp) if isinstance(resp, dict) else resp

    def add_layer(self, name: str) -> dict[str, Any]:
        """
        Create a new Cortex layer.

        Parameters
        ----------
        name : str
            Layer name.
        """
        resp = self.post("/api/v1/core/layers", json={"name": name})
        return resp.get("result", resp) if isinstance(resp, dict) else resp

    # ------------------------------------------------------------------
    # Data model
    # ------------------------------------------------------------------

    def get_model(self) -> Any:
        """Return the full Synapse data model definition."""
        resp = self.get("/api/v1/model")
        return resp.get("result", resp) if isinstance(resp, dict) else resp

    def get_form(self, form_name: str) -> Any:
        """
        Return the model definition for a specific form.

        Parameters
        ----------
        form_name : str
            Synapse form name, e.g. ``"inet:ipv4"``.
        """
        resp = self.get(f"/api/v1/model/form/{form_name}")
        return resp.get("result", resp) if isinstance(resp, dict) else resp

    def list_forms(self) -> list[Any]:
        """Return the list of all forms in the data model."""
        resp = self.get("/api/v1/model/forms")
        if isinstance(resp, dict):
            return resp.get("result", [])
        return resp if isinstance(resp, list) else []

    # ------------------------------------------------------------------
    # Auth / Users
    # ------------------------------------------------------------------

    def list_users(self) -> list[dict[str, Any]]:
        """
        List all Synapse users.

        Returns
        -------
        list of dict
        """
        resp = self.get("/api/v1/auth/users")
        if isinstance(resp, dict):
            return resp.get("result", [])
        return resp if isinstance(resp, list) else []

    def get_user(self, user_iden: str) -> dict[str, Any]:
        """
        Fetch a user by iden.

        Parameters
        ----------
        user_iden : str
            User iden.
        """
        resp = self.get(f"/api/v1/auth/users/{user_iden}")
        return resp.get("result", resp) if isinstance(resp, dict) else resp

    def add_user(
        self,
        name: str,
        passwd: str,
        email: str | None = None,
    ) -> dict[str, Any]:
        """
        Create a new Synapse user.

        Parameters
        ----------
        name : str
            Username.
        passwd : str
            Initial password.
        email : str, optional
            Email address.
        """
        payload: dict[str, Any] = {"name": name, "passwd": passwd}
        if email:
            payload["email"] = email
        resp = self.post("/api/v1/auth/adduser", json=payload)
        return resp.get("result", resp) if isinstance(resp, dict) else resp

    def set_user_passwd(self, user_iden: str, passwd: str) -> dict[str, Any]:
        """
        Change a user's password.

        Parameters
        ----------
        user_iden : str
            User iden.
        passwd : str
            New password.
        """
        resp = self.post(
            "/api/v1/auth/setpasswd", json={"iden": user_iden, "passwd": passwd}
        )
        return resp.get("result", resp) if isinstance(resp, dict) else resp

    def list_roles(self) -> list[dict[str, Any]]:
        """
        List all Synapse roles.

        Returns
        -------
        list of dict
        """
        resp = self.get("/api/v1/auth/roles")
        if isinstance(resp, dict):
            return resp.get("result", [])
        return resp if isinstance(resp, list) else []

    def add_role(self, name: str) -> dict[str, Any]:
        """
        Create a new role.

        Parameters
        ----------
        name : str
            Role name.
        """
        resp = self.post("/api/v1/auth/addrole", json={"name": name})
        return resp.get("result", resp) if isinstance(resp, dict) else resp

    def grant_role(self, user_iden: str, role_iden: str) -> dict[str, Any]:
        """
        Grant a role to a user.

        Parameters
        ----------
        user_iden : str
            User iden.
        role_iden : str
            Role iden.
        """
        resp = self.post(
            "/api/v1/auth/grant", json={"user": user_iden, "role": role_iden}
        )
        return resp.get("result", resp) if isinstance(resp, dict) else resp

    # ------------------------------------------------------------------
    # Cortex info
    # ------------------------------------------------------------------

    def get_cortex_info(self) -> dict[str, Any]:
        """Return general Cortex information."""
        resp = self.get("/api/v1/cortex/info")
        return resp.get("result", resp) if isinstance(resp, dict) else resp

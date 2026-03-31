"""
gnat.connectors.splunk.kvstore

Splunk KV Store (key-value store) commands.

The KV Store is a MongoDB-compatible JSON document store built into
Splunk that GNAT uses for:

- Caching enrichment results
- Storing deduplication state
- Persisting indicator correlation metadata
- Tracking connector run state (last_seen timestamps, etc.)

## KV Store REST API

Collections live at:
/servicesNS/<owner>/<app>/storage/collections/

Data records live at:
/servicesNS/<owner>/<app>/storage/collections/data/<collection>/

Every document auto-gets a `_key` field (UUID by default).
Splunk accepts JSON bodies for all KV Store CRUD operations.

## Query syntax

Splunk KV Store queries use MongoDB-style JSON filter objects:
{"field": "value"}                        -- exact match
{"field": {"$gt": 100}}                   -- comparison
{"$or": [{"f": "a"}, {"f": "b"}]}         -- logical OR
{"field": {"$regex": "^APT"}}             -- regex

## References

- https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTkvstore
  """

import json
import urllib.parse

from .client import SplunkClient
from .exceptions import SplunkNotFoundError


class SplunkKVStoreCommands:
    """
    KV Store collection and document operations.

    Parameters
    ----------
    client : SplunkClient
        Authenticated HTTP client.
    """

    def __init__(self, client: SplunkClient) -> None:
        self._client = client

    # ── Collection management ──────────────────────────────────────────────

    def list_collections(self) -> list[str]:
        """
        List all KV store collections in the configured app context.

        Returns
        -------
        list[str]
            Collection names.
        """
        response = self._client.get(
            "storage/collections/config",
            namespaced=True,
        )
        return [
            entry.get("name", "")
            for entry in response.get("entry", [])
        ]

    def create_collection(
        self,
        name: str,
        fields: dict[str, str] | None = None,
        accelerated_fields: dict[str, str] | None = None,
    ) -> dict:
        """
        Create a new KV store collection.

        Parameters
        ----------
        name : str
            Collection name. Must be alphanumeric + underscores.
        fields : dict[str, str] | None
            Field type definitions, e.g. ``{"ip": "string", "score": "number"}``.
            If omitted, Splunk uses schema-less mode (accepts any JSON).
        accelerated_fields : dict[str, str] | None
            Fields to index for fast lookup, e.g. ``{"ix_ip": "ip"}``.

        Returns
        -------
        dict
            Collection creation response.
        """
        data: dict = {"name": name}
        if fields:
            for field_name, field_type in fields.items():
                data[f"field.{field_name}"] = field_type
        if accelerated_fields:
            for idx_name, idx_field in accelerated_fields.items():
                data[f"accelerated_fields.{idx_name}"] = idx_field

        return self._client.post(
            "storage/collections/config",
            data=data,
            namespaced=True,
        )

    def delete_collection(self, name: str) -> None:
        """
        Delete a KV store collection and all its documents.

        Parameters
        ----------
        name : str
            Collection name to delete.
        """
        safe = urllib.parse.quote(name, safe="")
        self._client.delete(
            f"storage/collections/config/{safe}",
            namespaced=True,
        )

    def collection_exists(self, name: str) -> bool:
        """Return True if the named collection exists."""
        return name in self.list_collections()

    # ── Document CRUD ──────────────────────────────────────────────────────

    def list_records(
        self,
        collection: str,
        query: dict | None = None,
        fields: list[str] | None = None,
        count: int = 0,
        offset: int = 0,
        sort_key: str | None = None,
        sort_dir: str = "asc",
    ) -> list[dict]:
        """
        Query documents from a KV store collection.

        Parameters
        ----------
        collection : str
            Collection name.
        query : dict | None
            MongoDB-style filter. None returns all documents.
        fields : list[str] | None
            Field projection (only return these fields).
        count : int
            Max records (0 = all).
        offset : int
            Pagination offset.
        sort_key : str | None
            Field to sort by.
        sort_dir : str
            'asc' or 'desc'.

        Returns
        -------
        list[dict]
            Document records.
        """
        safe = urllib.parse.quote(collection, safe="")
        params: dict = {
            "output_mode": "json",
            "count": count,
            "offset": offset,
        }
        if query:
            params["query"] = json.dumps(query)
        if fields:
            params["fields"] = ",".join(fields)
        if sort_key:
            params["sort"] = f"{sort_key}:{sort_dir}"

        url = (
            f"{self._client.config.base_url}"
            f"/servicesNS/{self._client.config.owner}"
            f"/{self._client.config.app_context}"
            f"/storage/collections/data/{safe}"
        )
        response = self._client.get(url, params=params, namespaced=False)
        # KV store data endpoints return list directly
        if isinstance(response, list):
            return response
        return response.get("entry", [])

    def get_record(self, collection: str, key: str) -> dict | None:
        """
        Retrieve a single document by ``_key``.

        Parameters
        ----------
        collection : str
            Collection name.
        key : str
            Document ``_key``.

        Returns
        -------
        dict | None
            Document dict, or None if not found.
        """
        safe_coll = urllib.parse.quote(collection, safe="")
        safe_key = urllib.parse.quote(key, safe="")
        url = (
            f"{self._client.config.base_url}"
            f"/servicesNS/{self._client.config.owner}"
            f"/{self._client.config.app_context}"
            f"/storage/collections/data/{safe_coll}/{safe_key}"
        )
        try:
            return self._client.get(url, namespaced=False)
        except SplunkNotFoundError:
            return None

    def insert_record(self, collection: str, record: dict) -> dict:
        """
        Insert a new document into a KV store collection.

        Splunk assigns a ``_key`` unless one is provided in ``record``.

        Parameters
        ----------
        collection : str
            Collection name.
        record : dict
            Document to insert.

        Returns
        -------
        dict
            Response containing the assigned ``_key``.
        """
        safe = urllib.parse.quote(collection, safe="")
        url = (
            f"{self._client.config.base_url}"
            f"/servicesNS/{self._client.config.owner}"
            f"/{self._client.config.app_context}"
            f"/storage/collections/data/{safe}"
        )
        return self._client.post(
            url,
            raw_body=json.dumps(record).encode("utf-8"),
            content_type="application/json",
            namespaced=False,
        )

    def update_record(self, collection: str, key: str, record: dict) -> dict:
        """
        Replace a document (full update) by ``_key``.

        Parameters
        ----------
        collection : str
            Collection name.
        key : str
            Document ``_key`` to update.
        record : dict
            New document content.

        Returns
        -------
        dict
            Updated document.
        """
        safe_coll = urllib.parse.quote(collection, safe="")
        safe_key = urllib.parse.quote(key, safe="")
        url = (
            f"{self._client.config.base_url}"
            f"/servicesNS/{self._client.config.owner}"
            f"/{self._client.config.app_context}"
            f"/storage/collections/data/{safe_coll}/{safe_key}"
        )
        return self._client.put(url, data=record, namespaced=False)

    def delete_record(self, collection: str, key: str) -> None:
        """
        Delete a single document by ``_key``.

        Parameters
        ----------
        collection : str
            Collection name.
        key : str
            Document ``_key``.
        """
        safe_coll = urllib.parse.quote(collection, safe="")
        safe_key = urllib.parse.quote(key, safe="")
        url = (
            f"{self._client.config.base_url}"
            f"/servicesNS/{self._client.config.owner}"
            f"/{self._client.config.app_context}"
            f"/storage/collections/data/{safe_coll}/{safe_key}"
        )
        self._client.delete(url, namespaced=False)

    def delete_records(
        self,
        collection: str,
        query: dict | None = None,
    ) -> None:
        """
        Delete documents matching a query (or all documents if no query).

        Parameters
        ----------
        collection : str
            Collection name.
        query : dict | None
            MongoDB-style filter. Omit to delete ALL documents.
        """
        safe = urllib.parse.quote(collection, safe="")
        url = (
            f"{self._client.config.base_url}"
            f"/servicesNS/{self._client.config.owner}"
            f"/{self._client.config.app_context}"
            f"/storage/collections/data/{safe}"
        )
        if query:
            url += f"?query={urllib.parse.quote(json.dumps(query))}"
        self._client.delete(url, namespaced=False)

    def batch_insert(
        self,
        collection: str,
        records: list[dict],
        batch_size: int = 500,
    ) -> list[dict]:
        """
        Bulk insert documents using the KV store batch_save endpoint.

        Parameters
        ----------
        collection : str
            Collection name.
        records : list[dict]
            Documents to insert.
        batch_size : int
            Records per batch POST.

        Returns
        -------
        list[dict]
            Aggregated response bodies.
        """
        safe = urllib.parse.quote(collection, safe="")
        url = (
            f"{self._client.config.base_url}"
            f"/servicesNS/{self._client.config.owner}"
            f"/{self._client.config.app_context}"
            f"/storage/collections/data/{safe}/batch_save"
        )
        responses = []
        for i in range(0, len(records), batch_size):
            batch = records[i:i + batch_size]
            resp = self._client.post(
                url,
                raw_body=json.dumps(batch).encode("utf-8"),
                content_type="application/json",
                namespaced=False,
            )
            responses.append(resp)
        return responses

    def count_records(self, collection: str, query: dict | None = None) -> int:
        """
        Count documents in a collection, optionally filtered.

        Parameters
        ----------
        collection : str
            Collection name.
        query : dict | None
            MongoDB-style filter.

        Returns
        -------
        int
            Document count.
        """
        records = self.list_records(
            collection,
            query=query,
            fields=["_key"],
            count=0,
        )
        return len(records)

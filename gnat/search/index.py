# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.search.index
====================

:class:`SolrSearchIndex` — the Solr sidecar client.

This class is the **only** module in GNAT that knows Solr exists.
Everything else (ORM, pipeline, research library) talks to it through
the :class:`SearchIndex` abstract interface, which means you can swap
in Elasticsearch or a no-op stub without touching anything else.

Architecture constraints
------------------------
* **Read path**: ``search()`` returns STIX IDs only.  Callers fetch the
  full objects from the source of truth (Postgres / platform API).
  Solr is never authoritative.
* **Write path**: ``index()`` / ``index_batch()`` fire-and-forget from
  the pipeline layer.  A Solr outage never blocks an ingest run —
  errors are logged and counted but not raised.
* **Delete path**: called from ``STIXBase.delete()`` via the pipeline
  if wired in; keeps the index consistent without a full reindex.
* **Soft-commit / hard-commit**: all writes use ``softCommit=true``
  for NRT visibility.  A background hard-commit (``autoCommit`` in
  ``solrconfig.xml``) handles durability.  Do not hard-commit on every
  document write — that's the TQ mistake.

Solr schema assumptions (``managed-schema`` or ``schema.xml``)
--------------------------------------------------------------
The minimal field set this client expects::

    <field name="id"              type="string"      indexed="true"  stored="true" required="true"/>
    <field name="stix_type"       type="string"      indexed="true"  stored="true"/>
    <field name="source_platform" type="string"      indexed="true"  stored="true"/>
    <field name="created"         type="pdate"       indexed="true"  stored="true"/>
    <field name="modified"        type="pdate"       indexed="true"  stored="true"/>
    <field name="display_name"    type="string"      indexed="false" stored="true"/>
    <field name="text_content"    type="text_general" indexed="true" stored="false"/>

``text_content`` is ``stored="false"`` intentionally — the source of
truth holds the data; Solr holds only the inverted index.

Recommended ``solrconfig.xml`` auto-commit settings::

    <autoSoftCommit>
      <maxTime>5000</maxTime>          <!-- NRT: visible in 5 s -->
    </autoSoftCommit>
    <autoCommit>
      <maxTime>30000</maxTime>         <!-- Durability: flush every 30 s -->
      <openSearcher>false</openSearcher>
    </autoCommit>

Usage
-----
Direct::

    from gnat.search import SolrSearchIndex

    idx = SolrSearchIndex.from_config(cfg)
    idx.index(threat_actor_obj, source_platform="threatq")

    results = idx.search("Lazarus Group", stix_types=["threat-actor"])
    # returns list of STIX IDs → fetch full objects from your DB

Via IngestPipeline::

    pipeline = (
        IngestPipeline("daily-threatq")
        .read_from(reader)
        .map_with(mapper)
        .write_to(cli)
        .index_with(idx, source_platform="threatq")
        .run()
    )

Via ResearchLibrary (automatic when configured)::

    lib = ResearchLibrary.default()
    results = lib.search("Scattered Spider")   # routes to Solr transparently
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

import urllib3
from urllib3.util.retry import Retry

if TYPE_CHECKING:
    from gnat.config import GNATConfig
    from gnat.orm.base import STIXBase

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Abstract interface — everything outside this module uses this
# ---------------------------------------------------------------------------


class SearchIndex(ABC):
    """
    Abstract interface for all GNAT full-text search backends.

    Concrete implementations: :class:`SolrSearchIndex`, :class:`NullSearchIndex`.
    """

    @abstractmethod
    def index(
        self,
        obj: STIXBase,
        source_platform: str = "",
        extra_fields: dict[str, Any] | None = None,
    ) -> bool:
        """
        Index a single STIX object.

        Parameters
        ----------
        obj : STIXBase
            Object to index.  Must implement
            :meth:`~gnat.search.mixin.STIXSearchMixin.to_search_doc`
            or ``to_dict()`` as fallback.
        source_platform : str
            Connector that produced this object (stored as a facet field).
        extra_fields : dict, optional
            Additional metadata to merge into the index document.

        Returns
        -------
        bool
            ``True`` if the document was accepted by the backend,
            ``False`` on a non-fatal error (logged internally).
        """

    @abstractmethod
    def index_batch(
        self,
        objects: list[STIXBase],
        source_platform: str = "",
        extra_fields: dict[str, Any] | None = None,
    ) -> int:
        """
        Index a list of STIX objects in a single batch request.

        Returns
        -------
        int
            Number of documents successfully submitted.
        """

    @abstractmethod
    def delete(self, stix_id: str) -> bool:
        """
        Remove a document from the index by STIX ID.

        Returns ``True`` on success, ``False`` on non-fatal error.
        """

    @abstractmethod
    def search(
        self,
        query: str,
        stix_types: list[str] | None = None,
        source_platforms: list[str] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[str]:
        """
        Execute a full-text query against ``text_content``.

        Parameters
        ----------
        query : str
            User-supplied search string.  Passed to Solr as an
            ``edismax`` query against the ``text_content`` field.
        stix_types : list of str, optional
            Restrict results to these STIX types
            (e.g. ``["threat-actor", "malware"]``).
        source_platforms : list of str, optional
            Restrict results to objects from these connectors.
        limit : int
            Maximum number of IDs to return.
        offset : int
            Pagination offset.

        Returns
        -------
        list of str
            STIX IDs matching the query, ordered by Solr relevance score.
            Callers are responsible for fetching full objects from the
            source of truth.
        """

    @abstractmethod
    def ping(self) -> bool:
        """Return ``True`` if the backend is reachable."""


# ---------------------------------------------------------------------------
# Null implementation — safe default when Solr is not configured
# ---------------------------------------------------------------------------


class NullSearchIndex(SearchIndex):
    """
    No-op search index used when ``search_backend = memory`` (the default).

    All write methods return success without doing anything.
    ``search()`` always returns an empty list.
    ``ping()`` always returns ``True``.

    This lets :class:`~gnat.ingest.pipeline.IngestPipeline` and
    :class:`~gnat.research.library.ResearchLibrary` call index/search
    methods unconditionally without guarding for ``None``.
    """

    def index(self, obj, source_platform="", extra_fields=None) -> bool:
        return True

    def index_batch(self, objects, source_platform="", extra_fields=None) -> int:
        return len(objects)

    def delete(self, stix_id: str) -> bool:
        return True

    def search(
        self, query, stix_types=None, source_platforms=None, limit=50, offset=0
    ) -> list[str]:
        return []

    def ping(self) -> bool:
        return True

    def __repr__(self) -> str:  # pragma: no cover
        return "NullSearchIndex()"


# ---------------------------------------------------------------------------
# Solr implementation
# ---------------------------------------------------------------------------


class SolrSearchIndex(SearchIndex):
    """
    Solr sidecar client for GNAT full-text search.

    Parameters
    ----------
    base_url : str
        Solr base URL including collection path,
        e.g. ``"http://localhost:8983/solr/gnat"``.
    timeout : float
        HTTP timeout in seconds.  Defaults to ``10``.
    max_retries : int
        Retries on transient errors (429, 5xx).  Defaults to ``2``.
    verify_ssl : bool
        Whether to verify TLS certificates.  Defaults to ``True``.
    batch_size : int
        Maximum documents per ``index_batch()`` POST.  Defaults to ``100``.

    Examples
    --------
    >>> idx = SolrSearchIndex("http://localhost:8983/solr/gnat")
    >>> idx.ping()
    True
    >>> ids = idx.search("Lazarus Group", stix_types=["threat-actor"])
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = 10.0,
        max_retries: int = 2,
        verify_ssl: bool = True,
        batch_size: int = 100,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.batch_size = batch_size

        retry = Retry(
            total=max_retries,
            backoff_factor=0.3,
            status_forcelist={429, 500, 502, 503, 504},
            allowed_methods={"GET", "POST"},
        )
        kwargs: dict[str, Any] = {
            "retries": retry,
            "timeout": urllib3.Timeout(connect=timeout, read=timeout),
        }
        if not verify_ssl:
            kwargs["cert_reqs"] = "CERT_NONE"
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self._http = urllib3.PoolManager(**kwargs)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls, config: GNATConfig) -> SolrSearchIndex:
        """
        Construct a :class:`SolrSearchIndex` from a ``[search]`` INI section.

        Expected config keys::

            [search]
            backend     = solr
            solr_url    = http://localhost:8983/solr/gnat
            timeout     = 10
            max_retries = 2
            verify_ssl  = true
            batch_size  = 100

        Parameters
        ----------
        config : GNATConfig
            Loaded configuration object.

        Returns
        -------
        SolrSearchIndex

        Raises
        ------
        KeyError
            If the ``[search]`` section is absent or ``solr_url`` is missing.
        """
        cfg = config.get("search")
        url = cfg.get("solr_url", "").strip()
        if not url:
            raise KeyError(
                "[search] section is missing 'solr_url'. "
                "Set search.solr_url = http://<host>:8983/solr/<collection>"
            )
        return cls(
            base_url=url,
            timeout=float(cfg.get("timeout", 10)),
            max_retries=int(cfg.get("max_retries", 2)),
            verify_ssl=cfg.get("verify_ssl", "true").lower() == "true",
            batch_size=int(cfg.get("batch_size", 100)),
        )

    # ------------------------------------------------------------------
    # SearchIndex interface
    # ------------------------------------------------------------------

    def index(
        self,
        obj: STIXBase,
        source_platform: str = "",
        extra_fields: dict[str, Any] | None = None,
    ) -> bool:
        doc = self._to_doc(obj, source_platform, extra_fields)
        return self._post_documents([doc])

    def index_batch(
        self,
        objects: list[STIXBase],
        source_platform: str = "",
        extra_fields: dict[str, Any] | None = None,
    ) -> int:
        if not objects:
            return 0
        submitted = 0
        for chunk_start in range(0, len(objects), self.batch_size):
            chunk = objects[chunk_start : chunk_start + self.batch_size]
            docs = [self._to_doc(o, source_platform, extra_fields) for o in chunk]
            if self._post_documents(docs):
                submitted += len(docs)
        return submitted

    def delete(self, stix_id: str) -> bool:
        """Delete by STIX ID using Solr's delete-by-ID API."""
        url = f"{self.base_url}/update?softCommit=true"
        payload = {"delete": {"id": stix_id}}
        return self._post_json(url, payload)

    def search(
        self,
        query: str,
        stix_types: list[str] | None = None,
        source_platforms: list[str] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[str]:
        """
        Execute an eDisMax full-text query and return matching STIX IDs.

        Solr query structure
        --------------------
        * ``q``  — eDisMax against ``text_content`` only
        * ``fq`` — filter queries for ``stix_type`` and ``source_platform``
          (filter queries are cached separately by Solr, so they're free
          to layer on top of a cached FT result set)
        * ``fl`` — return ``id`` only; Solr is never the data source
        * ``rows`` / ``start`` — pagination
        """
        params: dict[str, Any] = {
            "q": query,
            "defType": "edismax",
            "qf": "text_content",
            "fl": "id",
            "rows": limit,
            "start": offset,
            "wt": "json",
        }

        fq: list[str] = []
        if stix_types:
            type_clause = " OR ".join(f'"{t}"' for t in stix_types)
            fq.append(f"stix_type:({type_clause})")
        if source_platforms:
            plat_clause = " OR ".join(f'"{p}"' for p in source_platforms)
            fq.append(f"source_platform:({plat_clause})")
        if fq:
            params["fq"] = fq

        url = f"{self.base_url}/select?{urlencode(params, doseq=True)}"
        try:
            resp = self._http.request("GET", url)
            if resp.status != 200:
                logger.warning("Solr search returned HTTP %s for query %r", resp.status, query)
                return []
            data = json.loads(resp.data.decode("utf-8"))
            docs = data.get("response", {}).get("docs", [])
            return [d["id"] for d in docs if "id" in d]
        except Exception as exc:  # noqa: BLE001
            logger.warning("Solr search failed for query %r: %s", query, exc)
            return []

    def ping(self) -> bool:
        """Check Solr admin ping endpoint."""
        try:
            resp = self._http.request("GET", f"{self.base_url}/admin/ping?wt=json")
            if resp.status == 200:
                data = json.loads(resp.data.decode("utf-8"))
                return data.get("status") == "OK"
        except Exception:  # noqa: BLE001
            pass
        return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _to_doc(
        self,
        obj: STIXBase,
        source_platform: str,
        extra_fields: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """
        Convert a STIX object to a flat Solr document.

        Prefers ``to_search_doc()`` (STIXSearchMixin) and falls back to
        a minimal doc built from ``to_dict()`` so that objects that have
        *not* had the mixin applied still get indexed safely.
        """
        if hasattr(obj, "to_search_doc"):
            return obj.to_search_doc(
                source_platform=source_platform,
                extra_fields=extra_fields,
            )
        # Fallback: minimal doc with best-effort text_content from all
        # string values in to_dict() that aren't structural fields.
        from gnat.search.mixin import _STRUCTURED_FIELDS

        raw = obj.to_dict()
        text_parts = [
            str(v)
            for k, v in raw.items()
            if k not in _STRUCTURED_FIELDS and isinstance(v, str) and v.strip()
        ]
        doc: dict[str, Any] = {
            "id": obj.id,
            "stix_type": obj.stix_type,
            "created": obj.created,
            "modified": obj.modified,
            "source_platform": source_platform,
            "display_name": raw.get("name") or raw.get("value") or obj.id,
            "text_content": " ".join(text_parts),
        }
        if extra_fields:
            doc.update(extra_fields)
        return doc

    def _post_documents(self, docs: list[dict[str, Any]]) -> bool:
        """POST a list of documents to Solr update endpoint with softCommit."""
        url = f"{self.base_url}/update?softCommit=true&wt=json"
        return self._post_json(url, docs)

    def _post_json(self, url: str, payload: Any) -> bool:
        """
        POST JSON payload to *url*.  Returns ``True`` on HTTP 200.
        Non-fatal errors are logged and swallowed — a Solr outage must
        never propagate into the ingest pipeline.
        """
        try:
            body = json.dumps(payload).encode("utf-8")
            resp = self._http.request(
                "POST",
                url,
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
            if resp.status == 200:
                return True
            logger.warning(
                "Solr update returned HTTP %s: %s",
                resp.status,
                resp.data.decode("utf-8", errors="replace")[:200],
            )
            return False
        except Exception as exc:  # noqa: BLE001
            logger.warning("Solr update failed: %s", exc)
            return False

    def __repr__(self) -> str:  # pragma: no cover
        return f"SolrSearchIndex(base_url={self.base_url!r})"

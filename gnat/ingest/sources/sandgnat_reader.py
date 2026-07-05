# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.ingest.sources.sandgnat_reader
======================================

SandGNAT detonation-result reader.

Pulls completed analyses from a SandGNAT sandbox over its export API and
yields the STIX 2.1 objects from each server-built bundle, ready for
:class:`~gnat.ingest.mappers.mappers.STIXPassthroughMapper`. Each yielded
object is stamped with ``x_sandgnat_analysis_id`` so workspace contents
trace back to the detonation that produced them.

Designed for FeedJob polling — pass ``since=ctx.last_success_iso`` so each
run only ingests analyses completed after the previous success::

    from gnat.ingest import IngestPipeline
    from gnat.ingest.sources import SandGNATReader
    from gnat.ingest.mappers import STIXPassthroughMapper

    reader = SandGNATReader(client=sandgnat_client, since="2026-07-01T00:00:00Z")
    result = (
        IngestPipeline("sandgnat-detonations")
        .read_from(reader)
        .map_with(STIXPassthroughMapper())
        .write_to(workspace_client)
    ).run()

Scheduled feed::

    job = FeedJob(
        job_id="sandgnat-poll",
        reader_factory=lambda ctx: SandGNATReader(
            client=sandgnat_client,
            since=ctx.last_success_iso,
        ),
        mapper_factory=lambda ctx: STIXPassthroughMapper(),
        interval_seconds=900,
        client=workspace_client,
    )
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Any

from gnat.ingest.base import RawRecord, SourceReader

logger = logging.getLogger(__name__)


class SandGNATReader(SourceReader):
    """
    Read STIX objects from completed SandGNAT detonations.

    For every ``completed`` analysis matching the filters, fetches the
    server-built STIX 2.1 bundle and yields its objects. Analyses whose
    bundle cannot be fetched (e.g. a status race between listing and the
    bundle pull) are logged and skipped — one bad analysis never aborts
    the feed run.

    Parameters
    ----------
    client : SandGNATClient, optional
        Connected SandGNAT connector. If omitted, one is built from the
        ``[sandgnat]`` config section when the reader opens.
    since : str, optional
        ISO-8601 timestamp; only analyses submitted after this instant
        are pulled. Wire to ``ctx.last_success_iso`` in a FeedJob.
    investigation_id : str, optional
        Only analyses tagged with this GNAT investigation.
    sha256 : str, optional
        Only analyses of this sample hash.
    stix_types : list of str, optional
        Only yield bundle objects of these STIX types.
    include_analysis_summary : bool
        Also yield a ``malware-analysis`` summary object per job (built
        via the connector's ``to_stix``), ahead of its bundle objects.
        Default True.
    max_analyses : int, optional
        Hard cap on analyses processed in one run.
    page_size : int
        Analyses fetched per export-API page (server caps at 200).
    """

    def __init__(
        self,
        client: Any = None,
        *,
        since: str | None = None,
        investigation_id: str | None = None,
        sha256: str | None = None,
        stix_types: list[str] | None = None,
        include_analysis_summary: bool = True,
        max_analyses: int | None = None,
        page_size: int = 100,
        **kwargs: Any,
    ):
        """Initialize SandGNATReader."""
        super().__init__(source_id=kwargs.pop("source_id", "sandgnat"), **kwargs)
        self._client = client
        self._since = since
        self._investigation_id = investigation_id
        self._sha256 = sha256
        self._stix_types = set(stix_types) if stix_types else None
        self._include_summary = include_analysis_summary
        self._max_analyses = max_analyses
        self._page_size = page_size

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def open(self) -> None:
        """Open the reader, building a client from config if none given."""
        if self._client is None:
            from gnat.config import GNATConfig
            from gnat.connectors.sandgnat.client import SandGNATClient

            cfg = GNATConfig().get("sandgnat")
            self._client = SandGNATClient(host=cfg.get("host", ""), api_key=cfg.get("api_key", ""))
            self._client.authenticate()
        super().open()

    # ------------------------------------------------------------------
    # Iteration
    # ------------------------------------------------------------------

    def _iter_records(self) -> Iterator[RawRecord]:
        """Yield STIX objects from completed detonation bundles."""
        from gnat.clients.base import GNATClientError

        filters: dict[str, Any] = {"status": "completed"}
        if self._since:
            filters["since"] = self._since
        if self._investigation_id:
            filters["investigation_id"] = self._investigation_id
        if self._sha256:
            filters["sha256"] = self._sha256

        processed = 0
        page = 1
        while True:
            jobs = self._client.list_objects(
                "malware-analysis",
                filters=filters,
                page=page,
                page_size=self._page_size,
            )
            if not jobs:
                return

            for job in jobs:
                if self._max_analyses is not None and processed >= self._max_analyses:
                    logger.info(
                        "%s: max_analyses=%d reached, stopping",
                        self.source_id,
                        self._max_analyses,
                    )
                    return
                processed += 1

                analysis_id = str(job.get("id", ""))
                yield from self._records_for_analysis(analysis_id, job, GNATClientError)

            if len(jobs) < self._page_size:
                return
            page += 1

    def _records_for_analysis(
        self, analysis_id: str, job: dict[str, Any], error_cls: type
    ) -> Iterator[RawRecord]:
        """Yield the summary object and bundle objects for one analysis."""
        if self._include_summary:
            try:
                summary = self._client.to_stix(dict(job))
            except Exception:  # noqa: BLE001 — summary is best-effort
                logger.warning(
                    "%s: could not build summary for analysis %s",
                    self.source_id,
                    analysis_id,
                )
            else:
                if self._type_allowed(summary.get("type", "")):
                    yield self._stamp(summary, analysis_id)

        try:
            objects = self._client.get_bundle_objects(analysis_id)
        except error_cls as exc:
            # Status races (listed as completed, bundle 409s) and transient
            # failures skip the analysis rather than aborting the run.
            logger.warning(
                "%s: skipping analysis %s — bundle unavailable (%s)",
                self.source_id,
                analysis_id,
                exc,
            )
            return

        for obj in objects:
            if not isinstance(obj, dict):
                continue
            if not self._type_allowed(obj.get("type", "")):
                continue
            yield self._stamp(dict(obj), analysis_id)

    def _type_allowed(self, obj_type: str) -> bool:
        return self._stix_types is None or obj_type in self._stix_types

    @staticmethod
    def _stamp(obj: dict[str, Any], analysis_id: str) -> dict[str, Any]:
        """Stamp detonation provenance without clobbering existing values."""
        obj.setdefault("x_sandgnat_analysis_id", analysis_id)
        return obj

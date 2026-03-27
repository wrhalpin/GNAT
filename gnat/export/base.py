"""
gnat.export.base
=====================

Core abstractions for the GNAT export/integration pipeline.

Export is a *push* operation — it differs from ingestion in a critical way:
the target often needs a **complete, authoritative list**, not an incremental
update.  A firewall EDL can't receive a diff; it needs the current full set
of blocked indicators.  This shapes the entire design.

Three-stage pipeline::

    Filter → Transform → Deliver

    Filter     — which objects to include (type, TLP, confidence, tags, age)
    Transform  — render objects into the target's native format
    Deliver    — push the rendered payload to the destination

All three stages are composable protocol classes.  Concrete implementations
live in ``gnat.export.filters``, ``gnat.export.transforms.*``, and
``gnat.export.delivery.*``.

Usage::

    from gnat.export import ExportPipeline
    from gnat.export.filters import TypeFilter, ConfidenceFilter, TLPFilter
    from gnat.export.transforms.edl import EDLTransform
    from gnat.export.delivery.file import FileDelivery

    pipeline = (
        ExportPipeline("tq-to-edl")
        .read_from(workspace)
        .filter_with(TypeFilter("indicator"))
        .filter_with(ConfidenceFilter(min_confidence=70))
        .filter_with(TLPFilter(["white", "green"]))
        .transform_with(EDLTransform(ioc_types=["ipv4", "domain", "url"]))
        .deliver_to(FileDelivery("/var/www/edl/indicators.txt"))
    )

    result = pipeline.run()
    print(result)   # ExportResult: 847 objects → 3 files

The pipeline is designed to be wrapped in a :class:`~gnat.export.jobs.ExportJob`
for scheduled delivery::

    from gnat.export.jobs import ExportJob
    from gnat.schedule import FeedScheduler

    job = ExportJob(
        job_id="tq-to-edl-hourly",
        pipeline_factory=lambda ctx: build_pipeline(),
        interval_seconds=3600,
    )
    scheduler = FeedScheduler()
    scheduler.add(job)
    scheduler.start()
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from gnat.context.workspace import Workspace
    from gnat.orm.base import STIXBase

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# ExportFilter — which objects to include
# ---------------------------------------------------------------------------

class ExportFilter(ABC):
    """
    Abstract base for export filters.

    A filter takes a stream of :class:`~gnat.orm.base.STIXBase` objects
    and yields only those that pass its predicate.
    """

    @abstractmethod
    def __call__(self, objects: Iterable["STIXBase"]) -> Iterator["STIXBase"]:
        """Yield objects that pass this filter."""

    def __and__(self, other: "ExportFilter") -> "CompositeFilter":
        return CompositeFilter([self, other])

    def __repr__(self) -> str:  # pragma: no cover
        return f"{self.__class__.__name__}()"


class CompositeFilter(ExportFilter):
    """Chain of filters applied left-to-right (logical AND)."""

    def __init__(self, filters: List["ExportFilter"]):
        self._filters = filters

    def __call__(self, objects: Iterable["STIXBase"]) -> Iterator["STIXBase"]:
        stream: Iterable["STIXBase"] = objects
        for f in self._filters:
            stream = f(stream)
        return iter(stream)

    def __and__(self, other: "ExportFilter") -> "CompositeFilter":
        return CompositeFilter(self._filters + [other])


class PassthroughFilter(ExportFilter):
    """Identity filter — passes everything."""

    def __call__(self, objects: Iterable["STIXBase"]) -> Iterator["STIXBase"]:
        return iter(objects)


# ---------------------------------------------------------------------------
# ExportTransform — render objects into a target format
# ---------------------------------------------------------------------------

class ExportTransform(ABC):
    """
    Abstract base for export transforms.

    A transform takes a list of :class:`~gnat.orm.base.STIXBase` objects
    and produces a :class:`TransformResult` — one or more named payloads
    ready to deliver.  The payloads are a dict so that transforms that
    produce multiple output files (e.g. separate IPv4/domain/URL EDL files)
    can return all of them in one call.

    Parameters
    ----------
    label : str, optional
        Human-readable name for log messages.
    """

    def __init__(self, label: str = ""):
        self.label = label or self.__class__.__name__

    @abstractmethod
    def transform(self, objects: List["STIXBase"]) -> "TransformResult":
        """
        Convert objects to one or more named payloads.

        Parameters
        ----------
        objects : list of STIXBase
            Objects that passed all filters.

        Returns
        -------
        TransformResult
            Named payloads ready for delivery.
        """

    def __repr__(self) -> str:  # pragma: no cover
        return f"{self.__class__.__name__}(label={self.label!r})"


@dataclass
class TransformResult:
    """
    Output of an :class:`ExportTransform`.

    Attributes
    ----------
    payloads : dict
        ``{name: content}`` — content is ``str`` (text), ``bytes``
        (binary), or ``dict``/``list`` (JSON-serializable).
    object_count : int
        Number of source objects that contributed to the output.
    metadata : dict
        Arbitrary metadata about the transform (counts, warnings, etc.).
    """

    payloads:     Dict[str, Any]   = field(default_factory=dict)
    object_count: int              = 0
    metadata:     Dict[str, Any]   = field(default_factory=dict)

    def payload_names(self) -> List[str]:
        return list(self.payloads.keys())

    def total_bytes(self) -> int:
        total = 0
        for v in self.payloads.values():
            if isinstance(v, bytes):
                total += len(v)
            elif isinstance(v, str):
                total += len(v.encode())
        return total


# ---------------------------------------------------------------------------
# ExportDelivery — push the payload to a destination
# ---------------------------------------------------------------------------

class ExportDelivery(ABC):
    """
    Abstract base for export delivery targets.

    A delivery target receives a :class:`TransformResult` and pushes each
    named payload to its destination.
    """

    @abstractmethod
    def deliver(self, result: TransformResult) -> "DeliveryResult":
        """
        Push the transform output to the destination.

        Parameters
        ----------
        result : TransformResult
            Named payloads from the transform stage.

        Returns
        -------
        DeliveryResult
            Outcome of the delivery attempt.
        """

    def __repr__(self) -> str:  # pragma: no cover
        return f"{self.__class__.__name__}()"


@dataclass
class DeliveryResult:
    """
    Outcome of one delivery attempt.

    Attributes
    ----------
    success : bool
        Whether all payloads were delivered without error.
    delivered : list of str
        Names of payloads that were successfully delivered.
    failed : list of str
        Names of payloads that failed to deliver.
    errors : list of str
        Error messages for failed deliveries.
    metadata : dict
        Delivery-specific metadata (URLs, response codes, file paths, etc.).
    """

    success:   bool           = True
    delivered: List[str]      = field(default_factory=list)
    failed:    List[str]      = field(default_factory=list)
    errors:    List[str]      = field(default_factory=list)
    metadata:  Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:  # pragma: no cover
        if self.success:
            return f"DeliveryResult: {len(self.delivered)} delivered"
        return (
            f"DeliveryResult: {len(self.delivered)} delivered, "
            f"{len(self.failed)} failed — {'; '.join(self.errors[:3])}"
        )


# ---------------------------------------------------------------------------
# ExportResult — summary of a complete pipeline run
# ---------------------------------------------------------------------------

@dataclass
class ExportResult:
    """
    Summary of a complete :class:`ExportPipeline` run.

    Attributes
    ----------
    pipeline_id : str
        Pipeline label.
    started_at : datetime
        When the pipeline started.
    finished_at : datetime or None
        When the pipeline completed, or ``None`` if still running.
    source_objects : int
        Total objects read from the source workspace.
    filtered_objects : int
        Objects that passed all filters.
    transform_result : TransformResult or None
        Output of the transform stage.
    delivery_result : DeliveryResult or None
        Outcome of the delivery stage.
    errors : list of str
        Pipeline-level errors (not per-payload errors).
    duration_seconds : float
        Wall-clock time for the run.
    """

    pipeline_id:      str
    started_at:       datetime
    finished_at:      Optional[datetime]    = None
    source_objects:   int                  = 0
    filtered_objects: int                  = 0
    transform_result: Optional[TransformResult] = None
    delivery_result:  Optional[DeliveryResult]  = None
    errors:           List[str]            = field(default_factory=list)
    duration_seconds: float                = 0.0

    @property
    def success(self) -> bool:
        return (
            not self.errors
            and (self.delivery_result is None or self.delivery_result.success)
        )

    def __str__(self) -> str:  # pragma: no cover
        status = "OK" if self.success else "FAILED"
        return (
            f"ExportResult[{status}] {self.pipeline_id}: "
            f"{self.source_objects} source → {self.filtered_objects} filtered → "
            f"{self.transform_result.object_count if self.transform_result else 0} transformed "
            f"in {self.duration_seconds:.1f}s"
        )


# ---------------------------------------------------------------------------
# ExportPipeline — orchestrates filter → transform → deliver
# ---------------------------------------------------------------------------

class ExportPipeline:
    """
    Fluent builder for a filter → transform → deliver pipeline.

    Parameters
    ----------
    pipeline_id : str
        Human-readable label used in logging and :class:`ExportResult`.

    Examples
    --------
    ::

        pipeline = (
            ExportPipeline("tq-to-palo-alto")
            .read_from(workspace)
            .filter_with(TypeFilter("indicator"))
            .filter_with(ConfidenceFilter(min_confidence=70))
            .transform_with(EDLTransform(ioc_types=["ipv4", "domain", "url"]))
            .deliver_to(FileDelivery("/srv/edl/"))
        )
        result = pipeline.run()
    """

    def __init__(self, pipeline_id: str = "export"):
        self.pipeline_id  = pipeline_id
        self._workspace:  Optional["Workspace"]      = None
        self._objects:    Optional[List["STIXBase"]] = None
        self._filters:    List[ExportFilter]          = []
        self._transform:  Optional[ExportTransform]   = None
        self._delivery:   Optional[ExportDelivery]    = None

    # ── Builder API ────────────────────────────────────────────────────────

    def read_from(
        self,
        source: Any,
    ) -> "ExportPipeline":
        """
        Set the object source.

        Parameters
        ----------
        source : Workspace or list of STIXBase or iterable
            If a :class:`~gnat.context.workspace.Workspace`, all objects
            in the workspace are used as the source.
            If a list/iterable, those objects are used directly.

        Returns
        -------
        ExportPipeline
            ``self`` for chaining.
        """
        from gnat.context.workspace import Workspace
        if isinstance(source, Workspace):
            self._workspace = source
        else:
            self._objects = list(source)
        return self

    def filter_with(self, *filters: ExportFilter) -> "ExportPipeline":
        """
        Add one or more filters.  Applied left-to-right (logical AND).

        Returns
        -------
        ExportPipeline
            ``self`` for chaining.
        """
        self._filters.extend(filters)
        return self

    def transform_with(self, transform: ExportTransform) -> "ExportPipeline":
        """
        Set the transform.  Only one transform is allowed per pipeline;
        for multiple output formats, create multiple pipelines.

        Returns
        -------
        ExportPipeline
            ``self`` for chaining.
        """
        self._transform = transform
        return self

    def deliver_to(self, delivery: ExportDelivery) -> "ExportPipeline":
        """
        Set the delivery target.

        Returns
        -------
        ExportPipeline
            ``self`` for chaining.
        """
        self._delivery = delivery
        return self

    # ── Execution ──────────────────────────────────────────────────────────

    def run(self) -> ExportResult:
        """
        Execute the pipeline synchronously.

        Order of operations:
        1. Collect all objects from the source.
        2. Apply all filters in order.
        3. Pass filtered objects to the transform.
        4. Pass the transform result to the delivery target.

        Returns
        -------
        ExportResult
            Summary of the run.
        """
        t0     = time.perf_counter()
        result = ExportResult(pipeline_id=self.pipeline_id, started_at=_utcnow())

        try:
            # 1. Source
            all_objects = self._collect_source()
            result.source_objects = len(all_objects)

            # 2. Filter
            filtered = self._apply_filters(all_objects)
            result.filtered_objects = len(filtered)

            if not filtered:
                logger.info(
                    "ExportPipeline %r: 0 objects after filtering "
                    "(source had %d) — skipping transform/deliver",
                    self.pipeline_id, result.source_objects,
                )
                result.finished_at      = _utcnow()
                result.duration_seconds = time.perf_counter() - t0
                return result

            # 3. Transform
            if self._transform is None:
                # No transform — produce a raw passthrough result
                tr = TransformResult(
                    payloads={"objects": filtered},
                    object_count=len(filtered),
                )
            else:
                tr = self._transform.transform(filtered)
            result.transform_result = tr

            logger.info(
                "ExportPipeline %r: %d → %d filtered → %d in transform "
                "(%s payloads, %d bytes)",
                self.pipeline_id, result.source_objects,
                result.filtered_objects, tr.object_count,
                len(tr.payloads), tr.total_bytes(),
            )

            # 4. Deliver
            if self._delivery is not None:
                dr = self._delivery.deliver(tr)
                result.delivery_result = dr
                if not dr.success:
                    for err in dr.errors:
                        result.errors.append(f"Delivery error: {err}")

        except Exception as exc:  # noqa: BLE001
            result.errors.append(str(exc))
            logger.error(
                "ExportPipeline %r: unhandled error — %s",
                self.pipeline_id, exc,
            )

        result.finished_at      = _utcnow()
        result.duration_seconds = time.perf_counter() - t0

        if result.success:
            logger.info(
                "ExportPipeline %r: complete in %.2fs",
                self.pipeline_id, result.duration_seconds,
            )
        else:
            logger.warning(
                "ExportPipeline %r: finished with errors: %s",
                self.pipeline_id, result.errors,
            )

        return result

    # ── Dry run ────────────────────────────────────────────────────────────

    def dry_run(self) -> ExportResult:
        """
        Execute filter + transform but skip delivery.

        Useful for previewing what would be pushed without actually sending
        anything to external systems.

        Returns
        -------
        ExportResult
            Same as :meth:`run` but ``delivery_result`` is always ``None``.
        """
        saved   = self._delivery
        self._delivery = None
        result  = self.run()
        self._delivery = saved
        return result

    def preview(self, n: int = 20) -> List["STIXBase"]:
        """
        Return the first *n* objects that would pass filtering.

        Does not transform or deliver anything.

        Parameters
        ----------
        n : int
            Maximum objects to return.  Default 20.

        Returns
        -------
        list of STIXBase
        """
        all_objects = self._collect_source()
        filtered    = self._apply_filters(all_objects)
        return filtered[:n]

    # ── Internal ────────────────────────────────────────────────────────────

    def _collect_source(self) -> List["STIXBase"]:
        if self._workspace is not None:
            return list(self._workspace.objects.values())
        if self._objects is not None:
            return self._objects
        raise RuntimeError(
            f"ExportPipeline {self.pipeline_id!r}: no source set. "
            "Call .read_from(workspace) before .run()."
        )

    def _apply_filters(self, objects: List["STIXBase"]) -> List["STIXBase"]:
        if not self._filters:
            return objects
        stream: Iterable["STIXBase"] = objects
        for f in self._filters:
            stream = f(stream)
        return list(stream)

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"ExportPipeline(id={self.pipeline_id!r}, "
            f"filters={len(self._filters)}, "
            f"transform={self._transform!r}, "
            f"delivery={self._delivery!r})"
        )

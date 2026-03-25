"""
ctm_sak.export
===============

Push-based export and integration pipeline for sharing threat intelligence
between platforms — EDLs, Netskope CE, STIX bundles, CSV, arbitrary HTTP.

Three-stage composable pipeline: Filter → Transform → Deliver

Quick start (ThreatQ → Palo Alto EDL)::

    from ctm_sak.export import ExportPipeline, ExportJob
    from ctm_sak.export.filters import TypeFilter, ConfidenceFilter, TLPFilter
    from ctm_sak.export.transforms.edl import EDLTransform
    from ctm_sak.export.delivery.targets import EDLServer
    from ctm_sak.schedule import FeedScheduler

    edl_server = EDLServer(port=8080)

    job = ExportJob(
        job_id="tq-to-edl",
        pipeline_factory=lambda ctx: (
            ExportPipeline("tq-to-palo-alto")
            .read_from(workspace)
            .filter_with(TypeFilter("indicator"))
            .filter_with(ConfidenceFilter(min_confidence=70))
            .filter_with(TLPFilter(["white", "green"]))
            .transform_with(EDLTransform(ioc_types=["ipv4", "domain", "url"]))
            .deliver_to(edl_server)
        ),
        interval_seconds=3600,
    )

    with FeedScheduler() as scheduler:
        scheduler.add(job)
        # Firewalls poll http://localhost:8080/indicators-ipv4.txt

ThreatQ → Netskope CE (FQDN + URL + SHA256)::

    from ctm_sak.export.transforms.netskope import NetskopeCETransform
    from ctm_sak.export.delivery.targets import PlatformDelivery

    job = ExportJob(
        job_id="tq-to-netskope-ce",
        pipeline_factory=lambda ctx: (
            ExportPipeline("tq-netskope")
            .read_from(workspace)
            .filter_with(TypeFilter("indicator"))
            .filter_with(ConfidenceFilter(min_confidence=70))
            .transform_with(NetskopeCETransform(
                ioc_types=["domain", "url", "sha256"],
                list_name="ThreatQ-Indicators",
            ))
            .deliver_to(PlatformDelivery(netskope_client))
        ),
        interval_seconds=900,
    )
"""

from ctm_sak.export.base import (
    ExportFilter,
    ExportTransform,
    ExportDelivery,
    ExportPipeline,
    ExportResult,
    TransformResult,
    DeliveryResult,
    PassthroughFilter,
)
from ctm_sak.export.jobs import ExportJob

__all__ = [
    # Core abstractions
    "ExportFilter",
    "ExportTransform",
    "ExportDelivery",
    "ExportPipeline",
    "ExportResult",
    "TransformResult",
    "DeliveryResult",
    "PassthroughFilter",
    # Scheduled export job
    "ExportJob",
]

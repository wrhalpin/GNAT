# How-to: Export Indicators

Recipes for filtering, transforming, and delivering threat intelligence to downstream systems.

---

## ThreatQ indicators → Palo Alto EDL

Serve a live Enforcement-based Detection List on port 8080 that firewalls poll:

```python
from gnat.export import ExportPipeline, ExportJob
from gnat.export.filters import TypeFilter, ConfidenceFilter, TLPFilter
from gnat.export.transforms.edl import EDLTransform
from gnat.export.delivery.targets import FileDelivery, EDLServer

# Serve live EDL on port 8080 (firewalls poll this)
edl_server = EDLServer(port=8080)

job = ExportJob(
    job_id = "tq-to-palo-alto",
    pipeline_factory = lambda ctx: (
        ExportPipeline("tq-palo-alto")
        .read_from(workspace)
        .filter_with(TypeFilter("indicator"))
        .filter_with(ConfidenceFilter(min_confidence=70))
        .filter_with(TLPFilter(["white", "green"]))
        .transform_with(EDLTransform(ioc_types=["ipv4", "domain", "url"]))
        .deliver_to(edl_server)
    ),
    interval_seconds = 3600,
)
```

---

## ThreatQ → Netskope CE (FQDN + URL + SHA256)

```python
from gnat.export.filters import IOCTypeFilter
from gnat.export.transforms.netskope import NetskopeCETransform
from gnat.export.delivery.targets import PlatformDelivery

job = ExportJob(
    job_id = "tq-to-netskope-ce",
    pipeline_factory = lambda ctx: (
        ExportPipeline("tq-netskope")
        .read_from(workspace)
        .filter_with(TypeFilter("indicator"))
        .filter_with(ConfidenceFilter(min_confidence=70))
        .filter_with(IOCTypeFilter(["domain", "url", "sha256"]))
        .transform_with(NetskopeCETransform(
            source_label = "ThreatQ",
            ioc_types    = ["domain", "url", "sha256"],
        ))
        .deliver_to(PlatformDelivery(netskope_client))
    ),
    interval_seconds = 900,   # every 15 minutes
)
```

---

## Export to STIX bundle file

```python
from gnat.export.transforms.netskope import STIXBundleTransform

result = (
    ExportPipeline("stix-export")
    .read_from(workspace)
    .filter_with(TypeFilter("indicator"))
    .transform_with(STIXBundleTransform())
    .deliver_to(FileDelivery("/var/exports/daily-bundle/"))
).run()
```

---

## See Also

- [How-to: Schedule Feeds](schedule-feeds.md)
- [How-to: Use Workspaces](use-workspaces.md)
- [Explanation: Export Integration Pipeline](../explanation/architecture/adrs/0017-export-integration-pipeline.md)

---

*Licensed under the Apache License, Version 2.0*

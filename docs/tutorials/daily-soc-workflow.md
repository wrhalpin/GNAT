# Tutorial: Daily SOC Workflow

This tutorial walks through a complete daily threat intelligence cycle:
check the research library, run AI research for stale topics, curate
staged objects, and push a live indicator EDL to your enforcement layer.

**Prerequisites**
- `gnat` installed and `config.ini` configured with ThreatQ and Claude credentials
- An EDL server or firewall that can poll port 8080

---

## 1. Import dependencies

```python
from gnat.research import ResearchLibrary, CurationJob
from gnat.agents import ResearchAgent, ParsingAgent, AgentConfig
from gnat.export import ExportPipeline
from gnat.export.filters import TypeFilter, ConfidenceFilter
from gnat.export.transforms.edl import EDLTransform
from gnat.export.delivery.targets import EDLServer
from gnat.ingest import IngestPipeline
```

---

## 2. Check the library — research only stale topics

The research library caches previous AI research results.
Skip topics that are still fresh to avoid redundant API calls.

```python
lib    = ResearchLibrary.default()
config = AgentConfig.from_ini()

for topic in ["APT29", "LockBit", "CVE-2024-3400"]:
    if not lib.is_fresh(topic):
        pipeline = (
            IngestPipeline(f"research-{topic}")
            .read_from(ResearchAgent(config, topics=[topic]))
            .map_with(ParsingAgent(config))
        )
        pipeline.run()
        lib.promote(workspace, topic=topic, researcher="automated",
                    note="Automated daily research cycle")
```

---

## 3. Curate staging → library

Move newly researched objects from the staging area into the library:

```python
CurationJob(lib).execute()
```

---

## 4. Export indicators to the EDL

Filter indicators by type and confidence, then serve them on port 8080
so your firewall or proxy can poll the list:

```python
edl_server = EDLServer(port=8080)

export_result = (
    ExportPipeline("daily-edl")
    .read_from(workspace)
    .filter_with(TypeFilter("indicator"))
    .filter_with(ConfidenceFilter(70))
    .transform_with(EDLTransform(ioc_types=["ipv4", "domain", "url"]))
    .deliver_to(edl_server)
).run()

print(f"EDL updated: {export_result.delivery_result.delivered}")
```

---

## Next steps

- Automate this cycle with `FeedScheduler` — see [Tutorial: Production Scheduled Pipeline](production-scheduled-pipeline.md)
- Add sector filtering to the EDL — see [How-to: Export Indicators](../how-to/export-indicators.md)
- Generate a PDF report at the end of the cycle — see [How-to: Generate Reports](../how-to/generate-reports.md)

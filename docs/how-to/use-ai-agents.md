# How-to: Use AI Agents

Run AI-assisted research, parsing, and content extraction workflows.

---

## Research agent — topic-driven

Research threat topics and extract STIX objects in a single pipeline:

```python
from gnat.agents import ResearchAgent, ParsingAgent, AgentConfig
from gnat.ingest import IngestPipeline

config = AgentConfig.from_ini()

# Research three threat topics and extract STIX intel
result = (
    IngestPipeline("threat-research")
    .read_from(ResearchAgent(
        config = config,
        topics = ["APT29", "Volt Typhoon", "CVE-2024-3400"],
    ))
    .map_with(ParsingAgent(config))
    .write_to(threatq_client)
).run()

print(f"Researched 3 topics → {result.written_objects} STIX objects")
```

---

## Research agent — monitored feeds (scheduled)

Poll threat intelligence blogs on a recurring schedule:

```python
job = FeedJob(
    job_id = "threat-feed-monitor",
    reader_factory = lambda ctx: ResearchAgent(
        config = AgentConfig.from_ini(),
        monitored_sources = [
            {"url": "https://unit42.paloaltonetworks.com/",
             "label": "Unit42"},
            {"url": "https://www.cisa.gov/news-events/cybersecurity-advisories",
             "label": "CISA Advisories"},
            {"url": "https://www.mandiant.com/resources/blog",
             "label": "Mandiant Blog"},
        ],
        newer_than = ctx.last_success_iso,
    ),
    mapper_factory   = lambda ctx: ParsingAgent(AgentConfig.from_ini()),
    interval_seconds = 21600,    # every 6 hours
    client           = threatq_client,
)
```

---

## M365 content via Copilot

Ingest from SharePoint, mailboxes, and Teams channels:

```python
from gnat.agents import CopilotReader

job = FeedJob(
    job_id = "m365-threat-intel",
    reader_factory = lambda ctx: CopilotReader.from_ini(
        sources = [
            {"type": "sharepoint", "name": "ThreatReports",
             "url": "https://contoso.sharepoint.com/sites/Security/ThreatReports"},
            {"type": "mailbox", "name": "VendorAdvisories",
             "query": "from:threatintel@vendor.com"},
            {"type": "teams_channel", "name": "SOC Intel",
             "team": "Security Operations", "channel": "Threat Intel"},
        ],
        newer_than = ctx.last_success_iso,
    ),
    mapper_factory   = lambda ctx: ParsingAgent(AgentConfig.from_ini()),
    interval_seconds = 3600,
)
```

---

## Parse unstructured text directly

Extract STIX objects from a raw advisory document:

```python
config = AgentConfig.from_ini()
agent  = ParsingAgent(config)

# Parse a threat advisory pasted as text
record = {
    "text":  open("advisory.txt").read(),
    "url":   "https://example.com/advisory",
    "topic": "LockBit 3.0",
}
for stix_obj in agent.map(record):
    print(stix_obj.stix_type, stix_obj.name, stix_obj.confidence)
    # All objects tagged x_source_type="ai_extracted", confidence <= 60
```

---

## See Also

- [How-to: Use the Research Library](use-research-library.md)
- [How-to: Schedule Feeds](schedule-feeds.md)
- [Explanation: AI Agent Layer](../explanation/architecture/adrs/0018-ai-agent-layer.md)

---

*Licensed under the Apache License, Version 2.0*

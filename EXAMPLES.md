# GNAT Examples

Code snippet reference for implementation and testing.
All examples assume `gnat` is installed and `config.ini` is configured.

---

## Table of Contents

1. [Configuration](#configuration)
2. [Connectors](#connectors)
3. [ORM / STIX Objects](#orm--stix-objects)
4. [Ingest Pipeline](#ingest-pipeline)
5. [Context and Workspaces](#context-and-workspaces)
6. [Export Pipeline (EDLs, Netskope CE)](#export-pipeline)
7. [Scheduling](#scheduling)
8. [AI Agents](#ai-agents)
9. [Research Library](#research-library)
10. [Report Generation](#report-generation)
11. [Visualization](#visualization)
12. [Async Client](#async-client)
13. [Full Workflows](#full-workflows)

---

## Configuration

### Minimal config.ini

```ini
[DEFAULT]
timeout    = 30
verify_ssl = true

[threatq]
host          = https://threatq.example.com
client_id     = my-client-id
client_secret = s3cr3t
auth_type     = oauth2

[claude]
api_key               = sk-ant-...
model                 = claude-sonnet-4-6
ai_confidence_ceiling = 60

[sector_aliases]
healthcare = Healthcare, Health, Medical, H-ISAC, Hospitals and Health Centers
financial  = Financial Services, Finance, Banking, FS-ISAC
```

### Loading config

```python
from gnat.config import SAKConfig

cfg = SAKConfig()                          # auto-finds ~/.gnat/config.ini
cfg = SAKConfig("/path/to/config.ini")     # explicit path
cfg = SAKConfig(os.environ["MY_CONFIG"])   # from env var

section = cfg.get("threatq")
print(section["host"])
```

---

## Connectors

### Connect to ThreatQ

```python
from gnat.connectors.threatq.client import ThreatQClient

client = ThreatQClient(
    host          = "https://threatq.example.com",
    client_id     = "my-id",
    client_secret = "my-secret",
)
client.authenticate()
client.health_check()

# List indicators
indicators = client.list_objects("indicator", page_size=50)

# Get one object
ind = client.get_object("indicator", "12345")

# Upsert
new_ind = client.upsert_object("indicator", {
    "value": "evil.com", "class": "Domain"
})
```

### Connect via SAKClient (config-driven)

```python
from gnat.client import SAKClient

client = SAKClient.from_config("threatq")   # reads [threatq] from config.ini
client.connect()
client.ping()
```

### VirusTotal

```python
from gnat.connectors.virustotal.client import VirusTotalClient

vt = VirusTotalClient(
    host    = "https://www.virustotal.com",
    api_key = "your-vt-api-key",
)
vt.authenticate()

# Look up a domain
domain_data = vt.get_object("indicator", "evil.com")

# Search for ransomware files (VT Intelligence required)
results = vt.list_objects("indicator",
    filters={"query": "type:peexe tag:ransomware"})

# Convert to STIX
for item in results:
    stix = vt.to_stix(item)
    print(stix["name"], stix["confidence"])
```

### ShadowServer

```python
from gnat.connectors.shadowserver.client import ShadowServerClient

ss = ShadowServerClient(
    api_key    = "your-ss-key",
    api_secret = "your-ss-secret",
)
ss.authenticate()

# Get open RDP exposures
records = ss.list_objects("indicator",
    filters={"report": "scan/rdp", "country": "US"})

# Get sinkholed IPs
sinkholes = ss.list_objects("indicator",
    filters={"report": "sinkhole", "date": "2024-03-21"})

for rec in records[:5]:
    print(ss.to_stix(rec))
```

### Rapid7 InsightVM

```python
from gnat.connectors.rapid7.client import Rapid7Client

r7 = Rapid7Client(
    host    = "https://us.api.insight.rapid7.com",
    api_key = "your-r7-key",
    product = "insightvm",
)
r7.authenticate()

# List critical vulnerabilities
vulns = r7.list_objects("vulnerability",
    filters={"severity": "critical", "status": "open"})

for v in vulns:
    stix = r7.to_stix(v)
    print(stix["name"], stix["x_cvss_score"], stix["x_actively_exploited"])
```

### Nucleus Security

```python
from gnat.connectors.nucleus.client import NucleusClient

ns = NucleusClient(
    api_key = "your-nucleus-key",
    project = "your-project-id",
)
ns.authenticate()

# List CISA KEV vulnerabilities
kev_vulns = ns.list_objects("vulnerability",
    filters={"kev": True, "status": "open"})

# High EPSS score vulnerabilities (>10% exploitation probability)
risky = ns.list_objects("vulnerability",
    filters={"epss_min": 0.10, "severity": "high"})

for v in risky:
    stix = ns.to_stix(v)
    print(stix["name"], stix["x_nucleus_epss"], stix["x_nucleus_kev"])
```

---

## ORM / STIX Objects

### Create STIX objects

```python
from gnat.orm import Indicator, ThreatActor, Vulnerability, AttackPattern, Relationship

# Indicator
ind = Indicator(
    name           = "evil.com",
    pattern        = "[domain-name:value = 'evil.com']",
    pattern_type   = "stix",
    confidence     = 75,
    indicator_types= ["malicious-activity"],
    x_tlp          = "green",
    x_target_sectors = ["Healthcare", "Opportunistic"],
)

# Threat actor
actor = ThreatActor(
    name               = "APT29",
    threat_actor_types = ["espionage"],
    aliases            = ["Cozy Bear", "The Dukes"],
    x_target_sectors   = ["Healthcare", "Government"],
)

# Vulnerability
vuln = Vulnerability(
    name                = "CVE-2024-3400",
    x_cve_id            = "CVE-2024-3400",
    x_cvss_score        = 10.0,
    x_actively_exploited= True,
    description         = "PAN-OS command injection",
)

# Relationship
rel = Relationship(
    relationship_type = "indicates",
    source_ref        = ind.id,
    target_ref        = actor.id,
)

# Serialize
print(ind.to_dict())
print(ind.to_stix_bundle())
```

---

## Ingest Pipeline

### Blocklist → ThreatQ

```python
from gnat.ingest import IngestPipeline
from gnat.ingest.sources.readers import PlainTextReader
from gnat.ingest.mappers.mappers import FlatIOCMapper

result = (
    IngestPipeline("blocklist-daily")
    .read_from(PlainTextReader("https://blocklist.example.com/ips.txt"))
    .map_with(FlatIOCMapper(confidence=70, tlp_marking="white"))
    .deduplicate(key_fields=["name"])
    .write_to(threatq_client)
).run()

print(result)  # IngestResult: 1247 records → 1247 mapped → 1201 written
```

### TAXII feed → ThreatQ (incremental)

```python
from gnat.ingest.sources.readers import TAXIICollectionReader

result = (
    IngestPipeline("taxii-daily")
    .read_from(TAXIICollectionReader(
        collection,
        added_after="2024-03-20T00:00:00Z",
    ))
    .map_with(STIXPassthroughMapper(client=threatq_client))
    .write_to(threatq_client)
).run()
```

### CSV file → workspace

```python
from gnat.ingest.sources.readers import CSVReader
from gnat.ingest.mappers.mappers import CSVIndicatorMapper

result = (
    IngestPipeline("csv-import")
    .read_from(CSVReader("threat_intel.csv"))
    .map_with(CSVIndicatorMapper(
        value_field    = "ioc_value",
        type_field     = "ioc_type",
        confidence_field = "score",
    ))
    .write_to(threatq_client)
).run()
```

### Splunk alerts → indicators (incremental)

```python
from gnat.ingest.sources.readers import SplunkReader

result = (
    IngestPipeline("splunk-alerts")
    .read_from(SplunkReader(
        splunk_client,
        search='search index=security sourcetype=alerts earliest=-24h',
    ))
    .map_with(SplunkResultMapper(
        indicator_field = "dest_ip",
        indicator_type  = "ipv4",
        confidence      = 65,
    ))
    .write_to(threatq_client)
).run()
```

---

## Context and Workspaces

### Create and use a workspace

```python
from gnat.context import GlobalContextRegistry, GlobalContext, Workspace, FlatFileStore
from gnat.context.workspace import WorkspaceManager

# Setup
store   = FlatFileStore(base_dir="~/.gnat/workspaces")
manager = WorkspaceManager(global_registry, store=store)

# Create / open
ws = manager.get_or_create("apt29-investigation")

# Add objects
ws.add(indicator, mark_dirty=True)
ws.add(actor, mark_dirty=True)

# Diff — what changed since last commit
diff = ws.diff()
print(diff["added"], diff["modified"])

# Commit to ThreatQ
ws.commit(client=threatq_client)

# Export STIX bundle
bundle = ws.export_bundle()
```

### Global context registry

```python
from gnat.context import GlobalContextRegistry, GlobalContext

reg = GlobalContextRegistry()
reg.register(GlobalContext("tq",    threatq_client,      priority=10))
reg.register(GlobalContext("rf",    rf_client,           priority=20, read_only=True))
reg.register(GlobalContext("cs",    crowdstrike_client,  priority=15))
reg.set_default("tq")

# Enrich from all contexts
ws.enrich(strategy="create_relationships")
```

---

## Export Pipeline

### ThreatQ indicators → Palo Alto EDL

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

### ThreatQ → Netskope CE (FQDN + URL + SHA256)

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

### Export to STIX bundle file

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

## Scheduling

### Basic scheduled feed

```python
from gnat.schedule import FeedJob, FeedScheduler
from gnat.ingest.sources.readers import PlainTextReader
from gnat.ingest.mappers.mappers import FlatIOCMapper

job = FeedJob(
    job_id         = "blocklist-hourly",
    reader_factory = lambda ctx: PlainTextReader("https://blocklist.example.com/ips.txt"),
    mapper_factory = lambda ctx: FlatIOCMapper(confidence=70),
    interval_seconds = 3600,
    client           = threatq_client,
    on_failure       = lambda rec: logger.error("Feed failed: %s", rec.error),
)

with FeedScheduler() as scheduler:
    scheduler.add(job)
    # Runs in background threads until process exits
```

### Incremental TAXII feed (uses last_success_iso)

```python
job = FeedJob(
    job_id = "taxii-daily",
    reader_factory = lambda ctx: TAXIICollectionReader(
        collection,
        added_after = ctx.last_success_iso or "2024-01-01T00:00:00Z",
    ),
    mapper_factory = lambda ctx: STIXPassthroughMapper(client=tq_client),
    cron           = "0 2 * * *",   # 02:00 daily
    client         = threatq_client,
)
```

### Health monitoring

```python
scheduler = FeedScheduler()
# ... add jobs ...
scheduler.start()

# Check health
for status in scheduler.statuses():
    if not status["is_healthy"]:
        print(f"UNHEALTHY: {status['job_id']} — {status['last_run_status']}")

# Summary
print(scheduler.summary())
# {'running': True, 'total_jobs': 5, 'healthy': 4, 'failing': 1, 'total_runs': 47}
```

---

## AI Agents

### Research agent — topic-driven

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

### Research agent — monitored feeds (scheduled)

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

### M365 content via Copilot

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

### Parse unstructured text directly

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

## Research Library

### Check before researching

```python
from gnat.research import ResearchLibrary

lib = ResearchLibrary.default()

topic = "APT29"
if lib.is_fresh(topic):
    # Use cached research
    entry = lib.get(topic)
    print(f"Using research by {entry.researcher}: {entry.note}")
    lib.load_into_workspace(topic, my_workspace)
else:
    # Run agents, then promote result
    # ... research pipeline ...
    lib.promote(
        workspace  = my_workspace,
        topic      = topic,
        researcher = "analyst1",
        note       = "New C2 infra confirmed by Unit42 and Mandiant.",
    )
```

### Browse the library

```python
lib = ResearchLibrary.default()

# List all fresh entries
for entry in lib.list_entries():
    print(f"{entry['topic']:30s} {entry['age_hours']:5.1f}h  "
          f"{'✓' if entry['is_fresh'] else 'STALE':6s}  "
          f"{entry['researcher']}")

# Search
results = lib.search("phishing")
for e in results:
    print(e.topic, e.note[:80])
```

### Scheduled curation

```python
from gnat.research import ResearchLibrary, CurationJob
from gnat.schedule import FeedScheduler

lib     = ResearchLibrary.default()
curator = CurationJob(lib, interval_seconds=4 * 3600)

with FeedScheduler() as sched:
    sched.add(curator)
```

---

## Report Generation

### Daily report — no AI

```python
from gnat.reports import ReportGenerator, ReportConfig, AIMode

config = ReportConfig(
    report_type = "daily",
    workspaces  = ["_ctmsak_library", "analyst-workspace"],
    sectors     = ["Healthcare", "Insurance", "Opportunistic"],
    ai_mode     = AIMode.NONE,
    formats     = ["pdf", "html", "markdown"],
    delivery    = ["email", "file"],
    email_to    = ["soc-team@example.com"],
    output_dir  = "/var/reports/daily",
    org_name    = "Acme Health",
)

result = ReportGenerator(manager, config).run()
print(result.files_written)
```

### Trends report — AI-assisted

```python
from gnat.agents import AgentConfig

config = ReportConfig(
    report_type = "trends",
    workspaces  = ["_ctmsak_library"],
    sectors     = ["Healthcare", "Opportunistic"],
    ai_mode     = AIMode.ASSISTED,
    formats     = ["pdf", "docx"],
    delivery    = ["sharepoint", "email"],
    sharepoint_url = "https://contoso.sharepoint.com/sites/Security/Reports",
    email_to    = ["soc-leads@example.com"],
    output_dir  = "/var/reports/trends",
    window_days = 30,
    org_name    = "Acme Health",
)

result = ReportGenerator(
    manager          = manager,
    config           = config,
    agent_config     = AgentConfig.from_ini(),
    research_library = ResearchLibrary.default(),
).run()
```

### Scheduled reports

```python
from gnat.reports import ReportJob
from gnat.schedule import FeedScheduler

daily_job = ReportJob(
    manager      = manager,
    config       = ReportConfig(
        report_type = "daily",
        formats     = ["pdf", "html"],
        delivery    = ["email"],
        email_to    = ["soc@example.com"],
        schedule    = "0 6 * * *",     # 06:00 daily
        org_name    = "Acme Health",
    ),
    agent_config     = AgentConfig.from_ini(),
    research_library = ResearchLibrary.default(),
)

yearly_job = ReportJob(
    manager = manager,
    config  = ReportConfig(
        report_type = "yearly",
        ai_mode     = AIMode.FULL,
        formats     = ["pdf", "docx"],
        delivery    = ["sharepoint", "email"],
        schedule    = "0 6 1 1 *",    # January 1st
    ),
    agent_config = AgentConfig.from_ini(),
)

with FeedScheduler() as sched:
    sched.add(daily_job)
    sched.add(yearly_job)
```

---

## Visualization

### GraphView — intent-driven

```python
from gnat.viz import GraphView

view = GraphView(workspace)

# How are objects connected?
view.render_relationship_graph()

# What types are in this workspace?
view.render_type_graph(show_edges=False)

# What connects to this threat actor? (ego network)
view.render_campaign_graph(
    seed_ids  = [actor.id],
    depth     = 2,
    path      = "campaign.html",
)

# Objects on a time axis
view.render_timeline_graph(
    stix_types = ["indicator", "vulnerability"],
    path       = "timeline.html",
)

# Risk scatter (confidence vs RF risk score)
view.render_risk_heatmap(
    x_field = "confidence",
    y_field = "x_rf_risk_score",
    path    = "risk.html",
)
```

### TabularView

```python
from gnat.viz import TabularView

view = TabularView(workspace)

view.show()                              # terminal output (rich)
view.to_html("table.html")              # dark-theme HTML
view.to_csv("indicators.csv")           # CSV export
view.to_excel("intel.xlsx")             # Excel / Power BI
```

---

## Async Client

### Gather from multiple platforms concurrently

```python
import asyncio
from gnat.async_client import AsyncSAKClient

async def gather_all():
    async with AsyncSAKClient() as client:
        results = await client.gather(
            platforms  = ["threatq", "crowdstrike", "splunk"],
            stix_type  = "indicator",
            filters    = {"confidence_min": 70},
        )
    return results

indicators = asyncio.run(gather_all())
print(f"Gathered {len(indicators)} indicators from 3 platforms")
```

---

## Full Workflows

### Daily SOC workflow — check library, research if needed, update EDL

```python
from gnat.research import ResearchLibrary
from gnat.agents import ResearchAgent, ParsingAgent, AgentConfig
from gnat.export import ExportPipeline, ExportJob
from gnat.export.filters import TypeFilter, ConfidenceFilter
from gnat.export.transforms.edl import EDLTransform
from gnat.export.delivery.targets import EDLServer
from gnat.schedule import FeedScheduler
from gnat.ingest import IngestPipeline

lib    = ResearchLibrary.default()
config = AgentConfig.from_ini()

# 1. Research topics if stale
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

# 2. Curate staging → library
from gnat.research import CurationJob
CurationJob(lib).execute()

# 3. Export indicators to EDL
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

### Server-side scheduled pipeline (production)

```python
from gnat.schedule import FeedJob, FeedScheduler
from gnat.reports import ReportJob, ReportConfig, AIMode
from gnat.research import ResearchLibrary, CurationJob
from gnat.agents import AgentConfig
from gnat.export import ExportJob

lib        = ResearchLibrary.default()
agent_cfg  = AgentConfig.from_ini()
scheduler  = FeedScheduler(on_job_error=lambda jid, exc: alert(jid, exc))

# Ingest feeds
scheduler.add(FeedJob("blocklist", lambda ctx: PlainTextReader(...),
                       lambda ctx: FlatIOCMapper(confidence=70),
                       interval_seconds=3600, client=tq_client))

scheduler.add(FeedJob("taxii", lambda ctx: TAXIICollectionReader(
                       collection, added_after=ctx.last_success_iso),
                       lambda ctx: STIXPassthroughMapper(client=tq_client),
                       cron="0 2 * * *"))

# Export to EDL
scheduler.add(ExportJob("edl-sync", lambda ctx: (
    ExportPipeline("edl")
    .read_from(workspace)
    .filter_with(TypeFilter("indicator"))
    .filter_with(ConfidenceFilter(70))
    .transform_with(EDLTransform(ioc_types=["ipv4","domain","url"]))
    .deliver_to(FileDelivery("/var/edl/"))
), interval_seconds=900))

# Export to Netskope CE
scheduler.add(ExportJob("netskope-sync", lambda ctx: (
    ExportPipeline("nsk")
    .read_from(workspace)
    .filter_with(TypeFilter("indicator"))
    .filter_with(ConfidenceFilter(70))
    .transform_with(NetskopeCETransform(source_label="ThreatQ"))
    .deliver_to(PlatformDelivery(netskope_client))
), interval_seconds=900))

# Curation
scheduler.add(CurationJob(lib, interval_seconds=4*3600))

# Daily report
scheduler.add(ReportJob(manager, ReportConfig(
    report_type="daily", formats=["pdf","html"],
    delivery=["email"], email_to=["soc@example.com"],
    schedule="0 6 * * *",
), agent_cfg, lib))

scheduler.start(run_immediately=True)
# Process keeps running — scheduler manages all jobs
```

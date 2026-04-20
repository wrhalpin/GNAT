# Tutorial: Incident to Campaign Intelligence

This tutorial walks through the complete workflow for connecting individual
security incidents to campaign-level threat intelligence using GNAT. You will
triage an XSOAR incident, collect artifacts across Splunk, Entra ID, and
CrowdStrike, enrich infrastructure using Shodan and VirusTotal, research the
threat actor via Recorded Future and ThreatQ, correlate multiple incidents into
a campaign, and produce and publish a structured intelligence report.

The scenario is a real-world OAuth device code phishing campaign that abused
Railway.com PaaS infrastructure to harvest and replay Microsoft 365 refresh
tokens across 340+ organisations — attributed to the EvilTokens
Phishing-as-a-Service platform.

**Prerequisites**
- `gnat` installed with analysis and reporting extras:
  `pip install "gnat[analysis,reporting]"`
- Platform clients configured in `gnat.ini`:
  XSOAR, Splunk, Entra ID, CrowdStrike, Shodan, VirusTotal, ThreatQ, Recorded Future
- Optional: `[claude]` section in `gnat.ini` for AI-assisted report drafting

---

## 1. Import dependencies

```python
import os
import itertools
from gnat.analysis.confidence import ConfidenceScore, SourceReliability, InformationCredibility
from gnat.analysis.tlp import TLPLevel
from gnat.analysis.investigations import (
    InvestigationService, InvestigationStore, InvestigationStatus,
)
from gnat.analysis.correlation import (
    EntityResolver, IndicatorRecord, RelationshipScorer,
    ClusterDetector, EnrichmentDispatcher,
)
from gnat.analysis.timeline import TimelineBuilder
from gnat.analysis.copilot.gap_detector import GapDetector
from gnat.analysis.copilot.drafting import ReportDraftingAssistant
from gnat.investigations import InvestigationBuilder, Seed, SeedType, materialize
from gnat.context import WorkspaceManager
from gnat.orm import AttackPattern, ThreatActor, Campaign, Relationship
from gnat.agents.base import AgentConfig
from gnat.agents.parsing import ParsingAgent
from gnat.agents.llm import LLMClient
from gnat.ingest.pipeline import IngestPipeline
from gnat.ingest.sources.plain_text import PlainTextReader
from gnat.reporting import ReportService, ReportStore, ReportType, report_to_stix_bundle
from gnat.export.edl import EDLDelivery, EDLConfig
from gnat.export.stix_bundle import STIXBundleExporter
from gnat.schedule import FeedScheduler, FeedJob
```

---

## 2. Set up storage and platform clients

GNAT uses a local SQLite database (or PostgreSQL in production) to persist
investigations and reports across sessions. All platform clients read their
credentials from `gnat.ini`.

```python
# Storage — shared database for both investigations and reports
db_url       = "sqlite:///" + os.path.expanduser("~/.gnat/gnat.db")
inv_store    = InvestigationStore(db_url)
report_store = ReportStore(db_url)
inv_store.create_all()
report_store.create_all()

inv_service    = InvestigationService(inv_store)
report_service = ReportService(report_store)
workspace_manager = WorkspaceManager.from_ini()

# Platform clients — initialize from gnat.ini credentials
from gnat.connectors.xsoar.client import XSOARClient
from gnat.connectors.splunk.client import SplunkClient
from gnat.connectors.entra_id.client import EntraIDClient
from gnat.connectors.crowdstrike.client import CrowdStrikeClient
from gnat.connectors.shodan.client import ShodanClient
from gnat.connectors.virustotal.client import VirusTotalClient
from gnat.connectors.threatq.client import ThreatQClient
from gnat.connectors.recordedfuture.client import RecordedFutureClient

xsoar   = XSOARClient.from_ini("xsoar")
splunk  = SplunkClient.from_ini("splunk")
entra   = EntraIDClient.from_ini("entra_id")
cs      = CrowdStrikeClient.from_ini("crowdstrike")
shodan  = ShodanClient.from_ini("shodan")
vt      = VirusTotalClient.from_ini("virustotal")
tq      = ThreatQClient.from_ini("threatq")
rf      = RecordedFutureClient.from_ini("recordedfuture")
```

---

## 3. Open an investigation

The investigation is the central case record. Everything collected in the
following steps, including notes, hypotheses, linked artifacts, and the final report,
is anchored to this object. Create an investigation when an incident is identified as
worthy of being elevated to campaign analysis.

```python
inv = inv_service.create(
    title      = "Railway PaaS M365 Token Replay — Feb 2026",
    created_by = "analyst@example.com",
    tlp        = TLPLevel.AMBER,
    tags       = ["m365", "oauth", "device-code-phishing", "token-replay", "railway"],
)

# Record the initial attribution hypothesis before the evidence shapes it —
# this forces explicit reasoning and creates an audit trail
inv_service.add_hypothesis(
    inv.id,
    statement  = "Anomalous M365 sign-ins from Railway.com IP ranges are part of a "
                 "coordinated OAuth device code phishing campaign, not isolated incidents.",
    created_by = "analyst@example.com",
)

inv_service.transition(inv.id, InvestigationStatus.IN_PROGRESS)
print(f"Investigation opened: {inv.id}")
```

---

## 4. Build the cross-platform evidence graph

`InvestigationBuilder` branches out from your seed indicators to every connected
platform simultaneously, normalizes the results into a unified evidence graph,
and adds cross-platform edges where the same entity appears on multiple
platforms. This replaces the manual process of querying each tool separately.

```python
builder = InvestigationBuilder({
    "xsoar":       xsoar,
    "splunk":      splunk,
    "entra_id":    entra,
    "crowdstrike": cs,
})

# Seed from the initial XSOAR alert and the Railway IPs it surfaced
graph = builder.build(
    seeds=[
        Seed("INC-20260219-004", SeedType.CASE_ID, hint_platform="xsoar"),
        Seed("162.220.234.41",   SeedType.IP),
        Seed("162.220.234.66",   SeedType.IP),
    ],
    title = inv.title,
)

print(graph.summary())
# EvidenceGraph: 41 nodes across 4 platforms, 28 edges

# Persist into a named workspace — all future STIX objects are written here
ws = materialize(graph, workspace_manager, workspace_name="railway-m365-2026")
```

Notice the graph summary. Each node represents a normalized artifact from one
platform; edges represent shared entities or relationships detected across
platforms. A high edge count relative to nodes indicates strong cross-platform
overlap, which can be an early signal that multiple tools are seeing the same activity.

---

## 5. Investigate infrastructure

Before correlating incidents, it is important to understand the infrastructure.
Railway.com's clean IP reputation is the key evasion technique in this campaign.
Neither Microsoft Identity Protection nor most perimeter controls flag logins
from these ranges as suspicious. Shodan and VirusTotal give you independent
views of what is actually running on these addresses.

```python
railway_ips = [
    "162.220.234.41",
    "162.220.234.66",
    "162.220.232.57",
    "162.220.232.99",
    "162.220.232.235",
]

for ip in railway_ips:
    # Community detections and prior reports
    vt_result = vt.get_object("indicator", ip)
    stats = vt_result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    print(f"[VirusTotal] {ip}: {stats.get('malicious', 0)} malicious detections")

    # Open ports and hosted services
    host = shodan.get_object("observable", ip)
    inv_service.add_note(
        inv.id,
        text   = f"Shodan {ip}: ports={host.get('ports')} org={host.get('org')}",
        author = "analyst@example.com",
    )

# Sweep the full Railway ASN for additional active token-harvest endpoints
from gnat.connectors.censys.client import CensysClient
censys = CensysClient.from_ini("censys")

endpoints = censys.list_objects(
    "observable",
    filters={"query": "autonomous_system.asn: 400107"},
)
print(f"Censys: {len(endpoints)} Railway-hosted endpoints in ASN 400107")
```

---

## 6. Query SIEM and identity logs

Shodan and VirusTotal tell you about the infrastructure. Splunk and Entra ID
tell you who in your environment authenticated from it. Run these queries
before proceeding to correlation; you need victim breadth to determine the
campaign scope.

```python
# Splunk — successful M365 sign-ins from Railway CIDR (SPL)
railway_logins = splunk.list_objects("event", filters={
    "query": (
        'index=o365 sourcetype="o365:management:activity" ResultStatus="Success" '
        '| where match(ClientIP, "^162\\.220\\.(23[2-5])\\.") '
        '| table _time, UserId, ClientIP, Operation, ApplicationId, UserAgent '
        '| sort _time'
    )
})
print(f"Splunk: {len(railway_logins)} successful Railway-sourced sign-ins")

# Splunk — synthetic iOS 18.7 / Safari 26.3 user agent (high-fidelity EvilTokens signal)
synthetic_ua_events = splunk.list_objects("event", filters={
    "query": (
        'index=o365 sourcetype="o365:management:activity" '
        'UserAgent="*Version/26.3*" UserAgent="*iPhone OS 18_7*" '
        '| table _time, UserId, ClientIP, UserAgent '
        '| sort _time'
    )
})
print(f"Splunk: {len(synthetic_ua_events)} synthetic UA matches (EvilTokens fingerprint)")

# Entra ID — confirm token scope and check whether access survived password resets
affected_users = list({login.get("UserId") for login in railway_logins})
for upn in affected_users:
    signins = entra.list_objects("signin", filters={
        "userPrincipalName": upn,
        "ipAddress":         "162.220.234.0/23",
    })
    inv_service.add_note(
        inv.id,
        text   = f"Entra ID: {upn} — {len(signins)} Railway sign-in(s); "
                 f"apps: {set(s.get('appDisplayName') for s in signins)}",
        author = "analyst@example.com",
    )

# CrowdStrike — confirm no endpoint compromise (this is a cloud-only vector)
for upn in affected_users:
    detections = cs.list_objects("detection", filters={"user": upn})
    if detections:
        inv_service.add_note(
            inv.id,
            text   = f"CrowdStrike: {len(detections)} detection(s) for {upn} — "
                     "review for post-token-capture endpoint activity",
            author = "analyst@example.com",
        )
```

---

## 7. Look up the threat actor in your TIP and Recorded Future

Cross-referencing with ThreatQ and Recorded Future before you build your own
hypothesis prevents reinventing the wheel. Another team or vendor may have
already attributed this infrastructure, and it also surfaces prior reporting
that can increase your attribution confidence score.

```python
# ThreatQ — check if Railway IPs carry existing scores or attribution
for ip in ["162.220.234.41", "162.220.234.66"]:
    hits = tq.list_objects("indicator", filters={"value": ip})
    if hits:
        inv_service.add_note(
            inv.id,
            text   = f"ThreatQ: {ip} score={hits[0].get('score')} "
                     f"status={hits[0].get('status')}",
            author = "analyst@example.com",
        )

# Recorded Future — research EvilTokens and NOIRLEGACY GROUP
for query in ["EvilTokens", "NOIRLEGACY GROUP", "Railway PaaS device code phishing"]:
    for hit in rf.list_objects("indicator", filters={"query": query}):
        inv_service.add_note(
            inv.id,
            text   = f"Recorded Future [{query}]: {hit.get('name')} — "
                     f"risk score {hit.get('risk', {}).get('score')}",
            author = "analyst@example.com",
        )
```

---

## 8. Extract IOCs from written advisories with ParsingAgent

When you have unstructured threat reporting, such as blog posts, vendor advisories,
internal emails, etc., `ParsingAgent` extracts structured STIX objects automatically.
This is the same `RecordMapper` interface used in the ingest pipeline, so the
output drops straight into your workspace.

```python
advisory_text = """
Threat actors are abusing Railway.com PaaS infrastructure to host token harvest
and replay endpoints targeting Microsoft 365. The EvilTokens PhaaS platform,
advertised on NOIRLEGACY GROUP's Telegram channel since 2026-02-16, exploits the
OAuth device code authorization flow. Victims are redirected through multi-hop
chains via Cisco Secure Email, Mimecast, and Cloudflare Workers before landing on
Railway-hosted pages at 162.220.234[.]41 and 162.220.234[.]66. The platform
inserts an X-Antibot-Token HTTP header. Captured OAuth refresh tokens grant
persistent 90-day M365 access that survives password resets. 340+ organizations
across the US, Canada, Australia, New Zealand, and Germany were affected.
"""

pipeline = (
    IngestPipeline(name="railway-advisory-parse")
    .read_from(PlainTextReader(text=advisory_text))
    .map_with(ParsingAgent(
        config             = AgentConfig.from_ini(),
        extract_indicators = True,
        extract_ttps       = True,
        extract_actors     = True,
    ))
)

for stix_obj in pipeline.iter_objects():
    print(f"Extracted: {stix_obj.stix_type}  {getattr(stix_obj, 'name', stix_obj.id)}")
    ws.add(stix_obj)
```

---

## 9. Build the chronological timeline

A timeline organizes all observed events into the sequence that reveals how the
attack unfolded. `TimelineBuilder` derives events from the evidence graph
automatically; supplement with manually entered campaign-level events that
platform APIs do not capture.

```python
tl_builder = TimelineBuilder()

events = tl_builder.from_evidence_graph(graph)

events += tl_builder.from_records([
    {
        "timestamp":       "2026-02-16T00:00:00Z",
        "title":           "EvilTokens PhaaS advertised on NOIRLEGACY GROUP Telegram",
        "source":          "osint",
        "mitre_technique": "T1583",
    },
    {
        "timestamp":       "2026-02-19T08:14:00Z",
        "title":           "INC-A: Construction bid lure delivered via email; "
                           "redirect chain through Cisco Secure Email rewriter",
        "source":          "splunk_o365",
        "mitre_technique": "T1566.002",
    },
    {
        "timestamp":       "2026-02-19T08:31:00Z",
        "title":           "INC-A: Victim enters device code at microsoft.com/devicelogin; "
                           "token captured by 162.220.234.41",
        "source":          "splunk_proxy",
        "mitre_technique": "T1528",
    },
    {
        "timestamp":       "2026-02-19T08:33:00Z",
        "title":           "INC-A: Refresh token replayed — Exchange Online access confirmed",
        "source":          "entra_id",
        "mitre_technique": "T1550.004",
    },
    {
        "timestamp":       "2026-02-24T11:07:00Z",
        "title":           "INC-B: DocuSign lure — second victim; Railway IP 162.220.234.66",
        "source":          "splunk_o365",
        "mitre_technique": "T1566.002",
    },
    {
        "timestamp":       "2026-03-02T00:00:00Z",
        "title":           "Campaign acceleration: voicemail, MS Forms, Dynamics 365 lure wave",
        "source":          "xsoar",
        "mitre_technique": "T1566.002",
    },
])

print("Timeline:")
for event in sorted(events, key=lambda e: e.timestamp):
    print(f"  [{event.event_type.value}]  {event.timestamp.isoformat()}  {event.title}")
```

Now store the observed techniques as STIX `AttackPattern` objects so they are
part of the campaign's STIX bundle when you publish:

```python
for tech_id, name, description in [
    ("T1566.002", "Phishing: Spearphishing Link",
     "Diverse lures via email; multi-hop redirect through trusted URL rewriters"),
    ("T1528",     "Steal Application Access Token",
     "OAuth device code flow; victim authenticates at microsoft.com/devicelogin"),
    ("T1550.004", "Use Alternate Authentication Material: Web Session Cookie",
     "Captured refresh token replayed; valid 90 days; survives password resets"),
    ("T1583",     "Acquire Infrastructure",
     "Railway.com PaaS; clean IP reputation bypasses Identity Protection scoring"),
]:
    ws.add(AttackPattern(
        name        = f"{tech_id} — {name}",
        description = description,
        x_mitre_id  = tech_id,
        x_tlp       = "amber",
    ))
```

---

## 10. Correlate incidents into a campaign

This step transforms a collection of individual incidents into
campaign intelligence. `EntityResolver` deduplicates indicators across
platforms; `RelationshipScorer` quantifies the strength of pairwise links;
`ClusterDetector` groups strongly-linked entities into campaign clusters.

Two or more matching signals justify a campaign hypothesis. Three or more
independent overlaps support HIGH confidence attribution.

```python
records = [
    # INC-A
    IndicatorRecord("entra_id", "162.220.234.41",              "ipv4-addr",   "INC-A"),
    IndicatorRecord("splunk",   "X-Antibot-Token",             "http-header", "INC-A"),
    IndicatorRecord("entra_id", "oauth-device-code-flow",      "technique",   "INC-A"),
    # INC-B
    IndicatorRecord("entra_id", "162.220.234.66",              "ipv4-addr",   "INC-B"),
    IndicatorRecord("splunk",   "X-Antibot-Token",             "http-header", "INC-B"),
    IndicatorRecord("entra_id", "oauth-device-code-flow",      "technique",   "INC-B"),
    # INC-C
    IndicatorRecord("splunk",   "162.220.232.57",              "ipv4-addr",   "INC-C"),
    IndicatorRecord("splunk",   "X-Antibot-Token",             "http-header", "INC-C"),
    IndicatorRecord("splunk",   "iPhone OS 18_7 Version/26.3", "user-agent",  "INC-C"),
    # INC-D
    IndicatorRecord("splunk",   "162.220.232.99",              "ipv4-addr",   "INC-D"),
    IndicatorRecord("splunk",   "X-Antibot-Token",             "http-header", "INC-D"),
    IndicatorRecord("splunk",   "iPhone OS 18_7 Version/26.3", "user-agent",  "INC-D"),
]

groups   = EntityResolver().resolve(records)
detector = ClusterDetector()
clusters = detector.detect(list(groups.values()))

for cluster in clusters:
    print(f"Campaign cluster ({cluster.confidence.band}): {cluster.member_ids}")
# Campaign cluster (HIGH): ['X-Antibot-Token', 'oauth-device-code-flow',
#                            'iPhone OS 18_7 Version/26.3', ...]
```

Three independent overlaps are present — shared Railway ASN infrastructure,
the `X-Antibot-Token` HTTP header, and the OAuth device code TTP chain — which
meets the threshold for HIGH confidence campaign linkage.

Enrich the pivot indicators for the final evidence picture:

```python
dispatcher = EnrichmentDispatcher({
    "shodan":     shodan,
    "virustotal": vt,
})

for ip in ["162.220.234.41", "162.220.234.66"]:
    enrichment = dispatcher.enrich(ip)
    for platform, data in enrichment.items():
        if data:
            print(f"  [{platform}] {ip}: {data}")
```

---

## 11. Attribute the campaign

Build the `Campaign` and `ThreatActor` STIX objects, link them with a
`Relationship`, and score the attribution confidence using the NATO Admiralty
Scale. Record full reasoning behind the attribution decision.

```python
campaign = Campaign(
    name               = "EvilTokens Railway M365 Token Replay Campaign — 2026",
    description        = "Large-scale OAuth device code phishing campaign via Railway.com PaaS.  "
                         "Attributed to EvilTokens PhaaS / NOIRLEGACY GROUP.",
    first_seen         = "2026-02-16T00:00:00Z",
    last_seen          = "2026-03-25T00:00:00Z",
    x_tlp              = "amber",
    x_victim_sectors   = ["Construction", "Legal", "Real Estate", "Finance", "Healthcare"],
    x_victim_countries = ["US", "CA", "AU", "NZ", "DE"],
)
ws.add(campaign)

actor = ThreatActor(
    name               = "EvilTokens / NOIRLEGACY GROUP",
    threat_actor_types = ["criminal"],
    aliases            = ["NOIRLEGACY GROUP"],
    description        = "Operators of the EvilTokens PhaaS platform — advertised on Telegram.  "
                         "Provide B2B Sender, Office 365 Capture Link, and SMTP Sender products.",
    x_tlp              = "amber",
)
ws.add(actor)

ws.add(Relationship(
    relationship_type = "attributed-to",
    source_ref        = campaign.id,
    target_ref        = actor.id,
))

# Platform attribution (EvilTokens) is HIGH; operator identity is UNKNOWN → overall MEDIUM
score = ConfidenceScore(
    source_reliability      = SourceReliability.B_USUALLY_RELIABLE,
    information_credibility = InformationCredibility.PROBABLY_TRUE,
    stix_confidence         = 60,
    rationale               = "EvilTokens PhaaS attributed via NOIRLEGACY GROUP Telegram "
                              "advertisement (2026-02-16) and matching HTTP fingerprints "
                              "(X-Antibot-Token, /api/device/ paths, synthetic iOS UA) "
                              "across all four incidents.  Recorded Future corroborates "
                              "Railway IP attribution.  Operators not yet identified.",
)
print(f"Attribution confidence: {score.label}")   # B2 (MEDIUM)

inv_service.link_threat_actors(inv.id, [actor.id])
```

Run gap detection to surface what evidence is missing before you write the
report — gaps found now are intelligence requirements for the next collection
cycle:

```python
gaps    = GapDetector().detect_all(inv_service.get(inv.id))
summary = GapDetector().summary(inv_service.get(inv.id))
print(f"Evidence gaps: {summary}")

for gap in gaps:
    print(f"  [{gap.severity}] {gap.description}")
    print(f"    → {gap.suggested_action}")
    inv_service.add_note(inv.id, text=f"Gap: {gap.description}", author="analyst@example.com")
```

---

## 12. Create the campaign report

`ReportService` manages the intelligence product lifecycle: DRAFT → REVIEW →
APPROVED → PUBLISHED. The eleven sections below follow the standard campaign
report structure — overview, affected assets, attacker actions, attribution,
motivation, impact, timeline, threat evolution, forecast, intelligence gaps,
and TTPs (*adjust report structure based on needs*)

```python
report = report_service.create(
    title       = "EvilTokens Railway M365 Token Replay Campaign — 2026",
    report_type = ReportType.CAMPAIGN_ANALYSIS,
    authors     = ["analyst@example.com"],
    tlp         = TLPLevel.AMBER,
    tags        = ["m365", "oauth", "device-code-phishing", "railway", "eviltokens", "phaas"],
)

report_service.add_section(report.id, order=1,
    title   = "Overview of Incidents",
    content = "Between 19 February and 25 March 2026, 340+ organisations across five "
              "countries were compromised via coordinated OAuth device code phishing "
              "using Railway.com PaaS infrastructure. Attributed to EvilTokens PhaaS / "
              "NOIRLEGACY GROUP. Captured refresh tokens granted persistent M365 access "
              "that survived password resets.",
)
report_service.add_section(report.id, order=2,
    title   = "Affected Assets, Users, and Locations",
    content = "340+ victim organisations: US, Canada, Australia, New Zealand, Germany. "
              "Sectors: Construction (26), Legal (18), Real Estate (14), Finance (12), "
              "Healthcare (11), Government (8). Compromised assets: Exchange Online "
              "and SharePoint Online identities. No endpoint compromise confirmed "
              "via CrowdStrike telemetry.",
)
report_service.add_section(report.id, order=3,
    title   = "Actions Taken by Attacker",
    content = "T1566.002 — Spearphishing Link: diverse lures (construction bids, DocuSign, "
              "voicemail, MS Forms) with 2–5-hop redirect chains through Cisco Secure Email, "
              "Mimecast, Trend Micro, and Cloudflare Workers.\n\n"
              "T1528 — Steal Application Access Token: Railway-hosted EvilTokens backend "
              "presents OAuth device code UI; victim completes OAuth grant at "
              "microsoft.com/devicelogin. Fingerprints: X-Antibot-Token header, "
              "/api/device/start and /api/device/status/ paths.\n\n"
              "T1550.004 — Token Replay: captured refresh token replayed against Exchange "
              "Online and SharePoint Online; valid 90 days; survives password resets.\n\n"
              "T1583 — Acquire Infrastructure: Railway.com PaaS; clean IP reputation "
              "bypasses Microsoft Identity Protection risk scoring.",
)

report_service.add_attribution(
    report.id,
    threat_actor_name  = "EvilTokens / NOIRLEGACY GROUP",
    threat_actor_ref   = actor.id,
    confidence         = score,
    mitre_attack_ids   = ["T1566.002", "T1528", "T1550.004", "T1583"],
    notes              = "Platform attribution HIGH. Operator identity unknown. "
                         "Continue collection on NOIRLEGACY GROUP Telegram activity.",
)

for order, title, content in [
    (5, "Motivation",
     "Financially motivated. Persistent M365 access enables BEC, wire fraud, and data "
     "theft. EvilTokens monetises token theft by selling platform access to fraud operators."),
    (6, "Impact",
     "Confirmed: OAuth refresh tokens compromised across 340+ orgs; persistent Exchange "
     "and SharePoint access. Potential: wire fraud, data exfiltration, email surveillance. "
     "CrowdStrike confirms no endpoint compromise — cloud-identity-only vector."),
    (7, "Timeline",
     "2026-02-16  T1583       EvilTokens advertised on NOIRLEGACY GROUP Telegram\n"
     "2026-02-19  T1566.002   Construction bid lure; INC-A Railway IP 162.220.234.41\n"
     "2026-02-19  T1528       Victim enters device code; token captured\n"
     "2026-02-19  T1550.004   Refresh token replayed; Exchange Online access confirmed\n"
     "2026-02-24  T1566.002   DocuSign lure — INC-B; Railway IP 162.220.234.66\n"
     "2026-03-02  T1566.002   Multi-lure wave: voicemail, MS Forms, Dynamics 365\n"
     "2026-03-19  DEFENSE     Conditional Access block deployed to ~60,000 tenants\n"
     "2026-03-25  ATTRIBUTION EvilTokens / NOIRLEGACY GROUP attribution confirmed"),
    (8, "Threat Evolution",
     "OAuth device code phishing is not new, but the EvilTokens PhaaS model "
     "operationalizes it at scale with AI-assisted lure generation.  Routing through "
     "enterprise-trusted URL rewriters to defeat inspection is increasingly paired with "
     "device code phishing to bypass both email filtering and MFA."),
    (9, "Forecast",
     "EvilTokens PhaaS model is commercially viable; additional customers likely operating "
     "via other Railway endpoints. Immediate actions:\n"
     "1. Block 162.220.232.0/22 and 162.220.234.0/22 in Conditional Access Named Locations.\n"
     "2. Revoke affected refresh tokens via Graph API /revokeSignInSessions.\n"
     "3. Restrict OAuth device code flow in Conditional Access where not operationally required.\n"
     "4. Enable Continuous Access Evaluation (CAE).\n"
     "5. Alert on UserAgent 'Version/26.3'+'iPhone OS 18_7' in Splunk O365 logs."),
    (10, "Intelligence Gaps",
     "GAP-1 [HIGH]: EvilTokens operators not identified. Action: NOIRLEGACY GROUP "
     "Telegram OSINT; Recorded Future cross-reference.\n\n"
     "GAP-2 [HIGH]: Post-compromise activity (email rules, data staging) not documented "
     "across all 340+ orgs. Action: Splunk hunt on Exchange audit logs for T1114.003.\n\n"
     "GAP-3 [MEDIUM]: Additional EvilTokens customers via Railway unknown.  "
     "Action: expand Railway ASN monitoring in Splunk; share CIDR blocks via ThreatQ.\n\n"
     "GAP-4 [MEDIUM]: AU/NZ/DE scope not independently corroborated.  "
     "Action: coordinate with regional ISAC partners."),
    (11, "TTPs",
     "T1566.002 — Spearphishing Link\n"
     "Lures: construction bid, DocuSign, voicemail, MS Forms, Dynamics 365 Customer Voice\n"
     "Redirect: 2–5 hops via Cisco/Mimecast/Trend Micro + Cloudflare Workers\n\n"
     "T1528 — Steal Application Access Token\n"
     "Infrastructure: Railway.com (162.220.232.0/22, 162.220.234.0/22)\n"
     "Fingerprint: X-Antibot-Token header; /api/device/start, /api/device/status/\n"
     "UA fingerprint: iPhone OS 18_7 Version/26.3 (synthetic — non-existent)\n"
     "Log signal: cmsi:cmsi from Railway IP ranges in Splunk/Entra ID\n\n"
     "T1550.004 — Token Replay: 90-day refresh token; survives password reset\n\n"
     "T1583 — Acquire Infrastructure: Railway.com PaaS; prompt-based deployment"),
]:
    report_service.add_section(report.id, order=order, title=title, content=content)

# Key findings
for statement, rationale in [
    ("84% of malicious auth events originated from three Railway IPs, confirming "
     "a centrally operated token harvest backend.",
     "Infrastructure overlap across 340+ victim sign-in logs in Splunk and Entra ID."),
    ("X-Antibot-Token HTTP header and /api/device/ path pattern are unique EvilTokens "
     "fingerprints — present across all observed incidents.",
     "Consistent across all four incidents; not present in unrelated campaigns in ThreatQ."),
    ("OAuth refresh tokens remained valid after password resets, extending attacker "
     "access beyond standard IR remediation steps.",
     "Confirmed via Entra ID post-reset sign-in logs for INC-A and INC-B."),
]:
    report_service.add_finding(
        report.id,
        statement  = statement,
        confidence = ConfidenceScore.high(rationale=rationale),
    )
```

---

## 13. AI-assisted drafting (optional)

If a `[claude]` section is configured in `gnat.ini`, generate an executive
summary draft before the peer review step. Apply the draft only after
analyst review. AI output should inform, not replace, analyst judgement.

```python
llm       = LLMClient.from_ini()
assistant = ReportDraftingAssistant(llm_client=llm)
draft     = assistant.draft_full(report)

print("--- Draft executive summary ---")
print(draft.executive_summary)

# Apply after review
report_service.update_summary(report.id, draft.executive_summary)
```

---

## 14. Submit, approve, and publish

Published reports are immutable and automatically generate a STIX 2.1 bundle.
The review step is especially important for any named-actor attribution.

```python
# Submit for peer review
report_service.submit_for_review(report.id)

# Second analyst approves
report_service.approve(report.id, reviewer="manager@example.com")

# Publish — immutable from this point; STIX bundle generated automatically
published = report_service.publish(report.id, changed_by="manager@example.com")
print(f"Published: {published.stix_report_ref}")

# Export STIX bundle
bundle = report_to_stix_bundle(published)
```

---

## 15. Disseminate and set up ongoing monitoring

Push the finished intelligence to consumers and schedule recurring enrichment
to catch infrastructure changes as the campaign evolves.

```python
# ThreatQ — push STIX bundle for team-wide access and indicator scoring
tq.upsert_object("report", bundle)

# XSOAR — deliver Railway IP blocklist for automated enforcement actions
edl = EDLDelivery(EDLConfig(output_path="/etc/gnat/railway-blocklist.txt", format="plain"))
edl.deliver([
    "162.220.234.41", "162.220.234.66",
    "162.220.232.57", "162.220.232.99", "162.220.232.235",
])

# Full STIX bundle for threat hunting and detection engineering
STIXBundleExporter().export(ws, output_path="/tmp/railway-m365-campaign-stix.json")

# Recurring enrichment — re-check Railway IPs every Monday morning
scheduler = FeedScheduler()
scheduler.add_job(FeedJob(
    job_id   = "railway-monitor",
    cron     = "0 8 * * 1",
    callback = lambda: dispatcher.enrich("162.220.234.41"),
))
scheduler.start()
```

---

## 16. Close the investigation

```python
inv_service.add_note(
    inv.id,
    text   = f"Campaign report published: {published.id}  "
             f"STIX ref: {published.stix_report_ref}",
    author = "analyst@example.com",
)
inv_service.transition(inv.id, InvestigationStatus.CLOSED)
print("Investigation closed.")
```

---

## Verification

After completing this tutorial you should have:

| Artifact | Location |
|----------|----------|
| Closed GNAT investigation with notes, hypothesis, and linked threat actor | `InvestigationStore` |
| `railway-m365-2026` workspace containing STIX objects from all platforms | `WorkspaceManager` |
| Published `CAMPAIGN_ANALYSIS` report with 11 sections and 3 findings | `ReportStore` |
| STIX bundle pushed to ThreatQ | ThreatQ indicator library |
| Railway IP blocklist at `/etc/gnat/railway-blocklist.txt` | Filesystem / XSOAR |
| STIX JSON export at `/tmp/railway-m365-campaign-stix.json` | Filesystem |
| Weekly Railway enrichment job running in `FeedScheduler` | In-process scheduler |

Confirm the report published successfully:

```python
from gnat.reporting import ReportStatus
assert report_service.get(published.id).status == ReportStatus.PUBLISHED
print("Report published successfully.")
```

---

## Next Steps

- Work through the [How-to: Incident to Campaign Intelligence](../how-to/incident-to-campaign-intelligence.md)
  reference for the full API surface, additional connector options, and
  enrichment variations not covered in this tutorial.
- See [How-to: Disseminate Intelligence](../how-to/disseminate-intelligence.md) to
  add TAXII 2.1 delivery and webhook notifications for downstream SIEM consumers.
- See [How-to: Schedule Feeds](../how-to/schedule-feeds.md) to replace the inline
  `FeedScheduler` call with a persistent, supervised scheduling layer.
- See [How-to: Use the Research Library](../how-to/use-research-library.md) to
  cache threat actor research so subsequent investigations on the same actor do
  not repeat API calls.

---

*Licensed under the Apache License, Version 2.0*

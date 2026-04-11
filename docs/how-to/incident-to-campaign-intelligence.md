# How-to: Incident to Campaign Intelligence

Transform individual security incidents into campaign-level threat intelligence
using GNAT — from high-priority triage through multi-platform artifact
collection, cross-incident correlation, attribution, and structured campaign
report production.

**Tool stack used in this guide:**

| Role | Platform |
|------|----------|
| Incident triage | Palo Alto XSOAR |
| SIEM | Splunk |
| Identity / M365 | Microsoft Entra ID |
| Threat Intelligence Platform | ThreatQ |
| Infrastructure enrichment | Shodan · Censys · VirusTotal |
| Attribution research | Recorded Future |
| EDR | CrowdStrike Falcon |

---

## 1. Triage — opening an investigation

Not all alerts warrant full intrusion analysis. Before spending analysis
time, open a GNAT investigation and confirm the incident meets the threshold for campaign-level work (see *Triage criteria*).

```python
import os
from gnat.analysis.investigations import (
    InvestigationService,
    InvestigationStore,
    InvestigationStatus,
)
from gnat.analysis.tlp import TLPLevel

# One-time setup — reuse across sessions
store.  = InvestigationStore("sqlite:///" + os.path.expanduser("~/.gnat/gnat.db"))
store.create_all()
service = InvestigationService(store)

# Open a new investigation for the suspected campaign
inv = service.create(
    title      = "Railway PaaS M365 Token Replay — Feb 2026",
    created_by = "analyst@example.com",
    tlp        = TLPLevel.AMBER,
    tags       = ["m365", "oauth", "device-code-phishing", "token-replay", "railway"],
)

service.transition(inv.id, InvestigationStatus.IN_PROGRESS)
print(f"Investigation opened: {inv.id}")
```

**Triage criteria:**

| Criterion | GNAT signal to watch |
|-----------|---------------------|
| Compromised privileged or admin account | Entra ID or XSOAR alert on admin session from anomalous IP |
| Successful credential / token theft | SIEM sign-in anomaly from cloud provider IP range not in baseline |
| Novel delivery mechanism or lure theme | New lure type unseen in prior feeds; multi-hop redirect chain through trusted URL rewriters |
| Infrastructure linked to known threat activity | Shodan / VirusTotal positive match on authentication source IP |
| Multi-org pattern in EDR telemetry | CrowdStrike surfaces same TTP across multiple unrelated tenants |
| MFA bypass without credential reset | Persistent M365 access via OAuth refresh token after password change |

---

## 2. Collect incident artifacts

Gather raw event data from the environment before beginning analysis. Use
`InvestigationBuilder` to pull correlated artifacts from every relevant
connector in a single pass.

```python
from gnat.investigations import InvestigationBuilder, Seed, SeedType, materialize
from gnat.context import WorkspaceManager

workspace_manager = WorkspaceManager.from_ini()

# Seed with every known indicator from the initial XSOAR alert.
# The Railway IP addresses and the XSOAR incident ID are the starting pivots.
builder = InvestigationBuilder({
    "xsoar":       xsoar_client,
    "splunk":      splunk_client,
    "entra_id":    entra_client,
    "crowdstrike": cs_client,
})

graph = builder.build(
    seeds=[
        Seed("162.220.234.41", SeedType.IP),
        Seed("162.220.234.66", SeedType.IP),
        Seed("INC-20260219-004", SeedType.CASE_ID, hint_platform="xsoar"),
    ],
    title = "Railway M365 token replay — initial artifact collection",
)

# Persist into a named workspace for the campaign
ws = materialize(graph, workspace_manager, workspace_name="railway-m365-2026")
print(graph.summary())
# "EvidenceGraph: 41 nodes across 4 platforms, 28 edges"
```

Add analyst notes as artifacts arrive to maintain a running record:

```python
service.add_note(
    inv.id,
    text   = "INC-20260219-004 (XSOAR): Anomalous M365 sign-in for finance team mailbox "
             "from 162.220.234.41 (Railway.com AS). Authentication used OAuth device code "
             "flow. Refresh token issued; MFA not re-challenged. Access persisted after "
             "password reset. CrowdStrike shows no endpoint compromise — cloud-only vector.",
    author = "analyst@example.com",
)
service.add_task(
    inv.id,
    title       = "Pull full Entra ID sign-in logs for 162.220.232.0/22 and "
                  "162.220.234.0/22 for the 30-day window preceding INC-20260219-004",
    assigned_to = "analyst2@example.com",
)
```

---

## 3. Investigate — multi-platform artifact analysis

With artifacts collected, investigate across infrastructure and identity telemetry, relevant SIEM logs, and threat intelligence.

### 3.1 Infrastructure pivoting on Railway IP ranges

```python
from gnat.connectors.shodan.client import ShodanClient
from gnat.connectors.censys.client import CensysClient
from gnat.connectors.virustotal.client import VirusTotalClient

shodan = ShodanClient(host="https://api.shodan.io",    api_key="<shodan-key>")
censys = CensysClient(host="https://search.censys.io", api_id="<id>", api_secret="<secret>")
vt     = VirusTotalClient(host="https://www.virustotal.com", api_key="<vt-key>")

railway_ips = [
    "162.220.234.41",
    "162.220.234.66",
    "162.220.232.57",
    "162.220.232.99",
    "162.220.232.235",
]

for ip in railway_ips:
    # IP reputation and community detections
    vt_result = vt.get_object("indicator", ip)
    stats     = vt_result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    print(f"[VirusTotal] {ip}: {stats.get('malicious', 0)} malicious / "
          f"{stats.get('suspicious', 0)} suspicious detections")

    # Enumerate services hosted on Railway infrastructure
    shodan_host = shodan.get_object("observable", ip)
    service.add_note(
        inv.id,
        text   = f"Shodan: {ip} — open ports: {shodan_host.get('ports')}, "
                 f"org: {shodan_host.get('org')}",
        author = "analyst@example.com",
    )

# Enumerate the full Railway ASN block for other active token-harvest endpoints
censys_results = censys.list_objects(
    "observable",
    filters={"query": "autonomous_system.asn: 400107"}, # Railway.com ASN
)
print(f"Censys: {len(censys_results)} Railway-hosted endpoints found in ASN 400107")

service.add_note(
    inv.id,
    text   = f"Censys ASN 400107 sweep: {len(censys_results)} active Railway endpoints; "
             "review for /api/device/ path exposure.",
    author = "analyst@example.com",
)
```

### 3.2 SIEM log analysis — Splunk

Query Splunk for Railway-sourced M365 sign-in events across the environment:

```python
from gnat.connectors.splunk.client import SplunkClient

splunk = SplunkClient(
    host     = "https://splunk.example.com:8089",
    username = "<username>",
    password = "<password>",
)

# Successful M365 sign-ins from Railway IP ranges (SPL)
railway_logins = splunk.list_objects("event", filters={
    "query": (
        'index=o365 sourcetype="o365:management:activity" ResultStatus="Success" '
        '| where match(ClientIP, "^162\\.220\\.(23[2-5])\\.") '
        '| table _time, UserId, ClientIP, Operation, ApplicationId, UserAgent '
        '| sort _time'
    )
})
print(f"Splunk: {len(railway_logins)} successful Railway-sourced sign-ins")

# High-fidelity detection: synthetic iOS 18.7 / Safari 26.3 user agent
synthetic_ua = splunk.list_objects("event", filters={
    "query": (
        'index=o365 sourcetype="o365:management:activity" '
        'UserAgent="*Version/26.3*" UserAgent="*iPhone OS 18_7*" '
        '| table _time, UserId, ClientIP, UserAgent '
        '| sort _time'
    )
})
print(f"Splunk: {len(synthetic_ua)} synthetic UA sign-in events (high-fidelity signal)")

for login in railway_logins + synthetic_ua:
    service.add_note(
        inv.id,
        text   = f"Splunk sign-in: {login.get('UserId')} from {login.get('ClientIP')} "
                 f"at {login.get('_time')} — op: {login.get('Operation')}",
        author = "analyst@example.com",
    )
```

### 3.3 Identity telemetry — Entra ID

Pull sign-in details and confirm token scope directly from Entra ID:

```python
from gnat.connectors.entra_id.client import EntraIDClient

entra = EntraIDClient(
    host          = "https://graph.microsoft.com",
    tenant_id     = "<tenant-id>",
    client_id     = "<client-id>",
    client_secret = "<client-secret>",
)

# Fetch sign-in events for affected users from Entra ID audit logs
affected_users = [login.get("UserId") for login in railway_logins]

for upn in set(affected_users):
    signins = entra.list_objects("signin", filters={
        "userPrincipalName": upn,
        "ipAddress":         "162.220.234.0/23",
    })
    service.add_note(
        inv.id,
        text   = f"Entra ID: {upn} — {len(signins)} Railway-sourced sign-in(s); "
                 f"apps: {set(s.get('appDisplayName') for s in signins)}",
        author = "analyst@example.com",
    )

# CrowdStrike — confirm no endpoint-level compromise on affected machines
for upn in set(affected_users):
    cs_detections = cs_client.list_objects("detection", filters={"user": upn})
    if cs_detections:
        service.add_note(
            inv.id,
            text   = f"CrowdStrike: {len(cs_detections)} detection(s) for {upn} — "
                     "review for post-token-capture endpoint activity",
            author = "analyst@example.com",
        )
```

### 3.4 Threat intelligence platform lookups — ThreatQ

```python
from gnat.connectors.threatq.client import ThreatQClient
from gnat.connectors.recordedfuture.client import RecordedFutureClient

tq = ThreatQClient(
    host          = "https://threatq.example.com",
    client_id     = "<client-id>",
    client_secret = "<client-secret>",
)
rf = RecordedFutureClient(
    host    = "https://api.recordedfuture.com",
    api_key = "<rf-key>",
)

# Check if Railway IPs are already attributed in ThreatQ
for ip in ["162.220.234.41", "162.220.234.66"]:
    tq_hits = tq.list_objects("indicator", filters={"value": ip})
    if tq_hits:
        service.add_note(
            inv.id,
            text   = f"ThreatQ match: {ip} — score {tq_hits[0].get('score')}, "
                     f"type {tq_hits[0].get('type')}",
            author = "analyst@example.com",
        )

# Research EvilTokens / NOIRLEGACY GROUP in Recorded Future
for query in ["EvilTokens", "NOIRLEGACY GROUP", "Railway PaaS phishing"]:
    rf_hits = rf.list_objects("indicator", filters={"query": query})
    for hit in rf_hits:
        service.add_note(
            inv.id,
            text   = f"Recorded Future [{query}]: {hit.get('name')} — "
                     f"risk score {hit.get('risk', {}).get('score')}",
            author = "analyst@example.com",
        )
```

### 3.5 AI-assisted IOC extraction from threat advisories

Parse written threat reports directly into structured STIX objects using
`ParsingAgent`:

```python
from gnat.agents.base import AgentConfig
from gnat.agents.parsing import ParsingAgent
from gnat.ingest.pipeline import IngestPipeline
from gnat.ingest.sources.plain_text import PlainTextReader

advisory_text = """
Threat actors are abusing Railway.com PaaS infrastructure to host token harvest
and replay endpoints targeting Microsoft 365. The EvilTokens PhaaS platform,
advertised on the NOIRLEGACY GROUP Telegram channel since 2026-02-16, provides
an Office 365 Capture Link product that exploits the OAuth device code
authorization flow. Victims are redirected through multi-hop chains leveraging trusted URL rewriters (Cisco Secure Email, Mimecast, Trend Micro) before landing
on Railway-hosted pages at 162.220.234[.]41 and 162.220.234[.]66 that serve
device code phishing UI. The platform inserts an X-Antibot-Token HTTP header
and exposes /api/device/start and /api/device/status/ endpoints. Captured OAuth
refresh tokens grant persistent 90-day M365 access that survives password resets.
340+ organizations across the US, Canada, Australia, New Zealand, and Germany
were affected.
"""

reader = PlainTextReader(text=advisory_text)
mapper = ParsingAgent(
    config             = AgentConfig.from_ini(),
    extract_indicators = True,
    extract_ttps       = True,
    extract_actors     = True,
)

pipeline = (
    IngestPipeline(name="railway-advisory-parse")
    .read_from(reader)
    .map_with(mapper)
)

for stix_obj in pipeline.iter_objects():
    print(stix_obj.stix_type, getattr(stix_obj, "name", stix_obj.id))
    ws.add(stix_obj)
```

---

## 4. Build the chronological timeline

Construct the intrusion sequence by date to visualize
the operational flow of the attacks. Build it from the evidence graph 
collected in step 2, then supplement with campaign-level events.

```python
from gnat.analysis.timeline import TimelineBuilder

builder = TimelineBuilder()

# Derive from the evidence graph (preferred — uses all platform timestamps)
events = builder.from_evidence_graph(graph)

# Supplement with campaign-level events from OSINT and external reporting
events += builder.from_records([
    {
        "timestamp":       "2026-02-16T00:00:00Z",
        "title":           "EvilTokens PhaaS first advertised on NOIRLEGACY GROUP Telegram",
        "source":          "osint",
        "mitre_technique": "T1583",
    },
    {
        "timestamp":       "2026-02-19T08:14:00Z",
        "title":           "INC-A: Spearphishing link delivered (construction bid lure); "
                           "redirect chain through Cisco Secure Email rewriter",
        "source":          "splunk_o365",
        "mitre_technique": "T1566.002",
    },
    {
        "timestamp":       "2026-02-19T08:31:00Z",
        "title":           "INC-A: Victim lands on Railway-hosted device code phishing page "
                           "(162.220.234.41); enters code at microsoft.com/devicelogin",
        "source":          "splunk_proxy",
        "mitre_technique": "T1528",
    },
    {
        "timestamp":       "2026-02-19T08:33:00Z",
        "title":           "INC-A: OAuth refresh token captured; EvilTokens backend replays "
                           "token — persistent Exchange Online access established",
        "source":          "entra_id",
        "mitre_technique": "T1550.004",
    },
    {
        "timestamp":       "2026-02-24T11:07:00Z",
        "title":           "INC-B: DocuSign impersonation lure — second victim; "
                           "Railway IP 162.220.234.66",
        "source":          "splunk_o365",
        "mitre_technique": "T1566.002",
    },
    {
        "timestamp":       "2026-03-02T00:00:00Z",
        "title":           "Campaign acceleration — multi-lure wave (voicemail, MS Forms, "
                           "Dynamics 365 Customer Voice impersonation)",
        "source":          "xsoar",
        "mitre_technique": "T1566.002",
    },
    {
        "timestamp":       "2026-03-19T00:00:00Z",
        "title":           "Conditional Access policy pushed blocking Railway IP ranges",
        "source":          "entra_id",
        "mitre_technique": None,
    },
])

for event in sorted(events, key=lambda e: e.timestamp):
    print(f"[{event.event_type.value}]  {event.timestamp.isoformat()}  {event.title}")
```

Map each observed technique to a MITRE ATT&CK `AttackPattern` object:

```python
from gnat.orm import AttackPattern

techniques = [
    ("T1566.002", "Phishing: Spearphishing Link",
     "Diverse lure themes (construction bids, DocuSign, voicemail, MS Forms) delivered "
     "via email; multi-hop redirect chains through trusted URL rewriting services"),
    ("T1528", "Steal Application Access Token",
     "OAuth device code flow exploited — victim enters attacker-generated code at "
     "microsoft.com/devicelogin; Railway-hosted backend captures the resulting refresh token"),
    ("T1550.004", "Use Alternate Authentication Material: Web Session Cookie",
     "Captured OAuth refresh token replayed against M365; token valid 90 days, "
     "survives password resets, not re-challenged by MFA"),
    ("T1583", "Acquire Infrastructure",
     "Railway.com PaaS used to deploy on-demand token harvest endpoints; "
     "clean IP reputation bypasses Microsoft Identity Protection risk scoring"),
]

attack_patterns = []
for tech_id, name, description in techniques:
    ap = AttackPattern(
        name        = f"{tech_id} — {name}",
        description = description,
        x_mitre_id  = tech_id,
        x_tlp       = "amber",
    )
    ws.add(ap)
    attack_patterns.append(ap)
```

---

## 5. Correlate incidents into a campaign

A campaign is identified when two or more incidents share overlapping
infrastructure, lure themes, or TTP chains. Use `EntityResolver` and
`ClusterDetector` to make that assessment systematic.

### 5.1 Build cross-incident indicator records

```python
from gnat.analysis.correlation import (
    EntityResolver,
    IndicatorRecord,
    RelationshipScorer,
    ClusterDetector,
    EnrichmentDispatcher,
)
import itertools

# One IndicatorRecord per (platform, observed-value) pair across all incidents
records = [
    # INC-A — 2026-02-19
    IndicatorRecord("entra_id",   "162.220.234.41",              "ipv4-addr",   "INC-A"),
    IndicatorRecord("splunk",     "/api/device/start",           "url-path",    "INC-A"),
    IndicatorRecord("splunk",     "X-Antibot-Token",             "http-header", "INC-A"),
    IndicatorRecord("entra_id",   "oauth-device-code-flow",      "technique",   "INC-A"),

    # INC-B — 2026-02-24
    IndicatorRecord("entra_id",   "162.220.234.66",              "ipv4-addr",   "INC-B"),
    IndicatorRecord("splunk",     "/api/device/status/",         "url-path",    "INC-B"),
    IndicatorRecord("splunk",     "X-Antibot-Token",             "http-header", "INC-B"),
    IndicatorRecord("entra_id",   "oauth-device-code-flow",      "technique",   "INC-B"),

    # INC-C — 2026-03-02
    IndicatorRecord("splunk",     "162.220.232.57",              "ipv4-addr",   "INC-C"),
    IndicatorRecord("splunk",     "X-Antibot-Token",             "http-header", "INC-C"),
    IndicatorRecord("entra_id",   "oauth-device-code-flow",      "technique",   "INC-C"),
    IndicatorRecord("splunk",     "iPhone OS 18_7 Version/26.3", "user-agent",  "INC-C"),

    # INC-D — 2026-03-02
    IndicatorRecord("splunk",     "162.220.232.99",              "ipv4-addr",   "INC-D"),
    IndicatorRecord("splunk",     "X-Antibot-Token",             "http-header", "INC-D"),
    IndicatorRecord("entra_id",   "oauth-device-code-flow",      "technique",   "INC-D"),
    IndicatorRecord("splunk",     "iPhone OS 18_7 Version/26.3", "user-agent",  "INC-D"),
]
```

### 5.2 Resolve cross-platform entity groups and score clusters

```python
resolver = EntityResolver()
groups   = resolver.resolve(records)

print("Cross-incident overlaps:")
for key, group in groups.items():
    if len(group.platforms) > 1:
        print(f" {key}: incidents={group.platforms} confidence={group.max_confidence}")

# Score pairwise relationship strength
scorer = RelationshipScorer()
for g1, g2 in itertools.combinations(groups.values(), 2):
    score = scorer.score(g1, g2)
    if score.numeric >= 0.4:
        print(f" LINK: {g1.canonical_key} ↔ {g2.canonical_key}: {score.label}")

# Cluster — identifies all four incidents as a single campaign
detector = ClusterDetector()
clusters = detector.detect(list(groups.values()))
for cluster in clusters:
    print(f"Campaign cluster ({cluster.confidence.band}): {cluster.member_ids}")
```

**Campaign linkage rule of thumb:**
- 2+ matching signals → campaign hypothesis justified
- 3+ independent overlaps → HIGH confidence; proceed to attribution

In this example, the shared Railway ASN infrastructure, identical
`X-Antibot-Token` HTTP header, OAuth device code TTP chain across all four
incidents, and the synthetic iOS 18.7 / Safari 26.3 user agent fingerprint
in INC-C and INC-D provide HIGH confidence that all incidents are a single
coordinated campaign.

### 5.3 Enrich pivot indicators

```python
dispatcher = EnrichmentDispatcher({
    "shodan":      shodan,
    "censys":      censys,
    "virustotal":  vt,
})

for ip in ["162.220.234.41", "162.220.234.66"]:
    enrichment = dispatcher.enrich(ip)
    for platform, data in enrichment.items():
        if data:
            print(f"  [{platform}] {ip}: {data}")
```

---

## 6. Attribute the campaign

Attribution assigns the most probable threat actor based on evidence overlap,
external reporting, and documented reasoning. Always express attribution with
an explicit confidence level.

```python
from gnat.analysis.confidence import ConfidenceScore, SourceReliability, InformationCredibility
from gnat.analysis.copilot.gap_detector import GapDetector
from gnat.orm import ThreatActor, Campaign, Relationship

# Build the Campaign SDO
campaign = Campaign(
    name               = "EvilTokens Railway M365 Token Replay Campaign — 2026",
    description        = "Large-scale OAuth device code phishing campaign leveraging Railway.com "
                         "PaaS infrastructure to harvest and replay M365 refresh tokens.  "
                         "Operated via the EvilTokens PhaaS platform, advertised by NOIRLEGACY "
                         "GROUP on Telegram.  340+ victim organisations across five countries.",
    first_seen         = "2026-02-16T00:00:00Z",
    last_seen          = "2026-03-25T00:00:00Z",
    x_tlp              = "amber",
    x_victim_sectors   = ["Construction", "Legal", "Real Estate", "Finance", "Healthcare", "Government"],
    x_victim_countries = ["US", "CA", "AU", "NZ", "DE"],
)
ws.add(campaign)

# Add attribution hypothesis to the investigation
service.add_hypothesis(
    inv.id,
    statement  = "The Railway M365 token replay campaign is conducted via the EvilTokens PhaaS "
                 "platform, advertised by NOIRLEGACY GROUP on Telegram. Platform attribution is "
                 "HIGH confidence; operator identity is unknown.",
    created_by = "analyst@example.com",
)

# Score attribution confidence
#
# EvilTokens PhaaS platform: HIGH (HTTP fingerprints + Telegram advertisement match)
# Human operators behind the platform: UNKNOWN — overall rating: MEDIUM
score = ConfidenceScore(
    source_reliability      = SourceReliability.B_USUALLY_RELIABLE,
    information_credibility = InformationCredibility.PROBABLY_TRUE,
    stix_confidence         = 60,
    rationale               = "EvilTokens PhaaS attributed via NOIRLEGACY GROUP Telegram "
                              "advertisement (first post 2026-02-16) and matching HTTP "
                              "fingerprints (X-Antibot-Token header, /api/device/ paths, "
                              "synthetic iOS UA) across all four incidents. Recorded Future "
                              "corroborates Railway IP attribution. Operators behind the "
                              "service are not yet identified.",
)
print(f"Attribution confidence: {score.label}") # "B2 (MEDIUM)"

actor = ThreatActor(
    name               = "EvilTokens / NOIRLEGACY GROUP",
    threat_actor_types = ["criminal"],
    aliases            = ["NOIRLEGACY GROUP"],
    description        = "Operators of the EvilTokens Phishing-as-a-Service platform, "
                         "advertised on Telegram. Offer B2B Sender, Office 365 Capture "
                         "Link, and SMTP Sender products for OAuth device code phishing.",
    x_confidence       = score.stix_confidence,
    x_tlp              = "amber",
)
ws.add(actor)

rel = Relationship(
    relationship_type = "attributed-to",
    source_ref        = campaign.id,
    target_ref        = actor.id,
)
ws.add(rel)

service.link_threat_actors(inv.id, [actor.id])
```

### Identify intelligence gaps

```python
detector = GapDetector()
gaps     = detector.detect_all(service.get(inv.id))

for gap in gaps:
    print(f"[{gap.severity}] {gap.description}")
    print(f"  → {gap.suggested_action}")

# Example gaps this workflow might surface:
# [HIGH] Human operators behind EvilTokens PhaaS not identified
#   → Pursue NOIRLEGACY GROUP Telegram OSINT; cross-reference with Recorded Future
#     for PhaaS actors matching Railway + device code + X-Antibot-Token profile
# [HIGH] Post-compromise activity chain not documented for majority of victims
#   → Hunt Exchange audit logs via Splunk for inbox forwarding rules (T1114.003)
#     and SharePoint access anomalies in Railway-authenticated sessions
# [MEDIUM] Additional EvilTokens customers operating via Railway unknown
#   → Expand Railway ASN monitoring in Splunk across all tenants; alert on
#     X-Antibot-Token header in proxy logs
# [MEDIUM] Geographic scope of campaign in AU, NZ, and DE not independently corroborated
#   → Coordinate with regional ISAC partners for local victim identification
```

---

## 7. Write the campaign report

Produce the structured campaign report using `ReportService`, then publish it
back to ThreatQ for team-wide access.

```python
from gnat.reporting import ReportService, ReportStore, ReportType, EvidenceLinkType
from gnat.analysis.confidence import ConfidenceScore

report_store   = ReportStore("sqlite:///" + os.path.expanduser("~/.gnat/gnat.db"))
report_store.create_all()
report_service = ReportService(report_store)

report = report_service.create(
    title       = "EvilTokens Railway M365 Token Replay Campaign — 2026",
    report_type = ReportType.CAMPAIGN_ANALYSIS,
    authors     = ["analyst@example.com"],
    tlp         = TLPLevel.AMBER,
    tags        = [
        "m365", "oauth", "device-code-phishing", "token-replay",
        "railway", "eviltokens", "phaas", "noirlegacy",
    ],
)

# Section 1 — Overview (typically written last)
report_service.add_section(report.id, order=1,
    title   = "Overview of Incidents",
    content = (
        "Between 19 February and 25 March 2026, more than 340 organisations across the US, "
        "Canada, Australia, New Zealand, and Germany were compromised via a coordinated OAuth "
        "device code phishing campaign. The campaign leveraged Railway.com PaaS infrastructure "
        "to host token harvest endpoints and is attributed to the EvilTokens Phishing-as-a-Service "
        "platform, advertised by NOIRLEGACY GROUP on Telegram from 16 February 2026. Captured "
        "OAuth refresh tokens provided persistent M365 access that survived password resets and "
        "was not re-challenged by MFA."
    ),
)

# Section 2 — Affected assets / users and locations
report_service.add_section(report.id, order=2,
    title   = "Affected Assets, Users, and Locations",
    content = (
        "340+ victim organisations confirmed across five countries: US, Canada, Australia, "
        "New Zealand, Germany. Sectors: Construction (26 orgs), Legal (18), Real Estate (14), "
        "Finance/Insurance (12), Healthcare (11), Government/Public Safety (8).\n\n"
        "Compromised assets: Microsoft 365 identities — Exchange Online mailboxes and SharePoint "
        "sites. No on-premises endpoint compromise confirmed via CrowdStrike telemetry.  "
        "OAuth refresh tokens for all affected users must be treated as fully compromised."
    ),
)

# Section 3 — Attacker actions (MITRE-mapped)
report_service.add_section(report.id, order=3,
    title   = "Actions Taken by Attacker",
    content = (
        "T1566.002 — Phishing: Spearphishing Link\n"
        "High-diversity lure set: construction bid proposals, DocuSign requests, voicemail "
        "notifications, and Microsoft Dynamics 365 Customer Voice impersonation. Each message "
        "uniquely crafted — automation or AI-assisted lure generation inferred from scale. "
        "Delivery confirmed via Splunk O365 audit logs.\n\n"
        "Redirect chain: phishing link → 2–5 hops through trusted URL rewriting services "
        "(Cisco Secure Email, Mimecast, Trend Micro, Cloudflare Workers) → Railway.com-hosted "
        "landing page. Chain abuses enterprise-trusted services to defeat URL inspection.\n\n"
        "T1528 — Steal Application Access Token\n"
        "Railway-hosted EvilTokens backend presents OAuth device code UI. Victim enters "
        "attacker-generated code at the legitimate microsoft.com/devicelogin, completing the "
        "OAuth grant. HTTP fingerprints: X-Antibot-Token header; /api/device/start and "
        "/api/device/status/ API paths. Confirmed via Splunk proxy logs.\n\n"
        "T1550.004 — Use Alternate Authentication Material: Web Session Cookie\n"
        "Captured OAuth refresh token replayed against Exchange Online and SharePoint Online. "
        "Token valid 90 days; remains valid after password reset; MFA not re-challenged. "
        "Confirmed via Entra ID sign-in audit logs.\n\n"
        "T1583 — Acquire Infrastructure\n"
        "Railway.com PaaS used for on-demand deployment of token harvest endpoints. "
        "162.220.232.0/22 and 162.220.234.0/22 IP ranges carry clean reputation — "
        "Microsoft Identity Protection does not flag logins from these ranges as risky. "
        "84% of malicious auth events sourced from three Railway IPs."
    ),
)

# Section 4 — Attribution
report_service.add_attribution(
    report.id,
    threat_actor_name  = "EvilTokens / NOIRLEGACY GROUP",
    threat_actor_ref   = actor.id,
    confidence         = ConfidenceScore(
        source_reliability      = SourceReliability.B_USUALLY_RELIABLE,
        information_credibility = InformationCredibility.PROBABLY_TRUE,
        stix_confidence         = 60,
        rationale               = "EvilTokens PhaaS attributed via NOIRLEGACY GROUP Telegram "
                                  "advertisement and HTTP fingerprints matching across all "
                                  "incidents. Recorded Future corroborates Railway IP "
                                  "attribution. Platform operators remain unidentified.",
    ),
    mitre_attack_ids   = ["T1566.002", "T1528", "T1550.004", "T1583"],
    notes              = "Platform attribution HIGH confidence. Operator attribution not yet "
                         "possible. Continue collection on NOIRLEGACY GROUP Telegram activity.",
)

# Section 5 — Motivation
report_service.add_section(report.id, order=5,
    title   = "Motivation",
    content = (
        "Financially motivated. Persistent M365 access enables business email compromise (BEC), "
        "wire fraud, and data theft. Targeting of construction, legal, real estate, and financial "
        "sectors is consistent with industries that conduct high-value wire transfers. EvilTokens "
        "PhaaS monetises token theft by selling platform access to downstream fraud operators."
    ),
)

# Section 6 — Impact
report_service.add_section(report.id, order=6,
    title   = "Impact",
    content = (
        "Confirmed: OAuth refresh tokens compromised for M365 users across 340+ organisations. "
        "Persistent Exchange Online and SharePoint Online access established. Access survived "
        "password resets in all observed cases per Entra ID audit logs.\n\n"
        "Potential: BEC-enabled wire fraud, client fund diversion, attorney-client privilege "
        "breach (legal sector), PHI access (healthcare sector), and ongoing email surveillance "
        "via forwarding rules. CrowdStrike telemetry shows no endpoint-level compromise, "
        "confirming this as a cloud-identity-only vector."
    ),
)

# Section 7 — Timeline
report_service.add_section(report.id, order=7,
    title   = "Timeline",
    content = (
        "2026-02-16  OSINT       T1583       EvilTokens PhaaS advertised on NOIRLEGACY GROUP Telegram\n"
        "2026-02-19  INC-A       T1566.002   Construction bid lure; redirect via Cisco Secure Email\n"
        "2026-02-19  INC-A       T1528       Victim enters device code; 162.220.234.41 captures token\n"
        "2026-02-19  INC-A       T1550.004   Refresh token replayed; Exchange Online access confirmed\n"
        "2026-02-24  INC-B       T1566.002   DocuSign lure — second victim; Railway IP 162.220.234.66\n"
        "2026-03-02  INC-C/D     T1566.002   Multi-lure wave: voicemail, MS Forms, Dynamics 365\n"
        "2026-03-19  DEFENSE     —           Conditional Access block deployed (Railway CIDR)\n"
        "2026-03-20  INTEL       —           External analysis published; 340+ orgs confirmed\n"
        "2026-03-25  ATTRIBUTION —           EvilTokens / NOIRLEGACY GROUP attribution confirmed"
    ),
)

# Section 8 — Threat evolution
report_service.add_section(report.id, order=8,
    title   = "Threat Evolution",
    content = (
        "OAuth device code phishing is not new, but the EvilTokens platform operationalizes it "
        "at scale via a commercial PhaaS model with AI-assisted lure generation.  The use of "
        "Railway.com's clean-reputation PaaS to bypass Microsoft Identity Protection risk scoring "
        "represents a novel evasion approach not previously observed at this scale.  The multi-hop "
        "redirect chain routing through enterprise-trusted URL rewriters (Cisco, Mimecast, Trend "
        "Micro) has been seen in prior campaigns but is increasingly paired with device code "
        "phishing to defeat URL inspection controls."
    ),
)

# Section 9 — Forecast
report_service.add_section(report.id, order=9,
    title   = "Forecast",
    content = (
        "The EvilTokens PhaaS model is commercially viable and will likely expand. Additional "
        "customers may already be operating the same toolchain via different Railway endpoints. "
        "Recommended immediate actions:\n\n"
        "1. Block 162.220.232.0/22 and 162.220.234.0/22 in Entra ID Conditional Access Named Locations.\n"
        "2. Revoke all refresh tokens for users with Railway-sourced sign-ins:\n"
        " POST /v1.0/users/{id}/revokeSignInSessions via Microsoft Graph.\n"
        "3. Restrict OAuth device code flow in Conditional Access authentication flow policy\n"
        " for all users where not operationally required.\n"
        "4. Enable Continuous Access Evaluation (CAE) for near-real-time token revocation\n"
        " on network or location change.\n"
        "5. Add Splunk alert: UserAgent contains 'Version/26.3' AND 'iPhone OS 18_7' in O365 logs."
    ),
)

# Section 10 — Intelligence gaps
report_service.add_section(report.id, order=10,
    title   = "Intelligence Gaps",
    content = (
        "GAP-1 [HIGH]: Human operators behind EvilTokens PhaaS not identified.\n"
        "Action: NOIRLEGACY GROUP Telegram OSINT; cross-reference Recorded Future for PhaaS "
        "actors matching Railway + device code + X-Antibot-Token infrastructure profile.\n\n"
        "GAP-2 [HIGH]: Post-compromise activity (email rules, data staged, wire transfers) "
        "not fully documented across the 340+ victim organisations.\n"
        "Action: Splunk hunt on Exchange audit logs for inbox forwarding rules (T1114.003) "
        "and SharePoint downloads created during Railway-authenticated sessions.\n\n"
        "GAP-3 [MEDIUM]: Additional EvilTokens PhaaS customers operating via Railway endpoints "
        "not yet identified.\n"
        "Action: Expand Railway ASN monitoring in Splunk; alert on X-Antibot-Token header "
        "in proxy logs across all tenants; share Railway CIDR blocks via ThreatQ.\n\n"
        "GAP-4 [MEDIUM]: Campaign scope in Australia, New Zealand, and Germany not yet "
        "independently corroborated.\n"
        "Action: Coordinate with regional ISAC partners; cross-reference CrowdStrike Falcon X "
        "threat intelligence for overlapping Railway-sourced M365 activity."
    ),
)

# Section 11 — TTPs
report_service.add_section(report.id, order=11,
    title   = "Tactics, Techniques and Procedures (TTPs)",
    content = (
        "T1566.002 — Phishing: Spearphishing Link\n"
        "  Lures: construction bid, DocuSign, voicemail, MS Forms, Dynamics 365 Customer Voice\n"
        "  Redirect: 2–5 hops via Cisco/Mimecast/Trend Micro URL rewriters + Cloudflare Workers\n\n"
        "T1528 — Steal Application Access Token\n"
        "  Method: OAuth device code flow; victim authenticates at microsoft.com/devicelogin\n"
        "  Infrastructure: Railway.com (162.220.232.0/22, 162.220.234.0/22)\n"
        "  HTTP fingerprint: X-Antibot-Token header; /api/device/start, /api/device/status/\n"
        "  UA fingerprint: iPhone OS 18_7 Version/26.3 (synthetic — non-existent version)\n"
        "  Log signal: cmsi:cmsi authentication signal from Railway IP ranges (Splunk/Entra ID)\n\n"
        "T1550.004 — Use Alternate Authentication Material: Web Session Cookie\n"
        "  Token type: OAuth refresh token (90-day validity)\n"
        "  Platforms: Exchange Online, SharePoint Online\n"
        "  Persistence: valid after password reset; MFA not re-challenged\n\n"
        "T1583 — Acquire Infrastructure\n"
        "  Platform: Railway.com PaaS — prompt-based deployment; on-demand teardown\n"
        "  Evasion: Railway IP ranges not flagged risky by Microsoft Identity Protection"
    ),
)

# Key findings linked to evidence
report_service.add_finding(
    report.id,
    statement  = "84% of malicious authentication events originated from three Railway IP "
                 "addresses, confirming a shared, centrally operated token harvest backend.",
    confidence = ConfidenceScore.high(
        rationale = "Direct infrastructure overlap across 340+ victim sign-in logs "
                    "confirmed via Splunk O365 and Entra ID audit data."
    ),
)
report_service.add_finding(
    report.id,
    statement  = "X-Antibot-Token HTTP header and /api/device/ path pattern are unique "
                 "EvilTokens PhaaS fingerprints — present across all observed incidents.",
    confidence = ConfidenceScore.high(
        rationale = "Consistent across all four analysed incidents; not observed in "
                    "unrelated campaigns in ThreatQ or Recorded Future."
    ),
)
report_service.add_finding(
    report.id,
    statement  = "OAuth refresh tokens remained valid after password resets, extending "
                 "attacker access beyond standard IR remediation steps.",
    confidence = ConfidenceScore.high(
        rationale = "Confirmed via Entra ID post-reset sign-in logs for INC-A and INC-B."
    ),
)
```

### AI-assisted executive summary drafting

```python
from gnat.agents.llm import LLMClient
from gnat.analysis.copilot.drafting import ReportDraftingAssistant

assistant = ReportDraftingAssistant(llm_client=LLMClient.from_ini())
draft     = assistant.draft_full(report)

print(draft.executive_summary)
print(draft.key_findings_narrative)

# Apply after analyst review
report_service.update_summary(report.id, draft.executive_summary)
```

---

## 8. Quality gate and lifecycle

Before disseminating, ensure all report sections are complete, every
attribution claim carries a documented confidence level, and TLP markings
are applied throughout.

```python
# Submit for peer review — required for any named-actor attribution
report_service.submit_for_review(report.id)

# Second analyst approves
report_service.approve(report.id, reviewer="manager@example.com")

# Publish — automatically generates a STIX 2.1 bundle
published = report_service.publish(report.id, changed_by="manager@example.com")
print(f"Published: {published.stix_report_ref}")

# Export STIX bundle for downstream sharing
from gnat.reporting import report_to_stix_bundle
bundle = report_to_stix_bundle(published)
```

---

## 9. Disseminate to intelligence consumers

```python
# CTI / TIP — push STIX bundle to ThreatQ for team-wide access and scoring
tq.upsert_object("report", bundle)

# IR / SOC — export Railway IP block list to XSOAR for automated enforcement actions
from gnat.export.edl import EDLDelivery, EDLConfig

edl = EDLDelivery(EDLConfig(output_path="/etc/gnat/railway-blocklist.txt", format="plain"))
edl.deliver([
    "162.220.234.41",
    "162.220.234.66",
    "162.220.232.57",
    "162.220.232.99",
    "162.220.232.235",
])

# Threat hunting — export full STIX bundle for detection hypothesis testing
from gnat.export.stix_bundle import STIXBundleExporter

exporter = STIXBundleExporter()
exporter.export(ws, output_path="/tmp/railway-m365-campaign-stix.json")

# Ongoing monitoring — re-enrich Railway IPs weekly for infrastructure changes
from gnat.schedule import FeedScheduler, FeedJob

scheduler = FeedScheduler()
scheduler.add_job(FeedJob(
    job_id   = "railway-monitor",
    cron     = "0 8 * * 1", # every Monday at 08:00
    callback = lambda: dispatcher.enrich("162.220.234.41"),
))
scheduler.start()
```

---

## See Also

- [How-to: Build Cross-Platform Investigations](build-investigations.md)
- [How-to: Use the Analysis Layer](use-analysis-layer.md)
- [How-to: Create Intelligence Reports](create-intelligence-reports.md)
- [How-to: Disseminate Intelligence](disseminate-intelligence.md)
- [How-to: Export Indicators](export-indicators.md)
- [How-to: Use AI Agents](use-ai-agents.md)
- [How-to: Use the Research Library](use-research-library.md)
- [How-to: Schedule Feeds](schedule-feeds.md)

---

*Licensed under the Apache License, Version 2.0*

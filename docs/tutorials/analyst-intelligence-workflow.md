# Tutorial: Analyst Intelligence Workflow

This tutorial walks through the full analyst intelligence lifecycle using
GNAT's analysis, investigation, reporting, and dissemination layers:
build a cross-platform evidence graph, run correlation and gap detection,
produce a structured intelligence report, and publish it to downstream consumers.

**Prerequisites**
- `gnat` installed with analysis and reporting extras: `pip install "gnat[analysis,reporting,serve]"`
- Platform clients configured in `gnat.ini` (at minimum one SOAR and one TIP)
- Optional: `[claude]` section in `gnat.ini` for AI-assisted drafting

---

## 1. Import dependencies

```python
import os
from gnat.analysis.confidence import ConfidenceScore, SourceReliability, InformationCredibility
from gnat.analysis.tlp import TLPLevel
from gnat.analysis.investigations import (
    InvestigationService, InvestigationStore, InvestigationStatus,
)
from gnat.analysis.correlation import EntityResolver, IndicatorRecord, ClusterDetector
from gnat.analysis.timeline import TimelineBuilder
from gnat.analysis.graph import GraphQuery
from gnat.analysis.copilot.gap_detector import GapDetector
from gnat.analysis.copilot.drafting import ReportDraftingAssistant
from gnat.investigations import InvestigationBuilder, Seed, SeedType, materialize
from gnat.reporting import ReportService, ReportStore, ReportType, ReportStatus
from gnat.dissemination import ExportService, ExportFormat, WebhookNotifier, WebhookSubscription
from gnat.agents.llm import LLMClient
```

---

## 2. Set up storage

```python
# Shared SQLite database for investigations and reports
# (use PostgreSQL URL in production: postgresql://user:pass@host/gnat)
inv_store    = InvestigationStore("sqlite:///" + os.path.expanduser("~/.gnat/gnat.db"))
report_store = ReportStore("sqlite:///" + os.path.expanduser("~/.gnat/gnat.db"))

inv_store.create_all()
report_store.create_all()

inv_service    = InvestigationService(inv_store)
report_service = ReportService(report_store)
```

---

## 3. Open an investigation

```python
inv = inv_service.create(
    title      = "BLACKCAT Ransomware — April 2026",
    created_by = "analyst@example.com",
    tlp        = TLPLevel.AMBER,
    tags       = ["ransomware", "blackcat", "healthcare"],
)

# Record initial hypothesis
inv_service.add_hypothesis(
    inv.id,
    statement  = "BLACKCAT actors gained initial access via spear-phishing.",
    created_by = "analyst@example.com",
)

inv_service.transition(inv.id, InvestigationStatus.IN_PROGRESS)
print(f"Investigation opened: {inv.id}")
```

---

## 4. Build the cross-platform evidence graph

Collect evidence from your connected platforms using the seeds identified in
the initial triage:

```python
builder = InvestigationBuilder({
    "xsoar":      xsoar_client,
    "threatq":    tq_client,
    "greymatter": gm_client,
})

graph = builder.build(
    seeds=[
        Seed("185.220.101.5",  SeedType.IP),
        Seed("evil-corp.com",  SeedType.DOMAIN),
        Seed("INC-4892",       SeedType.CASE_ID, hint_platform="xsoar"),
    ],
    title = inv.title,
)

print(graph.summary())
# EvidenceGraph: 47 nodes across 3 platforms, 31 edges

# Persist the graph into a workspace
ws = materialize(graph, workspace_manager, workspace_name="blackcat-apr-2026")
```

---

## 5. Correlate IOCs across platforms

```python
# Collect platform IOCs from the graph for cross-platform dedup
records = [
    IndicatorRecord(n.platform, n.value, n.metadata.get("ioc_type", "unknown"), n.node_id)
    for n in graph.nodes.values()
    if n.node_type.value == "observable"
]

resolver = EntityResolver()
groups   = resolver.resolve(records)

print(f"Resolved {len(records)} IOCs → {len(groups)} unique entities")
for key, group in groups.items():
    if group.is_cross_platform:
        print(f"  Cross-platform: {key} — {group.platforms}")

# Cluster related indicators
detector  = ClusterDetector()
clusters  = detector.detect(list(groups.values()))
for c in clusters:
    print(f"  Cluster ({c.confidence.band}): {len(c.member_ids)} members")
```

---

## 6. Pivot the evidence graph

```python
gq = GraphQuery(graph)

# Pivot from the XSOAR incident to all related entities (2 hops)
context = gq.pivot("xsoar::incident::INC-4892", hops=2)
context = gq.filter(context, min_confidence=0.5, platforms=["xsoar", "threatq"])

print(f"Pivot context: {context.node_count} nodes, {context.edge_count} edges")
print(f"Platforms: {context.platforms()}")
```

---

## 7. Reconstruct the timeline

```python
builder_tl = TimelineBuilder()
events     = builder_tl.from_evidence_graph(graph)

print("Timeline:")
for event in sorted(events, key=lambda e: e.timestamp):
    print(f"  [{event.event_type.value}] {event.timestamp.date()}  {event.title}")
```

---

## 8. Detect evidence gaps

```python
detector = GapDetector()
all_gaps = detector.detect_all(inv_service.get(inv.id))
summary  = detector.summary(inv_service.get(inv.id))

print(f"Evidence gaps: {summary}")
# {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 1, 'LOW': 0}

for gap in all_gaps:
    print(f"  [{gap.severity}] {gap.description}")
    print(f"    → {gap.suggested_action}")
    # Add notes to track remediation
    inv_service.add_note(inv.id, text=f"Gap identified: {gap.description}",
                         author="analyst@example.com")
```

---

## 9. Create an intelligence report

```python
report = report_service.create(
    title       = "BLACKCAT Ransomware — April 2026 Campaign Analysis",
    report_type = ReportType.INCIDENT_REPORT,
    authors     = ["analyst@example.com"],
    tlp         = TLPLevel.AMBER,
    tags        = ["ransomware", "blackcat", "healthcare"],
)

# Add key findings
report_service.add_finding(
    report.id,
    statement  = "Initial access was via spear-phishing targeting healthcare staff.",
    confidence = ConfidenceScore(
        source_reliability      = SourceReliability.B_USUALLY_RELIABLE,
        information_credibility = InformationCredibility.PROBABLY_TRUE,
        stix_confidence         = 75,
        rationale               = "Confirmed by email gateway logs and endpoint telemetry.",
    ),
)

report_service.add_finding(
    report.id,
    statement  = "C2 IP 185.220.101.5 was observed in two prior BLACKCAT campaigns.",
    confidence = ConfidenceScore.high(rationale="Cross-platform corroboration."),
)

# Add report body
report_service.add_section(
    report.id,
    title   = "Executive Summary",
    content = "A BLACKCAT ransomware intrusion was confirmed on 2026-04-01...",
    order   = 1,
)
report_service.add_section(
    report.id,
    title   = "Technical Analysis",
    content = "Initial access exploited a phishing lure posing as an HR notification...",
    order   = 2,
)

# Add attribution
report_service.add_attribution(
    report.id,
    threat_actor_name = "BLACKCAT / ALPHV",
    confidence        = ConfidenceScore.medium(),
    mitre_attack_ids  = ["T1566.001", "T1486"],
)
```

---

## 10. AI-assisted drafting (optional)

Requires `[claude]` section in `gnat.ini`:

```python
llm       = LLMClient.from_ini()
assistant = ReportDraftingAssistant(llm_client=llm)
result    = assistant.draft_full(report)

print("--- AI draft executive summary ---")
print(result.executive_summary)

# Apply after analyst review
report_service.update_summary(report.id, result.executive_summary)
```

---

## 11. Submit, approve, and publish

```python
# Submit for peer review
report_service.submit_for_review(report.id)

# Reviewer approves
report_service.approve(report.id, reviewer="manager@example.com")

# Publish — generates STIX bundle automatically
published = report_service.publish(report.id, changed_by="manager@example.com")
print(f"Published: {published.stix_report_ref}")
# Published: report--<uuid>
```

---

## 12. Disseminate to subscribers

```python
# Export to STIX bundle file
export_svc = ExportService(report_store)
result = export_svc.export(published.id, ExportFormat.STIX, "/var/intel/blackcat-apr-2026.json")
print(f"Exported {result.byte_count} bytes  SHA-256: {result.checksum}")

# Notify SIEM via webhook
notifier = WebhookNotifier()
notifier.subscribe(WebhookSubscription(
    id      = "siem-hook",
    url     = "https://siem.example.com/webhook/gnat",
    min_tlp = TLPLevel.GREEN,
    secret  = "hmac-shared-secret",
))
receipts = notifier.notify(published)
for r in receipts:
    print(f"Webhook {r.subscription_id}: {'✓' if r.success else '✗'}")
```

---

## 13. Close the investigation

```python
inv_service.add_note(
    inv.id,
    text   = f"Intelligence report published: {published.id}",
    author = "analyst@example.com",
)
inv_service.transition(inv.id, InvestigationStatus.CLOSED)
print("Investigation closed.")
```

---

## See Also

- [How-to: Use the Analysis Layer](../how-to/use-analysis-layer.md)
- [How-to: Build Cross-Platform Investigations](../how-to/build-investigations.md)
- [How-to: Create Intelligence Reports](../how-to/create-intelligence-reports.md)
- [How-to: Disseminate Intelligence](../how-to/disseminate-intelligence.md)
- [Tutorial: Daily SOC Workflow](daily-soc-workflow.md)

---

*Licensed under the Apache License, Version 2.0*

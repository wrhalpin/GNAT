# How-to: Create Intelligence Reports

Produce structured, lifecycle-managed intelligence products using
`gnat.reporting` — with STIX 2.1 export and AI-assisted drafting.

> **Note:** `gnat.reporting` manages *analyst intelligence products*
> (finished intelligence, incident reports, threat actor profiles).
> For operational PDF/HTML/DOCX generation (daily briefs, scheduled
> dashboards) see [How-to: Generate Reports](generate-reports.md).

---

## Setup

`ReportStore` uses SQLAlchemy and is included in the `[analysis]` or
`[reporting]` extras:

```bash
pip install "gnat[reporting]"   # or gnat[all]
```

```python
import os
from gnat.reporting import Report, ReportService, ReportStore, ReportType, ReportStatus

store   = ReportStore("sqlite:///" + os.path.expanduser("~/.gnat/gnat.db"))
store.create_all()                # zero-migration schema init
service = ReportService(store)
```

---

## Create a report

```python
from gnat.analysis.tlp import TLPLevel

report = service.create(
    title       = "BLACKCAT Ransomware — April 2026",
    report_type = ReportType.INCIDENT_REPORT,
    authors     = ["analyst@example.com"],
    tlp         = TLPLevel.AMBER,
    tags        = ["ransomware", "blackcat", "healthcare"],
)

print(report.id)       # UUID
print(report.status)   # ReportStatus.DRAFT
print(report.version)  # 1
```

Available report types: `INCIDENT_REPORT`, `THREAT_ACTOR_PROFILE`,
`CAMPAIGN_ANALYSIS`, `DAILY_BRIEF`, `VULNERABILITY_ADVISORY`,
`FINISHED_INTELLIGENCE`.

---

## Add findings and sections

```python
from gnat.reporting import EvidenceLinkType

# Add key findings (each gets a confidence score)
service.add_finding(
    report.id,
    statement  = "Threat actor reused C2 infrastructure from the March 2026 campaign.",
    confidence = ConfidenceScore.high(rationale="Confirmed by two independent analysts."),
)

service.add_finding(
    report.id,
    statement  = "Initial access vector was spear-phishing with malicious ISO attachment.",
)

# Link evidence to a finding
finding = service.get(report.id).key_findings[0]
service.add_evidence_link(
    report.id,
    finding_id    = finding.id,
    artifact_ref  = "indicator--abc123",
    link_type     = EvidenceLinkType.SUPPORTS,
    description   = "C2 IP observed in March campaign network log.",
)

# Add report body sections
service.add_section(
    report.id,
    title   = "Executive Summary",
    content = "This report details a BLACKCAT ransomware intrusion...",
    order   = 1,
)
service.add_section(
    report.id,
    title   = "Technical Analysis",
    content = "Initial access was achieved via spear-phishing...",
    order   = 2,
)
```

---

## Add attribution

```python
service.add_attribution(
    report.id,
    threat_actor_name  = "BLACKCAT / ALPHV",
    threat_actor_ref   = "threat-actor--alphv-id",
    confidence         = ConfidenceScore.medium(),
    mitre_attack_ids   = ["T1566.001", "T1486"],
    notes              = "Attribution based on tooling overlap with previous campaign.",
)
```

---

## Lifecycle transitions

```python
# DRAFT → REVIEW
service.submit_for_review(report.id)

# REVIEW → DRAFT (rejection)
service.reject(report.id, reviewer="manager@example.com",
               reason="Missing technical IOC section.")

# REVIEW → APPROVED
service.approve(report.id, reviewer="manager@example.com")

# APPROVED → PUBLISHED (generates STIX bundle automatically)
published = service.publish(report.id, changed_by="manager@example.com")

print(published.status)           # ReportStatus.PUBLISHED
print(published.stix_report_ref)  # "report--<uuid>" — the STIX SDO ID
```

Lifecycle state machine:

```
DRAFT ──► REVIEW ──► APPROVED ──► PUBLISHED
  ▲           │                        │
  └───────────┘                        ▼
  (reject → DRAFT)                 ARCHIVED
```

Published reports are **immutable** — content fields cannot be modified after
publication.

---

## Create a revision from a published report

```python
# Produces a new DRAFT with parent_report_id set and version incremented
revision = service.create_revision(published.id, changed_by="analyst@example.com")
print(revision.version)         # 2
print(revision.parent_report_id) # original report ID
```

---

## Export to STIX bundle

`publish()` triggers STIX generation automatically.  You can also call the
export function directly:

```python
from gnat.reporting import report_to_stix_bundle

bundle = report_to_stix_bundle(published)
print(bundle)   # {"type": "bundle", "id": "bundle--...", "objects": [...]}
# Objects: report SDO + identity SDO + threat-actor SDO (if attribution set)
#          + attributed-to Relationship SRO; all objects carry TLP marking refs
```

---

## AI-assisted drafting

Generate a draft executive summary and key-findings narrative before
submitting for review:

```python
from gnat.agents.llm import LLMClient
from gnat.analysis.copilot.drafting import ReportDraftingAssistant

assistant = ReportDraftingAssistant(llm_client=LLMClient.from_ini())
result    = assistant.draft_full(report)

print(result.executive_summary)
print(result.key_findings_narrative)

# Apply after analyst review
service.update_summary(report.id, result.executive_summary)
```

---

## List and query reports

```python
# All reports
all_reports = service.list()

# By status
drafts    = service.list(status=ReportStatus.DRAFT)
published = service.list(status=ReportStatus.PUBLISHED)

# By type
incidents = service.list(report_type=ReportType.INCIDENT_REPORT)

# Get a single report
report = service.get(report_id)

# Delete (only DRAFT and ARCHIVED)
service.delete(draft_report.id)
```

---

## Archive a report

```python
service.archive(report.id, changed_by="manager@example.com")
```

---

## See Also

- [How-to: Use the Analysis Layer](use-analysis-layer.md)
- [How-to: Disseminate Intelligence](disseminate-intelligence.md)
- [How-to: Generate Reports](generate-reports.md)
- [Explanation: Report Lifecycle](../explanation/architecture/adrs/0034-ADR-report-lifecycle.md)
- [Explanation: STIX Custom Objects](../explanation/architecture/adrs/0032-ADR-stix-custom-objects.md)

---

*Licensed under the Apache License, Version 2.0*

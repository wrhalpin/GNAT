# ADR-0034: Report Lifecycle State Machine

**Decision:** Five-state lifecycle: DRAFT → REVIEW → APPROVED →
PUBLISHED → ARCHIVED. Transitions are enforced by `ReportService`.
Direct jumps are not permitted except for explicit administrative
archive.

**State definitions:**

| State | Meaning | Who can set |
|-------|---------|-------------|
| DRAFT | Work in progress; content may be incomplete | Author |
| REVIEW | Submitted for peer or management review | Author |
| APPROVED | Review complete; approved for dissemination | Reviewer |
| PUBLISHED | Disseminated; STIX bundle generated; immutable content | Approver |
| ARCHIVED | Superseded or withdrawn; not for distribution | Any |

**Valid transitions:**

```
DRAFT ──► REVIEW ──► APPROVED ──► PUBLISHED
  ▲           │           │            │
  └───────────┘           │            │
  (reject back            │            │
   to DRAFT)              ▼            ▼
                       ARCHIVED    ARCHIVED
```

DRAFT ↔ REVIEW is the only bidirectional transition (review rejection
sends the report back to DRAFT for revision).

**Why APPROVED is separate from PUBLISHED:**
In most CTI teams, the analyst who writes the report is not the same
person who approves it for external distribution. Requiring explicit
approval before publish enforces a review gate. Teams without a formal
review process can configure `auto_approve = true` in the report template,
which collapses REVIEW → APPROVED → PUBLISHED into a single step.

**Why no CANCELLED state:**
Cancelled reports should be ARCHIVED, not deleted. Maintaining the full
history (including withdrawn intelligence) is a compliance and audit
requirement in most organisations.

**Immutability on PUBLISHED:**
Once a report reaches PUBLISHED, its content fields (body_sections,
key_findings, evidence_links) become read-only. Updates produce a new
Report version with `parent_report_id` pointing to the previous
published version and `version` incremented. This mirrors the STIX 2.1
versioning model where `modified` creates a logical new version rather
than mutating the original.

**Versioning implementation:**
`ReportService.publish(report_id)` increments `version`, sets
`published_at`, generates the STIX bundle, and marks content as
immutable via a `is_published` flag in storage. A new draft is created
with `parent_report_id` set when an analyst wants to revise a published
report.

**STIX `report` SDO generation:**
Triggered automatically on transition to PUBLISHED. The STIX bundle is
stored as `stix_bundle_json` in the report row and the STIX Report SDO
ID is written to `stix_report_ref`. Downstream dissemination consumers
poll for rows where `stix_report_ref IS NOT NULL` and status is
PUBLISHED.

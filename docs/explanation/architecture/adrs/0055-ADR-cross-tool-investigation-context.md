# ADR-0055: Cross-Tool Investigation Context

**Status:** Accepted

**Date:** 2026-04-23

## Context

GNAT is a CTI platform. Three addon tools produce evidence that feeds
into GNAT investigations:

- **SandGNAT** — malware sandbox (detonation results, extracted IOCs,
  behavioural reports)
- **SenseGNAT** — network sensor platform (pcap-derived observables,
  flow correlation, alert context)
- **RedGNAT** — red teaming framework (attack validation artifacts,
  technique execution logs, exposure proof)

Today these addons emit STIX bundles that GNAT ingests through its
standard TAXII 2.1 or STIX-JSON readers. The bundles land in the
workspace but have no structured link back to the Investigation that
triggered the analysis. Analysts must manually drag-and-drop sandbox
results into the right investigation, match sensor alerts to ongoing
hunts, and cross-reference red team findings by timestamp. This is
error-prone, does not scale, and breaks provenance.

The problem is not transport — TAXII ingest works. The problem is
**correlation identity**: there is no shared contract that tells GNAT
"this STIX object was produced in the context of Investigation X by
tool Y with relationship Z."

Requirements:

1. Addon tools must be able to stamp their output with an investigation
   reference before sending it to GNAT.
2. GNAT must be able to automatically file incoming stamped objects into
   the correct Investigation.
3. The contract must be STIX 2.1 compliant (custom properties are
   permitted per STIX 2.1 section 11.1).
4. Addons that do not stamp their output must still work — stamping is
   additive metadata, not a gate.
5. Cross-tenant investigation references must be rejected to preserve
   workspace isolation (ADR-0027).
6. No new transport protocol — reuse existing TAXII 2.1 ingest.

## Decision

### 1. Three custom STIX properties as the shared contract

Adopt the following custom properties, prefixed `x_gnat_` per STIX 2.1
custom property naming:

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `x_gnat_investigation_id` | string (UUID) | When investigation is known | Primary key of the `Investigation` row in GNAT |
| `x_gnat_investigation_origin` | string (enum) | Yes | Which tool produced this object |
| `x_gnat_investigation_link_type` | string (enum) | No (default: `"inferred"`) | Strength of the relationship |

Valid values for `x_gnat_investigation_origin`:
`"sandgnat"`, `"sensegnat"`, `"redgnat"`, `"gnat"`, `"external"`

Valid values for `x_gnat_investigation_link_type`:
`"confirmed"`, `"inferred"`, `"suggested"`

These properties may appear on any STIX SDO or SRO. They are custom
properties on existing standard types, not a new custom object.

### 2. Properties stamped on individual objects AND on a wrapping Grouping

Each addon run produces:

- Individual STIX objects (indicators, observables, relationships) with
  the three properties stamped directly on each object.
- A STIX `grouping` SDO that wraps the entire run output via
  `object_refs`. The Grouping also carries the three properties and
  adds `context = "investigation-context"` to identify it as an
  investigation-context wrapper.

The per-object stamps enable object-level queries ("show me all
SandGNAT indicators for Investigation X"). The Grouping enables
run-level operations ("show me the full detonation bundle from
SandGNAT run Y").

### 3. Investigation identity owned by GNAT

`Investigation` objects are created and owned exclusively by GNAT's
`gnat.analysis.investigations.InvestigationService`. Addons never
create investigations. When an addon is invoked in the context of an
investigation, GNAT passes the `investigation_id` to the addon as a
parameter. The addon stamps this ID on its output. If an addon runs
independently (no investigation context), it omits
`x_gnat_investigation_id` and stamps only `x_gnat_investigation_origin`.

### 4. Properties are additive metadata

Addons are not required to stamp properties. Objects without the three
properties are ingested normally through the existing TAXII 2.1 / STIX
ingest pipeline. The properties are additive metadata that enables
automatic filing but does not gate ingestion.

This means:

- Older addon versions that pre-date this contract continue to work.
- Third-party STIX producers that know nothing about GNAT investigations
  are unaffected.
- An addon can partially stamp — for example, setting only
  `x_gnat_investigation_origin` without an investigation ID, which
  records provenance without filing.

### 5. Receive path uses existing TAXII 2.1 ingest

No new protocol or endpoint is introduced. Stamped STIX bundles arrive
via the same TAXII 2.1 collection endpoint or STIX-JSON file reader
that handles all other ingest. The ingest pipeline inspects incoming
objects for the three properties and, when present, auto-files them
into the referenced Investigation via `InvestigationService`.

### 6. Cross-tenant investigation references rejected at ingest

When the ingest pipeline encounters an `x_gnat_investigation_id` that
references an investigation in a different tenant (per ADR-0027
workspace isolation), it:

- Rejects the cross-tenant link (does not file the object).
- Logs a warning with the object ID, claimed investigation ID, and
  source tenant.
- Strips the `x_gnat_investigation_id` property from the object.
- Ingests the object normally (without investigation filing).

This preserves tenant isolation without dropping the entire object.

### 7. Correlation confidence property

When GNAT's correlation engine (not an addon) infers a link between an
object and an investigation, it adds a fourth property:

| Property | Type | Range |
|----------|------|-------|
| `x_gnat_correlation_confidence` | integer | 0-100 |

This property is set only by GNAT's internal correlation, never by
addons. It follows the STIX confidence semantics (0 = no confidence,
100 = full confidence) and the Admiralty Scale mapping from ADR-0033.

### 8. AI-extracted objects capped at confidence 60

Objects extracted by AI agents (NLP extraction, AI-assisted parsing)
that are auto-linked to investigations carry a maximum
`x_gnat_correlation_confidence` of 60, consistent with the
`AI_CONFIDENCE_CEILING` policy from ADR-0033 and ADR-0051. AI can
suggest investigation links but cannot produce confirmed links without
analyst review.

## Consequences

**Positive:**

- Automatic filing of addon output into the correct investigation
  eliminates manual drag-and-drop and reduces analyst overhead.
- Full provenance chain from seed IOC through addon processing back to
  the investigation is preserved in STIX-native properties.
- No new transport mechanism — addons use the same TAXII 2.1 / STIX
  ingest path, reducing integration surface.
- Additive contract — existing workflows are unaffected; addons opt
  into stamping at their own pace.
- Tenant isolation is enforced without requiring addon awareness of
  multi-tenancy.

**Negative:**

- Three custom properties on every stamped object increase bundle size.
  For high-volume sensor telemetry (SenseGNAT) this may be measurable
  but is bounded by the property count (three small strings per object).
- Addons must be updated to stamp properties. Until updated, their
  output requires manual filing as before.
- The `x_gnat_` prefix is GNAT-specific and not interoperable with
  other platforms. This is intentional — investigation context is a
  GNAT-internal concern. Standard STIX consumers ignore unknown
  properties per STIX 2.1 section 3.2.

**Neutral:**

- The Grouping wrapper adds one SDO per addon run. This is negligible
  storage overhead.
- Future addons beyond the initial three (SandGNAT, SenseGNAT, RedGNAT)
  can participate by adding their tool name to the
  `x_gnat_investigation_origin` enum. No contract change is needed —
  only a registry update.

---

Related: ADR-0027 (Multi-Tenant Workspace Isolation — tenant scoping)
Related: ADR-0031 (Analysis Layer Architecture — Investigation model)
Related: ADR-0032 (STIX Custom Objects — `x-gnat-investigation` SDO)
Related: ADR-0033 (Confidence Scoring — AI ceiling, Admiralty Scale)
Related: ADR-0051 (Attribution & Campaign Tracking — evidence linking)
Related: ADR-0052 (Telemetry Ingestion — high-volume sensor path)

---

*Licensed under the Apache License, Version 2.0*

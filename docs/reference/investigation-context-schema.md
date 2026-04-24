# Investigation Context Schema Reference

Authoritative schema reference for the cross-tool investigation context
properties defined in ADR-0055. These custom STIX 2.1 properties enable
addon tools (SandGNAT, SenseGNAT, RedGNAT) to attach their output to
GNAT investigations.

---

## 1. Property Definitions

### `x_gnat_investigation_id`

| Attribute | Value |
|-----------|-------|
| Type | `string` |
| Format | UUID v4 (`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`) |
| Required | When the producing tool has an investigation context; omit otherwise |
| Scope | Tenant-scoped. Must reference an Investigation in the same tenant. |
| Set by | Addon tool (stamping) or GNAT correlation engine (auto-linking) |

The primary key of the `Investigation` row in GNAT's
`gnat.analysis.investigations` store. Must match an existing
investigation within the same tenant boundary (ADR-0027).

### `x_gnat_investigation_origin`

| Attribute | Value |
|-----------|-------|
| Type | `string` |
| Enum values | `"sandgnat"`, `"sensegnat"`, `"redgnat"`, `"gnat"`, `"external"` |
| Required | Yes, on all stamped objects |
| Set by | The producing tool |

Identifies which tool produced the STIX object.

| Value | Meaning |
|-------|---------|
| `sandgnat` | Malware sandbox (SandGNAT) — detonation results, extracted IOCs, behavioural analysis |
| `sensegnat` | Network sensor platform (SenseGNAT) — pcap observables, flow correlation, alerts |
| `redgnat` | Red teaming framework (RedGNAT) — attack validation, technique execution, exposure proof |
| `gnat` | GNAT core platform — objects created or linked by GNAT's own correlation/analysis |
| `external` | Third-party tool that has adopted the GNAT investigation context contract |

### `x_gnat_investigation_link_type`

| Attribute | Value |
|-----------|-------|
| Type | `string` |
| Enum values | `"confirmed"`, `"inferred"`, `"suggested"` |
| Required | No |
| Default | `"inferred"` |
| Set by | Addon tool or GNAT correlation engine |

Describes the strength of the relationship between the object and the
investigation.

| Value | Meaning | Typical source |
|-------|---------|----------------|
| `confirmed` | Analyst-verified link; the object is definitively part of this investigation | Analyst action, addon invoked with explicit investigation context |
| `inferred` | Automated correlation determined the link with reasonable confidence | GNAT correlation engine, addon auto-matching |
| `suggested` | Weak or speculative link; requires analyst review before promotion | AI extraction, low-confidence correlation |

### `x_gnat_correlation_confidence`

| Attribute | Value |
|-----------|-------|
| Type | `integer` |
| Range | 0-100 |
| Required | No |
| Set by | GNAT core only (never by addons) |

Numeric confidence that GNAT's correlation engine assigns when it
infers or suggests a link. Follows STIX 2.1 confidence semantics and
the Admiralty Scale mapping from ADR-0033. AI-generated links are
capped at 60 per the `AI_CONFIDENCE_CEILING` policy.

---

## 2. JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://gnat.example.com/schemas/investigation-context-v1.json",
  "title": "GNAT Investigation Context Properties",
  "description": "Custom STIX 2.1 properties for cross-tool investigation correlation (ADR-0055).",
  "type": "object",
  "properties": {
    "x_gnat_investigation_id": {
      "type": "string",
      "format": "uuid",
      "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
      "description": "Primary key of the Investigation in GNAT. Tenant-scoped."
    },
    "x_gnat_investigation_origin": {
      "type": "string",
      "enum": ["sandgnat", "sensegnat", "redgnat", "gnat", "external"],
      "description": "Tool that produced this object."
    },
    "x_gnat_investigation_link_type": {
      "type": "string",
      "enum": ["confirmed", "inferred", "suggested"],
      "default": "inferred",
      "description": "Strength of the relationship to the investigation."
    },
    "x_gnat_correlation_confidence": {
      "type": "integer",
      "minimum": 0,
      "maximum": 100,
      "description": "Correlation confidence (GNAT-internal only, never set by addons)."
    }
  },
  "required": ["x_gnat_investigation_origin"],
  "additionalProperties": true,
  "if": {
    "properties": {
      "x_gnat_investigation_origin": {
        "enum": ["sandgnat", "sensegnat", "redgnat", "gnat", "external"]
      }
    }
  },
  "then": {
    "properties": {
      "x_gnat_investigation_id": {
        "type": "string",
        "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
      }
    }
  }
}
```

---

## 3. Examples

### 3.1 Stamped Indicator (single object from SandGNAT)

A SandGNAT detonation extracts a C2 domain and stamps it with the
investigation context before sending it to GNAT via TAXII.

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--b1e3f5a2-7c4d-4e8a-9f1b-2d3c4e5f6a7b",
  "created": "2026-04-23T14:30:00.000Z",
  "modified": "2026-04-23T14:30:00.000Z",
  "name": "C2 domain extracted from sample detonation",
  "pattern": "[domain-name:value = 'malware-c2.example.net']",
  "pattern_type": "stix",
  "valid_from": "2026-04-23T14:30:00.000Z",
  "indicator_types": ["malicious-activity"],
  "confidence": 85,
  "x_gnat_investigation_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
  "x_gnat_investigation_origin": "sandgnat",
  "x_gnat_investigation_link_type": "confirmed"
}
```

### 3.2 Grouping wrapping a SandGNAT detonation bundle

Each SandGNAT detonation run produces a Grouping that references all
objects from that run. The Grouping carries the investigation context
and `context = "investigation-context"`.

```json
{
  "type": "bundle",
  "id": "bundle--f8a9b0c1-d2e3-4f5a-6b7c-8d9e0f1a2b3c",
  "objects": [
    {
      "type": "grouping",
      "spec_version": "2.1",
      "id": "grouping--c4d5e6f7-a8b9-4c0d-1e2f-3a4b5c6d7e8f",
      "created": "2026-04-23T14:35:00.000Z",
      "modified": "2026-04-23T14:35:00.000Z",
      "name": "SandGNAT detonation run — sample SHA256 abcdef1234567890",
      "description": "Full detonation results for investigation a1b2c3d4",
      "context": "investigation-context",
      "object_refs": [
        "indicator--b1e3f5a2-7c4d-4e8a-9f1b-2d3c4e5f6a7b",
        "malware--d2e3f4a5-b6c7-4d8e-9f0a-1b2c3d4e5f6a",
        "relationship--e3f4a5b6-c7d8-4e9f-0a1b-2c3d4e5f6a7b",
        "observed-data--f4a5b6c7-d8e9-4f0a-1b2c-3d4e5f6a7b8c"
      ],
      "x_gnat_investigation_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
      "x_gnat_investigation_origin": "sandgnat",
      "x_gnat_investigation_link_type": "confirmed"
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--b1e3f5a2-7c4d-4e8a-9f1b-2d3c4e5f6a7b",
      "created": "2026-04-23T14:30:00.000Z",
      "modified": "2026-04-23T14:30:00.000Z",
      "name": "C2 domain extracted from sample detonation",
      "pattern": "[domain-name:value = 'malware-c2.example.net']",
      "pattern_type": "stix",
      "valid_from": "2026-04-23T14:30:00.000Z",
      "indicator_types": ["malicious-activity"],
      "confidence": 85,
      "x_gnat_investigation_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
      "x_gnat_investigation_origin": "sandgnat",
      "x_gnat_investigation_link_type": "confirmed"
    },
    {
      "type": "malware",
      "spec_version": "2.1",
      "id": "malware--d2e3f4a5-b6c7-4d8e-9f0a-1b2c3d4e5f6a",
      "created": "2026-04-23T14:30:00.000Z",
      "modified": "2026-04-23T14:30:00.000Z",
      "name": "BLACKCAT ransomware sample",
      "is_family": false,
      "malware_types": ["ransomware"],
      "x_gnat_investigation_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
      "x_gnat_investigation_origin": "sandgnat",
      "x_gnat_investigation_link_type": "confirmed"
    },
    {
      "type": "relationship",
      "spec_version": "2.1",
      "id": "relationship--e3f4a5b6-c7d8-4e9f-0a1b-2c3d4e5f6a7b",
      "created": "2026-04-23T14:30:00.000Z",
      "modified": "2026-04-23T14:30:00.000Z",
      "relationship_type": "indicates",
      "source_ref": "indicator--b1e3f5a2-7c4d-4e8a-9f1b-2d3c4e5f6a7b",
      "target_ref": "malware--d2e3f4a5-b6c7-4d8e-9f0a-1b2c3d4e5f6a",
      "x_gnat_investigation_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
      "x_gnat_investigation_origin": "sandgnat",
      "x_gnat_investigation_link_type": "confirmed"
    }
  ]
}
```

### 3.3 SenseGNAT correlation-inferred link

When SenseGNAT correlates a network observable to an investigation
without explicit analyst confirmation, the link is `"inferred"`.

```json
{
  "type": "observed-data",
  "spec_version": "2.1",
  "id": "observed-data--a1b2c3d4-e5f6-4a7b-8c9d-aabbccddeeff",
  "created": "2026-04-23T15:10:00.000Z",
  "modified": "2026-04-23T15:10:00.000Z",
  "first_observed": "2026-04-23T15:00:00.000Z",
  "last_observed": "2026-04-23T15:05:00.000Z",
  "number_observed": 42,
  "object_refs": ["ipv4-addr--11223344-5566-4778-899a-bbccddeeff00"],
  "x_gnat_investigation_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
  "x_gnat_investigation_origin": "sensegnat",
  "x_gnat_investigation_link_type": "inferred"
}
```

### 3.4 Object without investigation context (normal ingest)

Objects without the `x_gnat_` properties are ingested normally. No
special handling occurs.

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--99887766-5544-4332-2110-ffeeddccbbaa",
  "created": "2026-04-23T16:00:00.000Z",
  "modified": "2026-04-23T16:00:00.000Z",
  "name": "Phishing domain from OSINT feed",
  "pattern": "[domain-name:value = 'phish.example.com']",
  "pattern_type": "stix",
  "valid_from": "2026-04-23T16:00:00.000Z"
}
```

---

## 4. Validation Rules

### 4.1 Investigation ID tenant scoping

The `x_gnat_investigation_id` is scoped to a tenant (ADR-0027). On
ingest, GNAT validates that the referenced investigation exists within
the same tenant as the receiving workspace.

**Rejection behaviour:**

1. Look up the investigation by `x_gnat_investigation_id`.
2. If the investigation exists in a **different tenant**: reject the
   link, strip `x_gnat_investigation_id`, log a warning, ingest the
   object without filing.
3. If the investigation **does not exist**: strip
   `x_gnat_investigation_id`, log a warning, ingest the object
   without filing.
4. If the investigation exists in the **same tenant**: file the object
   into the investigation.

### 4.2 Origin validation

`x_gnat_investigation_origin` must be one of the enumerated values.
Unknown values are logged and the property is preserved but the object
is not auto-filed.

### 4.3 Link type defaulting

If `x_gnat_investigation_link_type` is absent, the ingest pipeline
treats it as `"inferred"`.

### 4.4 AI confidence ceiling

Objects linked to an investigation by AI extraction (NLP agent, parsing
agent) carry a maximum `x_gnat_correlation_confidence` of 60. If an
AI agent attempts to set a higher value, the ingest pipeline clamps it
to 60 and logs a notice.

### 4.5 Correlation confidence source restriction

`x_gnat_correlation_confidence` is set only by GNAT's internal
correlation engine. If an addon includes this property on an incoming
object, the ingest pipeline strips it and logs a warning. Addons
express link strength via `x_gnat_investigation_link_type`, not via
the numeric confidence.

---

## 5. Error Cases

### 5.1 Cross-tenant investigation reference

**Input:**

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--deadbeef-1234-4567-890a-bcdef0123456",
  "created": "2026-04-23T17:00:00.000Z",
  "modified": "2026-04-23T17:00:00.000Z",
  "name": "Suspicious domain",
  "pattern": "[domain-name:value = 'evil.example.org']",
  "pattern_type": "stix",
  "valid_from": "2026-04-23T17:00:00.000Z",
  "x_gnat_investigation_id": "ffffffff-eeee-4ddd-cccc-bbbbaaaaaaaa",
  "x_gnat_investigation_origin": "sandgnat",
  "x_gnat_investigation_link_type": "confirmed"
}
```

**Result:** Investigation `ffffffff-eeee-4ddd-cccc-bbbbaaaaaaaa` belongs
to tenant `acme-corp` but the receiving workspace belongs to tenant
`globex`. The `x_gnat_investigation_id` is stripped. The indicator is
ingested into the `globex` workspace without investigation filing.

**Log:** `WARNING  ingest.context: Cross-tenant investigation reference rejected — object=indicator--deadbeef-1234-4567-890a-bcdef0123456 investigation=ffffffff-eeee-4ddd-cccc-bbbbaaaaaaaa source_tenant=acme-corp target_tenant=globex`

### 5.2 Unknown investigation ID

**Input:** Object references `x_gnat_investigation_id` =
`"00000000-0000-4000-8000-000000000000"` which does not exist in any
tenant.

**Result:** `x_gnat_investigation_id` is stripped. Object ingested
normally without filing.

**Log:** `WARNING  ingest.context: Unknown investigation ID — object=indicator--... investigation=00000000-0000-4000-8000-000000000000`

### 5.3 Malformed origin value

**Input:** `x_gnat_investigation_origin` = `"my_custom_scanner"` (not
in the enumerated set).

**Result:** Property is preserved on the object for audit purposes.
Object is ingested but not auto-filed into any investigation. A warning
is logged.

**Log:** `WARNING  ingest.context: Unknown investigation origin value — object=indicator--... origin=my_custom_scanner`

### 5.4 Addon sets correlation confidence

**Input:** An addon includes `x_gnat_correlation_confidence: 95` on
an outbound object.

**Result:** `x_gnat_correlation_confidence` is stripped at ingest.
Object is ingested normally; investigation filing (if
`x_gnat_investigation_id` is valid) proceeds using
`x_gnat_investigation_link_type` only.

**Log:** `WARNING  ingest.context: Addon-supplied correlation confidence stripped — object=indicator--... origin=sandgnat claimed_confidence=95`

---

## 6. Grouping Conventions

### 6.1 Grouping structure

Each addon run produces exactly one `grouping` SDO per run. The
Grouping uses `context = "investigation-context"` to distinguish
investigation-context wrappers from other STIX groupings.

### 6.2 Required Grouping fields

| Field | Value |
|-------|-------|
| `type` | `"grouping"` |
| `context` | `"investigation-context"` |
| `object_refs` | All STIX object IDs produced in this run |
| `x_gnat_investigation_origin` | The addon's origin value |
| `x_gnat_investigation_id` | Investigation ID (when known) |

### 6.3 Grouping name convention

`"<ToolName> <action> — <context>"`

Examples:
- `"SandGNAT detonation run — sample SHA256 abcdef1234567890"`
- `"SenseGNAT alert correlation — investigation a1b2c3d4"`
- `"RedGNAT technique validation — T1566.001 spearphishing"`

---

## 7. Property Interaction with Existing Models

| GNAT primitive | Interaction |
|----------------|-------------|
| `Investigation` | `x_gnat_investigation_id` maps to `Investigation.id`. Objects are appended to `Investigation.indicators` or `Investigation.observables` on filing. |
| `EvidenceGraph` | Filed objects are added as nodes in the investigation's `EvidenceGraph`. The `x_gnat_investigation_origin` is stored as the node's `platform` attribute. |
| `Report` | When a Report is generated from an Investigation, all filed objects (including addon-stamped ones) are included in the report's evidence base. Origin metadata flows through to the report. |
| `ConfidenceScore` | `x_gnat_correlation_confidence` maps to `ConfidenceScore.stix_confidence` when GNAT creates an internal correlation record. |
| `Campaign` | Addon-produced objects that are filed into an investigation inherit the investigation's campaign links (if any) via the existing `Investigation.campaigns` association. |

---

*Licensed under the Apache License, Version 2.0*
